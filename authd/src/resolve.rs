//! The resolver: one place that turns a name, a SID or a POSIX identifier into
//! a principal.
//!
//! Every path into authd that needs to know who somebody is comes through here —
//! a lookup on `/run/ident.sock`, and eventually a logon on `/run/logon.sock`.
//! That is the point of it existing rather than each caller doing its own.
//!
//! # Why the authority, and only the authority
//!
//! A source counts POSIX identifiers relative to a range whose base it must not
//! apply. authd adds the base. So the arithmetic that made a number absolute
//! exists in exactly one place, and only that place can invert it — a source
//! answering "who is uid 1001000" would be applying a base it was told to
//! leave alone.
//!
//! # Why one resolver rather than one per caller
//!
//! A bare name may exist in more than one source, and which wins is a property
//! of the machine rather than of any source in it. If two components resolved
//! separately they could disagree, and a program acting on one principal's
//! behalf while checking another's access is a confused deputy, not a cosmetic
//! inconsistency.
//!
//! # No cache
//!
//! Every lookup is a live PSI round trip. A cache is invisible on both wires —
//! authd's own answer and the source's are unchanged by one — so deferring it
//! costs nothing later, and a cache designed before the real query pattern is
//! known caches the wrong things.
//!
//! The consequence is real and expected: under proxy-only, listing a large
//! directory is slow. What is *not* deferred is the pair of properties a cache
//! will need — [`Outcome::Unavailable`] distinguished from [`Outcome::NotFound`]
//! here, and `Changed` accepted on the PSI side — because retrofitting either
//! would be a change of behaviour rather than an addition.

use std::sync::Arc;
use std::time::Duration;

use libauthd::ident::{Fields, Kind, Outcome, Reference, Value, Withheld, WithheldReason};
use libauthd::psi;
use peios::security::SidRef;

use crate::log;
use crate::source::{Inbound, Registry, Slot, Source};
use crate::well_known;

/// How long a source has to answer a lookup.
///
/// Shorter than a logon's budget, and deliberately: nothing is waiting on a
/// human here, and a name resolver is called synchronously from every process on
/// the system. A lookup that hangs stalls a caller that cannot be told why.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How much of the identity surface a caller may ask for at once.
///
/// Every source is asked for exactly the fields the caller wanted, so this
/// bounds nothing an authority does for itself — it is here to keep an
/// unrecognised bit from reaching a source that would have to reject it.
const KNOWN: Fields = Fields::KNOWN;

/// What a lookup produced.
pub struct Answer {
    pub outcome: Outcome,
    pub record: Option<libauthd::ident::Record>,
}

impl Answer {
    fn of(outcome: Outcome) -> Self {
        Self {
            outcome,
            record: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Resolve one key.
pub fn lookup(
    registry: &Registry,
    key: &libauthd::ident::Key,
    kind: Kind,
    fields: Fields,
) -> Answer {
    let fields = fields.intersection(KNOWN);
    // One budget for the whole request, however many sources answer it
    // (§2.14, obligation 31).
    let deadline = std::time::Instant::now() + QUERY_TIMEOUT;
    match key {
        libauthd::ident::Key::Name(name) => by_name(registry, name, kind, fields, deadline),
        libauthd::ident::Key::Sid(bytes) => match SidRef::from_bytes(bytes) {
            Some(sid) => by_sid(registry, sid, kind, fields, deadline),
            None => Answer::of(Outcome::Malformed),
        },
        libauthd::ident::Key::UnixId(id) => by_unix_id(registry, *id, kind, fields, deadline),
    }
}

/// A bare name, resolved in the configured order.
///
/// Two rules do the work, and both are about *not* falling through:
///
/// - A source that answers `Refused` ends the search. It holds the object and
///   declined to describe it; consulting the next source would hand back a
///   *different* principal that happens to share the name.
/// - A source that could not be reached makes the whole answer `Unavailable`,
///   even if a later source holds a matching name. Returning the later one would
///   resolve the name to a different SID than it does when the system is
///   healthy, so access decisions would be made against the wrong principal
///   precisely while something is broken.
fn by_name(
    registry: &Registry,
    name: &str,
    kind: Kind,
    fields: Fields,
    deadline: std::time::Instant,
) -> Answer {
    // Before the well-known lookup, not after. `well_known::by_name` trims, so
    // `" Everyone "` was answered `Found` where obligation 35 requires refusal
    // for a leading or trailing space.
    if !name_is_usable(name) {
        return Answer::of(Outcome::Malformed);
    }
    if let Some(answer) = well_known_by_name(name, kind, fields) {
        return answer;
    }

    for slot in registry.slots() {
        let source = match slot {
            Slot::Live(source) => source,
            // Configured and not here. Everything behind it is unreachable: a
            // name a later source holds is a *different* principal, so answering
            // from there would resolve it to a SID this machine does not give
            // when it is healthy — and access decisions would then be made
            // against the wrong person, precisely while something is broken.
            Slot::Absent(name) => {
                log::warn(format_args!(
                    "ident: {name} is configured and not registered; a name it \
                     might hold cannot be resolved from further down the order"
                ));
                return Answer::of(Outcome::Unavailable);
            }
        };
        match ask(
            &source,
            psi::Key::Name(name.to_string()),
            kind,
            fields,
            deadline,
        ) {
            Reply::Found(entry) => return found(&source, &entry, kind, fields),
            Reply::NotFound => continue,
            // A source refused. That is a fact about the source, identical for
            // every caller, so it is Unavailable — see the note on Reply.
            Reply::Refused => return Answer::of(Outcome::Unavailable),
            Reply::Unavailable => return Answer::of(Outcome::Unavailable),
        }
    }
    Answer::of(Outcome::NotFound)
}

/// A SID needs no search: it names its own domain, and identity confinement
/// makes at most one source authoritative for it.
/// Where a logon conversation should be sent (PSI §2.11).
///
/// One source, decided on the identifier before any credential exists —
/// never by trying sources in turn with the password, which is the PAM
/// stacking failure §2.11 exists to prevent.
pub enum Route {
    /// This source claims the identifier — or is the only source configured,
    /// in which case there is nothing to decide and nothing is asked.
    Owner(Arc<Source>),
    /// No configured source claims the identifier. The conversation still
    /// goes to this source — the first in the search order — because an
    /// authority MUST NOT distinguish an unknown principal from a bad
    /// credential (PGSS §2.10), by denial code or by observable behaviour.
    /// A short-circuit denial here would let anyone who can reach the
    /// socket test which names exist; a source runs its own blinded
    /// conversation for a name it does not hold and denies at the end,
    /// which is indistinguishable from a wrong password. Exactly one
    /// source sees the credential either way.
    Blind(Arc<Source>),
    /// The search order could not be walked to a decision: a configured
    /// source is absent, or one that had to answer could not. Falling
    /// through is forbidden — a name that resolves differently while
    /// something is broken has its authority chosen by whoever broke it —
    /// so the logon is denied `AuthorityUnavailable`, which is honest: an
    /// outage is not a secret the way a principal's existence is.
    Unavailable,
    /// Nothing is registered at all. "No sources means no accounts" — a
    /// denial, not a hang.
    NoSources,
}

/// Decide which single source answers a logon for `identifier`.
///
/// The same two no-fall-through rules as [`by_name`], because they guard the
/// same property: which principal a name means must not depend on what
/// happens to be broken. The resolution query carries no credential — asking
/// each source "do you own this name?" is the step §2.11 explicitly permits.
///
/// Well-known names are deliberately not consulted: nobody logs on as
/// `Everyone`, and a source cannot own a well-known SID, so such a name
/// takes the blind path and fails authentication like any other name nobody
/// holds.
pub fn route(registry: &Registry, identifier: &[u8]) -> Route {
    // Interpreted as a name because IdentifierType has one variant. A SID
    // identifier, when one exists, routes by domain containment
    // (`Registry::owning`) instead — a different mechanism, decided then.
    let name = String::from_utf8_lossy(identifier);

    // A name no source could hold — malformed, oversized — still gets the
    // blind conversation rather than a distinct refusal, for the same
    // enumeration-resistance reason as an unknown one.
    let usable = name_is_usable(&name);

    // One configured source is the degenerate case with no routing question:
    // every conversation goes there, exactly as before routing existed, and
    // no resolution round trip is added to the common deployment. This is
    // also what keeps a single logon-only source (no QUERIES capability)
    // usable — it cannot answer "do you own this name?", and with nobody
    // else configured the answer cannot matter.
    let slots = registry.slots();
    if let [slot] = slots.as_slice() {
        return match slot {
            Slot::Live(source) => Route::Owner(Arc::clone(source)),
            Slot::Absent(absent) => {
                log::warn(format_args!(
                    "logon: {absent} is configured and not registered; no logon \
                     can be answered"
                ));
                Route::Unavailable
            }
        };
    }

    let deadline = std::time::Instant::now() + QUERY_TIMEOUT;
    let mut fallback: Option<Arc<Source>> = None;
    for slot in slots {
        let source = match slot {
            Slot::Live(source) => source,
            Slot::Absent(absent) => {
                log::warn(format_args!(
                    "logon: {absent} is configured and not registered; a principal \
                     it might hold cannot be routed from further down the order"
                ));
                return Route::Unavailable;
            }
        };
        if fallback.is_none() {
            fallback = Some(Arc::clone(&source));
        }
        if !usable {
            continue;
        }
        match ask(
            &source,
            psi::Key::Name(name.to_string()),
            Kind::Principal,
            Fields::empty(),
            deadline,
        ) {
            Reply::Found(_) => return Route::Owner(source),
            Reply::NotFound => continue,
            // A source that had to answer and could not — including one that
            // declared no QUERIES capability, which can never say who it
            // holds. Continuing past it would fall through a name it might
            // own.
            Reply::Refused | Reply::Unavailable => return Route::Unavailable,
        }
    }

    match fallback {
        Some(source) => Route::Blind(source),
        None => Route::NoSources,
    }
}

fn by_sid(
    registry: &Registry,
    sid: &SidRef,
    kind: Kind,
    fields: Fields,
    deadline: std::time::Instant,
) -> Answer {
    if let Some(answer) = well_known_by_sid(sid, kind, fields) {
        return answer;
    }
    let Some(source) = registry.owning(sid) else {
        // No registered source claims this domain. Ordinarily that is an honest
        // absence — a file may well be owned by a principal of a domain this
        // machine has never heard of.
        //
        // But an unpinned source declares its domain when it registers, so an
        // absent one's domain is unknowable from configuration. With any source
        // missing, "nobody owns this" cannot be distinguished from "the source
        // that owns it is not here", and only the second is safe to cache.
        return Answer::of(if registry.complete() {
            Outcome::NotFound
        } else {
            Outcome::Unavailable
        });
    };
    match ask(
        &source,
        psi::Key::Sid(sid.as_bytes().to_vec()),
        kind,
        fields,
        deadline,
    ) {
        Reply::Found(entry) => found(&source, &entry, kind, fields),
        Reply::NotFound => Answer::of(Outcome::NotFound),
        Reply::Refused => Answer::of(Outcome::Unavailable),
        Reply::Unavailable => Answer::of(Outcome::Unavailable),
    }
}

/// The inversion no source can perform for itself.
fn by_unix_id(
    registry: &Registry,
    id: u32,
    kind: Kind,
    fields: Fields,
    deadline: std::time::Instant,
) -> Answer {
    if let Some(answer) = well_known_by_unix_id(id, kind, fields) {
        return answer;
    }
    let Some((source, relative)) = registry.rebasing(id) else {
        // A range is configured rather than declared, so an absent source's is
        // known exactly — which makes this the precise answer rather than the
        // conservative one the SID path has to give.
        return Answer::of(match registry.configured_range(id) {
            Some(entry) => {
                log::warn(format_args!(
                    "ident: {id} belongs to {}, which is configured and not registered",
                    entry.name
                ));
                Outcome::Unavailable
            }
            None => Outcome::NotFound,
        });
    };
    match ask(
        &source,
        psi::Key::RelativeId(relative),
        kind,
        fields,
        deadline,
    ) {
        Reply::Found(entry) => found(&source, &entry, kind, fields),
        Reply::NotFound => Answer::of(Outcome::NotFound),
        Reply::Refused => Answer::of(Outcome::Unavailable),
        Reply::Unavailable => Answer::of(Outcome::Unavailable),
    }
}

// ---------------------------------------------------------------------------
// Well-known principals
//
// Numbered below every source's base, in the band authd reserves for its own.
// No source is authoritative for them, so they are answered here and never
// asked about — which is also what stops two sources both claiming `Everyone`.
// ---------------------------------------------------------------------------

fn well_known_by_name(name: &str, kind: Kind, fields: Fields) -> Option<Answer> {
    let sid = well_known::by_name(name)?;
    well_known_answer(sid.as_ref(), kind, fields)
}

fn well_known_by_sid(sid: &SidRef, kind: Kind, fields: Fields) -> Option<Answer> {
    well_known::name_of(sid)?;
    well_known_answer(sid, kind, fields)
}

fn well_known_by_unix_id(id: u32, kind: Kind, fields: Fields) -> Option<Answer> {
    let sid = well_known::by_unix_id(id)?;
    well_known_answer(sid.as_ref(), kind, fields)
}

fn well_known_answer(sid: &SidRef, kind: Kind, fields: Fields) -> Option<Answer> {
    let name = well_known::name_of(sid)?;

    // Every one of these is a group. `SYSTEM` is the awkward case — it is a
    // principal that services run as — but nothing looks it up as one, and a
    // token's uid 0 is projected rather than resolved.
    if !Kind::Group.satisfies(kind) {
        return Some(Answer::of(Outcome::NotFound));
    }

    let mut values = Vec::new();
    let mut withheld = Vec::new();

    if fields.contains(Fields::UNIX_ID) {
        match well_known::unix_id(sid) {
            Some(id) => values.push(Value::UnixId(id)),
            // A logon SID: `Interactive`, `Network`, and the rest. They are not
            // groups in the POSIX sense — membership is a property of a session
            // rather than of an account — so they carry no number.
            None => withheld.push(Withheld {
                field: Fields::UNIX_ID,
                reason: WithheldReason::Absent,
            }),
        }
    }
    // Nothing records who is in these; authd staples them onto a token at
    // derivation. Absent rather than declined — declining would suggest an
    // answer exists somewhere and is being kept back.
    for field in KNOWN
        .difference(Fields::UNIX_ID)
        .intersection(fields)
        .iter()
    {
        withheld.push(Withheld {
            field,
            reason: WithheldReason::Absent,
        });
    }

    Some(Answer {
        outcome: Outcome::Found,
        record: Some(libauthd::ident::Record {
            sid: sid.as_bytes().to_vec(),
            qualified_name: name.to_string(),
            kind_found: Kind::Group,
            values,
            withheld,
        }),
    })
}

// ---------------------------------------------------------------------------
// Asking a source
// ---------------------------------------------------------------------------

enum Reply {
    Found(psi::QueryEntry),
    NotFound,
    Refused,
    /// The source did not answer. Never cacheable, and never a reason to try the
    /// next source in the order.
    Unavailable,
}

/// The fields a source has declared it can answer.
fn gated_fields(source: &Arc<Source>, fields: Fields) -> Fields {
    if source.capabilities().contains(psi::Capabilities::MEMBERS) {
        fields
    } else {
        fields.difference(Fields::MEMBERS)
    }
}

fn ask(
    source: &Arc<Source>,
    key: psi::Key,
    kind: Kind,
    fields: Fields,
    deadline: std::time::Instant,
) -> Reply {
    // §2.14, obligation 31: the time bound is on the *request*, not on each
    // source consulted for it. A walk across N slow-but-live sources used
    // to take N × QUERY_TIMEOUT; every ask now spends from one budget, and
    // a source reached with nothing left is Unavailable without a wire
    // round trip — the same answer its timeout would have produced.
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Reply::Unavailable;
    }
    // A source that did not declare it answers queries is not asked one. That is
    // what keeps a source written against an earlier PSI working untouched.
    //
    // It must not be recorded as having answered, though. Returning NotFound
    // let a source that was **never consulted** contribute a "no" to an
    // authoritative, cacheable absence — which obligation 41 forbids outright:
    // a source that was never consulted is not evidence that an object does not
    // exist. The enumeration path already gets the equivalent case right, by
    // appending such a source to `incomplete`.
    //
    // Declining is permanent rather than an outage, so `Unavailable` is not
    // comfortable either — it implies "try again" for something that will never
    // succeed. It is still the honest answer of the two, and the condition is
    // warned about at registration where an administrator can see it.
    if !source.capabilities().contains(psi::Capabilities::QUERIES) {
        return Reply::Unavailable;
    }

    let Some(mut conversation) = source.open() else {
        return Reply::Unavailable;
    };
    let query = psi::Query {
        // Obligation 34: an authority MUST NOT set a field bit gating a
        // capability the source did not declare. MEMBERS was defined, declared
        // by lpsd, and read by nothing — so it was set against every source
        // regardless.
        fields: gated_fields(source, fields),
        keys: vec![psi::QueryKey { key, kind }],
    };
    if let Err(error) = conversation.query(&query) {
        log::warn(format_args!("ident: {}: {error}", source.name()));
        return Reply::Unavailable;
    }

    let entry = match conversation.recv(remaining) {
        Ok(Inbound::Results(result)) => {
            conversation.finished();
            match result.results.into_iter().next() {
                Some(entry) => entry,
                None => {
                    log::warn(format_args!(
                        "ident: {}: answered one key with no results",
                        source.name()
                    ));
                    return Reply::Unavailable;
                }
            }
        }
        Ok(Inbound::Refuse(_)) => {
            conversation.finished();
            return Reply::Refused;
        }
        Ok(other) => {
            log::warn(format_args!(
                "ident: {}: answered a lookup with {other:?}",
                source.name()
            ));
            return Reply::Unavailable;
        }
        Err(stalled) => {
            log::warn(format_args!("ident: {}: {stalled:?}", source.name()));
            return Reply::Unavailable;
        }
    };

    match entry.outcome {
        Outcome::Found => Reply::Found(entry),
        Outcome::NotFound => Reply::NotFound,
        // §2.18 reserves Refused for "the caller may not make this request".
        // A source refusing is not that: it is a fact about the source,
        // identical for every caller, and the honest answer to the caller is
        // that a party which could have answered did not. Relaying it as
        // Refused let a client conclude that asking again on this principal's
        // behalf was pointless — the same damage as reporting it NotFound,
        // aimed at one caller instead of all of them.
        Outcome::Refused => Reply::Refused,
        // The decoder refuses these from a source, so reaching here would mean
        // the codec had changed underneath this match.
        Outcome::Unavailable | Outcome::Malformed => Reply::Unavailable,
    }
}

// ---------------------------------------------------------------------------
// Turning a source's answer into the authority's
// ---------------------------------------------------------------------------

/// Rebase, qualify and confine what a source said.
///
/// Three things happen here that a source cannot do for itself, and one that it
/// must not be trusted to have done:
///
/// - **Rebasing.** Every number a source states is relative; authd adds the base.
/// - **Qualification.** A source states its own spelling of a name and cannot
///   know what it is called in this machine's order.
/// - **Confinement.** A SID outside the source's domain is refused, exactly as
///   in an assertion. A query is not a weaker channel than a logon: a source
///   that could name another domain's principals here would have `ls -l` show
///   them as its own, and be believed the next time something compared that name
///   to a SID.
fn found(source: &Arc<Source>, entry: &psi::QueryEntry, wanted: Kind, fields: Fields) -> Answer {
    let Some(sid) = SidRef::from_bytes(&entry.sid) else {
        log::error(format_args!(
            "ident: {}: answered with bytes that are not a SID",
            source.name()
        ));
        return Answer::of(Outcome::Unavailable);
    };
    // Obligation 35: a name is refused "whether created locally, received in a
    // request, asserted by a source, or carried alongside a SID in a
    // reference". Only the request side was checked — and the request side is a
    // string a caller already had, while this one crosses a trust boundary into
    // a name resolver that renders it into a passwd-format record and into
    // authd's own log.
    //
    // The rationale is that the damage is done by the *reader*: a name carrying
    // a newline can forge a whole line in a passwd file, an audit record or a
    // log, and that cannot be prevented at the point the name is displayed. A
    // source is inside the TCB but is its lowest-trust part, and the thing a
    // third party is invited to write.
    if !name_is_usable(&entry.canonical_name) {
        log::error(format_args!(
            "ident: {}: answered with a name that is not usable, refusing the answer",
            source.name()
        ));
        return Answer::of(Outcome::Unavailable);
    }

    // Obligation 38: a Principal request is never answered with a group or
    // vice versa, and kind_found is Principal or Group, never Any. The
    // authority establishes that for itself rather than relaying the source's
    // answer and letting the client discover the mismatch.
    //
    // POSIX keeps users and groups in separate namespaces, which is why kind is
    // on the request at all: getpwnam and getgrnam can be asked the same string
    // and must get different objects. Relaying the wrong kind made
    // getpwnam("staff") return a group rendered as a struct passwd, with the
    // group's identifier in pw_uid.
    if entry.kind == Kind::Any {
        log::error(format_args!(
            "ident: {}: answered with kind Any, which is a valid question and not a valid answer",
            source.name()
        ));
        return Answer::of(Outcome::Unavailable);
    }
    if !entry.kind.satisfies(wanted) {
        log::warn(format_args!(
            "ident: {}: answered a {wanted:?} request with a {:?}",
            source.name(),
            entry.kind
        ));
        return Answer::of(Outcome::NotFound);
    }
    if !crate::domain::contains(source.domain().as_ref(), sid) {
        log::error(format_args!(
            "ident: {}: answered for {sid}, which is outside its domain {}",
            source.name(),
            source.domain()
        ));
        return Answer::of(Outcome::Unavailable);
    }

    let range = source.unix_id_range();
    let mut values = Vec::new();

    for value in &entry.values {
        values.push(match value {
            Value::UnixId(relative) => match range.and_then(|r| r.rebase(*relative)) {
                Some(absolute) => Value::UnixId(absolute),
                // Out of range, or the source has no range at all. Zero is the
                // protocol's only encoding of "no number for this SID"
                // (obligation 43), and substituting 65534 here destroyed that:
                // a client reads nobody/nogroup as a real identifier and cannot
                // tell "no source numbers this SID" from "genuinely numbered
                // 65534". Rendering the sentinel as `nobody` is a display
                // decision and belongs to nss, which already makes it.
                None => Value::UnixId(0),
            },
            Value::PrimaryGroup(reference) => Value::PrimaryGroup(rebase_ref(source, reference)),
            Value::Groups(refs) => Value::Groups(permitted_refs(source, sid, refs)),
            Value::Members(refs) => Value::Members(permitted_refs(source, sid, refs)),
            other => other.clone(),
        });
    }

    Answer {
        outcome: Outcome::Found,
        record: Some(libauthd::ident::Record {
            sid: entry.sid.clone(),
            qualified_name: qualify(source, &entry.canonical_name),
            kind_found: entry.kind,
            values,
            withheld: entry
                .withheld
                .iter()
                .filter(|w| fields.contains(w.field))
                .copied()
                .collect(),
        }),
    }
}

/// Rebase a reference, or give it authd's own number where authd owns it.
///
/// A source sends zero for a group it does not number — a well-known one it is
/// merely naming a membership in. authd's own table decides those, and applying
/// the source's base to `BUILTIN\Administrators` would land it inside the
/// source's range where it does not belong.
fn rebase_ref(source: &Arc<Source>, reference: &Reference) -> Reference {
    let unix_id = match SidRef::from_bytes(&reference.sid) {
        Some(sid) => well_known::unix_id(sid).or_else(|| {
            source
                .unix_id_range()
                .and_then(|range| range.rebase(reference.unix_id))
        }),
        None => None,
    };
    let name = match (
        reference.name.is_empty(),
        SidRef::from_bytes(&reference.sid),
    ) {
        (true, Some(sid)) => well_known::name_of(sid).unwrap_or_default().to_string(),
        _ => reference.name.clone(),
    };
    Reference {
        sid: reference.sid.clone(),
        name,
        // Zero, not UNMAPPED: see the note on Value::UnixId above.
        unix_id: unix_id.unwrap_or(0),
    }
}

/// A reference the source is not permitted to report, if any.
///
/// PSI authority obligation 37 requires identity confinement, membership scope
/// and numeric scope to be applied to a `QueryResult` exactly as to an
/// `Assertion`. Membership scope was applied on the logon path and nowhere
/// else, so a source with no foreign-membership permission could report
/// `BUILTIN\Administrators` in a group list over `/run/ident.sock` and have
/// authd relay it — confined on the channel that mints tokens and unconfined on
/// the channel that describes them.
///
/// That is worse than the inconsistency suggests. A POSIX-shaped tool reads
/// group membership from the name-resolution path and treats it as an
/// access-control input, because on other systems that path *is* the authority.
fn permitted_refs(source: &Arc<Source>, subject: &SidRef, refs: &[Reference]) -> Vec<Reference> {
    let scoped = !source.may_assert_foreign_memberships();
    refs.iter()
        .filter(|r| {
            // Rule 1 / obligation 37: every SID in a result is validated
            // structurally, including those inside a PRIMARY_GROUP, GROUPS or
            // MEMBERS reference — not only the `sid` of the result itself. The
            // logon path already did this; the lookup path validated the outer
            // SID and relayed whatever the references carried, so bytes that do
            // not parse as a SID went out to the caller.
            //
            // This runs for every source, permitted or not: the foreign-
            // membership permission says which *domains* a source may name, not
            // whether its bytes have to be a SID.
            let Some(sid) = SidRef::from_bytes(&r.sid) else {
                log::error(format_args!(
                    "ident: {}: reference of {} bytes is not a SID, dropping it",
                    source.name(),
                    r.sid.len()
                ));
                return false;
            };
            // Obligation 35 covers a name "carried alongside a SID in a
            // reference" as much as a canonical one. An empty name is not a
            // claim — `rebase_ref` fills it from the well-known table — so only
            // a non-empty one is held to the rule.
            if !r.name.is_empty() && !name_is_usable(&r.name) {
                log::error(format_args!(
                    "ident: {}: reference for {sid} carries a name that is not usable, \
                     dropping it",
                    source.name()
                ));
                return false;
            }
            // A reference that fails scope is dropped from the value rather
            // than failing the whole lookup: a name lookup is not a logon, and
            // the caller is better served by a short list than by Unavailable.
            // It must not be relayed either way.
            if scoped && !crate::domain::siblings(subject, sid) {
                log::error(format_args!(
                    "ident: {}: reported {sid} for {subject}, outside that principal's \
                     domain, and it may not assert foreign memberships",
                    source.name()
                ));
                return false;
            }
            true
        })
        .map(|r| rebase_ref(source, r))
        .collect()
}

/// The name authd hands out, whatever the caller asked with.
///
/// Bare today: no realm syntax exists, so there is nothing to qualify a name
/// with and inventing one now would bake in a spelling before the design that
/// decides it. What the caller can always rely on is the **SID** alongside it,
/// which is unambiguous by construction — and when realms arrive this is the one
/// function that changes.
fn qualify(_source: &Arc<Source>, canonical: &str) -> String {
    canonical.to_string()
}

/// Whether a name could name anything.
///
/// The reserved characters of PGSS §2.15. Refusing here rather than passing it
/// on means a source is never asked about a name no source is permitted to hold,
/// and it makes `jack@local` a clean refusal rather than a mysterious absence
/// once realms exist.
fn name_is_usable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= libauthd::ident::MAX_NAME_BYTES
        && name.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !name.bytes().any(|b| RESERVED_IN_NAME.contains(&b))
        && name.trim() == name
}

const RESERVED_IN_NAME: &[u8] = b"@\\/:,";

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// One page of every principal or group the machine can name.
///
/// The cursor names a source and carries that source's own opaque cursor inside
/// it, so a walk crosses sources one at a time and each source's paging stays
/// its own. authd never constructs or parses what a source issued.
pub struct Page {
    pub entries: Vec<libauthd::ident::Record>,
    pub next: Vec<u8>,
    /// Sources that declined or could not be reached. A short list that looks
    /// complete is what this exists to prevent.
    pub incomplete: Vec<String>,
}

/// Enumerate one page, or report that the cursor cannot be honoured.
///
/// `Err(Outcome::Malformed)` is obligation 49: an authority rejects a cursor it
/// did not issue, or can no longer honour, with `Malformed` — and specifically
/// must not silently restart the walk, nor answer with an empty page and an
/// empty `next` that reads as completion.
///
/// The code here used to do both, reasoning that "refusing would strand a
/// caller". It would, and that is the correct outcome: a client presenting a
/// cursor the authority cannot honour has already lost its place, and the only
/// honest answers are to say so or to start again *knowingly*. Restarting
/// silently hands back a second copy of the beginning appended to what the
/// caller already has, with no way to detect it.
pub fn enumerate(
    registry: &Registry,
    kind: Kind,
    fields: Fields,
    cursor: &[u8],
) -> Result<Page, Outcome> {
    let fields = fields.intersection(KNOWN);
    let deadline = std::time::Instant::now() + QUERY_TIMEOUT;
    let sources = registry.ordered();
    let (resume, inner) = match split_cursor(cursor) {
        Some(split) => split,
        None => return Err(Outcome::Malformed),
    };

    let mut entries = Vec::new();
    let mut incomplete = Vec::new();
    let mut inner = inner.to_vec();
    // Everything before the named source was walked on an earlier page. A source
    // that has appeared since is skipped rather than restarting the walk: its
    // absence from earlier pages is what `incomplete` is for.
    let mut reached = resume.is_none();

    for name in registry.absent() {
        // A source that is configured and not here contributed nothing, and a
        // listing that did not say so would look complete.
        incomplete.push(name);
    }

    for source in &sources {
        if !reached {
            if Some(source.name()) == resume.as_deref() {
                reached = true;
            } else {
                continue;
            }
        }
        if !source
            .capabilities()
            .contains(psi::Capabilities::ENUMERATES)
        {
            incomplete.push(source.name().to_string());
            continue;
        }
        match page_from(source, kind, fields, &inner, deadline) {
            Some(page) => {
                for entry in &page.entries {
                    if let Answer {
                        record: Some(record),
                        ..
                    } = found(source, entry, kind, fields)
                    {
                        entries.push(record);
                    }
                }
                if !page.next.is_empty() {
                    // More from this source. Resume here rather than moving on.
                    return Ok(Page {
                        entries,
                        next: make_cursor(source.name(), &page.next),
                        incomplete,
                    });
                }
            }
            None => incomplete.push(source.name().to_string()),
        }
        // Finished with this source; the next one starts from its own beginning.
        inner.clear();
    }

    // A cursor naming a source that is no longer in the order. The walk never
    // reached it, so every remaining source was skipped and the reply would be
    // an empty page with an empty `next` — which a client is required to read
    // as "the enumeration is complete". A truncated walk reported as a whole
    // one is exactly what obligation 49 exists to prevent.
    if !reached {
        log::warn(format_args!(
            "ident: enumeration cursor names {:?}, which is not in the source order",
            resume
        ));
        return Err(Outcome::Malformed);
    }

    Ok(Page {
        entries,
        next: Vec::new(),
        incomplete,
    })
}

/// Walk one group's members — `Enumerate` with `of` (PGSS §2.17), the
/// continuation path for a `MEMBERS` field withheld as `TooLarge`.
///
/// Members of one group are a lookup that overflowed, so this goes to the
/// **owning source only**, never across the order: the group is one object,
/// and exactly one source is authoritative for it. The client's cursor is
/// relayed to that source verbatim and its `next` comes back the same way —
/// opaque at both hops, and re-derived from `of` each page, so there is no
/// state to hold between requests.
///
/// The group is resolved before each page is fetched. That is one extra
/// round trip on a path only ever walked after a `TooLarge` withhold, and it
/// buys the answer's honesty: "no such group" must be `NotFound`, and
/// without the resolution step it would be indistinguishable from a
/// source-side refusal. Well-known groups come back `NotFound` too — their
/// membership is a rule, not a record, and no source can enumerate a rule.
pub fn enumerate_members(
    registry: &Registry,
    of: &libauthd::ident::Key,
    kind: Kind,
    fields: Fields,
    cursor: &[u8],
) -> Result<Page, Outcome> {
    let fields = fields.intersection(KNOWN);
    let deadline = std::time::Instant::now() + QUERY_TIMEOUT;
    let (source, key) = owning_group_source(registry, of, deadline)?;

    if !source
        .capabilities()
        .contains(psi::Capabilities::ENUMERATES)
    {
        // The one source that could answer declared it never will. For the
        // whole-table walk that is an `incomplete` entry; here it is the
        // whole answer.
        return Err(Outcome::Unavailable);
    }

    let mut conversation = source.open().ok_or(Outcome::Unavailable)?;
    let request = psi::EnumerateSource {
        kind,
        fields,
        of: Some(key),
        cursor: cursor.to_vec(),
    };
    if conversation.enumerate(&request).is_err() {
        return Err(Outcome::Unavailable);
    }
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let page = match conversation.recv(remaining) {
        Ok(Inbound::Page(page)) => {
            conversation.finished();
            page
        }
        Ok(Inbound::Refuse(_)) => {
            conversation.finished();
            return Err(Outcome::Unavailable);
        }
        _ => return Err(Outcome::Unavailable),
    };
    match page.outcome {
        Outcome::Found => {}
        // The group exists — the resolution above said so — and the
        // semantic refusals lpsd documents are all "no such group here", so
        // what remains is a cursor this walk did not issue. Saying so lets
        // the client restart deliberately, exactly as the whole-table walk
        // does.
        Outcome::Refused => return Err(Outcome::Malformed),
        _ => return Err(Outcome::Unavailable),
    }

    let mut entries = Vec::new();
    for entry in &page.entries {
        if let Answer {
            record: Some(record),
            ..
        } = found(&source, entry, kind, fields)
        {
            entries.push(record);
        }
    }
    Ok(Page {
        entries,
        next: page.next,
        incomplete: Vec::new(),
    })
}

/// Which single source holds this key **as a group**, and the key as that
/// source is asked it.
///
/// The same ownership rules as the lookup paths, minus the well-known
/// layer: nothing here answers for an object no source holds. Every arm
/// ends by asking the candidate source whether the key names a group it
/// actually has, which is what makes the caller's `NotFound` honest — a
/// key naming a *principal* is `NotFound` here too, because §2.17 requires
/// the named object to be a group and there is no enumerable group by that
/// key.
fn owning_group_source(
    registry: &Registry,
    of: &libauthd::ident::Key,
    deadline: std::time::Instant,
) -> Result<(Arc<Source>, psi::Key), Outcome> {
    let (source, key) = match of {
        libauthd::ident::Key::Name(name) => {
            if !name_is_usable(name) {
                return Err(Outcome::Malformed);
            }
            // A name is owned by whichever source claims it first in the
            // order, with by_name's no-fall-through rules.
            for slot in registry.slots() {
                let source = match slot {
                    Slot::Live(source) => source,
                    Slot::Absent(_) => return Err(Outcome::Unavailable),
                };
                match ask(
                    &source,
                    psi::Key::Name(name.clone()),
                    Kind::Group,
                    Fields::empty(),
                    deadline,
                ) {
                    Reply::Found(_) => return Ok((source, psi::Key::Name(name.clone()))),
                    Reply::NotFound => continue,
                    Reply::Refused | Reply::Unavailable => return Err(Outcome::Unavailable),
                }
            }
            return Err(Outcome::NotFound);
        }
        libauthd::ident::Key::Sid(bytes) => {
            let Some(sid) = SidRef::from_bytes(bytes) else {
                return Err(Outcome::Malformed);
            };
            match registry.owning(&sid) {
                Some(source) => (source, psi::Key::Sid(bytes.clone())),
                None if registry.complete() => return Err(Outcome::NotFound),
                None => return Err(Outcome::Unavailable),
            }
        }
        libauthd::ident::Key::UnixId(id) => match registry.rebasing(*id) {
            Some((source, relative)) => (source, psi::Key::RelativeId(relative)),
            None => {
                return Err(match registry.configured_range(*id) {
                    Some(_) => Outcome::Unavailable,
                    None => Outcome::NotFound,
                });
            }
        },
    };

    match ask(&source, key.clone(), Kind::Group, Fields::empty(), deadline) {
        Reply::Found(_) => Ok((source, key)),
        Reply::NotFound => Err(Outcome::NotFound),
        Reply::Refused | Reply::Unavailable => Err(Outcome::Unavailable),
    }
}

fn page_from(
    source: &Arc<Source>,
    kind: Kind,
    fields: Fields,
    cursor: &[u8],
    deadline: std::time::Instant,
) -> Option<psi::EnumerateResult> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return None;
    }
    let mut conversation = source.open()?;
    let request = psi::EnumerateSource {
        kind,
        fields,
        of: None,
        cursor: cursor.to_vec(),
    };
    if conversation.enumerate(&request).is_err() {
        return None;
    }
    match conversation.recv(remaining) {
        Ok(Inbound::Page(page)) => {
            conversation.finished();
            (page.outcome == Outcome::Found).then_some(page)
        }
        Ok(Inbound::Refuse(_)) => {
            conversation.finished();
            None
        }
        _ => None,
    }
}

/// A cursor is a source's *name* and that source's own bytes.
///
/// The name rather than a position in the order, because a source that
/// disconnects between pages shifts every position after it — and resuming the
/// wrong source with another source's cursor is a silently wrong walk rather
/// than a loud failure. A name identifies exactly one source or none.
///
/// The trailing bytes are the source's and are never looked at.
fn make_cursor(name: &str, inner: &[u8]) -> Vec<u8> {
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(inner);
    out
}

/// `None` for a cursor that does not parse; `Some((None, _))` for an empty one,
/// which begins a walk.
fn split_cursor(cursor: &[u8]) -> Option<(Option<String>, &[u8])> {
    if cursor.is_empty() {
        return Some((None, &[]));
    }
    let (&len, rest) = cursor.split_first()?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    let (name, inner) = rest.split_at(len);
    let name = core::str::from_utf8(name).ok()?;
    Some((Some(name.to_string()), inner))
}

/// The well-known principals, which belong to no source and so appear in no
/// source's enumeration.
///
/// Emitted by authd itself, and only where a caller asked for groups: every one
/// of them that carries a number is a group, and `getgrent` would otherwise
/// never see `Everyone` at all.
pub fn well_known_page(kind: Kind, fields: Fields) -> Vec<libauthd::ident::Record> {
    if kind != Kind::Group {
        return Vec::new();
    }
    well_known::numbered()
        .filter_map(|sid| {
            well_known_answer(sid.as_ref(), kind, fields.intersection(KNOWN))
                .and_then(|answer| answer.record)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::pump_for_test;
    use crate::unix_id;
    use libauthd::ident::{Key, Value};
    use libauthd::transport::{recv_message, send_message};
    use peios::security::Sid;
    use std::os::unix::net::UnixStream;
    use std::thread;

    const DOMAIN: &str = "S-1-5-21-1-2-3";
    const BASE: u32 = 1_000_000;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    /// A source that answers every query with one canned entry.
    ///
    /// Deliberately dumb: what these tests check is what *authd* does to an
    /// answer — rebasing, confinement, ordering — not how a source arrives at
    /// one, which is lpsd's tests.
    fn range() -> unix_id::Range {
        unix_id::Range::new(BASE, 1_000_000).expect("a usable range")
    }

    fn stub(
        name: &str,
        domain: &str,
        order: u32,
        answer: Option<psi::QueryEntry>,
    ) -> Arc<Registry> {
        let registry = Arc::new(Registry::for_test(&[(name, order, Some(range()))]));
        add_stub(&registry, name, domain, order, answer);
        registry
    }

    fn add_stub(
        registry: &Arc<Registry>,
        name: &str,
        domain: &str,
        order: u32,
        answer: Option<psi::QueryEntry>,
    ) {
        add_stub_with_foreign(registry, name, domain, order, answer, false);
    }

    /// A stub permitted to name groups outside the principal's domain, as lpsd
    /// is. Without it, membership scope drops a BUILTIN reference on the
    /// lookup path exactly as it does on the logon path.
    fn add_stub_with_foreign(
        registry: &Arc<Registry>,
        name: &str,
        domain: &str,
        order: u32,
        answer: Option<psi::QueryEntry>,
        foreign: bool,
    ) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let source = registry.admit_for_test_with_foreign(
            name,
            sid(domain),
            Some(range()),
            psi::Capabilities::QUERIES | psi::Capabilities::ENUMERATES,
            order,
            ours,
            foreign,
        );
        thread::spawn(move || serve_stub(theirs, answer));
        pump_for_test(&source);
    }

    /// [`stub`] whose source may assert foreign memberships.
    fn stub_with_foreign(
        name: &str,
        domain: &str,
        order: u32,
        answer: Option<psi::QueryEntry>,
    ) -> Arc<Registry> {
        let registry = Arc::new(Registry::for_test(&[(name, order, Some(range()))]));
        add_stub_with_foreign(&registry, name, domain, order, answer, true);
        registry
    }

    /// The other end of the socketpair: read a query, answer it, repeat.
    fn serve_stub(stream: UnixStream, answer: Option<psi::QueryEntry>) {
        while let Ok(received) = recv_message(&psi::FRAMING, &stream) {
            let Ok(envelope) = psi::decode_envelope(received.expose()) else {
                return;
            };
            let reply = match envelope.msg_type {
                psi::MSG_QUERY => psi::encode_query_result(
                    envelope.conversation,
                    &psi::QueryResult {
                        results: vec![answer.clone().unwrap_or(psi::QueryEntry {
                            outcome: Outcome::NotFound,
                            ..psi::QueryEntry::default()
                        })],
                    },
                ),
                psi::MSG_ENUMERATE_SOURCE => psi::encode_enumerate_result(
                    envelope.conversation,
                    &psi::EnumerateResult {
                        outcome: Outcome::Found,
                        entries: answer.clone().into_iter().collect(),
                        next: Vec::new(),
                    },
                ),
                _ => continue,
            };
            let Ok(reply) = reply else { return };
            if send_message(&stream, &reply).is_err() {
                return;
            }
        }
    }

    fn entry(sid_text: &str, name: &str, relative: u32) -> psi::QueryEntry {
        psi::QueryEntry {
            outcome: Outcome::Found,
            sid: sid(sid_text).as_ref().as_bytes().to_vec(),
            canonical_name: name.into(),
            kind: Kind::Principal,
            values: vec![
                Value::UnixId(relative),
                Value::Home(format!("/home/{name}")),
                Value::Shell("/bin/sh".into()),
            ],
            withheld: Vec::new(),
        }
    }

    /// The arithmetic no source can do for itself: 1000 relative becomes
    /// 1,001,000 absolute, and the inverse takes a caller straight back.
    #[test]
    fn a_relative_number_is_rebased_on_the_way_out() {
        let registry = stub(
            "lpsd",
            DOMAIN,
            1000,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        let answer = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::PASSWD,
        );
        assert_eq!(answer.outcome, Outcome::Found);
        let record = answer.record.expect("a record");
        assert_eq!(
            record.value(Fields::UNIX_ID),
            Some(&Value::UnixId(BASE + 1000)),
            "the source counted from its own zero and authd added the base"
        );
    }

    /// The inversion, and the reason authd is the only party that can perform it.
    #[test]
    fn an_absolute_number_reaches_the_source_that_owns_it() {
        let registry = stub(
            "lpsd",
            DOMAIN,
            1000,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        let answer = lookup(
            &registry,
            &Key::UnixId(BASE + 1000),
            Kind::Principal,
            Fields::UNIX_ID,
        );
        assert_eq!(answer.outcome, Outcome::Found);
        assert_eq!(answer.record.expect("a record").qualified_name, "jack");
    }

    #[test]
    fn a_number_in_no_sources_range_is_not_found() {
        let registry = stub("lpsd", DOMAIN, 1000, None);
        assert_eq!(
            lookup(
                &registry,
                &Key::UnixId(42),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::NotFound
        );
    }

    /// A source that named a principal outside its own domain would have `ls -l`
    /// show another source's people as its own.
    #[test]
    fn an_answer_outside_the_sources_domain_is_refused() {
        let registry = stub(
            "lpsd",
            DOMAIN,
            1000,
            Some(entry("S-1-5-21-9-9-9-1000", "impostor", 1000)),
        );
        let answer = lookup(
            &registry,
            &Key::Name("impostor".into()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(
            answer.outcome,
            Outcome::Unavailable,
            "a source that broke confinement is not to be believed about anything"
        );
    }

    /// Configured order, not registration order — added second, consulted first.
    #[test]
    fn a_bare_name_resolves_in_the_configured_order() {
        let registry = Arc::new(Registry::for_test(&[
            ("second", 2000, Some(range())),
            ("first", 10, Some(range())),
        ]));
        add_stub(
            &registry,
            "second",
            "S-1-5-21-7-7-7",
            2000,
            Some(entry("S-1-5-21-7-7-7-1000", "second-jack", 1000)),
        );
        add_stub(
            &registry,
            "first",
            DOMAIN,
            10,
            Some(entry("S-1-5-21-1-2-3-1000", "first-jack", 1000)),
        );

        let answer = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(
            answer.record.expect("a record").qualified_name,
            "first-jack",
            "the lower SearchOrder wins however the sources registered"
        );
    }

    /// A name held by nobody, asked of everybody.
    #[test]
    fn a_name_no_source_holds_falls_through_every_source() {
        let registry = Arc::new(Registry::for_test(&[
            ("a", 10, Some(range())),
            ("b", 20, Some(range())),
        ]));
        add_stub(&registry, "a", DOMAIN, 10, None);
        add_stub(&registry, "b", "S-1-5-21-7-7-7", 20, None);
        assert_eq!(
            lookup(
                &registry,
                &Key::Name("nobody".into()),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::NotFound
        );
    }

    /// A SID names its own domain, so exactly one source can be authoritative
    /// for it and no search is needed.
    #[test]
    fn a_sid_goes_straight_to_the_source_that_owns_the_domain() {
        let registry = Arc::new(Registry::for_test(&[
            ("wrong", 10, Some(range())),
            ("right", 20, Some(range())),
        ]));
        add_stub(&registry, "wrong", "S-1-5-21-7-7-7", 10, None);
        add_stub(
            &registry,
            "right",
            DOMAIN,
            20,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );

        let answer = lookup(
            &registry,
            &Key::Sid(sid("S-1-5-21-1-2-3-1000").as_ref().as_bytes().to_vec()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(
            answer.record.expect("a record").qualified_name,
            "jack",
            "the source earlier in the order does not get asked at all"
        );
    }

    #[test]
    fn a_sid_from_an_unknown_domain_is_not_found() {
        let registry = stub("lpsd", DOMAIN, 1000, None);
        assert_eq!(
            lookup(
                &registry,
                &Key::Sid(sid("S-1-5-21-8-8-8-1000").as_ref().as_bytes().to_vec()),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::NotFound,
            "a file owned by a domain this machine never heard of is an ordinary thing"
        );
    }

    /// Answered from authd's own table, with no source asked — these numbers are
    /// below every source's base and belong to nobody else.
    #[test]
    fn a_well_known_group_never_reaches_a_source() {
        let registry = Arc::new(Registry::for_test(&[]));
        let answer = lookup(
            &registry,
            &Key::Name("Administrators".into()),
            Kind::Group,
            Fields::UNIX_ID,
        );
        assert_eq!(answer.outcome, Outcome::Found);
        let record = answer.record.expect("a record");
        assert_eq!(record.kind_found, Kind::Group);
        assert_eq!(record.value(Fields::UNIX_ID), Some(&Value::UnixId(102)));
    }

    /// A source that has gone away is `Unavailable`, and the search stops there
    /// — a later source holding the same name would resolve it to a different
    /// SID than it does when the system is healthy.
    #[test]
    fn a_dead_source_earlier_in_the_order_makes_the_answer_unavailable() {
        let registry = Arc::new(Registry::for_test(&[
            ("dead", 10, None),
            ("live", 20, Some(range())),
        ]));
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let dead = registry.admit_for_test(
            "dead",
            sid(DOMAIN),
            None,
            psi::Capabilities::QUERIES,
            10,
            ours,
        );
        drop(theirs);
        pump_for_test(&dead);

        add_stub(
            &registry,
            "live",
            "S-1-5-21-7-7-7",
            20,
            Some(entry("S-1-5-21-7-7-7-1000", "jack", 1000)),
        );

        assert_eq!(
            lookup(
                &registry,
                &Key::Name("jack".into()),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::Unavailable,
            "the later source's principal is a different person"
        );
    }

    /// A source that never declared it answers queries is not asked one, which
    /// is what keeps a source written against an earlier PSI working untouched.
    #[test]
    fn a_source_that_declared_no_capabilities_is_not_queried() {
        let registry = Arc::new(Registry::for_test(&[("old", 10, None)]));
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        registry.admit_for_test(
            "old",
            sid(DOMAIN),
            None,
            psi::Capabilities::empty(),
            10,
            ours,
        );
        // Nothing serves `theirs`, so a query sent here would hang until the
        // timeout — the test finishing promptly is half the assertion.
        let answer = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::empty(),
        );
        drop(theirs);
        // The other half, and the one this ticket is about: a source that was
        // never consulted must not contribute a "no" to an authoritative,
        // cacheable absence. NotFound here would be that source answering a
        // question it was never asked.
        assert_eq!(
            answer.outcome,
            Outcome::Unavailable,
            "a source that declined to be asked has not answered NotFound"
        );
    }

    /// Obligation 34: an authority never sets a field bit gating a capability
    /// the source did not declare. MEMBERS was defined, declared by lpsd, and
    /// read by nothing — so it went out against every source.
    #[test]
    fn members_is_not_asked_of_a_source_that_did_not_declare_it() {
        let registry = Arc::new(Registry::for_test(&[("plain", 10, Some(range()))]));
        let (ours, _theirs) = UnixStream::pair().expect("socketpair");
        let plain = registry.admit_for_test(
            "plain",
            sid(DOMAIN),
            Some(range()),
            psi::Capabilities::QUERIES,
            10,
            ours,
        );
        assert!(
            !gated_fields(&plain, Fields::MEMBERS | Fields::GROUPS).contains(Fields::MEMBERS),
            "MEMBERS must be dropped for a source that did not declare it"
        );
        assert!(
            gated_fields(&plain, Fields::MEMBERS | Fields::GROUPS).contains(Fields::GROUPS),
            "an ungated field must survive"
        );

        let registry2 = Arc::new(Registry::for_test(&[("full", 10, Some(range()))]));
        let (ours2, _theirs2) = UnixStream::pair().expect("socketpair");
        let full = registry2.admit_for_test(
            "full",
            sid(DOMAIN),
            Some(range()),
            psi::Capabilities::QUERIES | psi::Capabilities::MEMBERS,
            10,
            ours2,
        );
        assert!(
            gated_fields(&full, Fields::MEMBERS).contains(Fields::MEMBERS),
            "a source that declared MEMBERS must still be asked for it"
        );
    }

    #[test]
    fn a_name_with_a_reserved_character_never_reaches_a_source() {
        let registry = stub("lpsd", DOMAIN, 1000, None);
        for name in ["jack@local", "PEIOS\\jack", "a/b", "a:b", "a,b", " jack"] {
            assert_eq!(
                lookup(
                    &registry,
                    &Key::Name(name.into()),
                    Kind::Principal,
                    Fields::empty()
                )
                .outcome,
                Outcome::Malformed,
                "{name}"
            );
        }
    }

    /// A group the source does not number gets authd's own value rather than
    /// the source's base, which would land a `BUILTIN` group inside the source's
    /// range where it does not belong.
    #[test]
    fn a_well_known_group_in_a_reply_takes_authds_number() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.values.push(Value::Groups(vec![Reference {
            sid: sid("S-1-5-32-544").as_ref().as_bytes().to_vec(),
            name: "Administrators".into(),
            // Zero: the source names the membership and numbers nothing.
            unix_id: 0,
        }]));
        // lpsd ships with MayAssertForeignMemberships, which is what lets it
        // name a BUILTIN alias for a principal of another domain at all.
        let registry = stub_with_foreign("lpsd", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::GROUPS,
        );
        let record = found.record.expect("a record");
        let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        assert_eq!(
            groups[0].unix_id, 102,
            "authd's table, not the source's base"
        );
    }

    /// Obligation 35: a name is refused "whether created locally, received in a
    /// request, asserted by a source, or carried alongside a SID in a
    /// reference". Only the request side was checked.
    ///
    /// The assertion side is the one that matters: it crosses a trust boundary
    /// into a resolver that renders the name into a passwd-format record and
    /// into authd's own log, and a name carrying a newline forges a whole line
    /// in either. The damage is done by the reader, so it cannot be prevented
    /// where the name is displayed.
    #[test]
    fn a_source_asserting_an_unusable_name_is_refused() {
        for bad in [
            "jack\nroot:x:0:0", // forges a passwd line
            "jack:x",           // a field separator
            "corp\\jack",       // a reserved character
            "jack@local",
            "jack/../root",
            " jack",      // leading space
            "jack ",      // trailing space
            "ja\u{7f}ck", // outside 0x20-0x7e
        ] {
            let answer = entry("S-1-5-21-1-2-3-1000", bad, 1000);
            let registry = stub("corp", DOMAIN, 1000, Some(answer));
            let found = lookup(
                &registry,
                &Key::Sid(sid("S-1-5-21-1-2-3-1000").as_ref().as_bytes().to_vec()),
                Kind::Principal,
                Fields::empty(),
            );
            assert!(
                found.record.is_none(),
                "{bad:?} must not be relayed to a caller"
            );
        }
    }

    /// And a name inside a reference, which the rule names explicitly.
    #[test]
    fn a_reference_carrying_an_unusable_name_is_dropped() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.values.push(Value::Groups(vec![
            Reference {
                sid: sid("S-1-5-21-1-2-3-1001").as_ref().as_bytes().to_vec(),
                name: "staff\nroot:x:0:".into(),
                unix_id: 1001,
            },
            Reference {
                sid: sid("S-1-5-21-1-2-3-1002").as_ref().as_bytes().to_vec(),
                name: "developers".into(),
                unix_id: 1002,
            },
        ]));
        let registry = stub("corp", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::GROUPS,
        );
        let record = found.record.expect("a record");
        let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["developers"]);
    }

    /// `well_known::by_name` trims, so the well-known lookup had to move behind
    /// the usability check — otherwise `" Everyone "` answered `Found` where
    /// the rule requires refusal for a leading or trailing space.
    #[test]
    fn a_well_known_name_with_surrounding_space_is_refused() {
        let registry = stub("corp", DOMAIN, 1000, None);
        for padded in [" Everyone", "Everyone ", " Everyone "] {
            let found = lookup(
                &registry,
                &Key::Name(padded.into()),
                Kind::Group,
                Fields::empty(),
            );
            assert_eq!(
                found.outcome,
                Outcome::Malformed,
                "{padded:?} must be refused, not trimmed into a match"
            );
        }
        // The exact name still resolves.
        let found = lookup(
            &registry,
            &Key::Name("Everyone".into()),
            Kind::Group,
            Fields::empty(),
        );
        assert_eq!(found.outcome, Outcome::Found);
    }

    /// Rule 1 / obligation 37: every SID in a result is validated
    /// structurally, including those inside a reference. The logon path did
    /// this; the lookup path validated only the outer `sid`, so bytes that do
    /// not parse as a SID were relayed to the caller.
    ///
    /// The check runs regardless of the foreign-membership permission — that
    /// permission says which *domains* a source may name, not whether its bytes
    /// have to be a SID.
    #[test]
    fn a_reference_whose_sid_does_not_parse_is_dropped() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.values.push(Value::Groups(vec![
            Reference {
                sid: vec![0xFF, 0x00, 0x13],
                name: "garbage".into(),
                unix_id: 7,
            },
            Reference {
                sid: sid("S-1-5-21-1-2-3-1001").as_ref().as_bytes().to_vec(),
                name: "staff".into(),
                unix_id: 1001,
            },
        ]));
        // A source that *may* assert foreign memberships, so the drop cannot be
        // attributed to the scope check.
        let registry = stub_with_foreign("lpsd", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::GROUPS,
        );
        let record = found.record.expect("a record");
        let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["staff"],
            "unparsed bytes must be dropped, and the valid reference kept"
        );
    }

    /// §2.18 reserves `Refused` for "the caller may not make this request", and
    /// requires it to stay unsent until an authority has a per-field
    /// restriction mechanism. authd has none.
    ///
    /// A source refusing is a fact about the source, identical for every
    /// caller. Relaying it as `Refused` let a client correctly conclude that
    /// asking again on this principal's behalf was pointless — the same damage
    /// as reporting `NotFound`, aimed at one caller instead of all of them.
    #[test]
    fn a_source_refusal_is_reported_as_unavailable_not_refused() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.outcome = Outcome::Refused;
        let registry = stub("corp", DOMAIN, 1000, Some(answer));

        for key in [
            Key::Name("jack".into()),
            Key::Sid(sid("S-1-5-21-1-2-3-1000").as_ref().as_bytes().to_vec()),
            Key::UnixId(BASE + 1000),
        ] {
            let found = lookup(&registry, &key, Kind::Principal, Fields::empty());
            assert_ne!(
                found.outcome,
                Outcome::Refused,
                "{key:?}: Refused is reserved for the caller lacking permission"
            );
            assert_eq!(found.outcome, Outcome::Unavailable, "{key:?}");
        }
    }

    /// Obligation 43: a `unix_id` of zero means the authority has no number
    /// for that SID, and zero is the *only* encoding of it. Substituting
    /// `UNMAPPED` (65534) put nobody/nogroup on the wire, which a client reads
    /// as a real identifier — so it could not tell "no source numbers this SID"
    /// from "genuinely numbered 65534".
    ///
    /// Rendering the sentinel as `nobody` is a display decision and belongs to
    /// nss, which already makes it from its own copy of the constant.
    #[test]
    fn an_unnumbered_reference_goes_on_the_wire_as_zero() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.values.push(Value::Groups(vec![Reference {
            // A group of the principal's own domain, so membership scope is
            // satisfied — but outside the source's range, so it has no number.
            sid: sid("S-1-5-21-1-2-3-999999").as_ref().as_bytes().to_vec(),
            name: "unnumbered".into(),
            unix_id: u32::MAX,
        }]));
        let registry = stub("lpsd", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::GROUPS,
        );
        let record = found.record.expect("a record");
        let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        assert_eq!(
            groups[0].unix_id, 0,
            "an unnumbered reference must be zero, never 65534"
        );
    }

    /// Obligation 37: identity confinement, membership scope and numeric scope
    /// apply to a `QueryResult` exactly as to an `Assertion`.
    ///
    /// Membership scope was applied on the logon path and nowhere else, so a
    /// source with no foreign-membership permission could report
    /// `BUILTIN\Administrators` over `/run/ident.sock` and have authd relay
    /// it — confined on the channel that mints tokens and unconfined on the
    /// channel that describes them. A POSIX-shaped tool reads group membership
    /// from the name-resolution path and treats it as an access-control input.
    #[test]
    fn a_foreign_group_is_dropped_from_a_lookup_when_the_source_may_not_assert_it() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.values.push(Value::Groups(vec![
            Reference {
                sid: sid("S-1-5-32-544").as_ref().as_bytes().to_vec(),
                name: "Administrators".into(),
                unix_id: 0,
            },
            Reference {
                sid: sid("S-1-5-21-1-2-3-1001").as_ref().as_bytes().to_vec(),
                name: "staff".into(),
                unix_id: 1001,
            },
        ]));
        // A source *without* the permission — a directory-backed one.
        let registry = stub("corp", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::GROUPS,
        );
        let record = found.record.expect("a record");
        let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["staff"],
            "the foreign group must be dropped, and the sibling kept"
        );
    }

    /// Obligation 38: a Principal request is never answered with a group, and
    /// vice versa. POSIX keeps the two in separate namespaces, which is why
    /// `kind` is on the request: getpwnam and getgrnam can be asked the same
    /// string and must get different objects.
    #[test]
    fn a_principal_request_is_not_answered_with_a_group() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "staff", 1000);
        answer.kind = Kind::Group;
        let registry = stub("lpsd", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("staff".into()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(found.outcome, Outcome::NotFound);
        assert!(found.record.is_none(), "no record may be relayed");
    }

    /// `Any` is a valid question and not a valid answer: the protocol forbids
    /// it in `kind_found` outright.
    #[test]
    fn a_source_answering_any_is_refused() {
        let mut answer = entry("S-1-5-21-1-2-3-1000", "jack", 1000);
        answer.kind = Kind::Any;
        let registry = stub("lpsd", DOMAIN, 1000, Some(answer));

        let found = lookup(
            &registry,
            &Key::Name("jack".into()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(found.outcome, Outcome::Unavailable);
    }

    #[test]
    fn enumerating_walks_every_source() {
        let registry = Arc::new(Registry::for_test(&[
            ("a", 10, Some(range())),
            ("b", 20, Some(range())),
        ]));
        add_stub(
            &registry,
            "a",
            DOMAIN,
            10,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        add_stub(
            &registry,
            "b",
            "S-1-5-21-7-7-7",
            20,
            Some(entry("S-1-5-21-7-7-7-1000", "ada", 1000)),
        );

        let page = enumerate(&registry, Kind::Principal, Fields::UNIX_ID, &[])
            .expect("an honourable cursor");
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|e| e.qualified_name.as_str())
            .collect();
        assert_eq!(names, vec!["jack", "ada"]);
        assert!(page.next.is_empty());
        assert!(page.incomplete.is_empty());
    }

    /// A short list that looks complete is what `incomplete` exists to prevent.
    #[test]
    fn a_source_that_does_not_enumerate_is_reported() {
        let registry = Arc::new(Registry::for_test(&[("quiet", 10, None)]));
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        registry.admit_for_test(
            "quiet",
            sid(DOMAIN),
            None,
            psi::Capabilities::QUERIES,
            10,
            ours,
        );
        let page = enumerate(&registry, Kind::Principal, Fields::empty(), &[])
            .expect("an honourable cursor");
        drop(theirs);
        assert!(page.entries.is_empty());
        assert_eq!(page.incomplete, vec!["quiet".to_string()]);
    }

    /// A source that disconnects between pages shifts every position after it,
    /// so a cursor keyed on position would resume the wrong source with another
    /// source's bytes — a silently wrong walk rather than a loud failure.
    #[test]
    fn an_enumeration_cursor_names_its_source() {
        let registry = Arc::new(Registry::for_test(&[
            ("a", 10, Some(range())),
            ("b", 20, Some(range())),
        ]));
        add_stub(
            &registry,
            "a",
            DOMAIN,
            10,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        add_stub(
            &registry,
            "b",
            "S-1-5-21-7-7-7",
            20,
            Some(entry("S-1-5-21-7-7-7-1000", "ada", 1000)),
        );

        // A cursor naming `b` resumes there, skipping `a` entirely.
        let mut cursor = vec![1u8];
        cursor.extend_from_slice(b"b");
        let page = enumerate(&registry, Kind::Principal, Fields::empty(), &cursor)
            .expect("an honourable cursor");
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|e| e.qualified_name.as_str())
            .collect();
        assert_eq!(names, vec!["ada"], "the walk resumes at the named source");
    }

    /// Obligation 49: a cursor the authority did not issue, or can no longer
    /// honour, is rejected with `Malformed`.
    ///
    /// The old behaviour was to start the walk over, reasoning that refusing
    /// would strand the caller. It would — and that is the honest outcome. A
    /// silent restart hands back a second copy of the beginning appended to
    /// what the caller already has, and nothing in the reply says so.
    #[test]
    fn an_unrecognised_cursor_is_malformed() {
        let registry = stub(
            "lpsd",
            DOMAIN,
            1000,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        for cursor in [
            vec![0xff],                      // a length longer than the cursor
            vec![4, 0xff, 0xff, 0xff, 0xff], // a name that is not UTF-8
            vec![9, 1, 2],                   // truncated
        ] {
            assert_eq!(
                enumerate(&registry, Kind::Principal, Fields::empty(), &cursor).err(),
                Some(Outcome::Malformed),
                "cursor {cursor:?} must be refused, not silently restarted"
            );
        }
    }

    /// A cursor naming a source that has since gone away is equally
    /// unhonourable. Left to run, the walk skips every source and returns an
    /// empty page with an empty `next` — which a client is required to read as
    /// completion, so a truncated walk reports as a whole one.
    #[test]
    fn a_cursor_naming_a_departed_source_is_malformed() {
        let registry = stub(
            "lpsd",
            DOMAIN,
            1000,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        let mut cursor = vec![5u8];
        cursor.extend_from_slice(b"gone!");
        assert_eq!(
            enumerate(&registry, Kind::Principal, Fields::empty(), &cursor).err(),
            Some(Outcome::Malformed),
        );
    }

    /// A configured source that is not here contributed nothing, and a listing
    /// that did not say so would look complete.
    #[test]
    fn an_absent_source_is_reported_in_an_enumeration() {
        let registry = Arc::new(Registry::for_test(&[
            ("here", 10, Some(range())),
            ("gone", 20, Some(range())),
        ]));
        add_stub(
            &registry,
            "here",
            DOMAIN,
            10,
            Some(entry("S-1-5-21-1-2-3-1000", "jack", 1000)),
        );
        let page = enumerate(&registry, Kind::Principal, Fields::empty(), &[])
            .expect("an honourable cursor");
        assert_eq!(page.incomplete, vec!["gone".to_string()]);
    }

    /// A range is configured rather than declared, so an absent source's is
    /// known exactly — and a number inside it must not answer as an absence a
    /// cache could keep.
    #[test]
    fn a_number_in_an_absent_sources_range_is_unavailable() {
        let registry = Arc::new(Registry::for_test(&[("gone", 10, Some(range()))]));
        assert_eq!(
            lookup(
                &registry,
                &Key::UnixId(BASE + 500),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::Unavailable
        );
    }

    /// An unpinned source declares its domain at registration, so an absent
    /// one's is unknowable — and "nobody owns this" cannot be told apart from
    /// "the owner is not here".
    #[test]
    fn a_sid_is_unavailable_rather_than_absent_while_a_source_is_missing() {
        let registry = Arc::new(Registry::for_test(&[("gone", 10, None)]));
        assert_eq!(
            lookup(
                &registry,
                &Key::Sid(sid("S-1-5-21-8-8-8-1000").as_ref().as_bytes().to_vec()),
                Kind::Principal,
                Fields::empty()
            )
            .outcome,
            Outcome::Unavailable
        );
    }

    #[test]
    fn the_well_known_groups_are_authds_to_enumerate() {
        let page = well_known_page(Kind::Group, Fields::UNIX_ID);
        assert!(page.iter().any(|r| r.qualified_name == "Everyone"));
        assert!(
            !page.iter().any(|r| r.qualified_name == "Interactive"),
            "a session property is not a row in a group table"
        );
        assert!(well_known_page(Kind::Principal, Fields::empty()).is_empty());
    }

    // -- routing (PSI §2.11) --------------------------------------------

    const OTHER_DOMAIN: &str = "S-1-5-21-7-8-9";

    fn two_source_registry(
        first_answer: Option<psi::QueryEntry>,
        second_answer: Option<psi::QueryEntry>,
    ) -> Arc<Registry> {
        let registry = Arc::new(Registry::for_test(&[
            ("first", 1, Some(range())),
            ("second", 2, Some(range())),
        ]));
        add_stub(&registry, "first", DOMAIN, 1, first_answer);
        add_stub(&registry, "second", OTHER_DOMAIN, 2, second_answer);
        registry
    }

    #[test]
    fn a_single_source_is_routed_to_without_being_asked() {
        // The degenerate case has no routing question, and deliberately no
        // resolution round trip: a single logon-only source that cannot
        // answer name queries still receives every conversation.
        let registry = stub("only", DOMAIN, 1, None);
        match route(&registry, b"jack") {
            Route::Owner(source) => assert_eq!(source.name(), "only"),
            _ => panic!("expected the only source"),
        }
    }

    #[test]
    fn a_name_routes_to_the_source_that_claims_it() {
        // The PEI-304 bug: every logon went to the first source in the
        // order. A name the second source holds must route there, or the
        // first source is handed a credential for a principal it does not
        // own.
        let registry = two_source_registry(None, Some(entry("S-1-5-21-7-8-9-500", "jack", 1)));
        match route(&registry, b"jack") {
            Route::Owner(source) => assert_eq!(source.name(), "second"),
            _ => panic!("expected the owning source"),
        }
    }

    #[test]
    fn an_unclaimed_name_blinds_via_the_first_source() {
        // Nobody owns the name. The conversation still runs — against
        // exactly one source, deterministically the first — because a
        // short-circuit denial would distinguish an unknown principal from
        // a bad credential (PGSS §2.10).
        let registry = two_source_registry(None, None);
        match route(&registry, b"nobody") {
            Route::Blind(source) => assert_eq!(source.name(), "first"),
            _ => panic!("expected the blind path"),
        }
    }

    #[test]
    fn an_absent_configured_source_denies_rather_than_falling_through() {
        // "second" is configured and never registered. A name it might hold
        // cannot be routed past it — falling through would let whoever took
        // a source down choose which authority answers for its principals.
        let registry = Arc::new(Registry::for_test(&[
            ("first", 1, Some(range())),
            ("second", 2, Some(range())),
        ]));
        add_stub(&registry, "first", DOMAIN, 1, None);
        match route(&registry, b"jack") {
            Route::Unavailable => {}
            _ => panic!("expected Unavailable"),
        }
    }

    #[test]
    fn no_sources_at_all_is_its_own_answer() {
        let registry = Registry::for_test(&[]);
        match route(&registry, b"jack") {
            Route::NoSources => {}
            _ => panic!("expected NoSources"),
        }
    }

    // -- member enumeration: Enumerate with `of` (PGSS §2.17) -----------

    #[test]
    fn members_of_a_group_come_from_its_owning_source() {
        let registry = stub(
            "only",
            DOMAIN,
            1,
            Some(entry("S-1-5-21-1-2-3-513", "devs", 5)),
        );
        let of = libauthd::ident::Key::Name("devs".into());
        let page = enumerate_members(&registry, &of, Kind::Principal, Fields::PASSWD, b"")
            .expect("a page");
        assert_eq!(page.entries.len(), 1);
        assert!(page.next.is_empty());
        assert!(page.incomplete.is_empty());
    }

    #[test]
    fn members_of_a_group_nobody_holds_is_not_found() {
        let registry = stub("only", DOMAIN, 1, None);
        let of = libauthd::ident::Key::Name("ghosts".into());
        match enumerate_members(&registry, &of, Kind::Principal, Fields::PASSWD, b"") {
            Err(Outcome::NotFound) => {}
            Ok(_) => panic!("expected NotFound, got a page"),
            Err(other) => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn members_cannot_be_walked_past_an_absent_source() {
        // "second" is configured and not registered; the group might be its.
        let registry = Arc::new(Registry::for_test(&[
            ("first", 1, Some(range())),
            ("second", 2, Some(range())),
        ]));
        add_stub(&registry, "first", DOMAIN, 1, None);
        let of = libauthd::ident::Key::Name("devs".into());
        match enumerate_members(&registry, &of, Kind::Principal, Fields::PASSWD, b"") {
            Err(Outcome::Unavailable) => {}
            Ok(_) => panic!("expected Unavailable, got a page"),
            Err(other) => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn an_unusable_of_name_is_malformed() {
        let registry = stub("only", DOMAIN, 1, None);
        let of = libauthd::ident::Key::Name(" devs ".into());
        match enumerate_members(&registry, &of, Kind::Principal, Fields::PASSWD, b"") {
            Err(Outcome::Malformed) => {}
            Ok(_) => panic!("expected Malformed, got a page"),
            Err(other) => panic!("expected Malformed, got {other:?}"),
        }
    }
}
