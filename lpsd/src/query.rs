//! Answering PSI queries — who a name, SID or relative identifier belongs to,
//! outside any logon.
//!
//! This is what makes `getpwuid` work. PGSS Logon chapter 6 asks authd; authd
//! does the range arithmetic that turns an absolute number into a source and a
//! relative identifier, and asks here.
//!
//! # Everything is relative
//!
//! Every number leaving this module is relative to the range authd assigned
//! lpsd, exactly as in an assertion. lpsd does not know its base and must not be
//! able to act on one — a source that could rebase could number its principals
//! onto uid 0.
//!
//! # Paging on a RID
//!
//! An enumeration cursor is a relative identifier, and the walk resumes at the
//! next object *above* it.
//!
//! RIDs are never reused (see [`crate::store`]), so a cursor stays meaningful
//! across a store that changed underneath it: a deleted principal is simply
//! absent, and one added during the walk lands past the end. So lpsd holds no
//! per-cursor state, and never has to refuse a cursor it issued — which is the
//! failure PSD-013 §5.6 permits a source precisely because most sources cannot
//! avoid it.

use libauthd::ident::{Fields, Kind, Outcome, Reference, Value, Withheld, WithheldReason};
use libauthd::psi;
use peios::security::SidRef;

use crate::store::{GroupRecord, Member, Object, Record, Store};

/// How much of a message body one page may fill before lpsd stops adding to it.
///
/// Well below PSI's ceiling, because authd re-encodes what it receives into a
/// PGSS Logon message with a *smaller* one. A page that fitted here and not
/// there would be a page nobody could deliver.
const PAGE_BUDGET_BYTES: usize = 48 * 1024;

/// The largest page lpsd will build, whatever the budget allows.
const PAGE_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Answer one query, key for key, in order.
///
/// The order matters more than it looks: authd pairs answers with questions by
/// position, so a reordered or short array would attach one principal's record
/// to another's name.
pub fn answer(store: &Store, query: &psi::Query) -> psi::QueryResult {
    psi::QueryResult {
        results: query
            .keys
            .iter()
            .map(|key| answer_one(store, key, query.fields))
            .collect(),
    }
}

fn answer_one(store: &Store, key: &psi::QueryKey, fields: Fields) -> psi::QueryEntry {
    let found = match &key.key {
        psi::Key::Name(name) => store.lookup_name(name),
        psi::Key::RelativeId(rid) => store.lookup_relative_id(*rid),
        // Not a SID at all resolves to nothing, rather than refusing the
        // conversation: one malformed key in a batch must not cost the other
        // sixty-three their answers.
        psi::Key::Sid(bytes) => SidRef::from_bytes(bytes).and_then(|sid| store.lookup_sid(sid)),
    };

    let Some(object) = found else {
        return not_found();
    };

    let kind = match &object {
        Object::Principal(_) => Kind::Principal,
        Object::Group(_) => Kind::Group,
    };
    if !kind.satisfies(key.kind) {
        // `getpwnam` must not be handed a group. The object exists, but not the
        // one that was asked for.
        return not_found();
    }

    match object {
        Object::Principal(record) => principal_entry(store, &record, fields),
        Object::Group(record) => group_entry(store, &record, fields),
    }
}

fn not_found() -> psi::QueryEntry {
    psi::QueryEntry {
        outcome: Outcome::NotFound,
        ..psi::QueryEntry::default()
    }
}

fn principal_entry(store: &Store, record: &Record, fields: Fields) -> psi::QueryEntry {
    let mut values = Vec::new();
    let mut withheld = Vec::new();

    if fields.contains(Fields::UNIX_ID) {
        values.push(Value::UnixId(record.unix_id));
    }
    if fields.contains(Fields::PRIMARY_GROUP) {
        values.push(Value::PrimaryGroup(Reference {
            sid: record.primary_group.sid.as_ref().as_bytes().to_vec(),
            name: record.primary_group.name.clone().unwrap_or_default(),
            unix_id: record.primary_group.unix_id.unwrap_or_default(),
        }));
    }
    if fields.contains(Fields::HOME) {
        values.push(Value::Home(record.home.clone()));
    }
    if fields.contains(Fields::SHELL) {
        values.push(Value::Shell(record.shell.clone()));
    }
    if fields.contains(Fields::DISPLAY_NAME) {
        values.push(Value::DisplayName(record.display_name.clone()));
    }
    if fields.contains(Fields::GROUPS) {
        values.push(Value::Groups(
            record
                .groups
                .iter()
                .map(|group| Reference {
                    sid: group.sid.as_ref().as_bytes().to_vec(),
                    name: group.name.clone().unwrap_or_default(),
                    unix_id: group.unix_id.unwrap_or_default(),
                })
                .collect(),
        ));
    }
    if fields.contains(Fields::CLAIMS) {
        values.push(Value::Claims(record.claims.clone()));
    }
    if fields.contains(Fields::ENABLED) {
        values.push(Value::Enabled(record.enabled));
    }
    // A principal is not a group, so its membership list is not absent for a
    // reason worth explaining — it is a question that does not apply.
    if fields.contains(Fields::MEMBERS) {
        withheld.push(Withheld {
            field: Fields::MEMBERS,
            reason: WithheldReason::Absent,
        });
    }

    let _ = store;
    psi::QueryEntry {
        outcome: Outcome::Found,
        sid: record.sid.as_ref().as_bytes().to_vec(),
        canonical_name: record.name.clone(),
        kind: Kind::Principal,
        values,
        withheld,
    }
}

fn group_entry(store: &Store, record: &GroupRecord, fields: Fields) -> psi::QueryEntry {
    let mut values = Vec::new();
    let mut withheld = Vec::new();

    if fields.contains(Fields::UNIX_ID) {
        match record.unix_id {
            Some(unix_id) => values.push(Value::UnixId(unix_id)),
            // A well-known group. lpsd does not own the number, and authd's own
            // table decides it.
            None => withheld.push(Withheld {
                field: Fields::UNIX_ID,
                reason: WithheldReason::Absent,
            }),
        }
    }
    if fields.contains(Fields::MEMBERS) {
        match members(store, record) {
            Ok(Some(refs)) => values.push(Value::Members(refs)),
            Ok(None) => withheld.push(Withheld {
                field: Fields::MEMBERS,
                // Nothing records who is in this group. Not `Declined`, which
                // would suggest an answer exists somewhere and lpsd is keeping
                // it back.
                reason: WithheldReason::Absent,
            }),
            Err(()) => withheld.push(Withheld {
                field: Fields::MEMBERS,
                reason: WithheldReason::TooLarge,
            }),
        }
    }

    // Everything else describes a principal. Absent rather than unimplemented:
    // lpsd does implement these, and this object simply has none.
    for field in [
        Fields::PRIMARY_GROUP,
        Fields::HOME,
        Fields::SHELL,
        Fields::DISPLAY_NAME,
        Fields::GROUPS,
        Fields::CLAIMS,
        Fields::ENABLED,
    ] {
        if fields.contains(field) {
            withheld.push(Withheld {
                field,
                reason: WithheldReason::Absent,
            });
        }
    }

    psi::QueryEntry {
        outcome: Outcome::Found,
        sid: record.sid.as_ref().as_bytes().to_vec(),
        canonical_name: record.name.clone(),
        kind: Kind::Group,
        values,
        withheld,
    }
}

/// A group's whole membership, or an indication of why not.
///
/// `Ok(None)` — nothing records edges into this group.
/// `Err(())` — it does, and the list will not fit in one reply.
fn members(store: &Store, record: &GroupRecord) -> Result<Option<Vec<Reference>>, ()> {
    if !record.enumerable {
        return Ok(None);
    }
    let Some(found) = store.members_of(record.sid.as_ref(), None) else {
        return Ok(None);
    };
    let refs: Vec<Reference> = found.iter().map(reference_of).collect();

    // Measured rather than guessed. A member is a SID, a name and a number, and
    // how many fit depends on how long the names are — so the honest test is to
    // encode it and look.
    if encoded_size(&Value::Members(refs.clone())) > PAGE_BUDGET_BYTES {
        return Err(());
    }
    Ok(Some(refs))
}

fn reference_of(member: &Member) -> Reference {
    Reference {
        sid: member.sid.as_ref().as_bytes().to_vec(),
        name: member.name.clone(),
        unix_id: member.unix_id,
    }
}

/// What one value costs on the wire.
///
/// Encodes a throwaway single-entry result to find out. Not a hot path: it runs
/// once per group whose membership was actually asked for.
fn encoded_size(value: &Value) -> usize {
    psi::encode_query_result(
        psi::CONVERSATION_CONTROL,
        &psi::QueryResult {
            results: vec![psi::QueryEntry {
                outcome: Outcome::Found,
                values: vec![value.clone()],
                ..psi::QueryEntry::default()
            }],
        },
    )
    .map(|bytes| bytes.len())
    // Refusing to encode *is* the answer to "does this fit".
    .unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Walk principals or groups, one page at a time.
pub fn enumerate(store: &Store, request: &psi::EnumerateSource) -> psi::EnumerateResult {
    let Ok(after) = cursor_of(&request.cursor) else {
        return refused();
    };

    let (entries, last) = match &request.of {
        // `Found` with an empty page says *there are none*. `Refused` says
        // *this source is not answering*. These four cases are the second, and
        // reporting them as the first told the authority a falsehood it had no
        // way to detect — so the non-retry contract had nothing to attach to
        // and authd kept the source in the walk and kept asking:
        //
        //   - a stapled group whose membership is a rule rather than a record,
        //     such as Everyone or Authenticated Users;
        //   - a key naming a principal where a group was required;
        //   - a group SID from another domain;
        //   - a key that resolves to nothing at all.
        //
        // The empty `Found` is reserved for a group that genuinely has no
        // recorded members. lpsd already draws the equivalent distinction on
        // the Query path, where it emits Withheld{MEMBERS, Absent} rather than
        // Value::Members([]); the enumeration path was the one that lost it.
        Some(key) => match group_members_page(store, key, after, request.fields) {
            Some(page) => page,
            None => return refused(),
        },
        None => match request.kind {
            Kind::Principal => principals_page(store, after, request.fields),
            Kind::Group => groups_page(store, after, request.fields),
            // authd is required not to send this. Refusing is the honest reply.
            Kind::Any => return refused(),
        },
    };

    psi::EnumerateResult {
        outcome: Outcome::Found,
        entries,
        // A cursor is set whenever the page filled, even if what remains turns
        // out to be nothing. The alternative — looking ahead to see — would cost
        // a second pass to save one empty round trip.
        next: match last {
            Some(rid) => rid.to_le_bytes().to_vec(),
            None => Vec::new(),
        },
    }
}

fn complete(entries: Vec<psi::QueryEntry>) -> psi::EnumerateResult {
    psi::EnumerateResult {
        outcome: Outcome::Found,
        entries,
        next: Vec::new(),
    }
}

/// `Ok(None)` begins a walk; `Ok(Some(rid))` resumes after one; `Err` is a
/// cursor lpsd cannot honour.
///
/// Source obligation 29: a source refuses a cursor it can no longer honour
/// rather than restarting or answering from a changed store. Restarting was
/// deliberate here — "refusing would strand a caller" — and it does strand one,
/// which is the honest outcome: the caller believes it is continuing and
/// receives a second copy of the beginning appended to what it already
/// collected, with a well-formed `Found` and a fresh `next` saying nothing is
/// wrong. Left alone, a store edit during a `getent passwd` becomes an
/// unbounded loop over a source that never finishes.
///
/// The refusal path is cheap to be strict about: lpsd's cursors are bare RIDs
/// and RIDs are never reused, so every cursor lpsd issued is honourable and
/// only a malformed one reaches the error.
fn cursor_of(bytes: &[u8]) -> Result<Option<u32>, ()> {
    if bytes.is_empty() {
        return Ok(None);
    }
    match <[u8; 4]>::try_from(bytes) {
        Ok(four) => Ok(Some(u32::from_le_bytes(four))),
        Err(_) => Err(()),
    }
}

/// A reply that declines to answer: `entries` and `next` empty, per
/// obligation 28. An authority records the source as not having contributed
/// and does not retry it for the rest of the enumeration.
fn refused() -> psi::EnumerateResult {
    psi::EnumerateResult {
        outcome: Outcome::Refused,
        entries: Vec::new(),
        next: Vec::new(),
    }
}

fn principals_page(
    store: &Store,
    after: Option<u32>,
    fields: Fields,
) -> (Vec<psi::QueryEntry>, Option<u32>) {
    page(
        store.principals_after(after),
        |record| record.rid,
        |record| principal_entry(store, record, fields),
    )
}

fn groups_page(
    store: &Store,
    after: Option<u32>,
    fields: Fields,
) -> (Vec<psi::QueryEntry>, Option<u32>) {
    page(
        store.groups_after(after),
        // The cursor must be the field `groups_after` filters on. It used to be
        // `unix_id`, which agrees with `rid` only because `create_group` sets
        // them equal — the store format does not require it, `decode` does not
        // check it, and `Store::add` explicitly blesses an imported `unix_id`
        // that differs. Where they diverged the walk resumed from the wrong
        // place: groups already returned came back again, or groups between the
        // two values were silently skipped, under a well-formed `next` that
        // terminated normally. Neither authd nor the client could detect it,
        // and `incomplete` — which exists for exactly this class of listing
        // that looks complete and is not — never fired.
        |record| record.rid.unwrap_or_default(),
        |record| group_entry(store, record, fields),
    )
}

fn group_members_page(
    store: &Store,
    key: &psi::Key,
    after: Option<u32>,
    fields: Fields,
) -> Option<(Vec<psi::QueryEntry>, Option<u32>)> {
    let object = match key {
        psi::Key::Name(name) => store.lookup_name(name),
        psi::Key::RelativeId(rid) => store.lookup_relative_id(*rid),
        psi::Key::Sid(bytes) => SidRef::from_bytes(bytes).and_then(|sid| store.lookup_sid(sid)),
    }?;
    let Object::Group(group) = object else {
        return None;
    };
    let found = store.members_of(group.sid.as_ref(), after)?;

    // Each member comes back as a principal record, so a caller filling a
    // `group` table gets names and numbers without a lookup apiece.
    Some(page(
        found,
        |member| member.rid,
        |member| match store.lookup_relative_id(member.rid) {
            Some(Object::Principal(record)) => principal_entry(store, &record, fields),
            _ => psi::QueryEntry {
                outcome: Outcome::Found,
                sid: member.sid.as_ref().as_bytes().to_vec(),
                canonical_name: member.name.clone(),
                kind: Kind::Principal,
                values: Vec::new(),
                withheld: Vec::new(),
            },
        },
    ))
}

/// Fill one page, stopping at the entry count or the size budget, whichever
/// comes first.
///
/// Returns the cursor to resume from, or `None` where everything fitted.
fn page<T>(
    items: Vec<T>,
    rid_of: impl Fn(&T) -> u32,
    entry_of: impl Fn(&T) -> psi::QueryEntry,
) -> (Vec<psi::QueryEntry>, Option<u32>) {
    let mut entries: Vec<psi::QueryEntry> = Vec::new();
    let mut used = 0usize;

    for (index, item) in items.iter().enumerate() {
        if index == PAGE_ENTRIES {
            return (entries, Some(rid_of(&items[index - 1])));
        }
        let entry = entry_of(item);
        used += entry_size(&entry);
        if used > PAGE_BUDGET_BYTES && !entries.is_empty() {
            // One entry short of the budget rather than one over. An entry too
            // large to share a page with anything is still sent alone, because
            // dropping it would make the walk skip a principal silently.
            return (entries, Some(rid_of(&items[index - 1])));
        }
        entries.push(entry);
    }
    (entries, None)
}

fn entry_size(entry: &psi::QueryEntry) -> usize {
    psi::encode_query_result(
        psi::CONVERSATION_CONTROL,
        &psi::QueryResult {
            results: vec![entry.clone()],
        },
    )
    .map(|bytes| bytes.len())
    .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{NewPrincipal, well_known_group};

    fn seeded() -> Store {
        let mut store = Store::provision().expect("must provision");
        store
            .add(
                NewPrincipal {
                    groups: vec![well_known_group("Administrators").unwrap()],
                    ..NewPrincipal::named("jack")
                },
                Some(b"password"),
            )
            .expect("must add");
        store.create_group("developers").expect("must create");
        store
    }

    fn ask(store: &Store, key: psi::Key, kind: Kind, fields: Fields) -> psi::QueryEntry {
        let result = answer(
            store,
            &psi::Query {
                fields,
                keys: vec![psi::QueryKey { key, kind }],
            },
        );
        result.results.into_iter().next().expect("one key, one result")
    }

    #[test]
    fn a_principal_answers_by_name_sid_and_relative_id() {
        let store = seeded();
        let by_name = ask(&store, psi::Key::Name("JACK".into()), Kind::Any, Fields::PASSWD);
        assert_eq!(by_name.outcome, Outcome::Found);
        assert_eq!(
            by_name.canonical_name, "jack",
            "the source's own spelling, not what was typed"
        );

        let by_rid = ask(&store, psi::Key::RelativeId(1000), Kind::Any, Fields::PASSWD);
        let by_sid = ask(
            &store,
            psi::Key::Sid(by_name.sid.clone()),
            Kind::Any,
            Fields::PASSWD,
        );
        assert_eq!(by_rid.sid, by_name.sid);
        assert_eq!(by_sid.sid, by_name.sid);
    }

    /// The number lpsd states is its own, and authd adds the base. Stating an
    /// absolute one would have it applied twice.
    #[test]
    fn a_unix_id_is_relative() {
        let store = seeded();
        let entry = ask(&store, psi::Key::Name("jack".into()), Kind::Any, Fields::UNIX_ID);
        assert_eq!(entry.value(Fields::UNIX_ID), Some(&Value::UnixId(1000)));
    }

    #[test]
    fn a_principal_is_not_answered_to_a_group_request() {
        let store = seeded();
        let entry = ask(&store, psi::Key::Name("jack".into()), Kind::Group, Fields::empty());
        assert_eq!(entry.outcome, Outcome::NotFound);
    }

    #[test]
    fn a_group_is_not_answered_to_a_principal_request() {
        let store = seeded();
        let entry = ask(
            &store,
            psi::Key::Name("developers".into()),
            Kind::Principal,
            Fields::empty(),
        );
        assert_eq!(entry.outcome, Outcome::NotFound);
    }

    #[test]
    fn a_passwd_record_comes_back_in_one_query() {
        let store = seeded();
        let entry = ask(&store, psi::Key::Name("jack".into()), Kind::Principal, Fields::PASSWD);
        assert!(entry.present().contains(Fields::PASSWD), "every passwd field at once");
        assert_eq!(entry.value(Fields::HOME), Some(&Value::Home("/home/jack".into())));
        assert_eq!(entry.value(Fields::SHELL), Some(&Value::Shell("/bin/sh".into())));
    }

    /// The direction sources actually hold. `initgroups` is one query.
    #[test]
    fn a_principals_groups_come_back_with_names() {
        let store = seeded();
        let entry = ask(&store, psi::Key::Name("jack".into()), Kind::Principal, Fields::GROUPS);
        let Some(Value::Groups(groups)) = entry.value(Fields::GROUPS) else {
            panic!("groups must be present");
        };
        assert!(
            groups.iter().any(|g| g.name == "Administrators"),
            "a reply of bare SIDs would cost a lookup per group"
        );
    }

    #[test]
    fn a_local_group_lists_its_members() {
        let mut store = seeded();
        let developers = store.resolve_group("developers").unwrap();
        store.add_membership("jack", developers).unwrap();

        let entry = ask(
            &store,
            psi::Key::Name("developers".into()),
            Kind::Group,
            Fields::GROUP,
        );
        let Some(Value::Members(members)) = entry.value(Fields::MEMBERS) else {
            panic!("members must be present");
        };
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "jack");
        assert_eq!(members[0].unix_id, 1000, "relative, like every other number");
    }

    /// `BUILTIN\Administrators` is well-known *and* enumerable: lpsd holds real
    /// memberships into it. Well-known-ness is not what decides this.
    #[test]
    fn a_well_known_group_with_recorded_members_lists_them() {
        let store = seeded();
        let entry = ask(
            &store,
            psi::Key::Name("Administrators".into()),
            Kind::Group,
            Fields::MEMBERS,
        );
        let Some(Value::Members(members)) = entry.value(Fields::MEMBERS) else {
            panic!("members must be present");
        };
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "jack");
    }

    /// Nothing records who is in `Everyone`; authd staples it onto every token.
    /// Absent, not declined — declining would suggest an answer exists.
    #[test]
    fn a_stapled_group_has_no_members_rather_than_withheld_ones() {
        let store = seeded();
        for name in ["Everyone", "Authenticated Users"] {
            let entry = ask(&store, psi::Key::Name(name.into()), Kind::Group, Fields::MEMBERS);
            assert_eq!(entry.outcome, Outcome::Found, "{name} is still nameable");
            assert!(entry.value(Fields::MEMBERS).is_none());
            assert_eq!(
                entry.withheld.iter().find(|w| w.field == Fields::MEMBERS).map(|w| w.reason),
                Some(WithheldReason::Absent),
                "{name} has no membership to record"
            );
        }
    }

    /// Every principal defaults to `Authenticated Users` as their primary group.
    /// Counting that as an edge would make it look enumerable.
    #[test]
    fn a_primary_group_does_not_make_a_stapled_group_enumerable() {
        let store = seeded();
        assert!(
            store
                .members_of(well_known_group("Authenticated Users").unwrap().as_ref(), None)
                .is_none()
        );
    }

    #[test]
    fn an_unknown_name_is_not_found() {
        let store = seeded();
        assert_eq!(
            ask(&store, psi::Key::Name("nobody".into()), Kind::Any, Fields::empty()).outcome,
            Outcome::NotFound
        );
    }

    /// One bad key in a batch must not cost the others their answers.
    #[test]
    fn a_malformed_sid_key_is_not_found_rather_than_fatal() {
        let store = seeded();
        let result = answer(
            &store,
            &psi::Query {
                fields: Fields::UNIX_ID,
                keys: vec![
                    psi::QueryKey {
                        key: psi::Key::Sid(vec![0xff, 0xff]),
                        kind: Kind::Any,
                    },
                    psi::QueryKey {
                        key: psi::Key::Name("jack".into()),
                        kind: Kind::Any,
                    },
                ],
            },
        );
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.results[0].outcome, Outcome::NotFound);
        assert_eq!(result.results[1].outcome, Outcome::Found);
    }

    #[test]
    fn results_come_back_one_per_key_in_order() {
        let store = seeded();
        let names = ["developers", "jack", "nobody"];
        let result = answer(
            &store,
            &psi::Query {
                fields: Fields::empty(),
                keys: names
                    .iter()
                    .map(|name| psi::QueryKey {
                        key: psi::Key::Name((*name).into()),
                        kind: Kind::Any,
                    })
                    .collect(),
            },
        );
        assert_eq!(result.results.len(), names.len());
        assert_eq!(result.results[0].kind, Kind::Group);
        assert_eq!(result.results[1].canonical_name, "jack");
        assert_eq!(result.results[2].outcome, Outcome::NotFound);
    }

    #[test]
    fn enumerating_principals_walks_the_whole_store() {
        let mut store = seeded();
        for name in ["ada", "grace", "alan"] {
            store.add(NewPrincipal::named(name), Some(b"pw")).unwrap();
        }
        let mut seen = Vec::new();
        let mut cursor = Vec::new();
        loop {
            let page = enumerate(
                &store,
                &psi::EnumerateSource {
                    kind: Kind::Principal,
                    fields: Fields::UNIX_ID,
                    of: None,
                    cursor: cursor.clone(),
                },
            );
            seen.extend(page.entries.iter().map(|e| e.canonical_name.clone()));
            if page.next.is_empty() {
                break;
            }
            cursor = page.next;
        }
        assert_eq!(seen, vec!["jack", "ada", "grace", "alan"]);
    }

    /// RIDs are never reused, so a cursor survives the store changing under it.
    #[test]
    fn a_cursor_survives_a_deletion_and_an_addition() {
        let mut store = seeded();
        for name in ["ada", "grace"] {
            store.add(NewPrincipal::named(name), Some(b"pw")).unwrap();
        }
        // Resume after jack (RID 1000), then change the store.
        store.remove("ada").unwrap();
        store.add(NewPrincipal::named("alan"), Some(b"pw")).unwrap();

        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Principal,
                fields: Fields::empty(),
                of: None,
                cursor: 1000u32.to_le_bytes().to_vec(),
            },
        );
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|e| e.canonical_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["grace", "alan"],
            "a deleted principal is absent and a new one lands past the end"
        );
    }

    #[test]
    fn enumerating_a_groups_members_pages_from_the_group() {
        let mut store = seeded();
        let developers = store.resolve_group("developers").unwrap();
        for name in ["ada", "grace"] {
            store.add(NewPrincipal::named(name), Some(b"pw")).unwrap();
            store.add_membership(name, developers.clone()).unwrap();
        }
        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Principal,
                fields: Fields::UNIX_ID,
                of: Some(psi::Key::Name("developers".into())),
                cursor: Vec::new(),
            },
        );
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|e| e.canonical_name.as_str())
            .collect();
        assert_eq!(names, vec!["ada", "grace"]);
        assert!(page.next.is_empty());
    }

    /// `groups_page` paged on `unix_id` while `Store::groups_after` filters on
    /// `rid`. The two agree only because `create_group` sets them equal — the
    /// store format does not require it, `decode` does not check it, and
    /// `Store::add` explicitly blesses an imported `unix_id` that differs.
    ///
    /// Where they diverge the walk resumes from the wrong place: with
    /// `unix_id > rid`, every group between the two values is **silently
    /// skipped**, under a well-formed `next` that terminates normally. Neither
    /// authd nor the client can detect it.
    ///
    /// Every existing test builds groups through `create_group`, where the two
    /// are equal by construction — which is why this survived.
    #[test]
    fn a_group_walk_pages_on_rid_so_a_skewed_unix_id_skips_nothing() {
        let mut store = seeded();
        // Enough to force more than one page, so a cursor is actually issued.
        let mut expected: Vec<String> = Vec::new();
        for i in 0..(PAGE_ENTRIES + 6) {
            let name = format!("grp{i:03}");
            store.create_group(&name).expect("must create");
            expected.push(name);
        }
        // Skew *every* group's unix_id far above its RID, rather than guessing
        // which one lands on the page boundary — `seeded()` contributes groups
        // of its own, so the boundary index is not the one this loop counted.
        // Whichever group ends the first page now issues a cursor around
        // 900_000, and `groups_after`'s `rid > after` filter returns nothing:
        // the walk terminates early with a well-formed `next` and the rest of
        // the groups silently missing.
        for i in 0..(PAGE_ENTRIES + 6) {
            store.skew_group_unix_id_for_test(&format!("grp{i:03}"), 900_000 + i as u32);
        }

        let mut seen: Vec<String> = Vec::new();
        let mut cursor = Vec::new();
        for _ in 0..8 {
            let page = enumerate(
                &store,
                &psi::EnumerateSource {
                    kind: Kind::Group,
                    fields: Fields::empty(),
                    of: None,
                    cursor: cursor.clone(),
                },
            );
            assert_eq!(page.outcome, Outcome::Found);
            seen.extend(page.entries.iter().map(|e| e.canonical_name.clone()));
            if page.next.is_empty() {
                break;
            }
            cursor = page.next;
        }

        for name in &expected {
            assert!(
                seen.iter().any(|s| s == name),
                "{name} was skipped by the walk"
            );
        }
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), seen.len(), "the walk returned a group twice");
    }

    /// Source obligation 29: a cursor the source cannot honour is refused,
    /// not silently restarted. Restarting hands the caller a second copy of
    /// the beginning appended to what it already has, under a well-formed
    /// `Found` with a fresh `next` — and a store edit during a `getent passwd`
    /// then becomes an unbounded loop over a source that never finishes.
    #[test]
    fn a_cursor_lpsd_did_not_issue_is_refused() {
        let store = seeded();
        for cursor in [vec![1u8], vec![1, 2, 3], vec![1, 2, 3, 4, 5]] {
            let page = enumerate(
                &store,
                &psi::EnumerateSource {
                    kind: Kind::Principal,
                    fields: Fields::empty(),
                    of: None,
                    cursor: cursor.clone(),
                },
            );
            assert_eq!(
                page.outcome,
                Outcome::Refused,
                "cursor {cursor:?} must be refused, not restarted"
            );
            assert!(page.entries.is_empty(), "a refusal carries no entries");
            assert!(page.next.is_empty(), "a refusal carries no next");
        }
    }

    /// An empty cursor begins a walk, and a four-byte one lpsd issued resumes
    /// it — the refusal must not swallow the honourable cases.
    #[test]
    fn an_issued_cursor_is_still_honoured() {
        let store = seeded();
        for cursor in [Vec::new(), 0u32.to_le_bytes().to_vec()] {
            let page = enumerate(
                &store,
                &psi::EnumerateSource {
                    kind: Kind::Principal,
                    fields: Fields::empty(),
                    of: None,
                    cursor,
                },
            );
            assert_eq!(page.outcome, Outcome::Found);
        }
    }

    /// Obligation 28: "will not enumerate" is `Refused`, not an empty `Found`.
    ///
    /// `Found` with an empty page says *there are none*. Reporting a refusal as
    /// one told the authority a falsehood it had no way to detect, and left the
    /// non-retry contract with nothing to attach to.
    #[test]
    fn a_membership_lpsd_will_not_produce_is_refused_not_reported_empty() {
        let store = seeded();
        for key in [
            // A stapled group: its membership is a rule, not a record.
            psi::Key::Name("Everyone".into()),
            // A principal where a group was required.
            psi::Key::Name("jack".into()),
            // A key that resolves to nothing at all.
            psi::Key::Name("no-such-thing".into()),
        ] {
            let page = enumerate(
                &store,
                &psi::EnumerateSource {
                    kind: Kind::Principal,
                    fields: Fields::empty(),
                    of: Some(key.clone()),
                    cursor: Vec::new(),
                },
            );
            assert_eq!(
                page.outcome,
                Outcome::Refused,
                "{key:?} must be refused, not reported as an empty membership"
            );
        }
    }

    /// And the empty `Found` stays reserved for what it means: a group that
    /// genuinely has no recorded members.
    #[test]
    fn a_group_with_no_members_is_found_and_empty() {
        let store = seeded();
        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Principal,
                fields: Fields::empty(),
                of: Some(psi::Key::Name("developers".into())),
                cursor: Vec::new(),
            },
        );
        assert_eq!(page.outcome, Outcome::Found);
        assert!(page.entries.is_empty());
    }

    #[test]
    fn enumerating_anything_at_all_is_refused() {
        let store = seeded();
        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Any,
                fields: Fields::empty(),
                of: None,
                cursor: Vec::new(),
            },
        );
        assert_eq!(page.outcome, Outcome::Refused);
    }

    #[test]
    fn enumerating_groups_omits_the_well_known_ones() {
        let store = seeded();
        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Group,
                fields: Fields::UNIX_ID,
                of: None,
                cursor: Vec::new(),
            },
        );
        let names: Vec<&str> = page
            .entries
            .iter()
            .map(|e| e.canonical_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["developers"],
            "well-known groups exist on every machine, so they are the authority's to enumerate"
        );
    }

    /// A page that filled says so, and one that did not is the end.
    #[test]
    fn a_full_page_carries_a_cursor() {
        let mut store = Store::provision().unwrap();
        for index in 0..PAGE_ENTRIES + 5 {
            store
                .add(NewPrincipal::named(&format!("p{index}")), Some(b"pw"))
                .unwrap();
        }
        let page = enumerate(
            &store,
            &psi::EnumerateSource {
                kind: Kind::Principal,
                fields: Fields::PASSWD,
                of: None,
                cursor: Vec::new(),
            },
        );
        assert_eq!(page.entries.len(), PAGE_ENTRIES);
        assert!(!page.next.is_empty(), "there is more to come");
    }
}
