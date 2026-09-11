//! What this machine grants a principal.
//!
//! M2–M5 built *who someone is* — SID, memberships, POSIX numbers, primary
//! group, profile, claims — all of it **asserted** by a principal source. This
//! is the other half: how much this machine trusts them. It is local policy,
//! authd's alone, and no source has any message with which to ask for it.
//!
//! # One record per principal
//!
//! ```text
//! Machine\Generic\Authn\Policy
//!   DeniedPrivileges  REG_MULTI_SZ  ["SeDebugPrivilege"]
//!   \Administrators
//!       Privileges    REG_MULTI_SZ  ["SeBackupPrivilege", …]
//!       Integrity     REG_SZ        "High"
//!   \Everyone
//!       Privileges    REG_MULTI_SZ  ["SeChangeNotifyPrivilege"]
//! ```
//!
//! Keyed by principal rather than by privilege so that **one key shows the
//! totality of a principal's authority**. Authority scattered across twenty
//! values is authority nobody audits: a privilege granted somewhere unexpected
//! does not surface when you look at the principal, and you would have to know
//! to check every other place. It is also the only shape that admits more than
//! privileges — integrity now, logon rights later — without a second tree.
//!
//! A subkey's name is a bare well-known name ([`crate::well_known`]) or a
//! literal SID. `BUILTIN\Administrators` is unrepresentable, because a backslash
//! is the registry's path separator.
//!
//! # If the key exists, the key is the whole answer
//!
//! There is no per-value merge with a compiled table. Either the key is absent —
//! an unconfigured machine, which falls back to [`FLOOR`] so it still boots and
//! still logs in — or the key exists, and nothing compiled contributes anything.
//!
//! The alternative, a compiled default that each record replaces, fails in the
//! wrong direction. An administrator who writes `Administrators → [SeBackup]`
//! believing they have locked the machine down would still be handing out
//! whatever the compiled table said for every principal they did not mention,
//! from a table they never saw. That is a *security* failure, and a silent one.
//! Under this rule a partial policy instead makes things stop working, which is
//! an availability failure — worse to hit, far better to diagnose.
//!
//! On any seeded machine the key exists, so [`FLOOR`] is inert by construction
//! and can never silently contribute. The defaults an operator actually gets
//! ship as registry data (`authd-policy.reg`), where they can be read and
//! edited, rather than being compiled in where they can be neither.

use libauthd::wire::{LogonType, LogonTypes};
use peios::registry::{Key, KeyAccess, OpenFlags};
use peios::security::{Acl, IntegrityLevel, Privileges, Sid, SidRef, sddl};

use super::{dword, multi_sz, sz};
use crate::log;
use crate::well_known;

/// Where a principal's policy record lives.
///
/// Under `Generic` rather than `Software\Authd` because this is Peios policy
/// about what a logon means, not configuration belonging to a particular
/// authority's implementation.
pub const KEY: &str = "Machine\\Generic\\Authn\\Policy";

/// The privileges a principal is granted.
const PRIVILEGES_VALUE: &str = "Privileges";

/// The integrity level a principal's token carries.
const INTEGRITY_VALUE: &str = "Integrity";

/// Which principal owns the objects a token creates.
const OWNER_VALUE: &str = "Owner";

/// The DACL objects a token creates inherit, as SDDL.
const DEFAULT_DACL_VALUE: &str = "DefaultDacl";

/// The logon types this principal may *originate* — request of the
/// authority on behalf of somebody else, over `/run/logon.sock`.
///
/// The other half of "client proposes, authority constrains" (PGSS §2.4,
/// obligation 15). Distinct from the wire's per-principal `LogonTypes`,
/// which is the source's statement about the account being signed in; this
/// one is the machine's statement about the *asker* — a graphical greeter
/// gets `["Interactive"]`, a web console `["Network"]`, and neither can
/// mint itself a console-shaped token by proposing a different type.
const LOGON_TYPES_VALUE: &str = "LogonTypes";

/// The security descriptor `/run/logon.sock` carries, as SDDL.
///
/// On the parent key beside [`DENIED_PRIVILEGES_VALUE`], because which
/// principals may reach the logon socket is machine-wide authentication
/// policy, not a property of any one principal's record. PGSS §2.4 requires
/// the socket's access to be controlled by a security descriptor — a site
/// admitting a graphical greeter or a web console widens this value, and
/// grants the peer's record a `LogonTypes` list to make the widening mean
/// something.
const LOGON_SOCKET_SD_VALUE: &str = "LogonSocketDescriptor";

/// Privileges no principal may hold, whatever any record says.
///
/// On the parent key rather than in a record, so it cannot collide with a
/// principal who happens to be called `Denied`, and so the lockdown is one edit
/// that no record you have not read can defeat.
const DENIED_PRIVILEGES_VALUE: &str = "DeniedPrivileges";

/// How many records authd will read.
///
/// A bound on work per logon, not a policy limit.
const MAX_RECORDS: usize = 256;

/// The integrity level of a principal no record names.
///
/// Compiled in **unconditionally** — unlike privileges, this is not a grant.
/// Every token must carry some level to be valid, so "the key exists" cannot be
/// allowed to mean "mint at Untrusted".
pub const DEFAULT_INTEGRITY: IntegrityLevel = IntegrityLevel::MEDIUM;

/// What an unconfigured machine grants, and nothing more.
///
/// Deliberately the bare minimum for a machine to *function* rather than a
/// useful set: without `SeChangeNotifyPrivilege` a process cannot traverse a
/// directory to reach a file, so a token lacking it cannot exec a shell. A
/// machine whose policy was never seeded still boots, still authenticates, and
/// still starts a session — with no administrative powers whatsoever, which is
/// both safe and obvious.
///
/// `SeCreateSymbolicLinkPrivilege` is deliberately **not** here even though it
/// is granted by the shipped seed. Build tools want it; nothing fails to start
/// without it. That keeps this list to exactly "what a logon needs to work".
const FLOOR: &[(&str, Privileges)] = &[("Everyone", Privileges::CHANGE_NOTIFY)];

/// The five named integrity tiers.
///
/// `IntegrityLevel` wraps a `u32` compared numerically, and any value is legal —
/// these are the ones with names. A record may write a raw `REG_DWORD` instead
/// to reach a level between them.
const TIERS: &[(&str, IntegrityLevel)] = &[
    ("Untrusted", IntegrityLevel::UNTRUSTED),
    ("Low", IntegrityLevel::LOW),
    ("Medium", IntegrityLevel::MEDIUM),
    ("High", IntegrityLevel::HIGH),
    ("System", IntegrityLevel::SYSTEM),
];

/// What policy decided for one logon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Present *and* enabled on the token. A privilege a caller had to enable
    /// before it worked would be a grant in name only.
    pub privileges: Privileges,
    /// The token's integrity level.
    pub integrity: IntegrityLevel,
    /// Which principal owns the objects this token creates. `None` means the
    /// user themselves, which is both the default and the ordinary case.
    pub owner: Option<Sid>,
    /// The DACL objects this token creates inherit when nothing else supplies
    /// one. `None` leaves the kernel's default in place.
    pub default_dacl: Option<Acl>,
}

/// One principal's record. Every field optional: absent means "this record does
/// not speak to that", which is not the same as "none".
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    sid: Sid,
    privileges: Option<Privileges>,
    integrity: Option<IntegrityLevel>,
    owner: Option<Sid>,
    default_dacl: Option<Acl>,
    /// `None` — the value is absent, this record does not speak to
    /// origination. `Some` with no bits set — an explicitly empty list,
    /// which *revokes*: the two must not be conflated, because
    /// `LogonTypes::permits` substitutes a default for the empty set that
    /// would silently turn "may originate nothing" into "may originate
    /// almost anything".
    logon_types: Option<LogonTypes>,
}

/// Everything the key says.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Configured {
    records: Vec<Record>,
    denied: Privileges,
}

impl Default for Configured {
    /// A configured machine that grants nothing — which is what an unreadable
    /// key means, and deliberately not what an absent one means.
    fn default() -> Self {
        Configured {
            records: Vec::new(),
            denied: Privileges::empty(),
        }
    }
}

/// Decide what a logon gets.
///
/// `groups` must be the **final** SID set the token will carry, including the
/// ones authd derives — `Everyone`, `Authenticated Users`, `Local`, the
/// logon-type SID. Evaluating against only the asserted memberships would mean
/// `Everyone`'s record never applied, and would quietly remove the ability to
/// write policy against how a logon happened.
pub fn evaluate(user: &SidRef, groups: &[&SidRef]) -> Outcome {
    let configured = read();
    let records = configured.records.as_slice();

    // Privileges union across every SID on the token. A record that names a
    // principal the token does not carry contributes nothing.
    let mut privileges = Privileges::empty();
    for record in records {
        let applies = record.sid.as_ref().as_bytes() == user.as_bytes()
            || groups
                .iter()
                .any(|group| group.as_bytes() == record.sid.as_ref().as_bytes());
        if applies {
            privileges |= record.privileges.unwrap_or_else(Privileges::empty);
        }
    }

    // The machine-wide mask, applied last so no record can defeat it.
    privileges &= !configured.denied;

    Outcome {
        privileges,
        integrity: integrity(records, user, groups),
        owner: owner(records, user, groups),
        default_dacl: default_dacl(records, user, groups),
    }
}

/// Which principal owns the objects this token creates.
///
/// The user's own record wins, as with integrity. Otherwise a *group* may name
/// one — that is the whole point of the setting, since the case it exists for is
/// "objects created by administrators are owned by Administrators" rather than
/// by the individual.
///
/// Groups are **not** ordered, so unlike integrity there is no sensible way to
/// pick between two that disagree: registry enumeration order is not something
/// policy should depend on. Two groups naming different owners is therefore a
/// misconfiguration, and it falls back to the user rather than picking
/// arbitrarily. Two naming the *same* owner is not a conflict.
fn owner(records: &[Record], user: &SidRef, groups: &[&SidRef]) -> Option<Sid> {
    let of = |sid: &SidRef| {
        records
            .iter()
            .find(|record| record.sid.as_ref().as_bytes() == sid.as_bytes())
            .and_then(|record| record.owner.clone())
    };

    if let Some(owner) = of(user) {
        return Some(owner);
    }

    let mut chosen: Option<Sid> = None;
    for group in groups {
        let Some(named) = of(group) else { continue };
        match &chosen {
            None => chosen = Some(named),
            Some(existing) if existing.as_ref().as_bytes() == named.as_ref().as_bytes() => {}
            Some(existing) => {
                log::warn(format_args!(
                    "policy names two different owners for this logon ({existing} and \
                     {named}); using the principal themselves, because group records \
                     have no order to break the tie with"
                ));
                return None;
            }
        }
    }
    chosen
}

/// The user's own record wins outright; otherwise the maximum across the groups.
///
/// Not the privilege rule, and the difference is deliberate: privileges are a
/// set that accumulates, integrity is a single number that has to be chosen.
///
/// A flat maximum was rejected because it made a principal impossible to *lower*
/// — a guest whose own record said `Low` would still come out Medium the moment
/// any group they belonged to named Medium. Letting the user's own record win
/// makes lowering work without a second mechanism.
///
/// The consequence, which is worth knowing rather than discovering: **a group
/// can no longer impose an integrity floor on a member.** If `Administrators`
/// names High and a member's own record names Low, that member gets Low.
///
/// Precedence is per *value*, not per record — a user record that sets
/// `Privileges` but no `Integrity` does not suppress the group computation, it
/// simply does not speak to integrity.
fn integrity(records: &[Record], user: &SidRef, groups: &[&SidRef]) -> IntegrityLevel {
    let of = |sid: &SidRef| {
        records
            .iter()
            .find(|record| record.sid.as_ref().as_bytes() == sid.as_bytes())
            .and_then(|record| record.integrity)
    };

    if let Some(level) = of(user) {
        return level;
    }

    groups
        .iter()
        .filter_map(|group| of(group))
        .max()
        .unwrap_or(DEFAULT_INTEGRITY)
}

/// Read the key, or fall back to the floor if there is no key to read.
fn read() -> Configured {
    let key = match Key::open(
        None,
        KEY,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return floor(),
        Err(error) => {
            // Present but unreadable — a descriptor that locked authd out, or a
            // damaged hive. Treating this as absent would silently restore every
            // privilege an administrator may have deliberately removed, at the
            // one moment nobody can check. Grant nothing instead, and say so.
            log::warn(format_args!(
                "{KEY} exists but cannot be read ({error}); granting no privileges. \
                 This is deliberate: an unreadable policy must not be mistaken for \
                 an absent one."
            ));
            return Configured::default();
        }
    };

    let mut records = Vec::new();
    for (index, subkey) in key.subkeys(None).enumerate() {
        if records.len() >= MAX_RECORDS {
            log::warn(format_args!(
                "ignoring policy records past the first {MAX_RECORDS} under {KEY}"
            ));
            break;
        }

        let subkey = match subkey {
            Ok(subkey) => subkey,
            Err(error) => {
                log::warn(format_args!(
                    "could not enumerate policy record {index} under {KEY}: {error}"
                ));
                break;
            }
        };

        let Ok(name) = String::from_utf8(subkey.name.clone()) else {
            log::warn(format_args!(
                "ignoring a policy record under {KEY} whose name is not UTF-8"
            ));
            continue;
        };

        // Resolving here, once, is what makes a mistyped principal *visible*.
        // A record naming nobody would otherwise sit in the key looking
        // authoritative and applying to no one, forever.
        let Some(sid) = resolve(&name) else {
            log::warn(format_args!(
                "ignoring policy record {KEY}\\{name}: not a well-known principal \
                 and not a SID"
            ));
            continue;
        };

        match Key::open(
            Some(&key),
            &name,
            KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        ) {
            Ok(entry) => records.push(Record {
                privileges: privileges(&entry, &name),
                integrity: integrity_of(&entry, &name),
                owner: owner_of(&entry, &name),
                default_dacl: default_dacl_of(&entry, &name),
                logon_types: logon_types_of(&entry, &name),
                sid,
            }),
            Err(error) => log::warn(format_args!(
                "could not read policy record {KEY}\\{name} ({error}); it grants nothing"
            )),
        }
    }

    Configured {
        denied: read_privilege_list(&key, KEY, DENIED_PRIVILEGES_VALUE)
            .unwrap_or_else(Privileges::empty),
        records,
    }
}

/// The compiled fallback for a machine with no policy key at all.
fn floor() -> Configured {
    Configured {
        records: FLOOR
            .iter()
            .filter_map(|(name, privileges)| {
                Some(Record {
                    sid: well_known::by_name(name)?,
                    privileges: Some(*privileges),
                    integrity: None,
                    owner: None,
                    default_dacl: None,
                    logon_types: None,
                })
            })
            .collect(),
        denied: Privileges::empty(),
    }
}

/// A record's key name as the SID it means. Well-known name first, then a
/// literal SID.
fn resolve(name: &str) -> Option<Sid> {
    well_known::by_name(name).or_else(|| name.trim().parse::<Sid>().ok())
}

fn privileges(entry: &Key, name: &str) -> Option<Privileges> {
    read_privilege_list(entry, &format!("{KEY}\\{name}"), PRIVILEGES_VALUE)
}

/// The configured SDDL for `/run/logon.sock`, if a site has stated one.
///
/// Read once at startup rather than per logon: a descriptor is applied to
/// the socket when it is bound, and rereading a value that can no longer be
/// applied would only misreport what is in force.
pub fn logon_socket_descriptor() -> Option<String> {
    let key = Key::open(None, KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()).ok()?;
    let value = key
        .query_value(LOGON_SOCKET_SD_VALUE.as_bytes(), None)
        .ok()?;
    match sz(&value.ty, &value.data) {
        Some(text) => Some(text.to_string()),
        None => {
            log::warn(format_args!(
                "{KEY}\\{LOGON_SOCKET_SD_VALUE} is not a REG_SZ; using the built-in \
                 descriptor"
            ));
            None
        }
    }
}

/// The logon types the peer named by `peer` may originate.
///
/// Consulted with the socket peer's user SID and nothing else — no group
/// union, deliberately. Origination is checked before any token exists, so
/// there is no final SID set to evaluate against; the socket yields exactly
/// one verified identity, and a right this consequential should be granted
/// to it by name rather than assembled from memberships nobody stated
/// together.
///
/// `None` means no record speaks to it. What that defaults to is the
/// caller's decision, not this module's — see `may_request`.
pub fn originator_logon_types(peer: &SidRef) -> Option<LogonTypes> {
    read()
        .records
        .iter()
        .find(|record| record.sid.as_ref().as_bytes() == peer.as_bytes())
        .and_then(|record| record.logon_types)
}

/// Read a `REG_MULTI_SZ` of logon-type names.
///
/// The same tolerance rule as privileges: an unknown name is dropped with a
/// warning rather than failing the list, because dropping one grants
/// strictly less — the safe direction for a grant.
fn logon_types_of(entry: &Key, name: &str) -> Option<LogonTypes> {
    let value = entry.query_value(LOGON_TYPES_VALUE.as_bytes(), None).ok()?;
    let path = format!("{KEY}\\{name}");
    let Some(names) = multi_sz(&value.ty, &value.data) else {
        log::warn(format_args!(
            "{path}\\{LOGON_TYPES_VALUE} is not a REG_MULTI_SZ (type {:#x}); ignoring it",
            value.ty.0
        ));
        return None;
    };
    Some(parse_logon_type_names(&names, &path))
}

/// Turn a list of logon-type names into the bitmask.
fn parse_logon_type_names(names: &[&str], path: &str) -> LogonTypes {
    let mut types = LogonTypes::UNSTATED;
    for name in names {
        match logon_type_by_name(name) {
            Some(logon_type) => types = types.with(logon_type),
            None => log::warn(format_args!(
                "{path}\\{LOGON_TYPES_VALUE} names {name:?}, which is not a logon \
                 type this build knows; ignoring it"
            )),
        }
    }
    types
}

/// The names an administrator writes, matching [`LogonType`]'s variants.
fn logon_type_by_name(name: &str) -> Option<LogonType> {
    Some(match name {
        "Interactive" => LogonType::Interactive,
        "Network" => LogonType::Network,
        "Batch" => LogonType::Batch,
        "Service" => LogonType::Service,
        "NetworkCleartext" => LogonType::NetworkCleartext,
        "NewCredentials" => LogonType::NewCredentials,
        _ => return None,
    })
}

/// Read a `REG_MULTI_SZ` of privilege names.
///
/// An unknown name is **dropped with a warning rather than failing the whole
/// list**. The names are an ABI vocabulary that grows: a policy written for a
/// newer Peios can legitimately mention a privilege this build cannot name, and
/// refusing the entire record would take away privileges the administrator did
/// spell correctly. Dropping the one grants strictly less, which is the safe
/// direction for a grant.
fn read_privilege_list(key: &Key, path: &str, value_name: &str) -> Option<Privileges> {
    let value = key.query_value(value_name.as_bytes(), None).ok()?;

    let Some(names) = multi_sz(&value.ty, &value.data) else {
        log::warn(format_args!(
            "{path}\\{value_name} is not a REG_MULTI_SZ (type {:#x}); ignoring it",
            value.ty.0
        ));
        return None;
    };

    let mut privileges = Privileges::empty();
    for name in names {
        match Privileges::parse_name(name) {
            Some(privilege) => privileges |= privilege,
            None => log::warn(format_args!(
                "{path}\\{value_name} names {name:?}, which is not a privilege this \
                 build knows; ignoring it"
            )),
        }
    }
    Some(privileges)
}

/// Read an integrity level, written either as a tier name or as a raw number.
///
/// Both spellings are accepted because they do different jobs: the name is the
/// readable form of the common case, and the number reaches levels no name can
/// express, since the kernel compares integrity numerically and any `u32` is
/// legal. A number that happens to equal a tier is accepted rather than refused
/// in favour of the name — being clever there would only break a scripted
/// writer.
fn integrity_of(entry: &Key, name: &str) -> Option<IntegrityLevel> {
    let value = entry.query_value(INTEGRITY_VALUE.as_bytes(), None).ok()?;

    if let Some(level) = dword(&value.ty, &value.data) {
        return Some(IntegrityLevel(level));
    }

    if let Some(text) = sz(&value.ty, &value.data) {
        if let Some(level) = tier(text) {
            return Some(level);
        }
        log::warn(format_args!(
            "{KEY}\\{name}\\{INTEGRITY_VALUE} is {text:?}, which is not an integrity \
             level; using the default"
        ));
        return None;
    }

    log::warn(format_args!(
        "{KEY}\\{name}\\{INTEGRITY_VALUE} is neither a REG_SZ nor a REG_DWORD \
         (type {:#x}); using the default",
        value.ty.0
    ));
    None
}

/// The DACL objects this token creates inherit when nothing else supplies one.
///
/// Same precedence as [`owner`], and for the same reason: a DACL is a single
/// value with no ordering, so two groups disagreeing cannot be resolved by
/// whichever the registry enumerated first. The user's own record wins;
/// otherwise a group may name one; two groups disagreeing falls back to the
/// kernel's default.
fn default_dacl(records: &[Record], user: &SidRef, groups: &[&SidRef]) -> Option<Acl> {
    let of = |sid: &SidRef| {
        records
            .iter()
            .find(|record| record.sid.as_ref().as_bytes() == sid.as_bytes())
            .and_then(|record| record.default_dacl.clone())
    };

    if let Some(acl) = of(user) {
        return Some(acl);
    }

    let mut chosen: Option<Acl> = None;
    for group in groups {
        let Some(named) = of(group) else { continue };
        match &chosen {
            None => chosen = Some(named),
            Some(existing) if existing.as_bytes() == named.as_bytes() => {}
            Some(_) => {
                log::warn(format_args!(
                    "policy names two different default DACLs for this logon; minting \
                     the token with none, because group records have no order to break \
                     the tie with -- an object it creates with no parent to inherit \
                     from will get a null DACL"
                ));
                return None;
            }
        }
    }
    chosen
}

/// Read a record's default DACL, written as SDDL.
///
/// SDDL rather than raw bytes because this has to be *auditable* — the whole
/// argument for policy living in the registry is that an operator can read it,
/// and a binary ACL in a policy key is exactly the thing nobody checks.
///
/// A malformed value is dropped with a warning rather than failing the logon.
/// The kernel's own default applies instead, which is the same outcome as not
/// configuring one — so a typo here costs the customisation, not the session.
fn default_dacl_of(entry: &Key, name: &str) -> Option<Acl> {
    let value = entry
        .query_value(DEFAULT_DACL_VALUE.as_bytes(), None)
        .ok()?;

    let Some(text) = sz(&value.ty, &value.data) else {
        log::warn(format_args!(
            "{KEY}\\{name}\\{DEFAULT_DACL_VALUE} is not a REG_SZ (type {:#x}); ignoring it",
            value.ty.0
        ));
        return None;
    };

    match sddl::parse_acl(text) {
        Ok(acl) => Some(acl),
        Err(error) => {
            log::warn(format_args!(
                "{KEY}\\{name}\\{DEFAULT_DACL_VALUE} is not a usable SDDL DACL \
                 ({text:?}: {error}); tokens will carry no default DACL and an \
                 object created with no parent to inherit from gets a null DACL"
            ));
            None
        }
    }
}

/// Read the principal a record names as the owner of created objects.
///
/// Named rather than indexed, deliberately. The token field is an *index* into
/// the token's own SID array, which is a number only authd can compute and which
/// would mean something different on the next logon; a policy key has to name
/// the principal and let authd do the conversion.
fn owner_of(entry: &Key, name: &str) -> Option<Sid> {
    let value = entry.query_value(OWNER_VALUE.as_bytes(), None).ok()?;

    let Some(text) = sz(&value.ty, &value.data) else {
        log::warn(format_args!(
            "{KEY}\\{name}\\{OWNER_VALUE} is not a REG_SZ (type {:#x}); ignoring it",
            value.ty.0
        ));
        return None;
    };

    match resolve(text) {
        Some(sid) => Some(sid),
        None => {
            log::warn(format_args!(
                "{KEY}\\{name}\\{OWNER_VALUE} is {text:?}, which is neither a well-known \
                 principal nor a SID; objects will be owned by their creator"
            ));
            None
        }
    }
}

/// A tier by name, matched case-insensitively.
fn tier(text: &str) -> Option<IntegrityLevel> {
    TIERS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(text.trim()))
        .map(|(_, level)| *level)
}

/// What this machine calls an integrity level, for rendering one back.
pub fn tier_name(level: IntegrityLevel) -> Option<&'static str> {
    TIERS
        .iter()
        .find(|(_, tier)| *tier == level)
        .map(|(name, _)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    fn record(
        name: &str,
        privileges: Option<Privileges>,
        integrity: Option<IntegrityLevel>,
    ) -> Record {
        Record {
            sid: resolve(name).expect("a resolvable principal"),
            privileges,
            integrity,
            owner: None,
            default_dacl: None,
            logon_types: None,
        }
    }

    fn owning(name: &str, owner: &str) -> Record {
        Record {
            owner: Some(resolve(owner).expect("a resolvable owner")),
            ..record(name, None, None)
        }
    }

    /// `evaluate` reads the registry, so the composition rules are tested
    /// against the pure halves it delegates to.
    fn union(
        records: &[Record],
        user: &SidRef,
        groups: &[&SidRef],
        denied: Privileges,
    ) -> Privileges {
        let mut privileges = Privileges::empty();
        for record in records {
            let applies = record.sid.as_ref().as_bytes() == user.as_bytes()
                || groups
                    .iter()
                    .any(|g| g.as_bytes() == record.sid.as_ref().as_bytes());
            if applies {
                privileges |= record.privileges.unwrap_or_else(Privileges::empty);
            }
        }
        privileges & !denied
    }

    // -----------------------------------------------------------------------
    // Integrity composition
    // -----------------------------------------------------------------------

    #[test]
    fn a_principal_no_record_names_gets_the_default() {
        let user = sid("S-1-5-21-1-2-3-1000");
        assert_eq!(integrity(&[], user.as_ref(), &[]), DEFAULT_INTEGRITY);
        assert_eq!(DEFAULT_INTEGRITY, IntegrityLevel::MEDIUM);
    }

    #[test]
    fn groups_compose_by_maximum() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let everyone = sid("S-1-1-0");
        let records = [
            record("Administrators", None, Some(IntegrityLevel::HIGH)),
            record("Everyone", None, Some(IntegrityLevel::LOW)),
        ];
        assert_eq!(
            integrity(
                &records,
                user.as_ref(),
                &[admins.as_ref(), everyone.as_ref()]
            ),
            IntegrityLevel::HIGH
        );
    }

    /// The rule that makes lowering possible at all. Under a flat maximum this
    /// principal would come out Medium and could never be pinned down.
    #[test]
    fn the_users_own_record_wins_outright_even_when_lower() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [
            record("Administrators", None, Some(IntegrityLevel::HIGH)),
            record("S-1-5-21-1-2-3-1000", None, Some(IntegrityLevel::LOW)),
        ];
        assert_eq!(
            integrity(&records, user.as_ref(), &[admins.as_ref()]),
            IntegrityLevel::LOW,
            "a group must not impose a floor on a member"
        );
    }

    /// Precedence is per value: a user record that says nothing about integrity
    /// must not suppress the group computation.
    #[test]
    fn a_user_record_without_an_integrity_value_falls_through_to_the_groups() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [
            record("S-1-5-21-1-2-3-1000", Some(Privileges::BACKUP), None),
            record("Administrators", None, Some(IntegrityLevel::HIGH)),
        ];
        assert_eq!(
            integrity(&records, user.as_ref(), &[admins.as_ref()]),
            IntegrityLevel::HIGH
        );
    }

    /// The emergent property worth keeping: policy can be written against how a
    /// logon happened, not only who it was.
    #[test]
    fn a_logon_type_sid_can_carry_a_level() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let network = sid("S-1-5-2");
        let records = [record("Network", None, Some(IntegrityLevel::LOW))];
        assert_eq!(
            integrity(&records, user.as_ref(), &[network.as_ref()]),
            IntegrityLevel::LOW
        );
    }

    #[test]
    fn a_record_for_a_principal_the_token_does_not_carry_is_ignored() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let records = [record("Administrators", None, Some(IntegrityLevel::HIGH))];
        assert_eq!(
            integrity(&records, user.as_ref(), &[]),
            DEFAULT_INTEGRITY,
            "policy must not apply to a principal who is not in the group"
        );
    }

    // -----------------------------------------------------------------------
    // Privilege composition
    // -----------------------------------------------------------------------

    #[test]
    fn privileges_union_across_every_sid_on_the_token() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let everyone = sid("S-1-1-0");
        let records = [
            record("Everyone", Some(Privileges::CHANGE_NOTIFY), None),
            record(
                "Administrators",
                Some(Privileges::BACKUP | Privileges::RESTORE),
                None,
            ),
        ];
        assert_eq!(
            union(
                &records,
                user.as_ref(),
                &[admins.as_ref(), everyone.as_ref()],
                Privileges::empty()
            ),
            Privileges::CHANGE_NOTIFY | Privileges::BACKUP | Privileges::RESTORE
        );
    }

    /// The lockdown knob: one edit that no record the operator has not read can
    /// defeat, applied after the union rather than before.
    #[test]
    fn denied_privileges_beat_every_record() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [record(
            "Administrators",
            Some(Privileges::BACKUP | Privileges::DEBUG),
            None,
        )];
        assert_eq!(
            union(
                &records,
                user.as_ref(),
                &[admins.as_ref()],
                Privileges::DEBUG
            ),
            Privileges::BACKUP
        );
    }

    #[test]
    fn an_empty_privilege_list_grants_nothing() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let records = [record(
            "S-1-5-21-1-2-3-1000",
            Some(Privileges::empty()),
            None,
        )];
        assert_eq!(
            union(&records, user.as_ref(), &[], Privileges::empty()),
            Privileges::empty()
        );
    }

    // -----------------------------------------------------------------------
    // The floor
    // -----------------------------------------------------------------------

    /// An unconfigured machine must still be able to start a shell — without
    /// ChangeNotify a process cannot traverse a directory to reach a file.
    #[test]
    fn the_floor_keeps_an_unseeded_machine_usable() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let everyone = sid("S-1-1-0");
        let configured = floor();
        assert_eq!(
            union(
                &configured.records,
                user.as_ref(),
                &[everyone.as_ref()],
                configured.denied
            ),
            Privileges::CHANGE_NOTIFY
        );
    }

    /// The floor is a floor, not a useful policy: no administrative power comes
    /// from it, so a machine whose seed never applied is safe as well as usable.
    #[test]
    fn the_floor_grants_no_administrative_privilege() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let everyone = sid("S-1-1-0");
        let configured = floor();
        let granted = union(
            &configured.records,
            user.as_ref(),
            &[admins.as_ref(), everyone.as_ref()],
            configured.denied,
        );
        for forbidden in [
            Privileges::BACKUP,
            Privileges::RESTORE,
            Privileges::DEBUG,
            Privileges::LOAD_DRIVER,
            Privileges::TCB,
            Privileges::CREATE_TOKEN,
        ] {
            assert!(
                !granted.contains(forbidden),
                "the floor must not grant {:?}",
                forbidden.canonical_name()
            );
        }
    }

    #[test]
    fn every_floor_entry_names_a_principal_that_resolves() {
        assert_eq!(
            floor().records.len(),
            FLOOR.len(),
            "a floor entry did not resolve"
        );
    }

    // -----------------------------------------------------------------------
    // Reading values
    // -----------------------------------------------------------------------

    #[test]
    fn tiers_are_named_case_insensitively() {
        assert_eq!(tier("Medium"), Some(IntegrityLevel::MEDIUM));
        assert_eq!(tier("medium"), Some(IntegrityLevel::MEDIUM));
        assert_eq!(tier("  HIGH  "), Some(IntegrityLevel::HIGH));
        assert_eq!(tier("Untrusted"), Some(IntegrityLevel::UNTRUSTED));
        assert_eq!(tier("System"), Some(IntegrityLevel::SYSTEM));
        assert_eq!(tier("Meduim"), None);
        assert_eq!(tier(""), None);
    }

    #[test]
    fn every_tier_round_trips() {
        for (name, level) in TIERS {
            assert_eq!(tier(name), Some(*level));
            assert_eq!(tier_name(*level), Some(*name));
        }
    }

    /// A level between the tiers has no name, which is precisely why the
    /// numeric spelling is accepted.
    #[test]
    fn a_level_between_tiers_has_no_name() {
        assert_eq!(tier_name(IntegrityLevel(8193)), None);
    }

    #[test]
    fn a_record_name_resolves_by_well_known_name_or_by_sid() {
        assert_eq!(
            resolve("Administrators").as_ref().map(|s| s.to_string()),
            Some("S-1-5-32-544".to_string())
        );
        assert_eq!(
            resolve("S-1-5-32-544").as_ref().map(|s| s.to_string()),
            Some("S-1-5-32-544".to_string())
        );
        assert_eq!(
            resolve("S-1-5-21-1-2-3-1000")
                .as_ref()
                .map(|s| s.to_string()),
            Some("S-1-5-21-1-2-3-1000".to_string())
        );
    }

    /// A mistyped principal must not silently apply to nobody — `read` logs it,
    /// which it can only do because resolution happens once, up front.
    // -----------------------------------------------------------------------
    // Owner
    // -----------------------------------------------------------------------

    #[test]
    fn nobody_named_means_the_principal_owns_what_they_create() {
        let user = sid("S-1-5-21-1-2-3-1000");
        assert_eq!(owner(&[], user.as_ref(), &[]), None);
    }

    /// The case the setting exists for: objects an administrator creates are
    /// owned by the group rather than by the individual.
    #[test]
    fn a_group_record_may_name_the_owner() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [owning("Administrators", "Administrators")];
        assert_eq!(
            owner(&records, user.as_ref(), &[admins.as_ref()]),
            Some(sid("S-1-5-32-544"))
        );
    }

    #[test]
    fn the_users_own_record_wins() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [
            owning("Administrators", "Administrators"),
            owning("S-1-5-21-1-2-3-1000", "Users"),
        ];
        assert_eq!(
            owner(&records, user.as_ref(), &[admins.as_ref()]),
            Some(sid("S-1-5-32-545"))
        );
    }

    /// Groups have no order, so two disagreeing must not be resolved by
    /// whichever the registry happened to enumerate first.
    #[test]
    fn two_groups_naming_different_owners_fall_back_to_the_creator() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let users = sid("S-1-5-32-545");
        let records = [
            owning("Administrators", "Administrators"),
            owning("Users", "Users"),
        ];
        assert_eq!(
            owner(&records, user.as_ref(), &[admins.as_ref(), users.as_ref()]),
            None,
            "an ambiguous owner must not be resolved arbitrarily"
        );
    }

    /// Agreement is not ambiguity.
    #[test]
    fn two_groups_naming_the_same_owner_agree() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let users = sid("S-1-5-32-545");
        let records = [
            owning("Administrators", "Administrators"),
            owning("Users", "Administrators"),
        ];
        assert_eq!(
            owner(&records, user.as_ref(), &[admins.as_ref(), users.as_ref()]),
            Some(sid("S-1-5-32-544"))
        );
    }

    // -----------------------------------------------------------------------
    // Default DACL
    // -----------------------------------------------------------------------

    fn with_dacl(name: &str, sddl_text: &str) -> Record {
        Record {
            default_dacl: Some(sddl::parse_acl(sddl_text).expect("valid SDDL")),
            ..record(name, None, None)
        }
    }

    #[test]
    fn no_record_naming_one_leaves_the_system_default() {
        let user = sid("S-1-5-21-1-2-3-1000");
        assert!(default_dacl(&[], user.as_ref(), &[]).is_none());
    }

    #[test]
    fn a_group_record_may_name_a_default_dacl() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [with_dacl("Administrators", "D:(A;;GA;;;SY)(A;;GA;;;BA)")];
        let chosen =
            default_dacl(&records, user.as_ref(), &[admins.as_ref()]).expect("the group's DACL");
        assert_eq!(chosen.view().expect("parseable").len(), 2);
    }

    #[test]
    fn the_users_own_default_dacl_wins() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let records = [
            with_dacl("Administrators", "D:(A;;GA;;;SY)(A;;GA;;;BA)"),
            with_dacl("S-1-5-21-1-2-3-1000", "D:(A;;GA;;;SY)"),
        ];
        let chosen =
            default_dacl(&records, user.as_ref(), &[admins.as_ref()]).expect("the user's DACL");
        assert_eq!(chosen.view().expect("parseable").len(), 1);
    }

    #[test]
    fn two_groups_naming_different_default_dacls_fall_back() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let users = sid("S-1-5-32-545");
        let records = [
            with_dacl("Administrators", "D:(A;;GA;;;BA)"),
            with_dacl("Users", "D:(A;;GA;;;SY)"),
        ];
        assert!(
            default_dacl(&records, user.as_ref(), &[admins.as_ref(), users.as_ref()]).is_none(),
            "an ambiguous default DACL must not be resolved arbitrarily"
        );
    }

    #[test]
    fn two_groups_naming_the_same_default_dacl_agree() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let admins = sid("S-1-5-32-544");
        let users = sid("S-1-5-32-545");
        let records = [
            with_dacl("Administrators", "D:(A;;GA;;;SY)"),
            with_dacl("Users", "D:(A;;GA;;;SY)"),
        ];
        assert!(
            default_dacl(&records, user.as_ref(), &[admins.as_ref(), users.as_ref()]).is_some()
        );
    }

    /// A conditional ACE in a default DACL must keep its expression — the whole
    /// reason `sddl::parse_acl` rebuilds rather than transcribes.
    #[test]
    fn a_conditional_ace_in_a_default_dacl_survives() {
        let acl = sddl::parse_acl("D:(XA;;GA;;;WD;(@USER.Department == \"Engineering\"))")
            .expect("valid conditional SDDL");
        let view = acl.view().expect("parseable");
        assert!(
            view.ace(0).and_then(|ace| ace.app_data()).is_some(),
            "the condition must survive into the token's default DACL"
        );
    }

    // -----------------------------------------------------------------------
    // The shipped seed
    // -----------------------------------------------------------------------

    /// The seed is the policy every machine that opts in actually gets, and a
    /// misspelled privilege there is dropped with a warning nobody reads — so
    /// `SeBackupPriviledge` would silently cost administrators their backup
    /// rights. Checking it here is the only place that mistake is cheap.
    ///
    /// Scans the whole file rather than parsing the JSON, so names mentioned in
    /// the explanatory comments are held to the same standard. That is
    /// deliberate: a comment naming a privilege that does not exist is
    /// documentation that will mislead somebody.
    #[test]
    fn every_privilege_the_seed_names_is_a_real_privilege() {
        const SEED: &str = include_str!("../../../registry.d/authd-policy.reg");

        let mut checked = 0;
        for candidate in SEED.split(|c: char| !c.is_ascii_alphanumeric()) {
            if !candidate.starts_with("Se") || !candidate.ends_with("Privilege") {
                continue;
            }
            assert!(
                Privileges::parse_name(candidate).is_some(),
                "authd-policy.reg names {candidate:?}, which is not a privilege"
            );
            checked += 1;
        }
        assert!(
            checked > 10,
            "expected the seed to name privileges; found {checked}, so the scan is broken"
        );
    }

    /// The seed names a default DACL on Everyone, and it has to be one the
    /// parser accepts: a value that fails to parse is dropped with a warning
    /// (`default_dacl_of`), which would silently reopen the null-DACL case
    /// this value exists to close. It must grant the owner through OWNER
    /// RIGHTS, because the kernel copies a default DACL onto a new file
    /// verbatim: a CREATOR OWNER placeholder would name nobody.
    #[test]
    fn the_seed_ships_a_default_dacl_that_parses_and_names_owner_rights() {
        const SEED: &str = include_str!("../../../registry.d/authd-policy.reg");

        let value = SEED
            .split("\"name\": \"DefaultDacl\"")
            .nth(1)
            .and_then(|rest| rest.split("\"data\": \"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .expect("the seed names a DefaultDacl value on a record");

        let acl = sddl::parse_acl(value).expect("the seed's DefaultDacl is valid SDDL");
        assert!(!acl.as_bytes().is_empty());
        assert!(
            value.contains("S-1-3-4"),
            "the default DACL must grant the owner through OWNER RIGHTS: {value}"
        );
        assert!(
            !value.contains("S-1-3-0") && !value.contains(";CO)"),
            "CREATOR OWNER is never substituted in a default DACL: {value}"
        );
    }

    /// The seed must never hand out the privileges that would make every other
    /// control in it decorative.
    #[test]
    fn the_seed_does_not_grant_the_privileges_reserved_to_the_tcb() {
        const SEED: &str = include_str!("../../../registry.d/authd-policy.reg");

        // Only the granted lists, not the prose explaining what is withheld.
        // Both reserved names appear in the comments by design.
        for line in SEED.lines() {
            let line = line.trim();
            if !line.starts_with('"') || !line.ends_with("\",") && !line.ends_with('"') {
                continue;
            }
            for reserved in [
                "SeCreateTokenPrivilege",
                "SeTcbPrivilege",
                "SeAssignPrimaryTokenPrivilege",
            ] {
                assert_ne!(
                    line.trim_matches(|c| c == '"' || c == ','),
                    reserved,
                    "the seed grants {reserved}, which belongs to the TCB alone"
                );
            }
        }
    }

    /// Insurance against a partial edit: privileges union across the token's
    /// SIDs, so an administrator keeping ChangeNotify directly means dropping
    /// the Everyone record locks out ordinary users but leaves someone able to
    /// repair it.
    #[test]
    fn the_seed_grants_administrators_change_notify_directly() {
        const SEED: &str = include_str!("../../../registry.d/authd-policy.reg");

        let administrators = SEED
            .split("Policy\\\\Administrators")
            .nth(1)
            .expect("the seed must carry an Administrators record");
        assert!(
            administrators.contains("SeChangeNotifyPrivilege"),
            "Administrators must hold SeChangeNotifyPrivilege directly, so a botched \
             edit to the Everyone record cannot lock every principal out of a shell"
        );
    }

    #[test]
    fn a_name_that_is_neither_well_known_nor_a_sid_does_not_resolve() {
        assert_eq!(resolve("Administrtors"), None);
        assert_eq!(resolve("Domain Admins"), None);
        assert_eq!(resolve("BUILTIN\\Administrators"), None);
        assert_eq!(resolve(""), None);
    }

    // -----------------------------------------------------------------------
    // Originator logon types (PGSS §2.4 obligation 15)
    // -----------------------------------------------------------------------

    #[test]
    fn logon_type_names_parse_to_the_bitmask() {
        let types = parse_logon_type_names(&["Interactive", "Network"], "test");
        assert!(types.bits() & (1 << LogonType::Interactive as u32) != 0);
        assert!(types.bits() & (1 << LogonType::Network as u32) != 0);
        assert!(types.bits() & (1 << LogonType::Service as u32) == 0);
    }

    #[test]
    fn an_unknown_logon_type_name_is_dropped_not_fatal() {
        let types = parse_logon_type_names(&["Interactive", "Telepathic"], "test");
        assert!(types.bits() & (1 << LogonType::Interactive as u32) != 0);
        assert_eq!(types.bits().count_ones(), 1);
    }

    #[test]
    fn an_empty_list_grants_nothing_despite_the_wire_default() {
        // The trap may_request avoids: LogonTypes::permits substitutes
        // DEFAULT for the empty set, which is right for a principal's own
        // sign-on surface and would turn "may originate nothing" into "may
        // originate almost anything" here. The raw bits are the grant.
        let types = parse_logon_type_names(&[], "test");
        assert_eq!(types.bits(), 0);
        assert!(
            types.permits(LogonType::Interactive),
            "permits() substitutes the default; if this stops holding, the \
             comment in may_request is stale"
        );
        assert!(types.bits() & (1 << LogonType::Interactive as u32) == 0);
    }
}
