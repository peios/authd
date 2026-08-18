//! Which principal sources may register, and what each is trusted to say.
//!
//! Under `Software\Authd` rather than `Generic`, and the split is deliberate:
//! principal sources are an *authd* concept — PSI is authd's protocol, not part
//! of PGSS — where [`super::principal`] holds what a logon means to any
//! authority.

use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};
use peios::security::{Sid, WellKnown};

use super::dword;
use crate::log;
use crate::service_sid;
use crate::unix_id;

/// The allowlist of principal sources.
///
/// **A subkey's name is the allowlist entry.** `Sources\lpsd` says "a service
/// named lpsd may register as a principal source", and authd checks that by
/// deriving lpsd's service SID and requiring the connecting peer's token to
/// carry it. So `reg ls` on this key answers "what may assert identity on this
/// machine?" exactly, with no second list anywhere to drift out of step.
pub const SOURCES_KEY: &str = "Machine\\Software\\Authd\\Sources";

/// Lifts the cross-reference restriction on asserted *group* memberships.
///
/// An ordinary source may only assert groups in the same domain as the
/// principal it just authenticated: a directory vouches for its own users and
/// its own groups, and nothing else. The local source is different in kind — it
/// is authoritative for local group membership of *any* principal, including
/// domain ones, which is what makes "`CORP\Domain Admins` is in
/// `BUILTIN\Administrators`" a *local* record rather than something a domain
/// controller can assert at you.
///
/// **Memberships only, never identity.** A source with this flag still may not
/// be the authority on *who someone is* outside its own domain, and the
/// distinction is not academic: the local source holds no domain credential, so
/// an identity-unrestricted lpsd could hand out a domain identity to anyone who
/// knew a *local* password. Confining identity keeps a compromise of it at
/// "administrator of this machine" rather than "any principal in the forest".
const FOREIGN_MEMBERSHIPS_VALUE: &str = "MayAssertForeignMemberships";

/// Pins the domain a source is permitted to declare.
///
/// A source declares the domain it is authoritative for when it registers, and
/// authd confines every identity it asserts to that domain. The declaration is
/// a *claim*: a source generates its own domain, so nothing about the SID can
/// prove the claim is honest.
///
/// Absent, authd accepts the declaration and applies the checks it can make
/// without one — the domain must be a claimable shape, it must not collide with
/// another registered source's, and a source that re-registers must declare
/// what it declared before.
///
/// **authd never writes it.** Pinning on first registration would need this
/// process — the one holding `SeCreateTokenPrivilege` — to hold a registry
/// write handle. Having the *source* write it was rejected too: that is the
/// lower-trust party writing into the key that governs what it may do.
const DOMAIN_VALUE: &str = "Domain";

/// Where this source sits when authd resolves a name nobody qualified.
///
/// Lower first. This is the value that decides who `jack` is on a machine with
/// more than one source, and it is deliberately explicit: resolving in
/// registration order would let a slow disk change which principal a name refers
/// to, and two components disagreeing about that is a confused deputy rather
/// than a cosmetic inconsistency.
const SEARCH_ORDER_VALUE: &str = "SearchOrder";

/// The order a source resolves at when it names none.
///
/// Mid-range, so a source can be configured either side of the default without
/// having to renumber the ones already there.
pub const DEFAULT_SEARCH_ORDER: u32 = 1000;

/// How many source entries authd will consider.
///
/// A bound on work done for an unauthenticated connection, not a policy limit.
const MAX_SOURCE_ENTRIES: usize = 64;

/// The bottom of a source's Unix ID range.
///
/// authd adds this to every relative id the source asserts, so `lpsd`'s first
/// principal — number 1 — projects to uid 1,000,001 when this is 1,000,000.
///
/// **Absent means no range, and no range means `nobody`.** Every principal from
/// an unconfigured source projects to 65534. That is the safe direction: 65534
/// grants nothing, and the alternative — assuming a base — would put two sources
/// on the same numbers the moment a second one existed.
const UNIX_ID_BASE_VALUE: &str = "UnixIDBase";

/// How many ids the range spans. Absent takes [`unix_id::DEFAULT_COUNT`].
///
/// This is not decoration. A source asserts *relative* numbers, so without a
/// ceiling a large enough one would land inside the next source's range — or,
/// were the base ever low, inside the band where 0 is root.
const UNIX_ID_COUNT_VALUE: &str = "UnixIDCount";

/// A principal source authd is willing to talk to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    /// The configured name, which is also the service name its SID derives
    /// from. Taken from the registry, never from the connecting process.
    pub name: String,
    /// The service SID a peer must carry to be this source.
    pub service_sid: Sid,
    /// Whether [`FOREIGN_MEMBERSHIPS_VALUE`] is set.
    pub may_assert_foreign_memberships: bool,
    /// The domain this source is required to declare, if [`DOMAIN_VALUE`] pins
    /// one. `None` means unpinned, not unrestricted — see [`DOMAIN_VALUE`].
    pub pinned_domain: Option<Sid>,
    /// The Unix ID range this source's numbers land in. `None` when
    /// [`UNIX_ID_BASE_VALUE`] is absent or unusable.
    pub unix_id_range: Option<unix_id::Range>,
    /// Where this source sits when resolving a bare name — see
    /// [`SEARCH_ORDER_VALUE`].
    pub search_order: u32,
}

/// Every configured principal source.
///
/// An empty list — including when the key does not exist — means **no source
/// may register**. An absent *policy* value means "use the documented default";
/// an absent *allowlist* must mean "nobody", because an allowlist that fails
/// open is not an allowlist. The cost is that an image which ships no seed
/// cannot authenticate anyone, which is the correct way for that mistake to
/// present.
pub fn sources() -> Vec<SourceEntry> {
    let key = match Key::open(
        None,
        SOURCES_KEY,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ) {
        Ok(key) => key,
        Err(error) => {
            log::warn(format_args!(
                "no principal sources are configured at {SOURCES_KEY} ({error}); \
                 none may register"
            ));
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    for (index, subkey) in key.subkeys(None).enumerate() {
        if entries.len() >= MAX_SOURCE_ENTRIES {
            log::warn(format_args!(
                "ignoring principal sources past the first {MAX_SOURCE_ENTRIES} under {SOURCES_KEY}"
            ));
            break;
        }

        let subkey = match subkey {
            Ok(subkey) => subkey,
            Err(error) => {
                log::warn(format_args!(
                    "could not enumerate source {index} under {SOURCES_KEY}: {error}"
                ));
                break;
            }
        };

        let Ok(name) = String::from_utf8(subkey.name.clone()) else {
            log::warn(format_args!(
                "ignoring a source under {SOURCES_KEY} whose name is not UTF-8"
            ));
            continue;
        };

        let Some(service_sid) = service_sid::of(&name) else {
            log::warn(format_args!(
                "ignoring source {name}: could not derive its service SID"
            ));
            continue;
        };

        let (may_assert_foreign_memberships, pinned_domain, unix_id_range, order) =
            match Key::open(Some(&key), &name, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
                Ok(entry) => (
                    is_set(&entry, FOREIGN_MEMBERSHIPS_VALUE),
                    pinned_domain(&entry, &name),
                    unix_id_range(&entry, &name),
                    search_order(&entry, &name),
                ),
                Err(error) => {
                    // The entry exists — it was just enumerated — so failing to
                    // reopen it is a real fault rather than the ordinary
                    // "unconfigured" case. Admit it with the narrower
                    // permission rather than dropping it.
                    log::warn(format_args!(
                        "could not read {SOURCES_KEY}\\{name} ({error}); assuming no \
                         foreign memberships and no Unix ID range"
                    ));
                    (false, None, None, DEFAULT_SEARCH_ORDER)
                }
            };

        entries.push(SourceEntry {
            name,
            service_sid,
            may_assert_foreign_memberships,
            pinned_domain,
            unix_id_range,
            search_order: order,
        });
    }

    entries
}

/// Read a pinned domain, if one is configured.
///
/// A malformed value is **not** treated as absent. Absence means "no pin"; a
/// value that cannot be parsed means an administrator tried to write a pin and
/// got it wrong, and quietly downgrading that to "unpinned" would remove the
/// control they were trying to apply, silently, at the moment they were trying
/// to apply it. Refusing the whole source entry is the safe direction.
fn pinned_domain(entry: &Key, name: &str) -> Option<Sid> {
    let value = match entry.query_value(DOMAIN_VALUE.as_bytes(), None) {
        Ok(value) => value,
        Err(_) => return None,
    };

    if value.ty != ValueType::SZ {
        log::warn(format_args!(
            "{SOURCES_KEY}\\{name}\\{DOMAIN_VALUE} is not a REG_SZ (type {:#x}); \
             {name} will not be able to register",
            value.ty.0
        ));
        return Some(unsatisfiable_pin());
    }

    let text = super::sz(&value.ty, &value.data).unwrap_or_default();

    match text.parse::<Sid>() {
        Ok(sid) => Some(sid),
        Err(_) => {
            log::warn(format_args!(
                "{SOURCES_KEY}\\{name}\\{DOMAIN_VALUE} is not a SID ({text:?}); \
                 {name} will not be able to register"
            ));
            Some(unsatisfiable_pin())
        }
    }
}

/// Read a source's Unix ID range, if one is configured and usable.
///
/// Unlike a pinned domain, a malformed value here is treated as absent rather
/// than as an unsatisfiable constraint. The two differ because of what each
/// value *is*: a pin is a restriction, so discarding it would remove a control.
/// A range is a grant — it is what lets a source's principals project to real
/// numbers at all — so discarding it grants strictly less.
fn unix_id_range(entry: &Key, name: &str) -> Option<unix_id::Range> {
    let base = match entry.query_value(UNIX_ID_BASE_VALUE.as_bytes(), None) {
        Ok(value) => match dword(&value.ty, &value.data) {
            Some(base) => base,
            None => {
                log::warn(format_args!(
                    "{SOURCES_KEY}\\{name}\\{UNIX_ID_BASE_VALUE} is not a REG_DWORD; \
                     {name}'s principals will project to nobody"
                ));
                return None;
            }
        },
        // Absent, which is a supported state: the source simply has no range.
        Err(_) => return None,
    };

    let count = match entry.query_value(UNIX_ID_COUNT_VALUE.as_bytes(), None) {
        Ok(value) => match dword(&value.ty, &value.data) {
            Some(count) => count,
            None => {
                log::warn(format_args!(
                    "{SOURCES_KEY}\\{name}\\{UNIX_ID_COUNT_VALUE} is not a REG_DWORD; \
                     using the default of {}",
                    unix_id::DEFAULT_COUNT
                ));
                unix_id::DEFAULT_COUNT
            }
        },
        Err(_) => unix_id::DEFAULT_COUNT,
    };

    match unix_id::Range::new(base, count) {
        Ok(range) => Some(range),
        Err(error) => {
            log::warn(format_args!(
                "{SOURCES_KEY}\\{name} configures an unusable Unix ID range \
                 (base {base}, count {count}): {error}; {name}'s principals will project \
                 to nobody"
            ));
            None
        }
    }
}

/// Stands in for a pin nobody can parse.
///
/// `S-1-0-0` (Null) is never a claimable domain shape, so a source pinned to it
/// can never satisfy the pin. That turns "the administrator wrote a broken pin"
/// into "this source cannot register", which is the outcome a broken pin should
/// have — visible, and failing towards nobody registering.
fn unsatisfiable_pin() -> Sid {
    Sid::well_known(WellKnown::Null)
}

/// Where a source sits when resolving a bare name.
///
/// Lower is consulted first. Sources sharing a value are ordered by name, so the
/// result never depends on which source happened to register first — a slow disk
/// must not be able to change which principal `jack` refers to.
fn search_order(key: &Key, name: &str) -> u32 {
    match key.query_value(SEARCH_ORDER_VALUE.as_bytes(), None) {
        Ok(value) => match dword(&value.ty, &value.data) {
            Some(order) => order,
            None => {
                log::warn(format_args!(
                    "{SOURCES_KEY}\\{name}\\{SEARCH_ORDER_VALUE} is not a REG_DWORD; \
                     resolving it at the default {DEFAULT_SEARCH_ORDER}"
                ));
                DEFAULT_SEARCH_ORDER
            }
        },
        Err(_) => DEFAULT_SEARCH_ORDER,
    }
}

/// Whether a value is present and not zero. Absent is false.
///
/// This grants a permission rather than restoring a documented default, so
/// silence must mean "no".
fn is_set(key: &Key, name: &str) -> bool {
    match key.query_value(name.as_bytes(), None) {
        Ok(value) => dword(&value.ty, &value.data).is_some_and(|v| v != 0),
        Err(_) => false,
    }
}
