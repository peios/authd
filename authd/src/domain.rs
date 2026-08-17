//! What a domain is, and what living in one means.
//!
//! Every scoping rule authd applies reduces to one of the three predicates
//! here, so they are kept together rather than spread across the places that
//! ask. All three work on the binary form: a SID is
//!
//! ```text
//! revision u8 | sub_authority_count u8 | identifier_authority [u8; 6] (big-endian)
//!             | sub_authority u32 (little-endian) * count
//! ```
//!
//! and comparing bytes means these hold for any domain, well-known or not,
//! without a table of special cases to keep current.

use peios::security::SidRef;

/// Bytes before the first sub-authority.
const PRELUDE: usize = 8;
/// `S-1-5-…` — the NT authority, big-endian in the identifier field.
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
/// `S-1-5-21-…` — SECURITY_NT_NON_UNIQUE: a domain issued by a machine rather
/// than by the specification.
const NON_UNIQUE: u32 = 21;
/// `S-1-5-21-{A}-{B}-{C}`.
const LOCAL_DOMAIN_SUB_AUTHORITIES: u8 = 4;

fn sub_authority(sid: &[u8], index: usize) -> Option<u32> {
    let at = PRELUDE + index * 4;
    let bytes = sid.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn count(sid: &[u8]) -> Option<u8> {
    sid.get(1).copied()
}

/// Whether this is a well-formed domain a source may claim: `S-1-5-21-A-B-C`.
///
/// The shape is the entire check, and it is enough. A source cannot claim
/// `BUILTIN` (`S-1-5-32`), or the NT authority's own well-known range
/// (`S-1-5-18`, `S-1-5-11`, …), or `S-1-1-0`, because none of them are four
/// sub-authorities under NT-authority-21. That is why there is no list of
/// forbidden domains here to be kept in step with the SID catalogue: the
/// permitted shape excludes every one of them by construction.
///
/// It does *not* establish that the domain is this source's to claim. Nothing
/// can, from the SID alone — see `source::register` for the checks that give a
/// claim weight.
pub fn is_claimable(sid: &SidRef) -> bool {
    let bytes = sid.as_bytes();
    bytes.len() == PRELUDE + LOCAL_DOMAIN_SUB_AUTHORITIES as usize * 4
        && bytes.first() == Some(&1)
        && count(bytes) == Some(LOCAL_DOMAIN_SUB_AUTHORITIES)
        && bytes[2..PRELUDE] == NT_AUTHORITY
        && sub_authority(bytes, 0) == Some(NON_UNIQUE)
}

/// Whether `principal` is a principal of `domain` — the domain's SID plus
/// exactly one RID.
///
/// Exactly one: `S-1-5-21-A-B-C-1000-1` is not a principal of
/// `S-1-5-21-A-B-C`, and admitting it would let a source that owns one domain
/// mint names in a nested namespace nobody had agreed it owned.
pub fn contains(domain: &SidRef, principal: &SidRef) -> bool {
    let (domain, principal) = (domain.as_bytes(), principal.as_bytes());
    let Some(domain_count) = count(domain) else {
        return false;
    };
    if count(principal) != Some(domain_count + 1) {
        return false;
    }
    let shared = PRELUDE + domain_count as usize * 4;
    if principal.len() != shared + 4 || domain.len() != shared {
        return false;
    }
    // Revision, identifier authority, and every sub-authority the domain has —
    // but *not* the sub-authority count at byte 1, which differs by exactly one
    // by construction. Comparing the prelude wholesale here would make this
    // always false.
    domain.first() == principal.first()
        && domain[2..PRELUDE] == principal[2..PRELUDE]
        && domain[PRELUDE..shared] == principal[PRELUDE..shared]
}

/// Whether two SIDs are siblings — same domain, different RID.
///
/// Used for group memberships, where the question is "is this group in the same
/// domain as the user?" rather than "which domain is it?". Being a *relative*
/// test is what let membership scoping be enforced before any source declared a
/// domain at all.
pub fn siblings(a: &SidRef, b: &SidRef) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() || a.len() < PRELUDE + 4 || a[..PRELUDE] != b[..PRELUDE] {
        return false;
    }
    a[PRELUDE..a.len() - 4] == b[PRELUDE..b.len() - 4]
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::security::Sid;

    fn sid(text: &str) -> Sid {
        text.parse().expect("must parse")
    }

    #[test]
    fn a_local_domain_is_claimable() {
        assert!(is_claimable(sid("S-1-5-21-1-2-3").as_ref()));
        assert!(is_claimable(sid("S-1-5-21-0-0-0").as_ref()));
        assert!(is_claimable(
            sid("S-1-5-21-4294967295-4294967295-4294967295").as_ref()
        ));
    }

    #[test]
    fn well_known_namespaces_are_not_claimable() {
        // The point of the shape rule: none of these needs naming to be
        // excluded.
        for text in [
            "S-1-5-32",      // BUILTIN
            "S-1-5-32-544",  // BUILTIN\Administrators
            "S-1-5-18",      // LocalSystem
            "S-1-5-11",      // Authenticated Users
            "S-1-1-0",       // Everyone
            "S-1-0-0",       // Null
            "S-1-5",         // the NT authority itself
            "S-1-5-21",      // the non-unique prefix with no domain
            "S-1-5-21-1",    // too few
            "S-1-5-21-1-2",  // too few
            "S-1-5-22-1-2-3", // not the non-unique prefix
        ] {
            assert!(
                !is_claimable(sid(text).as_ref()),
                "{text} must not be claimable as a domain"
            );
        }
    }

    #[test]
    fn a_principal_sid_is_not_itself_a_domain() {
        assert!(!is_claimable(sid("S-1-5-21-1-2-3-1000").as_ref()));
    }

    #[test]
    fn a_domain_contains_its_principals() {
        let domain = sid("S-1-5-21-1-2-3");
        assert!(contains(domain.as_ref(), sid("S-1-5-21-1-2-3-1000").as_ref()));
        assert!(contains(domain.as_ref(), sid("S-1-5-21-1-2-3-500").as_ref()));
        assert!(contains(domain.as_ref(), sid("S-1-5-21-1-2-3-0").as_ref()));
    }

    #[test]
    fn a_domain_does_not_contain_another_domains_principals() {
        let domain = sid("S-1-5-21-1-2-3");
        assert!(!contains(domain.as_ref(), sid("S-1-5-21-1-2-4-1000").as_ref()));
        assert!(!contains(domain.as_ref(), sid("S-1-5-21-9-9-9-1000").as_ref()));
        assert!(!contains(domain.as_ref(), sid("S-1-5-32-544").as_ref()));
        assert!(!contains(domain.as_ref(), sid("S-1-5-18").as_ref()));
    }

    #[test]
    fn a_domain_does_not_contain_itself() {
        let domain = sid("S-1-5-21-1-2-3");
        assert!(
            !contains(domain.as_ref(), domain.as_ref()),
            "a domain SID is not a principal, and must not be assertable as one"
        );
    }

    #[test]
    fn containment_is_exactly_one_rid_deep() {
        let domain = sid("S-1-5-21-1-2-3");
        assert!(!contains(
            domain.as_ref(),
            sid("S-1-5-21-1-2-3-1000-1").as_ref()
        ));
    }

    #[test]
    fn a_prefix_of_a_domain_does_not_contain_it() {
        // Guards the length check: without it, a shorter "domain" whose bytes
        // are a prefix would swallow everything below it.
        assert!(!contains(
            sid("S-1-5-21-1-2").as_ref(),
            sid("S-1-5-21-1-2-3-1000").as_ref()
        ));
    }

    #[test]
    fn siblings_share_a_domain() {
        assert!(siblings(
            sid("S-1-5-21-1-2-3-1000").as_ref(),
            sid("S-1-5-21-1-2-3-513").as_ref()
        ));
        assert!(siblings(
            sid("S-1-5-32-544").as_ref(),
            sid("S-1-5-32-545").as_ref()
        ));
    }

    #[test]
    fn siblings_rejects_different_domains() {
        let user = sid("S-1-5-21-1-2-3-1000");
        for other in [
            // A different directory entirely.
            "S-1-5-21-9-9-9-512",
            // One sub-authority differing is enough.
            "S-1-5-21-1-2-4-1000",
            // BUILTIN is its own namespace, which is the case that matters.
            "S-1-5-32-544",
            // Shorter, longer, and other authorities.
            "S-1-5-21-1-2-3",
            "S-1-5-21-1-2-3-4-1000",
            "S-1-1-0",
            "S-1-5-18",
        ] {
            assert!(
                !siblings(user.as_ref(), sid(other).as_ref()),
                "{other} must not count as a sibling of {user}"
            );
        }
    }

    #[test]
    fn a_sid_is_its_own_sibling() {
        let jack = sid("S-1-5-21-1-2-3-1000");
        assert!(siblings(jack.as_ref(), jack.as_ref()));
    }
}
