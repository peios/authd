//! Deriving a service's SID from its name.
//!
//! `S-1-5-80-h1-h2-h3-h4-h5`, where the five hash values are the SHA-1 of the
//! uppercased service name encoded as UTF-16LE, split into five little-endian
//! 32-bit integers. A platform rule, documented under well-known principals.
//!
//! # Why authd cares
//!
//! This is how a principal source proves it is the source it claims to be — and
//! the answer is that it does not prove anything, because peinit already did.
//! peinit computes this SID for every service it launches and puts it in the
//! token's group list, which is precisely what keeps the platform daemons
//! distinguishable when they all run as SYSTEM.
//!
//! So authd never has to trust a name it was sent. It derives the SID for each
//! name in its own configuration and asks the kernel whether the peer's token
//! carries it. There is no shared secret and nothing to provision, because the
//! derivation is a pure function of a name only peinit can act on.
//!
//! # Two implementations, one test vector
//!
//! peinit has its own copy of this derivation. Two implementations of a
//! security-critical rule is a real hazard — a silent disagreement would mean
//! authd rejecting the source peinit launched, or worse — so
//! [`tests::agrees_with_peinit`] pins this one to the identical vector peinit
//! asserts on. They cannot drift without a test failing.
//!
//! The better fix is one implementation in libpeios, next to the other SID
//! helpers, consumed by both. That touches a shared component, so it is flagged
//! rather than done here.

use peios::security::Sid;
use sha1::{Digest, Sha1};

/// The `S-1-5-80` sub-authority every service SID begins with.
const SERVICE_AUTHORITY: u32 = 80;

/// The SID peinit puts on the token of a service with this name.
///
/// `None` only if the name produces a SID the security library rejects, which
/// for a fixed six-sub-authority shape means never in practice.
pub fn of(service_name: &str) -> Option<Sid> {
    // Uppercased, UTF-16LE, exactly as the platform rule specifies. Note this
    // is where case-insensitivity comes from: `LPSD` and `lpsd` are one
    // service, so a configuration key's case cannot change who is admitted.
    let mut encoded = Vec::with_capacity(service_name.len() * 2);
    for unit in service_name.to_uppercase().encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }

    let digest = Sha1::digest(&encoded);
    let mut sub_authorities = Vec::with_capacity(6);
    sub_authorities.push(SERVICE_AUTHORITY);
    for chunk in digest.chunks_exact(4) {
        sub_authorities.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    // NT Authority (5), then 80 and the five digest words.
    Sid::build(5, &sub_authorities).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector `peinit/src/security/service_sid.rs` asserts on. If this ever
    /// fails, the two derivations have diverged and every source will be
    /// refused — which is the failure this test exists to make loud.
    #[test]
    fn agrees_with_peinit() {
        assert_eq!(
            of("app").unwrap().to_string(),
            "S-1-5-80-2426739453-2501902915-3009591593-922485235-2122754908"
        );
    }

    #[test]
    fn is_case_insensitive() {
        // A configuration key's case must not change who is admitted.
        assert_eq!(of("lpsd").unwrap(), of("LPSD").unwrap());
        assert_eq!(of("lpsd").unwrap(), of("LpSd").unwrap());
    }

    #[test]
    fn distinct_names_get_distinct_sids() {
        assert_ne!(of("lpsd").unwrap(), of("udpsd").unwrap());
        assert_ne!(of("lpsd").unwrap(), of("authd").unwrap());
        // A near-miss must not collide: this is the whole basis of admission.
        assert_ne!(of("lpsd").unwrap(), of("lpsd ").unwrap());
        assert_ne!(of("lpsd").unwrap(), of("lpsd2").unwrap());
    }

    #[test]
    fn the_shape_is_a_service_sid() {
        let sid = of("lpsd").unwrap();
        let text = sid.to_string();
        assert!(
            text.starts_with("S-1-5-80-"),
            "{text} must be in the service-SID range"
        );
        // "S", the revision and the authority, then 80 and five digest words.
        assert_eq!(text.split('-').count(), 3 + 6);
    }

    #[test]
    fn an_empty_name_still_derives() {
        // Not useful, but it must not panic: names come from configuration.
        assert!(of("").is_some());
    }
}
