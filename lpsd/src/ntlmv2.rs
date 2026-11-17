//! MS-NLMP §3.3.2 NTLMv2 verification. Reusable NT material never leaves the
//! source; only the exchange-specific SessionBaseKey does.
use crate::mschapv2::NtHash;
use auth_core::ntlmv2::{Answer, PROOF_BYTES, SessionKey};
use hmac::{Hmac, Mac};
use md5::Md5;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacMd5 = Hmac<Md5>;

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 16]> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let mut out = Zeroizing::new([0; 16]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Uppercase UTF-16LE one code unit at a time, as NTOWFv2 requires. Names are
/// printable ASCII (PGSS §2.15); anything else takes its Unicode simple
/// mapping where that is a single BMP character, and is otherwise unchanged.
fn uppercase_utf16le(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    for unit in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([unit[0], unit[1]]);
        let upper = char::from_u32(u32::from(unit))
            .and_then(|c| {
                let mut mapped = c.to_uppercase();
                match (mapped.next(), mapped.next()) {
                    (Some(single), None) => u16::try_from(u32::from(single)).ok(),
                    _ => None,
                }
            })
            .unwrap_or(unit);
        out.extend_from_slice(&upper.to_le_bytes());
    }
    out
}

/// NTOWFv2: keyed with the NT hash, over the uppercased user and the domain
/// exactly as received.
fn response_key(hash: &NtHash, answer: &Answer) -> Zeroizing<[u8; 16]> {
    let user = uppercase_utf16le(&answer.user);
    hmac_md5(&hash.0, &[&user, &answer.domain])
}

/// Verify `answer` against the authority's `challenge`. Returns the
/// SessionBaseKey on success. The proof comparison takes constant time.
pub fn verify(hash: &NtHash, challenge: &[u8; 8], answer: &Answer) -> Option<SessionKey> {
    let key = response_key(hash, answer);
    let (proof, client_challenge) = answer.nt_response.split_at(PROOF_BYTES);
    let expected = hmac_md5(key.as_ref(), &[challenge, client_challenge]);
    if !bool::from(expected.as_ref().ct_eq(proof)) {
        return None;
    }
    let session = hmac_md5(key.as_ref(), &[proof]);
    Some(SessionKey(*session))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    /// MS-NLMP §4.2.4.1.3 `temp`: version 1, time 0, client challenge 0xaa,
    /// then NetBIOS domain "Domain" and server "Server" pairs, MsvAvEOL, Z(4).
    const TEMP: &str = concat!(
        "0101000000000000",
        "0000000000000000",
        "aaaaaaaaaaaaaaaa",
        "00000000",
        "02000c0044006f006d00610069006e00",
        "01000c0053006500720076006500720000000000",
        "00000000",
    );
    /// MS-NLMP §4.2.4.2.2 NTProofStr and §4.2.4.1.2 SessionBaseKey for user
    /// "User", domain "Domain", password "Password".
    const NT_PROOF: &str = "68cd0ab851e51c96aabc927bebef6a1c";
    const SESSION_BASE_KEY: &str = "8de40ccadbc14a82f15cb0ad0de95ca3";

    fn answer(user: &str, domain: &str) -> Answer {
        let mut nt_response = hex(NT_PROOF);
        nt_response.extend(hex(TEMP));
        Answer {
            user: utf16le(user),
            domain: utf16le(domain),
            nt_response,
        }
    }

    fn password() -> NtHash {
        NtHash::derive(b"Password").unwrap()
    }

    #[test]
    fn the_ms_nlmp_example_verifies_and_yields_its_session_base_key() {
        assert_eq!(
            response_key(&password(), &answer("User", "Domain")).to_vec(),
            hex("0c868a403bfd7a93a3001ef22ef02e3f"),
        );
        let key = verify(&password(), &SERVER_CHALLENGE, &answer("User", "Domain"))
            .expect("the published example verifies");
        assert_eq!(key.0.to_vec(), hex(SESSION_BASE_KEY));
    }

    /// The user is uppercased before keying, so its case is irrelevant; the
    /// domain is used exactly as received, so its case is not.
    #[test]
    fn user_case_is_folded_and_domain_case_is_not() {
        assert!(verify(&password(), &SERVER_CHALLENGE, &answer("user", "Domain")).is_some());
        assert!(verify(&password(), &SERVER_CHALLENGE, &answer("User", "DOMAIN")).is_none());
    }

    #[test]
    fn a_wrong_password_challenge_or_proof_is_refused() {
        let wrong = NtHash::derive(b"password").unwrap();
        assert!(verify(&wrong, &SERVER_CHALLENGE, &answer("User", "Domain")).is_none());

        let mut challenge = SERVER_CHALLENGE;
        challenge[7] ^= 1;
        assert!(verify(&password(), &challenge, &answer("User", "Domain")).is_none());

        // Tampering with the client challenge, such as its AvPairs, breaks the
        // proof that covers it.
        let mut tampered = answer("User", "Domain");
        let last = tampered.nt_response.len() - 5;
        tampered.nt_response[last] ^= 1;
        assert!(verify(&password(), &SERVER_CHALLENGE, &tampered).is_none());
    }

    #[test]
    fn uppercasing_is_per_code_unit() {
        assert_eq!(
            &*uppercase_utf16le(&utf16le("jack-1")),
            &utf16le("JACK-1")[..]
        );
        // ß has no single-character uppercase, so it stays as it is.
        assert_eq!(&*uppercase_utf16le(&utf16le("ß")), &utf16le("ß")[..]);
        assert_eq!(&*uppercase_utf16le(&utf16le("é")), &utf16le("É")[..]);
    }
}
