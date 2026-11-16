//! RFC 2759 verification. Reusable NT material never leaves the source.
use des::{
    Des,
    cipher::{BlockEncrypt, KeyInit},
};
use md4::{Digest, Md4};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct NtHash(pub [u8; 16]);

impl core::fmt::Debug for NtHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NtHash([redacted])")
    }
}

impl NtHash {
    /// NT passwords are exact UTF-16LE, with no normalization or case folding.
    /// Non-UTF-8 legacy byte passwords remain usable through Argon2 only.
    pub fn derive(password: &[u8]) -> Option<Self> {
        let text = core::str::from_utf8(password).ok()?;
        let mut hash = Md4::new();
        for unit in text.encode_utf16() {
            let mut bytes = Zeroizing::new(unit.to_le_bytes());
            hash.update(bytes.as_mut());
        }
        let mut result = hash.finalize();
        let mut out = Self([0; 16]);
        out.0.copy_from_slice(&result);
        result.as_mut_slice().zeroize();
        Some(out)
    }

    pub fn verify(
        &self,
        challenge: &[u8; 16],
        username: &[u8],
        response: &auth_core::mschapv2::Response,
    ) -> Option<auth_core::mschapv2::Success> {
        let expected = self.response(challenge, username, &response.peer_challenge);
        if !bool::from(expected.ct_eq(&response.nt_response)) {
            return None;
        }
        let mut hash_hash = Zeroizing::new([0; 16]);
        hash_hash.copy_from_slice(&Md4::digest(self.0));
        let mut digest = Sha1::new();
        digest.update(hash_hash.as_ref());
        digest.update(response.nt_response);
        digest.update(b"Magic server to client signing constant");
        let inner = digest.finalize();
        let mut digest = Sha1::new();
        digest.update(inner);
        digest.update(challenge_hash(
            challenge,
            &response.peer_challenge,
            username,
        ));
        digest.update(b"Pad to make it do more than one iteration");
        Some(auth_core::mschapv2::Success(digest.finalize().into()))
    }

    pub(crate) fn response(
        &self,
        challenge: &[u8; 16],
        username: &[u8],
        peer: &[u8; 16],
    ) -> [u8; 24] {
        let challenge = challenge_hash(challenge, peer, username);
        let mut padded = Zeroizing::new([0; 21]);
        padded[..16].copy_from_slice(&self.0);
        let mut result = [0; 24];
        for (key, out) in padded
            .as_chunks::<7>()
            .0
            .iter()
            .zip(result.as_chunks_mut::<8>().0.iter_mut())
        {
            let mut expanded = Zeroizing::new([0; 8]);
            expanded[0] = key[0] & 0xfe;
            expanded[1] = ((key[0] << 7) | (key[1] >> 1)) & 0xfe;
            expanded[2] = ((key[1] << 6) | (key[2] >> 2)) & 0xfe;
            expanded[3] = ((key[2] << 5) | (key[3] >> 3)) & 0xfe;
            expanded[4] = ((key[3] << 4) | (key[4] >> 4)) & 0xfe;
            expanded[5] = ((key[4] << 3) | (key[5] >> 5)) & 0xfe;
            expanded[6] = ((key[5] << 2) | (key[6] >> 6)) & 0xfe;
            expanded[7] = (key[6] << 1) & 0xfe;
            for byte in expanded.iter_mut() {
                *byte |= u8::from(byte.count_ones() % 2 == 0);
            }
            let cipher = Des::new_from_slice(expanded.as_ref()).expect("fixed DES key length");
            let mut block = challenge.into();
            cipher.encrypt_block(&mut block);
            out.copy_from_slice(&block);
        }
        result
    }
}

fn challenge_hash(challenge: &[u8; 16], peer: &[u8; 16], username: &[u8]) -> [u8; 8] {
    // RFC 2759 excludes a Windows-style domain prefix, but retains exact case.
    let username = username.rsplit(|b| *b == b'\\').next().unwrap_or(username);
    let mut hash = Sha1::new();
    hash.update(peer);
    hash.update(challenge);
    hash.update(username);
    hash.finalize()[..8].try_into().expect("SHA1 output length")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        core::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
    }
    #[test]
    fn rfc2759_section_9_2_and_tampered_proofs() {
        let hash = NtHash::derive(b"clientPass").unwrap();
        assert_eq!(hash.0, hex("44EBBA8D5312B8D611474411F56989AE"));
        let challenge = hex("5B5D7C7D7B3F2F3E3C2C602132262628");
        let mut response = auth_core::mschapv2::Response {
            peer_challenge: hex("21402324255E262A28295F2B3A337C7E"),
            nt_response: hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"),
        };
        let success = hash.verify(&challenge, b"User", &response).unwrap();
        assert_eq!(success.0, hex("407A5589115FD0D6209F510FE9C04566932CDA56"));
        assert!(hash.verify(&challenge, b"user", &response).is_none());
        assert_eq!(
            hash.verify(&challenge, b"DOMAIN\\User", &response),
            Some(success)
        );
        response.nt_response[0] ^= 1;
        assert!(hash.verify(&challenge, b"User", &response).is_none());
    }
    #[test]
    fn encoding_is_exact_and_debug_is_redacted() {
        assert!(NtHash::derive(&[0xff]).is_none());
        assert_ne!(
            NtHash::derive("é".as_bytes()),
            NtHash::derive("e\u{301}".as_bytes())
        );
        assert_eq!(
            format!("{:?}", NtHash::derive(b"password").unwrap()),
            "NtHash([redacted])"
        );
    }
}
