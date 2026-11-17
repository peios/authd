//! Typed NTLMv2 material for the identity-in-answer exchange (PGSS §2.11).
//! Framing and bounds only; cryptography belongs to the source.
use crate::frame::{Reader, WireError};

/// The authority-issued `ServerChallenge`, carried as the prompt's parameters.
pub const CHALLENGE_BYTES: usize = 8;
pub const SESSION_KEY_BYTES: usize = 16;
/// `NTProofStr` length.
pub const PROOF_BYTES: usize = 16;
pub const MAX_NAME_BYTES: usize = 512;
/// NTProofStr, the 28-byte NTLMv2_CLIENT_CHALLENGE header and an MsvAvEOL pair.
pub const MIN_NT_RESPONSE_BYTES: usize = PROOF_BYTES + 28 + 4;
pub const MAX_NT_RESPONSE_BYTES: usize = 4096;

/// The client's answer: the AUTHENTICATE message's `UserName`, `DomainName`
/// and `NtChallengeResponse`, byte for byte. `user` and `domain` are UTF-16LE.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
    pub nt_response: Vec<u8>,
}

impl core::fmt::Debug for Answer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ntlmv2Answer([redacted])")
    }
}

impl Answer {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut out =
            Vec::with_capacity(12 + self.user.len() + self.domain.len() + self.nt_response.len());
        for bytes in [&self.user, &self.domain, &self.nt_response] {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let value = Self {
            user: r.bytes(MAX_NAME_BYTES)?.to_vec(),
            domain: r.bytes(MAX_NAME_BYTES)?.to_vec(),
            nt_response: r.bytes(MAX_NT_RESPONSE_BYTES)?.to_vec(),
        };
        if !r.at_end() {
            return Err(WireError::UnknownValue);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), WireError> {
        if self.user.len() > MAX_NAME_BYTES
            || self.domain.len() > MAX_NAME_BYTES
            || self.nt_response.len() > MAX_NT_RESPONSE_BYTES
        {
            return Err(WireError::TooLong);
        }
        // RespType and HiRespType open the client challenge, after NTProofStr.
        if self.user.is_empty()
            || self.nt_response.len() < MIN_NT_RESPONSE_BYTES
            || self.nt_response[PROOF_BYTES..PROOF_BYTES + 2] != [1, 1]
        {
            return Err(WireError::UnknownValue);
        }
        utf16(&self.user)?;
        utf16(&self.domain)?;
        Ok(())
    }

    /// The user name as UTF-8, for routing. The proof still covers the
    /// original UTF-16 bytes.
    pub fn user_name(&self) -> Result<String, WireError> {
        utf16(&self.user)
    }

    /// The domain as UTF-8, for audit. It selects no source (PGSS §2.11).
    pub fn domain_name(&self) -> Result<String, WireError> {
        utf16(&self.domain)
    }
}

/// Strict UTF-16LE: an odd length or an unpaired surrogate is malformed.
fn utf16(bytes: &[u8]) -> Result<String, WireError> {
    let (units, odd) = bytes.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(WireError::UnknownValue);
    }
    let units = units.iter().map(|unit| u16::from_le_bytes(*unit));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| WireError::UnknownValue)
}

/// The NTLM `SessionBaseKey`: exchange-specific, never a reusable credential.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey(pub [u8; SESSION_KEY_BYTES]);

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ntlmv2SessionKey([redacted])")
    }
}

/// It signs and seals a live protocol session, so it does not outlive its use.
impl Drop for SessionKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            // SAFETY: byte is exclusively borrowed from this live array. Volatile
            // stores keep the wipe although the value is released immediately.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub fn decode_session_key(bytes: &[u8]) -> Result<Option<SessionKey>, WireError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(SessionKey(
        bytes.try_into().map_err(|_| WireError::UnknownValue)?,
    )))
}

/// The key is present exactly when NTLMv2 was the verified method.
pub fn validate_session_key(
    kind: Option<crate::wire::CredentialType>,
    key: &Option<SessionKey>,
) -> Result<(), WireError> {
    if (kind == Some(crate::wire::CredentialType::Ntlmv2)) != key.is_some() {
        return Err(WireError::UnknownValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn answer() -> Answer {
        let mut nt_response = vec![7; PROOF_BYTES];
        nt_response.extend_from_slice(&[1, 1]);
        nt_response.resize(MIN_NT_RESPONSE_BYTES, 0);
        Answer {
            user: utf16le("jack"),
            domain: utf16le("DESKTOP-4F2A"),
            nt_response,
        }
    }

    #[test]
    fn an_answer_round_trips_and_names_its_user() {
        let encoded = answer().encode().unwrap();
        let decoded = Answer::decode(&encoded).unwrap();
        assert!(decoded == answer());
        assert_eq!(decoded.user_name().unwrap(), "jack");
        assert_eq!(decoded.domain_name().unwrap(), "DESKTOP-4F2A");
        for len in 0..encoded.len() {
            assert!(Answer::decode(&encoded[..len]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Answer::decode(&trailing).is_err());
    }

    #[test]
    fn malformed_answers_are_refused() {
        let empty_user = Answer {
            user: Vec::new(),
            ..answer()
        };
        assert!(empty_user.encode().is_err());

        let odd = Answer {
            user: b"jac".to_vec(),
            ..answer()
        };
        assert!(odd.encode().is_err());

        // A lone high surrogate.
        let unpaired = Answer {
            user: vec![0x00, 0xd8],
            ..answer()
        };
        assert!(unpaired.encode().is_err());

        let mut short = answer();
        short.nt_response.truncate(MIN_NT_RESPONSE_BYTES - 1);
        assert!(short.encode().is_err());

        let mut version = answer();
        version.nt_response[PROOF_BYTES] = 2;
        assert!(version.encode().is_err());

        // An empty domain is what a client that names none sends.
        let no_domain = Answer {
            domain: Vec::new(),
            ..answer()
        };
        assert!(Answer::decode(&no_domain.encode().unwrap()).is_ok());
    }

    #[test]
    fn the_session_key_is_present_exactly_for_ntlmv2() {
        use crate::wire::CredentialType;
        assert!(decode_session_key(&[]).unwrap().is_none());
        assert!(decode_session_key(&[0; 15]).is_err());
        assert!(decode_session_key(&[0; 17]).is_err());
        let key = decode_session_key(&[9; 16]).unwrap();
        assert!(validate_session_key(Some(CredentialType::Ntlmv2), &key).is_ok());
        assert!(validate_session_key(Some(CredentialType::Password), &key).is_err());
        assert!(validate_session_key(Some(CredentialType::Ntlmv2), &None).is_err());
        assert!(validate_session_key(None, &None).is_ok());
        assert_eq!(
            format!("{:?}", key.unwrap()),
            "Ntlmv2SessionKey([redacted])"
        );
    }
}
