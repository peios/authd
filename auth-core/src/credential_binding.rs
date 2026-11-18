//! Source-owned credential identity and revision, never proof or authority.
use crate::frame::WireError;

pub const BINDING_BYTES: usize = 32;
pub const MAX_BINDINGS: usize = 64;

/// Scoped to the authenticated principal and its authoritative source.
/// Replacing credential material preserves its reference and changes revision.
/// Equality is meaningful; ordering and arithmetic are not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialBinding {
    pub reference: [u8; 16],
    pub revision: [u8; 16],
}

impl CredentialBinding {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != BINDING_BYTES {
            return Err(WireError::UnknownValue);
        }
        let value = Self {
            reference: bytes[..16]
                .try_into()
                .map_err(|_| WireError::UnknownValue)?,
            revision: bytes[16..]
                .try_into()
                .map_err(|_| WireError::UnknownValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.reference == [0; 16] || self.revision == [0; 16] {
            return Err(WireError::UnknownValue);
        }
        Ok(())
    }

    pub fn encode(self) -> [u8; BINDING_BYTES] {
        let mut bytes = [0; BINDING_BYTES];
        bytes[..16].copy_from_slice(&self.reference);
        bytes[16..].copy_from_slice(&self.revision);
        bytes
    }
}

/// Append authenticated credential metadata after the optional operation GUID.
/// Old PGSS readers skip both length-framed trailing fields.
pub fn with_authenticated_binding(
    message: &[u8],
    binding: &CredentialBinding,
) -> Result<crate::Secret, WireError> {
    use crate::{authentication, frame, wire};
    binding.validate()?;
    let mut body = frame::open_body(&wire::FRAMING, message, wire::MSG_AUTHENTICATED)?;
    authentication::read_authenticated_body(&mut body)?;
    let missing_guid = body.at_end();
    if !missing_guid {
        let guid = body.bytes(16)?;
        if !guid.is_empty() && (guid.len() != 16 || guid == [0; 16]) {
            return Err(WireError::UnknownValue);
        }
        if !body.at_end() {
            return Err(WireError::UnknownValue);
        }
    }
    let total = message
        .len()
        .checked_add(if missing_guid { 40 } else { 36 })
        .ok_or(WireError::TooLong)?;
    if total > wire::MAX_MESSAGE_BYTES {
        return Err(WireError::TooLong);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(message);
    if missing_guid {
        encoded.extend_from_slice(&0u32.to_le_bytes());
    }
    encoded.extend_from_slice(&(BINDING_BYTES as u32).to_le_bytes());
    encoded.extend_from_slice(&binding.encode());
    encoded[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    encoded[12..16].copy_from_slice(&((total - 16) as u32).to_le_bytes());
    let result = crate::Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(result)
}

pub fn authenticated_binding(message: &[u8]) -> Result<Option<CredentialBinding>, WireError> {
    use crate::{authentication, frame, wire};
    let mut body = frame::open_body(&wire::FRAMING, message, wire::MSG_AUTHENTICATED)?;
    authentication::read_authenticated_body(&mut body)?;
    if body.at_end() {
        return Ok(None);
    }
    // Correlation is diagnostic only. Invalid or truncated GUID metadata must
    // not change an otherwise valid authentication result. A malformed first
    // frame cannot safely locate a subsequent binding, so report it unknown.
    if body.bytes(wire::MAX_MESSAGE_BYTES).is_err() {
        return Ok(None);
    }
    if body.at_end() {
        return Ok(None);
    }
    let binding = CredentialBinding::decode(body.bytes(BINDING_BYTES)?)?;
    if !body.at_end() {
        return Err(WireError::UnknownValue);
    }
    Ok(Some(binding))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success() -> Vec<u8> {
        crate::authentication::encode_authenticated(&crate::authentication::Authenticated {
            user_sid: vec![1; 12],
            canonical_name: "source\\jack".into(),
            verified_credentials: vec![crate::wire::CredentialType::Password],
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn bindings_extend_old_results_and_coexist_with_diagnostic_correlation() {
        let original = success();
        let binding = CredentialBinding {
            reference: [1; 16],
            revision: [2; 16],
        };
        assert_eq!(authenticated_binding(&original), Ok(None));
        for message in [
            crate::Secret::from_slice(&original),
            crate::correlation::with_operation_guid(&original, &[3; 16]).unwrap(),
        ] {
            let encoded = with_authenticated_binding(message.expose(), &binding).unwrap();
            assert_eq!(authenticated_binding(encoded.expose()), Ok(Some(binding)));
            assert_eq!(
                crate::authentication::decode_authenticated(encoded.expose())
                    .unwrap()
                    .canonical_name,
                "source\\jack"
            );
            assert!(with_authenticated_binding(encoded.expose(), &binding).is_err());
        }
    }

    #[test]
    fn malformed_diagnostic_metadata_does_not_change_authentication() {
        let message = crate::correlation::with_operation_guid(&success(), &[3; 16]).unwrap();
        let original_len = success().len();
        for tail in [
            &[1, 0, 0, 0, 9][..],
            &[16, 0, 0, 0, 1][..],
            &[255, 255, 255, 255][..],
        ] {
            let mut bytes = message.expose()[..original_len].to_vec();
            bytes.extend_from_slice(tail);
            let len = bytes.len() as u32;
            bytes[8..12].copy_from_slice(&len.to_le_bytes());
            bytes[12..16].copy_from_slice(&(len - 16).to_le_bytes());
            assert_eq!(authenticated_binding(&bytes), Ok(None));
        }
        let binding = CredentialBinding {
            reference: [1; 16],
            revision: [2; 16],
        };
        let mut bytes = with_authenticated_binding(message.expose(), &binding)
            .unwrap()
            .expose()
            .to_vec();
        bytes[original_len + 4..original_len + 20].fill(0);
        assert_eq!(authenticated_binding(&bytes), Ok(Some(binding)));
        let last = bytes.len() - 32;
        bytes[last..].fill(0);
        assert!(authenticated_binding(&bytes).is_err());
    }

    #[test]
    fn invalid_and_incomplete_bindings_cannot_be_current_credentials() {
        for len in [0, 1, 16, 31, 33] {
            assert!(CredentialBinding::decode(&vec![1; len]).is_err());
        }
        let binding = CredentialBinding {
            reference: [1; 16],
            revision: [2; 16],
        };
        assert_eq!(CredentialBinding::decode(&binding.encode()), Ok(binding));
        for invalid in [
            CredentialBinding {
                reference: [0; 16],
                revision: [2; 16],
            },
            CredentialBinding {
                reference: [1; 16],
                revision: [0; 16],
            },
        ] {
            assert!(CredentialBinding::decode(&invalid.encode()).is_err());
        }
    }
}
