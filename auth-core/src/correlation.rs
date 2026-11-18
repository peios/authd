//! Optional authority-issued operation identifiers on PGSS authentication replies.
//! This trailing field is diagnostic metadata, never an identity or a capability.
use crate::{
    frame::{self, Reader, WireError},
    wire, Secret,
};

/// Append the optional OperationGuid byte string to a freshly encoded reply.
/// Older decoders skip it under PGSS's length-framed structure rules.
/// The result is wiped even when the original reply contains session keys.
pub fn with_operation_guid(message: &[u8], guid: &[u8; 16]) -> Result<Secret, WireError> {
    let (kind, len) = wire::decode_header(message)?;
    if !matches!(
        kind,
        wire::MSG_CREDENTIAL_REQUEST
            | wire::MSG_ACCESS_DENIED
            | wire::MSG_ACCESS_GRANTED
            | wire::MSG_AUTHENTICATED
    ) {
        return Err(WireError::UnexpectedMessage(kind));
    }
    let body = message.get(12..16).ok_or(WireError::Truncated)?;
    let body = u32::from_le_bytes(body.try_into().map_err(|_| WireError::Truncated)?) as usize;
    let total = len.checked_add(20).ok_or(WireError::TooLong)?;
    if len != message.len()
        || body.checked_add(16) != Some(len)
        || total > wire::MAX_MESSAGE_BYTES
        || *guid == [0; 16]
    {
        return Err(WireError::TooLong);
    }
    // Reserve the final capacity before copying potentially secret bytes.
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(message);
    encoded.extend_from_slice(&16u32.to_le_bytes());
    encoded.extend_from_slice(guid);
    encoded[8..12].copy_from_slice(&(total as u32).to_le_bytes());
    encoded[12..16].copy_from_slice(&((body + 20) as u32).to_le_bytes());
    let result = Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(result)
}

fn optional_guid(r: &mut Reader<'_>) -> Result<Option<[u8; 16]>, WireError> {
    if r.at_end() {
        return Ok(None);
    }
    match r.bytes(16)? {
        [] => Ok(None),
        bytes if bytes.len() == 16 && bytes != [0; 16] => {
            Ok(Some(bytes.try_into().map_err(|_| WireError::UnknownValue)?))
        }
        _ => Err(WireError::UnknownValue),
    }
}

/// Read diagnostic metadata without changing the public credential/result layouts.
/// An old authority omits the field. Callers must not infer authority or change
/// an authentication decision from missing or malformed diagnostic metadata.
pub fn reply_operation_guid(message: &[u8]) -> Result<Option<[u8; 16]>, WireError> {
    let (kind, _) = wire::decode_header(message)?;
    let mut r = frame::open_body(&wire::FRAMING, message, kind)?;
    match kind {
        wire::MSG_CREDENTIAL_REQUEST => {
            wire::read_credential_request_body(&mut r)?;
        }
        wire::MSG_ACCESS_DENIED => {
            r.u32()?;
            r.string(wire::MAX_REASON_BYTES)?;
        }
        wire::MSG_ACCESS_GRANTED => {
            r.u64()?;
            wire::read_profile_body(&mut r.open()?)?;
            r.bytes(crate::ntlmv2::SESSION_KEY_BYTES)?;
        }
        wire::MSG_AUTHENTICATED => {
            crate::authentication::read_authenticated_body(&mut r)?;
        }
        _ => return Ok(None),
    }
    optional_guid(&mut r)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_optional_guid_preserves_old_decoders_and_rejects_incomplete_metadata() {
        let original = wire::encode_access_denied(&wire::AccessDenied {
            denial: wire::Denial::AuthenticationFailed,
            reason: "not accepted".into(),
        })
        .unwrap();
        assert_eq!(reply_operation_guid(&original), Ok(None));
        let guid = [7; 16];
        let encoded = with_operation_guid(&original, &guid).unwrap();
        assert_eq!(reply_operation_guid(encoded.expose()), Ok(Some(guid)));
        assert_eq!(
            wire::decode_access_denied(encoded.expose()).unwrap().reason,
            "not accepted"
        );
        for missing in 1..=19 {
            let mut short = encoded.expose()[..encoded.expose().len() - missing].to_vec();
            let len = short.len() as u32;
            short[8..12].copy_from_slice(&len.to_le_bytes());
            short[12..16].copy_from_slice(&(len - 16).to_le_bytes());
            assert!(reply_operation_guid(&short).is_err());
        }
    }
    #[test]
    fn prompts_have_the_same_identity_without_changing_the_credential_protocol() {
        let original = wire::encode_credential_request(&wire::CredentialRequest {
            messages: vec![],
            prompts: vec![],
        })
        .unwrap();
        let encoded = with_operation_guid(&original, &[3; 16]).unwrap();
        assert!(
            wire::decode_credential_request(encoded.expose())
                .unwrap()
                .prompts
                .is_empty()
        );
        assert_eq!(reply_operation_guid(encoded.expose()), Ok(Some([3; 16])));
    }
}
