//! Fixed-size, typed MSCHAPv2 material; cryptography belongs to the source.
use crate::wire::WireError;

#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    pub peer_challenge: [u8; 16],
    pub nt_response: [u8; 24],
}
impl Response {
    pub fn encode(&self) -> Vec<u8> {
        [self.peer_challenge.as_slice(), self.nt_response.as_slice()].concat()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 40 {
            return Err(WireError::UnknownValue);
        }
        Ok(Self {
            peer_challenge: bytes[..16]
                .try_into()
                .map_err(|_| WireError::UnknownValue)?,
            nt_response: bytes[16..]
                .try_into()
                .map_err(|_| WireError::UnknownValue)?,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Success(pub [u8; 20]);
impl core::fmt::Debug for Success {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mschapv2Success([redacted])")
    }
}

pub fn decode_success(bytes: &[u8]) -> Result<Option<Success>, WireError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(Success(
        bytes.try_into().map_err(|_| WireError::UnknownValue)?,
    )))
}

pub fn validate_success(
    kind: Option<crate::wire::CredentialType>,
    success: &Option<Success>,
) -> Result<(), WireError> {
    if (kind == Some(crate::wire::CredentialType::Mschapv2)) != success.is_some() {
        return Err(WireError::UnknownValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_and_success_have_exact_lengths() {
        let response = Response {
            peer_challenge: [1; 16],
            nt_response: [2; 24],
        };
        let encoded = response.encode();
        assert!(Response::decode(&encoded).unwrap() == response);
        for len in 0..40 {
            assert!(Response::decode(&encoded[..len]).is_err());
        }
        assert!(Response::decode(&[0; 41]).is_err());
        assert!(decode_success(&[]).unwrap().is_none());
        assert!(decode_success(&[0; 19]).is_err());
        assert!(decode_success(&[0; 21]).is_err());
        assert!(
            validate_success(
                Some(crate::wire::CredentialType::Password),
                &Some(Success([0; 20]))
            )
            .is_err()
        );
        assert!(validate_success(Some(crate::wire::CredentialType::Mschapv2), &None).is_err());
    }
}
