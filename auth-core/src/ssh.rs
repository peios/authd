//! Bounded SSH credential material. No cryptography or trust decisions live here.
//! The source verifies signatures; the authorized originator supplies a binding
//! derived from its live transport. A binding supplied by an arbitrary caller
//! is not evidence of freshness.

use crate::wire::WireError;

pub const MAX_KEY: usize = 8192;
pub const MAX_SIGNATURE: usize = 8192;
pub const MAX_ALGORITHM: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub connection: [u8; 16],
    pub session: Vec<u8>,
    pub username: String,
}

impl Binding {
    pub fn validate(&self) -> Result<(), WireError> {
        if !(16..=64).contains(&self.session.len())
            || self.username.is_empty()
            || self.username.len() > 256
            || self.username.chars().any(char::is_control)
            || self.connection == [0; 16]
        {
            return Err(WireError::UnknownValue);
        }
        Ok(())
    }

    /// RFC 4252 section 7. Every signed field is reconstructed from the pinned
    /// binding and typed offer; callers cannot submit an arbitrary transcript.
    pub fn signed_data(&self, offer: &Offer) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        offer.validate()?;
        let mut data = Vec::new();
        ssh_string(&mut data, &self.session);
        data.push(50);
        ssh_string(&mut data, self.username.as_bytes());
        ssh_string(&mut data, b"ssh-connection");
        ssh_string(&mut data, b"publickey");
        data.push(1);
        ssh_string(&mut data, offer.algorithm.as_bytes());
        ssh_string(&mut data, &offer.key);
        Ok(data)
    }
}

fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub algorithm: String,
    pub key: Vec<u8>,
    /// Empty is a candidate query, never an authentication proof.
    pub signature: Vec<u8>,
}

impl Offer {
    fn validate(&self) -> Result<(), WireError> {
        if self.algorithm.is_empty()
            || self.algorithm.len() > MAX_ALGORITHM
            || !self.algorithm.is_ascii()
            || self.algorithm.bytes().any(|b| b <= b' ' || b >= 127)
            || self.key.is_empty()
            || self.key.len() > MAX_KEY
            || self.signature.len() > MAX_SIGNATURE
        {
            return Err(WireError::TooLong);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut out = vec![0; 4];
        out.push(u8::from(!self.signature.is_empty()));
        for bytes in [self.algorithm.as_bytes(), &self.key, &self.signature] {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let len = out.len() as u32;
        out[..4].copy_from_slice(&len.to_le_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = crate::frame::Reader::new(bytes);
        if r.u32()? as usize != bytes.len() {
            return Err(WireError::TooLong);
        }
        let op = r.u8()?;
        let value = Self {
            algorithm: r.string(MAX_ALGORITHM)?.to_owned(),
            key: r.bytes(MAX_KEY)?.to_vec(),
            signature: r.bytes(MAX_SIGNATURE)?.to_vec(),
        };
        if !r.at_end() || op > 1 || (op == 0) != value.signature.is_empty() {
            return Err(WireError::UnknownValue);
        }
        value.validate()?;
        Ok(value)
    }
}

/// Typed probe result inside Prompt.parameters, never a display-string signal.
pub fn disposition(value: u8) -> Result<Vec<u8>, WireError> {
    if value > 2 {
        return Err(WireError::UnknownValue);
    }
    Ok(vec![5, 0, 0, 0, value])
}

pub fn read_disposition(bytes: &[u8]) -> Result<u8, WireError> {
    if bytes.len() != 5 || bytes[..4] != [5, 0, 0, 0] || bytes[4] > 2 {
        return Err(WireError::UnknownValue);
    }
    Ok(bytes[4])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> Offer {
        Offer {
            algorithm: "ssh-ed25519".into(),
            key: vec![7; 51],
            signature: vec![8; 83],
        }
    }

    #[test]
    fn malformed_and_ambiguous_proof_is_rejected() {
        let encoded = offer().encode().unwrap();
        assert_eq!(Offer::decode(&encoded).unwrap(), offer());
        for at in 0..encoded.len() {
            assert!(Offer::decode(&encoded[..at]).is_err());
        }
        let mut wrong = encoded.clone();
        wrong[4] = 0;
        assert!(Offer::decode(&wrong).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Offer::decode(&trailing).is_err());
    }

    #[test]
    fn signed_data_binds_identity_transport_and_key() {
        let binding = Binding {
            connection: [1; 16],
            session: vec![2; 32],
            username: "alice".into(),
        };
        let original = binding.signed_data(&offer()).unwrap();
        assert_eq!(&original[..4], &32u32.to_be_bytes());
        assert_eq!(original[36], 50);
        let mut changed = binding.clone();
        changed.username = "bob".into();
        assert_ne!(original, changed.signed_data(&offer()).unwrap());
        changed = binding.clone();
        changed.session[0] ^= 1;
        assert_ne!(original, changed.signed_data(&offer()).unwrap());
        let mut key = offer();
        key.key[0] ^= 1;
        assert_ne!(original, binding.signed_data(&key).unwrap());
    }
}
