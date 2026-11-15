//! General authentication: shared collection requirements and an explicitly
//! disclosed identity result. Success carries no token, session or bearer proof.

use crate::claim::{self, Claim};
use crate::frame::{self, Reader, WireError, Writer};
use crate::wire::{self, CredentialType, IdentifierType};

pub const MSG_AUTHENTICATE_START: u16 = 0x0004;
pub const MSG_AUTHENTICATED: u16 = 0x8004;
pub const MAX_GROUPS: usize = 1024;

/// Collection support is not a proof requirement. `None` allows a source's
/// intentional no-credential policy; a password consumer must require Password.
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    pub identifier_type: IdentifierType,
    pub identifier: Vec<u8>,
    pub supported_credential_types: Vec<CredentialType>,
    pub required_credential_type: Option<CredentialType>,
    pub ssh_binding: Option<crate::ssh::Binding>,
}

impl AuthenticationRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.identifier.len() > wire::MAX_IDENTIFIER_BYTES
            || self.supported_credential_types.len() > wire::MAX_SUPPORTED_CREDENTIAL_TYPES
        {
            return Err(WireError::TooLong);
        }
        if self
            .required_credential_type
            .is_some_and(|t| !self.supported_credential_types.contains(&t))
            || self
                .supported_credential_types
                .contains(&CredentialType::SshPublicKey)
                != self.ssh_binding.is_some()
            || self.ssh_binding.as_ref().is_some_and(|b| {
                self.identifier_type != IdentifierType::Username
                    || b.username.as_bytes() != self.identifier
            })
        {
            return Err(WireError::UnknownValue);
        }
        if let Some(binding) = &self.ssh_binding {
            binding.validate()?;
        }
        Ok(())
    }

    pub fn accepts(&self, actual: Option<CredentialType>) -> bool {
        self.required_credential_type
            .is_none_or(|required| actual == Some(required))
            && actual.is_none_or(|t| self.supported_credential_types.contains(&t))
    }
}

/// Names follow existing claim lookup: ASCII letters are case-insensitive,
/// while non-ASCII characters retain their existing exact spelling.
pub fn canonical_claim_name(name: &str) -> Result<String, WireError> {
    if name.is_empty() || name.len() > claim::MAX_NAME_BYTES || name.contains('\0') {
        return Err(WireError::UnknownValue);
    }
    Ok(name.to_ascii_lowercase())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub groups: bool,
    pub claims: Vec<String>,
}

impl DisclosureRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.claims.len() > claim::MAX_CLAIMS {
            return Err(WireError::TooLong);
        }
        let mut names = Vec::with_capacity(self.claims.len());
        for name in &self.claims {
            let canonical = canonical_claim_name(name)?;
            if names.contains(&canonical) {
                return Err(WireError::UnknownValue);
            }
            names.push(canonical);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AuthenticateStart {
    pub authentication: AuthenticationRequest,
    pub disclosure: DisclosureRequest,
}

#[derive(Debug, Clone, Default)]
pub struct Authenticated {
    pub user_sid: Vec<u8>,
    pub canonical_name: String,
    /// Empty means a deliberate source-authorized no-credential success.
    pub verified_credentials: Vec<CredentialType>,
    /// None means not requested. Some(empty) is a complete empty membership set.
    pub groups: Option<Vec<Vec<u8>>>,
    pub claims: Vec<Claim>,
    /// Requested and authorized, but absent from the source result.
    pub absent_claims: Vec<String>,
}

impl Authenticated {
    /// A success must answer precisely the requested disclosure and proof.
    /// Do not turn an omitted group set into a complete empty membership set.
    pub fn validate_for(&self, request: &AuthenticateStart) -> Result<(), WireError> {
        let invalid = || WireError::UnknownValue;
        let valid_sid = |sid: &[u8]| {
            sid.len() >= 8
                && sid[0] == 1
                && sid[1] <= 15
                && sid.len() == 8 + usize::from(sid[1]) * 4
        };
        if !valid_sid(&self.user_sid)
            || self.groups.is_some() != request.disclosure.groups
            || self.verified_credentials.iter().any(|t| {
                !request
                    .authentication
                    .supported_credential_types
                    .contains(t)
            })
            || request
                .authentication
                .required_credential_type
                .is_some_and(|t| !self.verified_credentials.contains(&t))
        {
            return Err(invalid());
        }
        for (index, credential) in self.verified_credentials.iter().enumerate() {
            if self.verified_credentials[..index].contains(credential) {
                return Err(invalid());
            }
        }
        if let Some(groups) = &self.groups {
            for (index, sid) in groups.iter().enumerate() {
                if !valid_sid(sid) || groups[..index].contains(sid) {
                    return Err(invalid());
                }
            }
        }
        let requested = request
            .disclosure
            .claims
            .iter()
            .map(|name| canonical_claim_name(name))
            .collect::<Result<Vec<_>, _>>()?;
        let mut answered = Vec::new();
        for claim in &self.claims {
            claim.validate().map_err(|_| invalid())?;
        }
        for name in self
            .claims
            .iter()
            .map(|c| &c.name)
            .chain(&self.absent_claims)
        {
            let name = canonical_claim_name(name)?;
            if !requested.contains(&name) || answered.contains(&name) {
                return Err(invalid());
            }
            answered.push(name);
        }
        if answered.len() != requested.len() {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) fn write_request(
    w: &mut Writer,
    request: &AuthenticationRequest,
) -> Result<(), WireError> {
    request.validate()?;
    w.u8(request.identifier_type as u8);
    w.bytes(&request.identifier, wire::MAX_IDENTIFIER_BYTES)?;
    let supported: Vec<u8> = request
        .supported_credential_types
        .iter()
        .map(|v| *v as u8)
        .collect();
    w.bytes(&supported, wire::MAX_SUPPORTED_CREDENTIAL_TYPES)?;
    w.u8(request.required_credential_type.map_or(0, |v| v as u8));
    w.u8(u8::from(request.ssh_binding.is_some()));
    if let Some(binding) = &request.ssh_binding {
        let at = w.open();
        for byte in binding.connection {
            w.u8(byte);
        }
        w.bytes(&binding.session, 64)?;
        w.string(&binding.username, 256)?;
        w.close(at);
    }
    Ok(())
}

pub(crate) fn read_request(r: &mut Reader<'_>) -> Result<AuthenticationRequest, WireError> {
    let identifier_type = IdentifierType::from_u8(r.u8()?).ok_or(WireError::UnknownValue)?;
    let identifier = r.bytes(wire::MAX_IDENTIFIER_BYTES)?.to_vec();
    let supported_credential_types = r
        .bytes(wire::MAX_SUPPORTED_CREDENTIAL_TYPES)?
        .iter()
        .filter_map(|v| CredentialType::from_u8(*v))
        .collect();
    let required_credential_type = match r.u8()? {
        0 => None,
        v => Some(CredentialType::from_u8(v).ok_or(WireError::UnknownValue)?),
    };
    let ssh_binding = match r.u8()? {
        0 => None,
        1 => {
            let mut b = r.open()?;
            let value = crate::ssh::Binding {
                connection: b.take(16)?.try_into().map_err(|_| WireError::Truncated)?,
                session: b.bytes(64)?.to_vec(),
                username: b.string(256)?.to_owned(),
            };
            if !b.at_end() {
                return Err(WireError::UnknownValue);
            }
            Some(value)
        }
        _ => return Err(WireError::UnknownValue),
    };
    let request = AuthenticationRequest {
        identifier_type,
        identifier,
        supported_credential_types,
        required_credential_type,
        ssh_binding,
    };
    request.validate()?;
    Ok(request)
}

fn write_names(w: &mut Writer, names: &[String]) -> Result<(), WireError> {
    w.count(names.len(), claim::MAX_CLAIMS)?;
    for name in names {
        let at = w.open();
        w.string(name, claim::MAX_NAME_BYTES)?;
        w.close(at);
    }
    Ok(())
}

fn read_names(r: &mut Reader<'_>) -> Result<Vec<String>, WireError> {
    r.array(claim::MAX_CLAIMS, |b| {
        Ok(b.string(claim::MAX_NAME_BYTES)?.to_owned())
    })
}

pub fn encode_authenticate_start(start: &AuthenticateStart) -> Result<Vec<u8>, WireError> {
    start.disclosure.validate()?;
    let mut w = Writer::new(&wire::FRAMING, MSG_AUTHENTICATE_START);
    let body = w.open();
    let nested = w.open();
    write_request(&mut w, &start.authentication)?;
    w.close(nested);
    w.u8(u8::from(start.disclosure.groups));
    write_names(&mut w, &start.disclosure.claims)?;
    w.close(body);
    w.finish()
}

pub fn decode_authenticate_start(buf: &[u8]) -> Result<AuthenticateStart, WireError> {
    let mut r = frame::open_body(&wire::FRAMING, buf, MSG_AUTHENTICATE_START)?;
    let authentication = read_request(&mut r.open()?)?;
    let groups = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(WireError::UnknownValue),
    };
    let disclosure = DisclosureRequest {
        groups,
        claims: read_names(&mut r)?,
    };
    disclosure.validate()?;
    Ok(AuthenticateStart {
        authentication,
        disclosure,
    })
}

pub fn encode_authenticated(result: &Authenticated) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&wire::FRAMING, MSG_AUTHENTICATED);
    let body = w.open();
    w.bytes(&result.user_sid, frame::MAX_SID_BYTES)?;
    w.string(&result.canonical_name, crate::ident::MAX_NAME_BYTES)?;
    let verified: Vec<u8> = result
        .verified_credentials
        .iter()
        .map(|v| *v as u8)
        .collect();
    w.bytes(&verified, wire::MAX_SUPPORTED_CREDENTIAL_TYPES)?;
    w.u8(u8::from(result.groups.is_some()));
    if let Some(groups) = &result.groups {
        w.count(groups.len(), MAX_GROUPS)?;
        for group in groups {
            let at = w.open();
            w.bytes(group, frame::MAX_SID_BYTES)?;
            w.close(at);
        }
    }
    claim::write_claims(&mut w, &result.claims)?;
    write_names(&mut w, &result.absent_claims)?;
    w.close(body);
    w.finish()
}

pub fn decode_authenticated(buf: &[u8]) -> Result<Authenticated, WireError> {
    let mut r = frame::open_body(&wire::FRAMING, buf, MSG_AUTHENTICATED)?;
    let user_sid = r.bytes(frame::MAX_SID_BYTES)?.to_vec();
    let canonical_name = r.string(crate::ident::MAX_NAME_BYTES)?.to_owned();
    let verified_credentials = r
        .bytes(wire::MAX_SUPPORTED_CREDENTIAL_TYPES)?
        .iter()
        .map(|v| CredentialType::from_u8(*v).ok_or(WireError::UnknownValue))
        .collect::<Result<_, _>>()?;
    let groups = match r.u8()? {
        0 => None,
        1 => Some(r.array(MAX_GROUPS, |b| Ok(b.bytes(frame::MAX_SID_BYTES)?.to_vec()))?),
        _ => return Err(WireError::UnknownValue),
    };
    let claims = claim::read_claims(&mut r)?;
    let absent_claims = read_names(&mut r)?;
    Ok(Authenticated {
        user_sid,
        canonical_name,
        verified_credentials,
        groups,
        claims,
        absent_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password() -> AuthenticationRequest {
        AuthenticationRequest {
            identifier_type: IdentifierType::Username,
            identifier: b"jack".to_vec(),
            supported_credential_types: vec![CredentialType::Password],
            required_credential_type: Some(CredentialType::Password),
            ssh_binding: None,
        }
    }

    #[test]
    fn password_support_does_not_accept_credential_free_success() {
        assert!(!password().accepts(None));
        assert!(password().accepts(Some(CredentialType::Password)));
        let mut request = password();
        request.required_credential_type = None;
        assert!(request.accepts(None));
    }

    #[test]
    fn canonical_identity_name_keeps_the_source_name_bound() {
        let result = Authenticated {
            canonical_name: "x".repeat(crate::ident::MAX_NAME_BYTES),
            ..Authenticated::default()
        };
        let encoded = encode_authenticated(&result).unwrap();
        assert_eq!(
            decode_authenticated(&encoded).unwrap().canonical_name,
            result.canonical_name
        );
    }

    #[test]
    fn disclosure_cannot_request_case_aliases_twice() {
        assert!(
            DisclosureRequest {
                groups: false,
                claims: vec!["Department".into(), "department".into()]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn success_distinguishes_unrequested_empty_and_absent() {
        for groups in [None, Some(Vec::new())] {
            let result = Authenticated {
                groups: groups.clone(),
                absent_claims: vec!["department".into()],
                ..Authenticated::default()
            };
            let decoded = decode_authenticated(&encode_authenticated(&result).unwrap()).unwrap();
            assert_eq!(decoded.groups, groups);
            assert_eq!(decoded.absent_claims, ["department"]);
        }
    }

    #[test]
    fn every_truncated_general_authentication_message_is_rejected() {
        let request = AuthenticateStart {
            authentication: password(),
            disclosure: DisclosureRequest {
                groups: true,
                claims: vec!["department".into()],
            },
        };
        let messages = [
            encode_authenticate_start(&request).unwrap(),
            encode_authenticated(&Authenticated {
                absent_claims: vec!["department".into()],
                ..Default::default()
            })
            .unwrap(),
        ];
        for (index, bytes) in messages.iter().enumerate() {
            for end in 0..bytes.len() {
                if index == 0 {
                    assert!(decode_authenticate_start(&bytes[..end]).is_err());
                } else {
                    assert!(decode_authenticated(&bytes[..end]).is_err());
                }
            }
        }
    }

    #[test]
    fn incomplete_or_unrequested_disclosure_cannot_be_a_success() {
        let request = AuthenticateStart {
            authentication: password(),
            disclosure: DisclosureRequest {
                groups: true,
                claims: vec!["department".into()],
            },
        };
        let mut result = Authenticated {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            canonical_name: "jack".into(),
            verified_credentials: vec![CredentialType::Password],
            groups: Some(Vec::new()),
            absent_claims: vec!["Department".into()],
            claims: Vec::new(),
        };
        assert!(result.validate_for(&request).is_ok());
        result.groups = None;
        assert!(result.validate_for(&request).is_err());
        result.groups = Some(Vec::new());
        result.absent_claims.clear();
        assert!(result.validate_for(&request).is_err());
        result.absent_claims.push("private".into());
        assert!(result.validate_for(&request).is_err());
        result.absent_claims = vec!["department".into()];
        result.verified_credentials.clear();
        assert!(result.validate_for(&request).is_err());
    }
}
