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

/// Names follow KACS's per-character Unicode lowercase mapping, without
/// normalization or full case folding. The original spelling stays on the wire.
pub fn canonical_claim_name(name: &str) -> Result<String, WireError> {
    if name.is_empty() || name.len() > claim::MAX_NAME_BYTES || name.contains('\0') {
        return Err(WireError::UnknownValue);
    }
    Ok(crate::claim_name::canonical_chars(name).collect())
}

/// Compare names using the same allocation-free rule as KACS. Validate names
/// separately when accepting untrusted protocol or source inputs.
pub fn claim_names_equal(left: &str, right: &str) -> bool {
    crate::claim_name::names_equal(left, right)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ClaimSelection {
    /// Do not disclose claims.
    #[default]
    None,
    /// Resolve exactly these names, including explicit authorized absence.
    Named(Vec<String>),
    /// Disclose readable claims without revealing restricted names or counts.
    AllPermitted,
}

impl ClaimSelection {
    pub fn names(&self) -> &[String] {
        match self {
            Self::Named(names) => names,
            _ => &[],
        }
    }
}

/// The knowledge supplied by the claim result, independently of its length.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaimCoverage {
    #[default]
    None = 0,
    Named = 1,
    Complete = 2,
    Filtered = 3,
}

impl ClaimCoverage {
    fn from_u8(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Named),
            2 => Ok(Self::Complete),
            3 => Ok(Self::Filtered),
            _ => Err(WireError::UnknownValue),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisclosureRequest {
    pub groups: bool,
    pub claims: ClaimSelection,
}

impl DisclosureRequest {
    pub fn validate(&self) -> Result<(), WireError> {
        let claims = self.claims.names();
        if matches!(&self.claims, ClaimSelection::Named(names) if names.is_empty()) {
            return Err(WireError::UnknownValue);
        }
        if claims.len() > claim::MAX_CLAIMS {
            return Err(WireError::TooLong);
        }
        let mut names = Vec::with_capacity(claims.len());
        for name in claims {
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
    pub mschapv2_success: Option<crate::mschapv2::Success>,
    pub user_sid: Vec<u8>,
    pub canonical_name: String,
    /// Empty means a deliberate source-authorized no-credential success.
    pub verified_credentials: Vec<CredentialType>,
    /// None means not requested. Some(empty) is a complete empty membership set.
    pub groups: Option<Vec<Vec<u8>>>,
    pub claims: Vec<Claim>,
    pub claim_coverage: ClaimCoverage,
    /// Requested and authorized, but absent from the source result.
    pub absent_claims: Vec<String>,
}

impl Authenticated {
    /// A success must answer precisely the requested disclosure and proof.
    /// Do not turn an omitted group set into a complete empty membership set.
    pub fn validate_for(&self, request: &AuthenticateStart) -> Result<(), WireError> {
        crate::mschapv2::validate_success(
            self.verified_credentials
                .contains(&CredentialType::Mschapv2)
                .then_some(CredentialType::Mschapv2),
            &self.mschapv2_success,
        )?;
        request.disclosure.validate()?;
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
            .names()
            .iter()
            .map(|name| canonical_claim_name(name))
            .collect::<Result<Vec<_>, _>>()?;
        let named = matches!(request.disclosure.claims, ClaimSelection::Named(_));
        let coverage_valid = match request.disclosure.claims {
            ClaimSelection::None => {
                self.claim_coverage == ClaimCoverage::None
                    && self.claims.is_empty()
                    && self.absent_claims.is_empty()
            }
            ClaimSelection::Named(_) => self.claim_coverage == ClaimCoverage::Named,
            ClaimSelection::AllPermitted => {
                matches!(
                    self.claim_coverage,
                    ClaimCoverage::Complete | ClaimCoverage::Filtered
                ) && self.absent_claims.is_empty()
            }
        };
        if !coverage_valid || self.claims.len() > claim::MAX_CLAIMS {
            return Err(invalid());
        }
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
            if (named && !requested.contains(&name)) || answered.contains(&name) {
                return Err(invalid());
            }
            answered.push(name);
        }
        if named && answered.len() != requested.len() {
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
    match &start.disclosure.claims {
        ClaimSelection::None => w.u8(0),
        ClaimSelection::Named(names) => {
            w.u8(1);
            write_names(&mut w, names)?;
        }
        ClaimSelection::AllPermitted => w.u8(2),
    }
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
        claims: match r.u8()? {
            0 => ClaimSelection::None,
            1 => ClaimSelection::Named(read_names(&mut r)?),
            2 => ClaimSelection::AllPermitted,
            _ => return Err(WireError::UnknownValue),
        },
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
    w.u8(result.claim_coverage as u8);
    claim::write_claims(&mut w, &result.claims)?;
    write_names(&mut w, &result.absent_claims)?;
    w.bytes(result.mschapv2_success.as_ref().map_or(&[], |v| &v.0), 20)?;
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
    let claim_coverage = ClaimCoverage::from_u8(r.u8()?)?;
    let claims = claim::read_claims(&mut r)?;
    let absent_claims = read_names(&mut r)?;
    let mschapv2_success = crate::mschapv2::decode_success(r.bytes(20)?)?;
    Ok(Authenticated {
        mschapv2_success,
        user_sid,
        canonical_name,
        verified_credentials,
        groups,
        claims,
        claim_coverage,
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
    fn claim_modes_and_coverage_round_trip_without_inventing_absence() {
        for selection in [
            ClaimSelection::None,
            ClaimSelection::Named(vec!["department".into()]),
            ClaimSelection::AllPermitted,
        ] {
            let request = AuthenticateStart {
                authentication: password(),
                disclosure: DisclosureRequest {
                    groups: false,
                    claims: selection,
                },
            };
            let decoded =
                decode_authenticate_start(&encode_authenticate_start(&request).unwrap()).unwrap();
            assert_eq!(decoded.disclosure, request.disclosure);
            for coverage in [
                ClaimCoverage::None,
                ClaimCoverage::Named,
                ClaimCoverage::Complete,
                ClaimCoverage::Filtered,
            ] {
                let mut result = Authenticated {
                    user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                    verified_credentials: vec![CredentialType::Password],
                    claim_coverage: coverage,
                    ..Default::default()
                };
                if coverage == ClaimCoverage::Named {
                    result.absent_claims.push("department".into());
                }
                let expected = matches!(
                    (&request.disclosure.claims, coverage),
                    (ClaimSelection::None, ClaimCoverage::None)
                        | (ClaimSelection::Named(_), ClaimCoverage::Named)
                        | (
                            ClaimSelection::AllPermitted,
                            ClaimCoverage::Complete | ClaimCoverage::Filtered
                        )
                );
                let decoded =
                    decode_authenticated(&encode_authenticated(&result).unwrap()).unwrap();
                assert_eq!(decoded.validate_for(&request).is_ok(), expected);
            }
        }
    }

    #[test]
    fn all_permitted_cannot_report_hidden_claim_names_as_absent() {
        let request = AuthenticateStart {
            authentication: password(),
            disclosure: DisclosureRequest {
                groups: false,
                claims: ClaimSelection::AllPermitted,
            },
        };
        let result = Authenticated {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            verified_credentials: vec![CredentialType::Password],
            claim_coverage: ClaimCoverage::Filtered,
            absent_claims: vec!["salary".into()],
            ..Default::default()
        };
        assert!(result.validate_for(&request).is_err());
        assert!(
            DisclosureRequest {
                groups: false,
                claims: ClaimSelection::Named(Vec::new())
            }
            .validate()
            .is_err()
        );
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
                claims: ClaimSelection::Named(vec!["Department".into(), "department".into()])
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn unicode_equivalence_applies_to_requests_values_and_absences() {
        assert_eq!(canonical_claim_name("Équipe").unwrap(), "équipe");
        assert_eq!(canonical_claim_name("İ").unwrap(), "i\u{307}");
        assert!(!claim_names_equal("é", "e\u{301}"));
        let mut request = AuthenticateStart {
            authentication: password(),
            disclosure: DisclosureRequest {
                groups: false,
                claims: ClaimSelection::Named(vec!["équipe".into()]),
            },
        };
        let mut result = Authenticated {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            mschapv2_success: None,
            verified_credentials: vec![CredentialType::Password],
            claim_coverage: ClaimCoverage::Named,
            claims: vec![Claim {
                name: "Équipe".into(),
                flags: 0,
                values: claim::Values::String(vec!["Engineering".into()]),
            }],
            ..Default::default()
        };
        assert!(result.validate_for(&request).is_ok());
        result.absent_claims.push("équipe".into());
        assert!(result.validate_for(&request).is_err());
        result.claims.clear();
        assert!(result.validate_for(&request).is_ok());
        request.disclosure.claims = ClaimSelection::Named(vec!["Équipe".into(), "équipe".into()]);
        assert!(request.disclosure.validate().is_err());
        request.disclosure.claims = ClaimSelection::AllPermitted;
        result.claim_coverage = ClaimCoverage::Complete;
        result.absent_claims.clear();
        result.claims = ["Équipe", "équipe"]
            .map(|name| Claim {
                name: name.into(),
                flags: 0,
                values: claim::Values::String(vec!["Engineering".into()]),
            })
            .to_vec();
        assert!(result.validate_for(&request).is_err());
    }

    #[test]
    fn legacy_ascii_only_absence_is_rejected_by_framing() {
        let result = Authenticated {
            claim_coverage: ClaimCoverage::Named,
            absent_claims: vec!["équipe".into()],
            ..Default::default()
        };
        let mut encoded = encode_authenticated(&result).unwrap();
        encoded[4..6].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            decode_authenticated(&encoded).unwrap_err(),
            WireError::UnsupportedVersion(3)
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
                claims: ClaimSelection::Named(vec!["department".into()]),
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
                claims: ClaimSelection::Named(vec!["department".into()]),
            },
        };
        let mut result = Authenticated {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            canonical_name: "jack".into(),
            verified_credentials: vec![CredentialType::Password],
            groups: Some(Vec::new()),
            absent_claims: vec!["Department".into()],
            mschapv2_success: None,
            claims: Vec::new(),
            claim_coverage: ClaimCoverage::Named,
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
