//! Access checks use the connected caller's actual token, including capability
//! and service SIDs. Hold one descriptor snapshot for a request's checks.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use auth_core::wire::{ClaimSelection, DisclosureRequest};
use auth_policy::authentication as rights;
use peios::access::{AccessCheck, AuditContext};
use peios::security::{AccessMask, GenericMapping, SecurityDescriptor};
use peios::token::Token;

pub struct Authorization {
    token: Token,
    descriptor: SecurityDescriptor,
}

impl Authorization {
    pub fn open(stream: &UnixStream) -> Option<Self> {
        let token = Token::open_peer(stream.as_fd()).ok()?;
        let descriptor = rights::descriptor()
            .map_err(|error| {
                crate::log::error(format_args!(
                    "unusable AuthenticationSecurity: {error}; refusing"
                ));
            })
            .ok()?;
        Some(Self { token, descriptor })
    }

    pub fn permits(&self, desired: u32) -> bool {
        self.check(desired, None)
    }

    pub fn discloses(&self, request: &DisclosureRequest) -> bool {
        (!request.groups || self.permits(rights::READ_GROUPS))
            && match &request.claims {
                ClaimSelection::Named(names) => names.iter().all(|name| self.discloses_claim(name)),
                ClaimSelection::None | ClaimSelection::AllPermitted => true,
            }
    }

    /// A namespace grant alone does not rule out a claim-specific deny. Mark
    /// potentially filtered policies independently of which claims exist.
    pub fn discloses_all_claims(&self) -> bool {
        self.permits(rights::READ_CLAIM) && namespace_cannot_filter(&self.descriptor)
    }

    pub fn disclosed_claims(
        &self,
        selection: &ClaimSelection,
        asserted: &[auth_core::Claim],
    ) -> DisclosedClaims {
        disclose_claims(
            selection,
            asserted,
            matches!(selection, ClaimSelection::AllPermitted) && self.discloses_all_claims(),
            |name| self.discloses_claim(name),
        )
    }

    pub fn discloses_claim(&self, name: &str) -> bool {
        rights::claim_guid(name).is_ok_and(|guid| self.check(rights::READ_CLAIM, Some(guid)))
    }

    fn check(&self, desired: u32, claim: Option<[u8; 16]>) -> bool {
        check(&self.token, &self.descriptor, desired, claim)
    }
}

fn namespace_cannot_filter(descriptor: &SecurityDescriptor) -> bool {
    let Ok(view) = descriptor.view() else {
        return false;
    };
    // Scoped policy and conditional SACL processing may further narrow
    // disclosure. Refuse to promise completeness for that configuration.
    if view.sacl().is_some_and(|acl| !acl.is_empty()) {
        return false;
    }
    view.dacl().is_none_or(|acl| {
        (0..acl.len()).all(|index| {
            acl.ace(index).is_some_and(|ace| {
                use peios::security::AceType;
                let can_deny = matches!(
                    ace.ace_type(),
                    AceType::AccessDenied | AceType::Other(0x06 | 0x0a | 0x0c)
                );
                let claim_rights = rights::READ_CLAIM | 0x8000_0000 | 0x1000_0000;
                !can_deny || ace.mask() & claim_rights == 0
            })
        })
    })
}

fn check(
    token: &Token,
    descriptor: &SecurityDescriptor,
    desired: u32,
    claim: Option<[u8; 16]>,
) -> bool {
    let mapping = GenericMapping::new(
        rights::READ_GROUPS | rights::READ_CLAIM,
        0,
        rights::AUTHENTICATE | rights::LOGON,
        rights::ALL,
    );
    let mut check = AccessCheck::new(descriptor, AccessMask::from_bits_retain(desired), mapping);
    check.token(token.as_fd());
    let context = AuditContext::new("authd-authentication", &[]).ok();
    if let Some(context) = &context {
        check.audit_context(context);
    }
    // A scalar access check does not distinguish object ACE targets.
    // Operations, groups and the complete claims field address the root;
    // only a named claim adds its leaf. A claim-specific generic grant or
    // deny must not change authority to invoke an operation or read groups.
    let mut nodes = vec![peios_sys::kacs_object_type_entry {
        level: 0,
        _reserved: 0,
        guid: rights::CLAIM_NAMESPACE,
    }];
    if let Some(guid) = claim {
        nodes.push(peios_sys::kacs_object_type_entry {
            level: 1,
            _reserved: 0,
            guid,
        });
    }
    check.check_list(&nodes).is_ok_and(|results| {
        results
            .last()
            .is_some_and(|r| r.status == 0 && r.granted & desired == desired)
    })
}

pub struct DisclosedClaims {
    pub values: Vec<auth_core::Claim>,
    pub absent: Vec<String>,
    pub coverage: auth_core::wire::ClaimCoverage,
}

fn disclose_claims(
    selection: &ClaimSelection,
    asserted: &[auth_core::Claim],
    complete: bool,
    mut permits: impl FnMut(&str) -> bool,
) -> DisclosedClaims {
    use auth_core::wire::ClaimCoverage;
    let mut result = DisclosedClaims {
        values: Vec::new(),
        absent: Vec::new(),
        coverage: ClaimCoverage::None,
    };
    match selection {
        ClaimSelection::None => {}
        ClaimSelection::Named(names) => {
            result.coverage = ClaimCoverage::Named;
            for name in names {
                match asserted
                    .iter()
                    .find(|claim| claim.name.eq_ignore_ascii_case(name))
                {
                    Some(claim) => result.values.push(claim.clone()),
                    None => result.absent.push(name.clone()),
                }
            }
        }
        ClaimSelection::AllPermitted => {
            result.coverage = if complete {
                ClaimCoverage::Complete
            } else {
                ClaimCoverage::Filtered
            };
            result.values.extend(
                asserted
                    .iter()
                    .filter(|claim| complete || permits(&claim.name))
                    .cloned(),
            );
        }
    }
    result
}

pub fn permits(stream: &UnixStream, right: u32) -> bool {
    Authorization::open(stream).is_some_and(|authorization| authorization.permits(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::{Claim, claim::Values, wire::ClaimCoverage};
    #[test]
    fn coverage_depends_on_policy_rather_than_presence_of_hidden_claims() {
        let visible = Claim {
            name: "Department".into(),
            flags: 0,
            values: Values::String(vec!["Home".into()]),
        };
        let hidden = Claim {
            name: "Salary".into(),
            flags: 0,
            values: Values::Uint64(vec![100]),
        };
        for source in [vec![visible.clone()], vec![visible.clone(), hidden]] {
            let result = disclose_claims(&ClaimSelection::AllPermitted, &source, false, |name| {
                name != "Salary"
            });
            assert_eq!(result.coverage, ClaimCoverage::Filtered);
            assert_eq!(result.values.len(), 1);
            assert_eq!(result.values[0].name, "Department");
            assert!(result.absent.is_empty());
        }
        let result = disclose_claims(&ClaimSelection::AllPermitted, &[], false, |_| false);
        assert_eq!(result.coverage, ClaimCoverage::Filtered);
        let result = disclose_claims(&ClaimSelection::AllPermitted, &[], true, |_| {
            panic!("unrestricted policy")
        });
        assert_eq!(result.coverage, ClaimCoverage::Complete);
    }

    #[test]
    fn possible_claim_denies_prevent_namespace_completeness() {
        for (aces, expected) in [
            ("(A;;0xf;;;SY)", true),
            ("(D;;0x2;;;BA)(A;;0xf;;;SY)", true),
            ("(D;;0x8;;;BA)(A;;0xf;;;SY)", false),
            (
                "(OD;;GA;c4abd379-a4d6-5910-bccf-9f01f9a4738f;;BA)(A;;0xf;;;SY)",
                false,
            ),
            (
                "(OD;;GR;c4abd379-a4d6-5910-bccf-9f01f9a4738f;;BA)(A;;0xf;;;SY)",
                false,
            ),
        ] {
            let sd = peios::security::sddl::parse(&format!("O:SYG:SYD:{aces}")).unwrap();
            assert_eq!(namespace_cannot_filter(&sd), expected);
        }
    }
}
