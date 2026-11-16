//! Access checks use the connected caller's actual token, including capability
//! and service SIDs. Hold one descriptor snapshot for a request's checks.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use auth_core::wire::DisclosureRequest;
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
            && request.claims.iter().all(|name| self.discloses_claim(name))
    }

    pub fn discloses_claim(&self, name: &str) -> bool {
        rights::claim_guid(name).is_ok_and(|guid| self.check(rights::READ_CLAIM, Some(guid)))
    }

    fn check(&self, desired: u32, claim: Option<[u8; 16]>) -> bool {
        let mapping = GenericMapping::new(
            rights::READ_GROUPS | rights::READ_CLAIM,
            0,
            rights::AUTHENTICATE | rights::LOGON,
            rights::ALL,
        );
        let mut check = AccessCheck::new(
            &self.descriptor,
            AccessMask::from_bits_retain(desired),
            mapping,
        );
        check.token(self.token.as_fd());
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
}

pub fn permits(stream: &UnixStream, right: u32) -> bool {
    Authorization::open(stream).is_some_and(|authorization| authorization.permits(right))
}
