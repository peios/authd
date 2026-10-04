//! What this machine grants a principal: `Machine\Generic\Authn\Policy`,
//! read at every logon.
//!
//! The reading and the rules are libauthd-policy's, so that Principals
//! Manager, saying what someone gets, says what authd mints; see
//! [`libauthd_policy`]. This is authd's side: read the key, log what is wrong
//! with it, and decide.

use libauthd::wire::LogonTypes;
use libauthd_policy::Policy;
use peios::security::SidRef;

use crate::log;

pub use libauthd_policy::{Outcome, tier_name};

/// The key, read now, with what is wrong with it logged.
fn read() -> Policy {
    let policy = Policy::read();
    for problem in &policy.problems {
        log::warn(format_args!("{problem}"));
    }
    policy
}

/// Decide what a logon gets. `groups` must be the **final** SID set the token
/// will carry, the derived SIDs included (see [`libauthd_policy::derived_sids`]).
pub fn evaluate(user: &SidRef, groups: &[&SidRef]) -> Outcome {
    let evaluation = read().evaluate(user, groups);
    for problem in &evaluation.problems {
        log::warn(format_args!("{problem}"));
    }
    evaluation.outcome
}

/// The logon types the peer named by `peer` may originate. `None` means no
/// record speaks to it. What that defaults to is the caller's decision — see
/// `may_request`.
pub fn originator_logon_types(peer: &SidRef) -> Option<LogonTypes> {
    read().originator_logon_types(peer)
}

/// The configured SDDL for `/run/logon.sock`, if a site has stated one.
pub fn logon_socket_descriptor() -> Option<String> {
    libauthd_policy::logon_socket_descriptor().unwrap_or_else(|problem| {
        log::warn(format_args!("{problem}"));
        None
    })
}
