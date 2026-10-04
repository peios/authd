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

/// Who may end another principal's logon session (PGSS §2.22): the configured
/// descriptor, or the built-in one where none is configured.
///
/// `None` where one is configured and cannot be used — not a REG_SZ, empty,
/// unreadable, or not SDDL — and then nobody may: falling back to the
/// built-in descriptor could grant more than the site wrote. Logged each time,
/// since it is read each time.
pub fn session_end_descriptor() -> Option<peios::security::SecurityDescriptor> {
    let text = match libauthd_policy::session_end_descriptor() {
        Ok(text) => text,
        Err(problem) => {
            log::error(format_args!("{problem}"));
            return None;
        }
    };
    match peios::security::sddl::parse(&text) {
        Ok(sd) => Some(sd),
        Err(error) => {
            log::error(format_args!(
                "{}\\{} is not a usable descriptor ({error}); nobody may end another \
                 principal's session until it is corrected or removed",
                libauthd_policy::KEY,
                libauthd_policy::SESSION_END_SD_VALUE
            ));
            None
        }
    }
}

/// The configured SDDL for `/run/logon.sock`, if a site has stated one.
pub fn logon_socket_descriptor() -> Option<String> {
    libauthd_policy::logon_socket_descriptor().unwrap_or_else(|problem| {
        log::warn(format_args!("{problem}"));
        None
    })
}
