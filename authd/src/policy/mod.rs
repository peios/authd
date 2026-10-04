//! Policy, read from the registry.
//!
//! Two different questions live here, in two different registry subtrees,
//! and keeping them apart is the point of the split:
//!
//! - [`principal`] — **what this machine grants a principal.** Under
//!   `Machine\Generic\Authn\Policy`, because it is Peios policy about what a
//!   logon *means*; a different authority answering on `/run/logon.sock` should
//!   read the same key.
//! - [`sources`] — **which principal sources may register.** Under
//!   `Machine\Software\Authd`, because principal sources are an authd concept:
//!   PSI is authd's protocol, not part of PGSS.
//!
//! # Read per logon, not at startup
//!
//! Policy that only takes effect after restarting the authority is a footgun: a
//! change appears to do nothing, and the fix is to restart the one daemon on
//! the system that is most disruptive to restart. A logon happens at human
//! speed and the read is a syscall against a kernel-side registry, so paying it
//! each time buys immediacy for nothing that matters.
//!
//! # authd never writes
//!
//! Nothing here opens a registry key for writing, and nothing creates one. That
//! keeps the process holding `SeCreateTokenPrivilege` away from a registry write
//! handle, and it means policy behaves identically on a machine that has never
//! been configured and one where an administrator deleted the key.
//! libauthd-policy's writers exist only with its `write` feature, which authd
//! does not turn on.

pub mod principal;
pub mod sources;

pub use libauthd_policy::{dword, sz};
pub use principal::{
    Outcome, logon_socket_descriptor, originator_logon_types, session_end_descriptor,
};
pub use sources::{SOURCES_KEY, SourceEntry, sources};

#[cfg(test)]
mod tests {
    use super::*;

    /// The two keys answer different questions and must not be confused: one is
    /// what a logon means to any authority, the other is this implementation's
    /// list of who may assert identity.
    #[test]
    fn generic_policy_and_authd_configuration_are_separate_subtrees() {
        assert!(libauthd_policy::KEY.starts_with("Machine\\Generic\\"));
        assert!(sources::SOURCES_KEY.starts_with("Machine\\Software\\Authd\\"));
    }

    #[test]
    fn the_policy_key_paths_are_well_formed() {
        // Components cannot be empty, so no leading, trailing or doubled
        // separator. The canonical separator is a backslash.
        for path in [libauthd_policy::KEY, sources::SOURCES_KEY] {
            assert!(!path.starts_with('\\'), "{path}");
            assert!(!path.ends_with('\\'), "{path}");
            assert!(!path.contains("\\\\"), "{path}");
            assert!(!path.contains('/'), "{path}");
            assert!(path.starts_with("Machine\\"), "{path}");
        }
    }
}
