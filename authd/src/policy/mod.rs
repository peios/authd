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

use peios::registry::ValueType;

pub mod principal;
pub mod sources;

pub use principal::{Outcome, logon_socket_descriptor, originator_logon_types};
pub use sources::{SOURCES_KEY, SourceEntry, sources};

/// Read a `REG_DWORD`'s value, if that is what this is.
///
/// The type tag *and* the length are both checked. The registry validates
/// neither — it stores a tag and some bytes — so a value claiming to be a
/// DWORD while carrying three bytes is representable, and must not be read as
/// though the missing byte were zero.
fn dword(ty: &ValueType, data: &[u8]) -> Option<u32> {
    if *ty != ValueType::DWORD {
        return None;
    }
    data.try_into().ok().map(u32::from_le_bytes)
}

/// Read a `REG_SZ`'s text, if that is what this is.
///
/// Stops at the first NUL rather than trusting the stored length: the registry
/// keeps a byte count, and a writer that included the terminator and one that
/// did not would otherwise produce values that compare unequal.
fn sz<'a>(ty: &ValueType, data: &'a [u8]) -> Option<&'a str> {
    if *ty != ValueType::SZ {
        return None;
    }
    data.split(|&byte| byte == 0)
        .next()
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .map(str::trim)
}

/// Read a `REG_MULTI_SZ` as a list of strings.
///
/// A `REG_MULTI_SZ` is NUL-separated and double-NUL terminated, so splitting on
/// NUL yields one or two trailing empties. Empty entries are dropped rather than
/// preserved — nothing this reads has a meaningful empty element, and a writer
/// that omitted the final terminator would otherwise produce a different list
/// from one that included it.
///
/// **A value carrying no strings is a successful read of an empty list**, not a
/// failure. That is how "this principal gets nothing" is written, and it has to
/// be distinguishable from the value being absent.
fn multi_sz<'a>(ty: &ValueType, data: &'a [u8]) -> Option<Vec<&'a str>> {
    if *ty != ValueType::MULTI_SZ {
        return None;
    }
    Some(
        data.split(|&byte| byte == 0)
            .filter_map(|bytes| core::str::from_utf8(bytes).ok())
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_dword_reads_back() {
        assert_eq!(dword(&ValueType::DWORD, &0u32.to_le_bytes()), Some(0));
        assert_eq!(dword(&ValueType::DWORD, &1u32.to_le_bytes()), Some(1));
        assert_eq!(
            dword(&ValueType::DWORD, &0xdead_beefu32.to_le_bytes()),
            Some(0xdead_beef)
        );
    }

    /// A short "DWORD" must not be padded into a zero.
    #[test]
    fn a_wrongly_sized_dword_is_not_a_dword() {
        assert_eq!(dword(&ValueType::DWORD, &[0, 0, 0]), None);
        assert_eq!(dword(&ValueType::DWORD, &[0, 0, 0, 0, 0]), None);
        assert_eq!(dword(&ValueType::DWORD, &[]), None);
    }

    /// The registry stores a type tag and bytes and validates neither, so a
    /// string spelled "0" is representable here. It is not a DWORD.
    #[test]
    fn another_type_is_not_a_dword() {
        assert_eq!(dword(&ValueType::SZ, b"0\0"), None);
        assert_eq!(dword(&ValueType::BINARY, &0u32.to_le_bytes()), None);
        assert_eq!(dword(&ValueType::QWORD, &0u64.to_le_bytes()), None);
    }

    #[test]
    fn an_sz_stops_at_the_terminator_and_trims() {
        assert_eq!(sz(&ValueType::SZ, b"High\0"), Some("High"));
        assert_eq!(sz(&ValueType::SZ, b"High"), Some("High"));
        assert_eq!(sz(&ValueType::SZ, b"  High  \0"), Some("High"));
        assert_eq!(sz(&ValueType::SZ, b"High\0trailing"), Some("High"));
        assert_eq!(sz(&ValueType::DWORD, b"High\0"), None);
    }

    #[test]
    fn a_multi_sz_splits_on_nul_and_drops_the_terminators() {
        assert_eq!(
            multi_sz(&ValueType::MULTI_SZ, b"one\0two\0\0"),
            Some(vec!["one", "two"])
        );
        // A writer that omitted the final terminator must produce the same list.
        assert_eq!(
            multi_sz(&ValueType::MULTI_SZ, b"one\0two"),
            Some(vec!["one", "two"])
        );
        assert_eq!(
            multi_sz(&ValueType::MULTI_SZ, b"  one  \0two\0\0"),
            Some(vec!["one", "two"])
        );
    }

    /// "Grant nothing" is a successful read of an empty list, and must not be
    /// confusable with the value being absent or malformed.
    #[test]
    fn an_empty_multi_sz_is_an_empty_list_rather_than_a_failure() {
        assert_eq!(multi_sz(&ValueType::MULTI_SZ, b"\0\0"), Some(Vec::new()));
        assert_eq!(multi_sz(&ValueType::MULTI_SZ, b""), Some(Vec::new()));
    }

    #[test]
    fn another_type_is_not_a_multi_sz() {
        assert_eq!(multi_sz(&ValueType::SZ, b"one\0"), None);
        assert_eq!(multi_sz(&ValueType::DWORD, &0u32.to_le_bytes()), None);
    }

    /// The two keys answer different questions and must not be confused: one is
    /// what a logon means to any authority, the other is this implementation's
    /// list of who may assert identity.
    #[test]
    fn generic_policy_and_authd_configuration_are_separate_subtrees() {
        assert!(principal::KEY.starts_with("Machine\\Generic\\"));
        assert!(sources::SOURCES_KEY.starts_with("Machine\\Software\\Authd\\"));
    }

    #[test]
    fn the_policy_key_paths_are_well_formed() {
        // Components cannot be empty, so no leading, trailing or doubled
        // separator. The canonical separator is a backslash.
        for path in [principal::KEY, sources::SOURCES_KEY] {
            assert!(!path.starts_with('\\'), "{path}");
            assert!(!path.ends_with('\\'), "{path}");
            assert!(!path.contains("\\\\"), "{path}");
            assert!(!path.contains('/'), "{path}");
            assert!(path.starts_with("Machine\\"), "{path}");
        }
    }
}
