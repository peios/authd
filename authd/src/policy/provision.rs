//! Which logons provision the principal's profile.
//!
//! On a successful logon whose profile names a home, authd creates the home
//! directory and the principal's `Users\<SID>` Registry root when they are
//! absent. Some sites do not want every kind of logon to do that: Windows
//! creates no profile for a network logon, and a file server with many
//! accounts would otherwise accumulate homes for people who never sign in at
//! the machine. `ProvisionLogonTypes` limits provisioning to the logon types
//! it lists. Absent, every type provisions, so file sharing can serve homes.
//!
//! The value is read at each logon, like the rest of authd's policy. A value
//! of the wrong type is reported and ignored, leaving the default: this
//! setting suppresses a side effect and grants nothing, so the default is
//! the unsurprising direction.

use crate::log;
use auth_core::wire::LogonType;
use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};
use std::io::ErrorKind;

/// authd's own configuration key.
pub const AUTHD_KEY: &str = "Machine\\Software\\Authd";

const PROVISION_VALUE: &str = "ProvisionLogonTypes";

/// Whether a logon of `logon_type` provisions the principal's profile.
pub fn provisions(logon_type: LogonType) -> bool {
    let key = match Key::open(None, AUTHD_KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(error) if error.kind() == ErrorKind::NotFound => return true,
        Err(error) => {
            log::warn(format_args!(
                "cannot read {AUTHD_KEY} ({error}); provisioning as by default"
            ));
            return true;
        }
    };
    match key.query_value(PROVISION_VALUE.as_bytes(), None) {
        Ok(value) => {
            let (provisions, problems) = decide(&value.ty, &value.data, logon_type);
            for problem in problems {
                log::warn(format_args!("{problem}"));
            }
            provisions
        }
        Err(error) if error.kind() == ErrorKind::NotFound => true,
        Err(error) => {
            log::warn(format_args!(
                "cannot read {AUTHD_KEY}\\{PROVISION_VALUE} ({error}); provisioning as by default"
            ));
            true
        }
    }
}

/// The decision for one stored value, with any problems to report. Unknown
/// names are dropped, as in every logon-type list.
fn decide(ty: &ValueType, data: &[u8], logon_type: LogonType) -> (bool, Vec<String>) {
    let Some(names) = super::multi_sz(ty, data) else {
        return (
            true,
            vec![format!(
                "{AUTHD_KEY}\\{PROVISION_VALUE} is not a REG_MULTI_SZ (type {:#x}); ignoring it",
                ty.0
            )],
        );
    };
    let mut problems = Vec::new();
    let mut listed = false;
    for name in names {
        match auth_policy::LOGON_TYPE_NAMES
            .iter()
            .find(|(known, _)| *known == name)
        {
            Some((_, known)) => listed |= *known == logon_type,
            None => problems.push(format!(
                "{AUTHD_KEY}\\{PROVISION_VALUE} names {name:?}, which is not a logon type this \
                 build knows; ignoring it"
            )),
        }
    }
    (listed, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multi(names: &[&str]) -> Vec<u8> {
        auth_policy::encode_multi_sz(names.iter().copied())
    }

    #[test]
    fn only_listed_types_provision() {
        let data = multi(&["Interactive", "RemoteInteractive"]);
        assert!(decide(&ValueType::MULTI_SZ, &data, LogonType::Interactive).0);
        assert!(!decide(&ValueType::MULTI_SZ, &data, LogonType::Network).0);
    }

    #[test]
    fn an_empty_list_provisions_nothing() {
        let data = multi(&[]);
        assert!(!decide(&ValueType::MULTI_SZ, &data, LogonType::Interactive).0);
    }

    #[test]
    fn unknown_names_are_dropped_and_reported() {
        let data = multi(&["Network", "Telepathic"]);
        let (provisions, problems) = decide(&ValueType::MULTI_SZ, &data, LogonType::Network);
        assert!(provisions);
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn a_value_of_the_wrong_type_leaves_the_default() {
        let (provisions, problems) = decide(&ValueType::DWORD, &[0, 0, 0, 0], LogonType::Network);
        assert!(provisions);
        assert_eq!(problems.len(), 1);
    }
}
