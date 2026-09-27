//! Provision a private registry root after authenticated logon. Preferences
//! belong to the principal, so a username or source-supplied path is never used.
use peios::registry::{CreateFlags, Disposition, Key, KeyAccess, SecInfo, Transaction};
use peios::security::{SidRef, sddl};

pub fn ensure(user: &SidRef) {
    if let Err(error) = create(user) {
        crate::log::warn(format_args!(
            "could not provision registry for {user}: {error}"
        ));
    }
}

fn create(user: &SidRef) -> Result<(), String> {
    let tx = Transaction::begin().map_err(|e| e.to_string())?;
    let (key, disposition) = Key::create(
        None,
        &format!("Users\\{user}"),
        KeyAccess::ALL_ACCESS,
        CreateFlags::empty(),
        None,
        Some(&tx),
    )
    .map_err(|e| e.to_string())?;
    if disposition == Disposition::OpenedExisting {
        // Never take ownership of or reset an existing principal's settings.
        return Ok(());
    }
    let sd = sddl::parse(&format!(
        "O:{user}G:{user}D:P(A;CI;KA;;;{user})(A;CI;KA;;;SY)(A;CI;KA;;;BA)"
    ))
    .map_err(|e| format!("descriptor: {e:?}"))?;
    key.set_security(
        SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
        &sd,
        Some(&tx),
    )
    .map_err(|e| e.to_string())?;
    // Creation and the private descriptor become visible together.
    tx.commit().map_err(|e| e.to_string())
}
