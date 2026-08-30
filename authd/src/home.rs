//! Creating a principal's home directory at logon.
//!
//! Nothing else on Peios does. `lpsd` records the path and says so
//! outright — *"lpsd only records the path; nothing here creates the
//! directory"* — and `login` treats a missing home as non-fatal and
//! starts the session in `/`. So before this existed, every account but
//! the seeded administrator logged in with nowhere to write.
//!
//! # Why the authority and not the client
//!
//! `login` cannot do it. It makes the user's token its own primary
//! token and only then chdirs, so by the time it touches the home
//! directory it is the unprivileged principal — and `/home` grants
//! Everyone traverse but not create, by design (fsbase's
//! `sd_overrides`). Its own comment reaches the same conclusion from
//! the other direction: creating the directory there *"would put
//! directory provisioning inside the one program that must keep working
//! when everything else is broken."*
//!
//! # Why no logon-type check
//!
//! The rule is "create `profile.home` if it is non-empty and absent",
//! and that self-scopes. A service identity is minted through
//! [`crate::attest`], which builds `Profile::default()` — *"a service
//! has no profile"* — so `home` is empty and nothing fires. Checking
//! the logon type as well would be machinery that never changes an
//! outcome.
//!
//! # Failure is never fatal to the logon
//!
//! Every path here reports and returns. A principal whose home could
//! not be created still gets a session, in `/`, exactly as it did
//! before — matching the posture `login` already takes. Being locked
//! out of a machine is a worse outcome than starting in the wrong
//! directory, and a home directory is not identity: it appears in no
//! ACL and decides no access.

use std::io;
use std::path::Path;

use peios::file::{self, SecInfo};
use peios::security::{SdView, SidRef, sddl};

use crate::log;

/// `AT_SYMLINK_NOFOLLOW` for `get_sd`'s `at_flags`.
///
/// A home directory that is really a symlink must be judged as the
/// symlink it is. Following it would read the descriptor of whatever it
/// points at, which is the attacker's choice rather than ours.
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Build the descriptor a new home directory gets.
///
/// Owner is the principal, so [CREATOR OWNER] rules elsewhere resolve to
/// it and so it may re-stamp its own directory. The DACL is protected
/// (`P`): without that, `/`'s inheritable Everyone read ACE merges in
/// and every home on the machine is world-readable, which is the whole
/// thing this exists to prevent.
///
/// Administrators is granted alongside SYSTEM. That is a real choice
/// rather than a reflex: the alternative is to grant neither and make an
/// administrator take ownership first, which leaves a visible trace in a
/// way that quietly reading a file does not. Windows grants it, every
/// backup and repair tool assumes it, and an administrator on Peios can
/// already take ownership at will — so withholding it would buy the
/// appearance of privacy rather than privacy, at the cost of breaking
/// every tool that walks the tree. If that trade is ever revisited, this
/// is the line to change.
fn home_sddl(user: &SidRef) -> String {
    format!(
        "O:{user}G:{user}D:P(A;OICI;GA;;;{user})(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"
    )
}

/// Ensure `home` exists for `user`, creating it if it does not.
///
/// `home` has already been held to the absolute-path rule by the caller;
/// an empty string means the authority has nothing to say and nothing
/// happens.
pub fn ensure(user: &SidRef, home: &str) {
    if home.is_empty() {
        return;
    }
    let path = Path::new(home);
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() {
                log::warn(format_args!(
                    "home {home} for {user} exists but is not a directory; leaving it alone"
                ));
                return;
            }
            check_existing(user, home, path);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create(user, home, path),
        Err(error) => log::warn(format_args!(
            "could not inspect home {home} for {user}: {error}"
        )),
    }
}

/// An existing home directory is never re-stamped, and one owned by
/// somebody else is reported rather than adopted.
///
/// Adopting it would be a privilege-escalation shape: point an account's
/// `home` at a directory belonging to another principal and the
/// authority hands it over at the next logon. Re-stamping even a
/// correctly-owned one would be its own hazard — an administrator who
/// deliberately widened a home directory would find it silently narrowed
/// again on every login.
fn check_existing(user: &SidRef, home: &str, path: &Path) {
    let Ok(blob) = file::get_sd(None, path, SecInfo::OWNER, AT_SYMLINK_NOFOLLOW) else {
        // No descriptor readable: an unmanaged filesystem, or a kernel
        // without the KACS SD syscalls. Nothing to check and nothing to
        // do; the directory exists, which is what was asked.
        return;
    };
    let Ok(sd) = SdView::parse(blob.as_bytes()) else {
        log::warn(format_args!("home {home} for {user} has an unreadable descriptor"));
        return;
    };
    match sd.owner() {
        Some(owner) if owner == user => {}
        Some(owner) => log::warn(format_args!(
            "home {home} for {user} already exists and is owned by {owner}; \
             leaving it alone — the session will start there without owning it"
        )),
        None => log::warn(format_args!(
            "home {home} for {user} already exists with no owner in its descriptor"
        )),
    }
}

/// Create the directory and stamp it.
///
/// Only the leaf: `create_dir`, not `create_dir_all`. A principal source
/// asserts the path, and minting a tree of directories on its say-so
/// turns a typo into structure that outlives the mistake. A missing
/// parent is reported instead, which is a much easier thing to diagnose
/// than an unexpected `/hoem` appearing at the root.
///
/// Between the `create_dir` and the `set_sd` the directory carries what
/// it inherited from `/home`, which is SYSTEM and Administrators and
/// nothing else — fsbase's Everyone ACE there is not inheritable. So the
/// window is closed rather than open: the failure mode of interrupting
/// this is a directory its owner cannot enter, not one anybody can read.
fn create(user: &SidRef, home: &str, path: &Path) {
    if let Err(error) = std::fs::create_dir(path) {
        log::warn(format_args!(
            "could not create home {home} for {user}: {error}"
        ));
        return;
    }
    let text = home_sddl(user);
    let sd = match sddl::parse(&text) {
        Ok(sd) => sd,
        Err(error) => {
            log::error(format_args!(
                "could not build a descriptor for home {home} of {user}: {error:?}"
            ));
            return;
        }
    };
    let info = SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL;
    if let Err(error) = file::set_sd(None, path, info, &sd, AT_SYMLINK_NOFOLLOW) {
        // The directory is left in place: it inherited SYSTEM and
        // Administrators, so an administrator can finish the job with
        // `sd`. Removing it would destroy nothing today but would race
        // anything that had already looked.
        log::error(format_args!(
            "created home {home} for {user} but could not stamp its descriptor: {error}; \
             it is unusable by its owner until an administrator sets one"
        ));
        return;
    }
    log::info(format_args!("created home {home} for {user}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> peios::security::Sid {
        text.parse().expect("a valid SID")
    }

    #[test]
    fn the_descriptor_names_the_principal_as_owner_and_protects_the_dacl() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let text = home_sddl(user.as_ref());
        assert!(
            text.starts_with("O:S-1-5-21-1-2-3-1000G:S-1-5-21-1-2-3-1000"),
            "the principal must own its own home: {text}"
        );
        assert!(
            text.contains("D:P("),
            "the DACL must be protected or / leaks Everyone read into it: {text}"
        );
        assert!(
            text.contains("(A;OICI;GA;;;S-1-5-21-1-2-3-1000)"),
            "the principal must have full control of its own home: {text}"
        );
    }

    #[test]
    fn the_descriptor_parses() {
        let user = sid("S-1-5-21-1-2-3-1000");
        sddl::parse(&home_sddl(user.as_ref())).expect("home descriptor must be valid SDDL");
    }

    #[test]
    fn an_empty_home_does_nothing() {
        // The service case: attest builds Profile::default(), so `home`
        // is empty and no service identity grows a directory. Reaching
        // the filesystem at all here would be the bug.
        let user = sid("S-1-5-80-0");
        ensure(user.as_ref(), "");
    }
}
