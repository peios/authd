//! **libnss_peios.so.2** — how a POSIX program comes to see a Peios principal.
//!
//! A Linux program calls `getpwuid` and has never heard of a token. This object
//! is what stands between that call and the authority: it forwards the question
//! to `/run/ident.sock` and renders the answer as a `struct passwd`.
//!
//! # A shim, not a design
//!
//! The protocol is in Peios' terms — SIDs, canonical names, claims — and this
//! flattens it into POSIX's. The flattening is one-directional and lossy on
//! purpose: `gr_mem` cannot express a group whose membership is a rule, a
//! `struct passwd` has nowhere to put a claim, and a `uid_t` cannot say which
//! domain it came from. None of that is a defect in the protocol; it is what
//! `passwd` is.
//!
//! The rule the shim holds itself to is **one round trip per libc call**. A
//! `getpwuid` asks for the six fields it needs in one request; a `getgrnam`
//! asks for members with their names already resolved, so filling `gr_mem` costs
//! nothing further; `initgroups` asks the principal, which is the direction
//! sources actually hold. Anything that needed a second request would be a
//! missing field in the protocol rather than a job for this file.
//!
//! # What the return values mean
//!
//! Three of the five statuses carry weight, and confusing two of them is the
//! bug this module most has to avoid:
//!
//! - **`NotFound`** — the authority asked everything that could have answered,
//!   and there is no such principal. Safe to remember.
//! - **`TryAgain`** — something that could have answered did not. **Not** an
//!   absence. glibc's caller retries; a caller that recorded this as `NotFound`
//!   would remember an outage as a fact, and keep reporting it after the outage
//!   ended.
//! - **`Unavail`** — the authority is not there, or would not say. There is
//!   nothing behind this module, so nothing resolves. That is the correct
//!   answer before the authority is running rather than a gap: identity comes
//!   from the authority, and until it exists there is none to have.
//!
//! # Not one option among several
//!
//! Peios' glibc is patched so the identity databases are not configurable and
//! reach this module and nothing else. There is no `nsswitch.conf` line behind
//! it and no `files` under it, because there is no `/etc/passwd` — uid 0 is a
//! projection of the SYSTEM token rather than an account, and nothing resolves a
//! name in order to find it.
//!
//! That is not tidiness. A second search order the authority cannot see is a
//! second answer to *who is `jack`*, and a program acting for one principal
//! while its access is checked against another is the bug the whole resolution
//! design exists to prevent. Adding a source of identity here means writing a
//! principal source — a process the authority confines — not an object injected
//! into every address space on the system.
//!
//! # Names are forwarded, never parsed
//!
//! `getpwnam` hands over whatever string it was given, unchanged. Which source
//! owns a bare name, and what a qualified one will mean when realms exist, are
//! the authority's to decide — because a machine where two components resolve
//! names differently is one where a program can act for one principal while its
//! access is checked against another.

#![deny(unsafe_op_in_unsafe_fn)]

mod buffer;
mod client;
mod render;

use core::ffi::{c_char, c_int, c_long};

use libauthd::ident::{Fields, Kind, Key};

use crate::buffer::Packer;
use crate::client::{Client, Found};

/// glibc's `enum nss_status`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    TryAgain = -2,
    Unavail = -1,
    NotFound = 0,
    Success = 1,
}

/// Translate a lookup outcome, setting `errno` where the contract requires it.
///
/// # Safety
///
/// `errnop` must be a valid pointer, as glibc always provides.
unsafe fn status_of(found: &Found, errnop: *mut c_int) -> NssStatus {
    match found {
        Found::Record(_) => NssStatus::Success,
        Found::NotFound => NssStatus::NotFound,
        Found::TryAgain => {
            // `EAGAIN` rather than `ERANGE`: the distinction tells glibc to
            // retry the *call*, where `ERANGE` would have it retry with a
            // larger buffer and get the same answer forever.
            unsafe { errnop.write(libc::EAGAIN) };
            NssStatus::TryAgain
        }
        Found::Unavailable => NssStatus::Unavail,
    }
}

/// The buffer was too small. glibc calls again with a larger one.
///
/// # Safety
///
/// `errnop` must be a valid pointer.
unsafe fn out_of_room(errnop: *mut c_int) -> NssStatus {
    unsafe { errnop.write(libc::ERANGE) };
    NssStatus::TryAgain
}

/// Borrow a C string as UTF-8, or refuse.
///
/// # Safety
///
/// `pointer` must be NUL-terminated or null.
unsafe fn borrow<'a>(pointer: *const c_char) -> Option<&'a str> {
    if pointer.is_null() {
        return None;
    }
    unsafe { core::ffi::CStr::from_ptr(pointer) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// passwd
// ---------------------------------------------------------------------------

/// # Safety
///
/// glibc's `getpwnam_r` contract: `name` is NUL-terminated, `result` and
/// `errnop` are writable, and `buf` has `buflen` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getpwnam_r(
    name: *const c_char,
    result: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let Some(name) = (unsafe { borrow(name) }) else {
        return NssStatus::NotFound;
    };
    // Forwarded verbatim. Which source owns `jack` is the authority's answer,
    // not this module's — see the module docs.
    unsafe { passwd_lookup(Key::Name(name.to_string()), result, buf, buflen, errnop) }
}

/// # Safety
///
/// As [`_nss_peios_getpwnam_r`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getpwuid_r(
    uid: libc::uid_t,
    result: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { passwd_lookup(Key::UnixId(uid), result, buf, buflen, errnop) }
}

/// # Safety
///
/// As [`_nss_peios_getpwnam_r`].
unsafe fn passwd_lookup(
    key: Key,
    result: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let Ok(mut client) = Client::open() else {
        return NssStatus::Unavail;
    };
    let found = client.lookup(key, Kind::Principal, Fields::PASSWD);
    let status = unsafe { status_of(&found, errnop) };
    let Found::Record(record) = found else {
        return status;
    };

    let mut packer = unsafe { Packer::new(buf, buflen) };
    match render::passwd(&record, &mut packer) {
        Some(entry) => {
            unsafe { result.write(entry) };
            NssStatus::Success
        }
        None => unsafe { out_of_room(errnop) },
    }
}

// ---------------------------------------------------------------------------
// group
// ---------------------------------------------------------------------------

/// # Safety
///
/// glibc's `getgrnam_r` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getgrnam_r(
    name: *const c_char,
    result: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let Some(name) = (unsafe { borrow(name) }) else {
        return NssStatus::NotFound;
    };
    unsafe { group_lookup(Key::Name(name.to_string()), result, buf, buflen, errnop) }
}

/// # Safety
///
/// As [`_nss_peios_getgrnam_r`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getgrgid_r(
    gid: libc::gid_t,
    result: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    unsafe { group_lookup(Key::UnixId(gid), result, buf, buflen, errnop) }
}

/// # Safety
///
/// As [`_nss_peios_getgrnam_r`].
unsafe fn group_lookup(
    key: Key,
    result: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let Ok(mut client) = Client::open() else {
        return NssStatus::Unavail;
    };
    // Members *with their names*, in one request. A reply of bare SIDs would
    // turn one `getgrnam` into one call per member.
    let found = client.lookup(key, Kind::Group, Fields::GROUP);
    let status = unsafe { status_of(&found, errnop) };
    let Found::Record(record) = found else {
        return status;
    };

    let mut packer = unsafe { Packer::new(buf, buflen) };
    match render::group(&record, &mut packer) {
        Some(entry) => {
            unsafe { result.write(entry) };
            NssStatus::Success
        }
        None => unsafe { out_of_room(errnop) },
    }
}

// ---------------------------------------------------------------------------
// initgroups
// ---------------------------------------------------------------------------

/// Which groups a principal is in.
///
/// The direction sources actually hold, and the reason `gr_mem` never has to be
/// walked to answer it: glibc has this dedicated entry point precisely so that
/// "what groups is this user in" need not go through "who is in this group".
///
/// # Safety
///
/// glibc's `initgroups_dyn` contract: `start`, `size` and `groupsp` are
/// writable, and `*groupsp` points to `*size` `gid_t`s allocated with `malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_initgroups_dyn(
    user: *const c_char,
    group: libc::gid_t,
    start: *mut c_long,
    size: *mut c_long,
    groupsp: *mut *mut libc::gid_t,
    limit: c_long,
    errnop: *mut c_int,
) -> NssStatus {
    let Some(user) = (unsafe { borrow(user) }) else {
        return NssStatus::NotFound;
    };
    let Ok(mut client) = Client::open() else {
        return NssStatus::Unavail;
    };

    let found = client.lookup(
        Key::Name(user.to_string()),
        Kind::Principal,
        Fields::GROUPS | Fields::PRIMARY_GROUP,
    );
    let status = unsafe { status_of(&found, errnop) };
    let Found::Record(record) = found else {
        return status;
    };

    for gid in render::gids(&record) {
        // The caller has already placed the principal's primary group. Adding it
        // again would be harmless but untidy, and some callers count.
        if gid == group {
            continue;
        }
        match unsafe { push_gid(gid, start, size, groupsp, limit) } {
            Ok(()) => {}
            Err(status) => {
                if status == NssStatus::TryAgain {
                    unsafe { errnop.write(libc::ENOMEM) };
                }
                return status;
            }
        }
    }
    NssStatus::Success
}

/// Append one gid, growing the caller's array if it will take it.
///
/// # Safety
///
/// As [`_nss_peios_initgroups_dyn`].
unsafe fn push_gid(
    gid: libc::gid_t,
    start: *mut c_long,
    size: *mut c_long,
    groupsp: *mut *mut libc::gid_t,
    limit: c_long,
) -> Result<(), NssStatus> {
    let used = unsafe { start.read() };
    let capacity = unsafe { size.read() };
    let groups = unsafe { groupsp.read() };

    // Already present. glibc's own modules do this, and the alternative is a
    // supplementary list with duplicates in it.
    for index in 0..used {
        if unsafe { groups.offset(index as isize).read() } == gid {
            return Ok(());
        }
    }

    if used >= capacity {
        // The caller's ceiling, not ours. Stopping here is success with fewer
        // groups, which is what every other module does — failing would deny a
        // logon over a membership the principal may not even need.
        if limit > 0 && used >= limit {
            return Ok(());
        }
        let wanted = if limit > 0 {
            capacity.saturating_mul(2).min(limit)
        } else {
            capacity.saturating_mul(2)
        };
        let Ok(bytes) = usize::try_from(wanted).map(|n| n * size_of::<libc::gid_t>()) else {
            return Err(NssStatus::TryAgain);
        };
        // SAFETY: `*groupsp` came from `malloc`, which is what the contract says
        // and what makes `realloc` on it defined.
        let grown = unsafe { libc::realloc(groups as *mut libc::c_void, bytes) };
        if grown.is_null() {
            return Err(NssStatus::TryAgain);
        }
        unsafe {
            groupsp.write(grown as *mut libc::gid_t);
            size.write(wanted);
        }
    }

    unsafe {
        groupsp.read().offset(used as isize).write(gid);
        start.write(used + 1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

mod enumerate;

pub use enumerate::{
    _nss_peios_endgrent, _nss_peios_endpwent, _nss_peios_getgrent_r, _nss_peios_getpwent_r,
    _nss_peios_setgrent, _nss_peios_setpwent,
};
