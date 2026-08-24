//! `setpwent` / `getpwent` / `endpwent`, and the same three for groups.
//!
//! An enumeration is the one place this module holds state, because the libc
//! interface makes it a session: `setpwent` opens, `getpwent` steps, `endpwent`
//! closes. So a connection and a cursor live for the length of one, where every
//! other entry point connects, asks, and lets go.
//!
//! # Pages, not entries
//!
//! The authority answers a page at a time and `getpwent` hands back one entry at
//! a time, so a page is held and drained before the next is asked for. That is
//! also the only place batching pays in this design: a synchronous caller
//! stepping one record at a time can never fill a batch, but an enumeration
//! knows in advance that it wants everything.
//!
//! # Why the state is global
//!
//! Because the libc interface is. There is one `getpwent` cursor per process,
//! and glibc serialises calls to it, so a mutex here is a formality that keeps
//! the compiler happy rather than a design decision. A caller that wants
//! independent walks has to use something else, and every Unix has always said
//! so.
//!
//! An empty page is **not** the end. Only an empty cursor is — the authority may
//! legitimately return nothing while working through a source that had nothing
//! to contribute, and a caller that stopped early would silently see a short
//! `getent passwd`.

use core::ffi::{c_char, c_int};
use std::sync::Mutex;

use libauthd::ident::{Fields, Kind, Record};

use crate::buffer::Packer;
use crate::client::{Client, Paged};
use crate::{NssStatus, out_of_room, render, try_again};

/// One walk in progress.
struct Walk {
    client: Client,
    /// The page currently being handed out, newest last so `pop` is the front.
    page: Vec<Record>,
    cursor: Vec<u8>,
    /// Whether the authority has said there is no more.
    done: bool,
}

static PASSWD: Mutex<Option<Walk>> = Mutex::new(None);
static GROUP: Mutex<Option<Walk>> = Mutex::new(None);

fn begin(slot: &Mutex<Option<Walk>>) -> NssStatus {
    let Ok(client) = Client::open() else {
        return NssStatus::Unavail;
    };
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    *held = Some(Walk {
        client,
        page: Vec::new(),
        cursor: Vec::new(),
        done: false,
    });
    NssStatus::Success
}

fn end(slot: &Mutex<Option<Walk>>) -> NssStatus {
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    // Dropping the walk closes the connection, which is what tells the authority
    // it may stop holding whatever the cursor referred to.
    *held = None;
    NssStatus::Success
}

/// What a step of the walk produced.
///
/// `Exhausted` is the *only* variant that means the enumeration is over, and it
/// is reachable only when the authority returned an empty cursor. Everything
/// else is a failure the caller must report as one — obligation 26 forbids
/// presenting a walk abandoned for any other reason as a complete one.
enum Step {
    Record(Box<Record>),
    /// The cursor came back empty: this really is the end.
    Exhausted,
    /// Something that could have answered did not.
    TryAgain,
    /// The authority cannot be reached.
    Unavailable,
}

/// The next record, fetching a page when the held one runs out.
fn next(slot: &Mutex<Option<Walk>>, kind: Kind, fields: Fields) -> Step {
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    let Some(walk) = held.as_mut() else {
        // No walk is open, which is the caller's error rather than an absence.
        return Step::Unavailable;
    };

    loop {
        if let Some(record) = walk.page.pop() {
            return Step::Record(Box::new(record));
        }
        if walk.done {
            return Step::Exhausted;
        }
        match walk.client.enumerate(kind, fields, &walk.cursor) {
            Paged::Page(page) => {
                // Obligation 25: a client displaying an enumeration says when
                // it is partial, and MUST NOT discard the list without doing
                // so. The NSS interface has nowhere to put it, so syslog is
                // where it goes — an administrator reading an account listing
                // otherwise cannot tell a machine with four principals from one
                // whose directory did not answer.
                report_incomplete(&page.incomplete);
                // Reversed once, so `pop` hands them back in arrival order.
                walk.page = page.entries;
                walk.page.reverse();
                walk.cursor = page.next;
                // An empty cursor is the end. An empty *page* is not: the
                // authority may return one while working through a source with
                // nothing to contribute, and stopping there would truncate the
                // walk without saying so.
                walk.done = walk.cursor.is_empty();
            }
            Paged::TryAgain => return Step::TryAgain,
            Paged::Unavailable => return Step::Unavailable,
        }
    }
}

/// Put a record back at the front of the page, so a retry re-renders it.
///
/// `getpwent_r` pops before rendering, so a buffer too small for the record
/// lost it: glibc retries with a larger buffer and gets the *next* one, and the
/// entry that triggered the resize vanishes from the enumeration with nothing
/// recording it. That is the same failure mode as a silently truncated walk,
/// one row at a time.
fn put_back(slot: &Mutex<Option<Walk>>, record: Record) {
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(walk) = held.as_mut() {
        walk.page.push(record);
    }
}

/// Name the sources that did not contribute.
///
/// syslog rather than stderr: this code runs inside whatever process called
/// `getent`, and writing to its stderr would corrupt the output of anything
/// that parses it. The NSS interface has nowhere structured to put this, which
/// is the real obstacle — but a syslog line is better than discarding the one
/// field that exists to say an enumeration is partial.
fn report_incomplete(incomplete: &[String]) {
    if incomplete.is_empty() {
        return;
    }
    let message = format!(
        "nss_peios: enumeration is partial; these sources did not contribute: {}",
        incomplete.join(", ")
    );
    let Ok(message) = std::ffi::CString::new(message) else {
        return;
    };
    // SAFETY: syslog is variadic; the format string is a literal "%s" and the
    // one argument is a valid NUL-terminated pointer that outlives the call.
    unsafe {
        libc::syslog(libc::LOG_WARNING, c"%s".as_ptr(), message.as_ptr());
    }
}

// ---------------------------------------------------------------------------
// passwd
// ---------------------------------------------------------------------------

/// # Safety
///
/// Called by glibc with no arguments; nothing is dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_setpwent(_stayopen: c_int) -> NssStatus {
    begin(&PASSWD)
}

/// # Safety
///
/// glibc's `getpwent_r` contract: `result` and `errnop` are writable and `buf`
/// has `buflen` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getpwent_r(
    result: *mut libc::passwd,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let record = match next(&PASSWD, Kind::Principal, Fields::PASSWD) {
        Step::Record(record) => *record,
        // Only an empty cursor reaches here, so NotFound really is the end.
        Step::Exhausted => return NssStatus::NotFound,
        Step::TryAgain => return unsafe { try_again(errnop) },
        Step::Unavailable => return NssStatus::Unavail,
    };
    let mut packer = unsafe { Packer::new(buf, buflen) };
    match render::passwd(&record, &mut packer) {
        Some(entry) => {
            unsafe { result.write(entry) };
            NssStatus::Success
        }
        None => {
            // Put it back before asking for a bigger buffer, so glibc's retry
            // re-renders this record rather than skipping to the next.
            put_back(&PASSWD, record);
            unsafe { out_of_room(errnop) }
        }
    }
}

/// # Safety
///
/// Called by glibc with no arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_endpwent() -> NssStatus {
    end(&PASSWD)
}

// ---------------------------------------------------------------------------
// group
// ---------------------------------------------------------------------------

/// # Safety
///
/// Called by glibc with no arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_setgrent(_stayopen: c_int) -> NssStatus {
    begin(&GROUP)
}

/// # Safety
///
/// glibc's `getgrent_r` contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_getgrent_r(
    result: *mut libc::group,
    buf: *mut c_char,
    buflen: libc::size_t,
    errnop: *mut c_int,
) -> NssStatus {
    let record = match next(&GROUP, Kind::Group, Fields::GROUP) {
        Step::Record(record) => *record,
        Step::Exhausted => return NssStatus::NotFound,
        Step::TryAgain => return unsafe { try_again(errnop) },
        Step::Unavailable => return NssStatus::Unavail,
    };
    let mut packer = unsafe { Packer::new(buf, buflen) };
    match render::group(&record, &mut packer) {
        Some(entry) => {
            unsafe { result.write(entry) };
            NssStatus::Success
        }
        None => {
            put_back(&GROUP, record);
            unsafe { out_of_room(errnop) }
        }
    }
}

/// # Safety
///
/// Called by glibc with no arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_endgrent() -> NssStatus {
    end(&GROUP)
}
