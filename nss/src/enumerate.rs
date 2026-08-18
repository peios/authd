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
use crate::client::Client;
use crate::{NssStatus, out_of_room, render};

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

/// The next record, fetching a page when the held one runs out.
fn next(slot: &Mutex<Option<Walk>>, kind: Kind, fields: Fields) -> Option<Record> {
    let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
    let walk = held.as_mut()?;

    loop {
        if let Some(record) = walk.page.pop() {
            return Some(record);
        }
        if walk.done {
            return None;
        }
        let page = walk.client.enumerate(kind, fields, &walk.cursor)?;
        // Reversed once, so `pop` hands them back in the order they arrived.
        walk.page = page.entries;
        walk.page.reverse();
        walk.cursor = page.next;
        // An empty cursor is the end. An empty *page* is not: the authority may
        // return one while working through a source with nothing to contribute,
        // and stopping there would truncate the walk without saying so.
        walk.done = walk.cursor.is_empty();
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
    let Some(record) = next(&PASSWD, Kind::Principal, Fields::PASSWD) else {
        return NssStatus::NotFound;
    };
    let mut packer = unsafe { Packer::new(buf, buflen) };
    match render::passwd(&record, &mut packer) {
        Some(entry) => {
            unsafe { result.write(entry) };
            NssStatus::Success
        }
        // The record is gone, and glibc will call again with a larger buffer and
        // get the *next* one. Putting it back would need a push-front the page
        // does not have, and the cost of not doing so is one skipped entry in a
        // case that means the caller's buffer is smaller than one record.
        None => unsafe { out_of_room(errnop) },
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
    let Some(record) = next(&GROUP, Kind::Group, Fields::GROUP) else {
        return NssStatus::NotFound;
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

/// # Safety
///
/// Called by glibc with no arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _nss_peios_endgrent() -> NssStatus {
    end(&GROUP)
}
