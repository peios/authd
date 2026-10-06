//! Ending a logon session on request — PGSS Logon §2.22.
//!
//! The kernel has no call that ends a session: a session lasts as long as a
//! token of it does (Kernel TRM §3.2.7). Signing somebody out is therefore
//! ending the processes that run in their session, after which the kernel
//! destroys it when the last reference drops. That is what this does, and all
//! it does.
//!
//! # Why the authority, and not the program that asks
//!
//! A process in the session may be protected, or carry a descriptor that does
//! not grant an administrator `PROCESS_TERMINATE`, so a window doing the walk
//! itself could stop halfway and leave half a session. authd is SYSTEM at
//! PeiosTcb and can finish the job. And one place deciding who may sign whom
//! out means one policy and one record of it, whichever program asked.
//!
//! # Not a process factory
//!
//! PGSS §2.1 forbids an authority to start anything. Ending a session starts
//! nothing: it signals processes that already exist, and only those whose
//! **primary** token belongs to the session. A thread impersonating a token of
//! the session for one request — a service answering the user — is not in the
//! session and is never signalled.
//!
//! # Who may
//!
//! See [`decide`]. In short: never SYSTEM's or Anonymous's session or a
//! service's; your own session if you are a person signed in as yourself; and
//! anybody else's if the descriptor at `SessionEndSecurity` grants you
//! [`SESSION_END`] — SYSTEM and Administrators by default.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use libauthd::transport::send_message;
use libauthd::wire::{
    Denial, LogonTypes, SessionEndAllowed, SessionEnded, encode_session_end_allowed,
    encode_session_ended,
};
use libauthd_policy::SESSION_END;
use peios::access::{AccessCheck, AuditContext};
use peios::security::{AccessMask, GenericMapping, Sid, SidRef};
use peios::token::{Token, TokenAccess};

use crate::audit;
use crate::conversation::deny;
use crate::log;

/// The `object.kind` of the access check against `SessionEndSecurity`: the
/// right to end other principals' sessions, which is authd's alone to guard.
/// Named for authd, as eventd's `eventd-admin` and peinit's `peinit-system`
/// are, because `SESSION_END` is authd's mask and decodes against nothing
/// else; a bare `session` would read as the kernel's session object.
const AUDIT_KIND: &str = "authd-session-end";

/// How long a process is given to exit after `SIGTERM`, before `SIGKILL`.
///
/// A shell saving its history or an editor writing a swap file needs a moment;
/// a person waiting at Task Manager should not wait long. The wait ends early
/// once everything signalled has exited.
pub(crate) const GRACE: Duration = Duration::from_secs(5);

/// How long a process is given to die after `SIGKILL`, before the next walk
/// looks again. `SIGKILL` cannot be caught, so this is only the time the
/// kernel takes.
pub(crate) const KILL_WAIT: Duration = Duration::from_secs(1);

/// How many times the session is walked and its processes signalled.
///
/// More than one because a process can fork during the grace period, and the
/// child holds the session too. Bounded because a session whose processes keep
/// appearing faster than they are ended must not hold a conversation forever;
/// what survives is reported as `remaining`.
pub(crate) const MAX_ROUNDS: u32 = 3;

/// The longest the rounds can take, which the reply waits for. Held to the
/// conversation's own bound by a test.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const ROUNDS_BOUND: Duration =
    Duration::from_secs((GRACE.as_secs() + KILL_WAIT.as_secs()) * MAX_ROUNDS as u64);

/// The kernel's list of live sessions (Kernel TRM §3.2.7).
const SESSIONS: &str = "/sys/kernel/security/kacs/sessions";

/// SYSTEM's session, created by the kernel at boot.
const SYSTEM_SESSION: u64 = 999;
/// Anonymous's session, created by the kernel at boot.
const ANONYMOUS_SESSION: u64 = 998;

/// A logon type's value, as the kernel lists it.
const SERVICE_LOGON: u32 = 5;

/// What a request asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request {
    /// `SessionEnd`: end it.
    End,
    /// `SessionEndQuery`: would ending it be permitted? Changes nothing.
    Query,
}

/// One live session, as the kernel lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Listed {
    pub id: u64,
    pub user: Sid,
    pub logon_type: u32,
}

/// Every session in the kernel's listing. A line that does not read is
/// skipped, and a field this build does not know is ignored, as the TRM
/// requires of a consumer.
pub(crate) fn parse_sessions(text: &str) -> Vec<Listed> {
    text.lines()
        .filter_map(|line| {
            let mut id = None;
            let mut user = None;
            let mut logon_type = None;
            for field in line.split_whitespace() {
                let Some((key, value)) = field.split_once('=') else {
                    continue;
                };
                match key {
                    "logon_session_id" => id = value.parse::<u64>().ok(),
                    "user_sid" => {
                        user = unhex(value)
                            .as_deref()
                            .and_then(SidRef::from_bytes)
                            .map(SidRef::to_sid);
                    }
                    "logon_type" => logon_type = value.parse::<u32>().ok(),
                    _ => {}
                }
            }
            Some(Listed {
                id: id?,
                user: user?,
                logon_type: logon_type?,
            })
        })
        .collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Whether a logon type is one a person signs in with: every type the
/// authority's own default permits a principal, which is every type but
/// `Service` (§2.16).
fn is_person_logon(logon_type: u32) -> bool {
    logon_type < 32 && LogonTypes::DEFAULT.bits() & (1 << logon_type) != 0
}

/// Whether `caller` may end `target` as their own session, needing no grant.
///
/// The session's user must be the caller, signed in by a logon type a person
/// has, as an account of an issued domain. A service account signed in as a
/// service, or a well-known identity, is not "a person signing themselves
/// out", whatever its user SID.
fn is_own(caller: &SidRef, target: &Listed) -> bool {
    target.user.as_ref() == caller
        && is_person_logon(target.logon_type)
        && crate::domain::is_issued_principal(caller)
}

/// Sessions nobody may end here: the kernel's two, which every process on the
/// machine depends on, and every service's, which is stopped through the
/// service manager rather than signed out.
fn is_protected(target: &Listed) -> bool {
    target.id == SYSTEM_SESSION
        || target.id == ANONYMOUS_SESSION
        || target.logon_type == SERVICE_LOGON
}

/// Whether `caller` may end the session `target` names — `None` where the
/// kernel lists no such session.
///
/// `may_end_others` is the access check against the configured descriptor,
/// run only when the answer depends on it.
///
/// A caller who may not end other principals' sessions is told
/// `PermissionDenied` for a session that does not exist, as for one that does:
/// the kernel lets only SYSTEM and Administrators list sessions, and this must
/// not become a way for anybody else to.
pub(crate) fn decide(
    caller: &SidRef,
    target: Option<&Listed>,
    may_end_others: impl FnOnce() -> bool,
) -> Result<(), Denial> {
    if let Some(target) = target {
        if is_protected(target) {
            return Err(Denial::PermissionDenied);
        }
        if is_own(caller, target) {
            return Ok(());
        }
    }
    if !may_end_others() {
        return Err(Denial::PermissionDenied);
    }
    match target {
        Some(_) => Ok(()),
        None => Err(Denial::NoSuchSession),
    }
}

/// The access check against `SessionEndSecurity`, for [`SESSION_END`], with
/// the caller's own token.
///
/// Fails closed: a descriptor that cannot be used, or a check that cannot be
/// run, grants nothing.
///
/// The check names what it guarded with an audit context of kind
/// [`AUDIT_KIND`], so that when the descriptor's SACL asks for it KACS records
/// the decision — a refusal above all — as `kacs.audit.access.checked` with
/// `object.kind` `authd-session-end` (PGSS §6.7). authd writes no denial event
/// of its own: access decisions are KACS's to record.
fn may_end_others(token: &Token) -> bool {
    let Some(sd) = crate::policy::session_end_descriptor() else {
        return false;
    };
    // One right, so every generic right means it.
    let mapping = GenericMapping::new(SESSION_END, SESSION_END, SESSION_END, SESSION_END);
    let context = match AuditContext::new(AUDIT_KIND, &[]) {
        Ok(context) => Some(context),
        Err(error) => {
            // A constant kind cannot fail to encode; if it somehow does, the
            // decision still stands and only its record goes unnamed.
            log::error(format_args!(
                "could not build the session-end audit context: {error}"
            ));
            None
        }
    };
    let mut check = AccessCheck::new(&sd, AccessMask::from_bits_retain(SESSION_END), mapping);
    check.token(token.as_fd());
    if let Some(context) = &context {
        check.audit_context(context);
    }
    match check.check() {
        Ok(decision) => decision.allowed,
        Err(error) => {
            log::error(format_args!(
                "could not check who may end sessions: {error}; refusing"
            ));
            false
        }
    }
}

/// Serve a `SessionEnd` or `SessionEndQuery` for `logon_session_id`, start to
/// terminal. `peer` is the verified user of the connected peer's token.
pub(crate) fn serve(
    stream: &UnixStream,
    peer: &Sid,
    logon_session_id: u64,
    request: Request,
) -> io::Result<()> {
    // The caller's token, for the access check and to learn which session the
    // caller is in. `peer::identity` has already refused a restricted one.
    let token = match Token::open_peer(stream.as_fd()) {
        Ok(token) => token,
        Err(error) => {
            log::warn(format_args!("could not open the peer's token: {error}"));
            return deny(
                stream,
                Denial::PermissionDenied,
                "Caller identity could not be established.",
            );
        }
    };

    let listing = match fs::read_to_string(SESSIONS) {
        Ok(text) => text,
        Err(error) => {
            log::error(format_args!("could not read {SESSIONS}: {error}"));
            return deny(
                stream,
                Denial::Internal,
                "The authority could not read the sessions.",
            );
        }
    };
    let sessions = parse_sessions(&listing);
    let target = sessions.iter().find(|listed| listed.id == logon_session_id);

    if let Err(denial) = decide(peer.as_ref(), target, || may_end_others(&token)) {
        if request == Request::End {
            log::warn(format_args!(
                "refused to end session {logon_session_id} for {peer}: {denial:?}"
            ));
        }
        let reason = match denial {
            Denial::NoSuchSession => "There is no such session.",
            _ => "You may not end that session.",
        };
        return deny(stream, denial, reason);
    }
    // `decide` admits no absent session.
    let Some(target) = target.cloned() else {
        return deny(
            stream,
            Denial::Internal,
            "The authority could not end the session.",
        );
    };

    if request == Request::Query {
        let message = encode_session_end_allowed(&SessionEndAllowed)
            .map_err(|_| io::Error::other("could not encode SessionEndAllowed"))?;
        return send_message(stream, &message);
    }

    let own_connection = token.auth_id().is_ok_and(|id| id.0 == logon_session_id);
    // Every token authd holds is a reference to its session. The caller's must
    // not be one of the things keeping it alive.
    drop(token);

    log::info(format_args!(
        "ending session {} (user={} type={}) at the request of {peer}",
        target.id, target.user, target.logon_type
    ));

    let mut live = Live::new();
    if own_connection {
        // The caller is in the session being ended, and will be gone before
        // there is anything to report. So the answer goes first, saying what
        // was found, and then the work is done.
        let found = live.holding(logon_session_id);
        let message = encode_session_ended(&SessionEnded {
            ended: u32::try_from(found.found.len()).unwrap_or(u32::MAX),
            remaining: 0,
        })
        .map_err(|_| io::Error::other("could not encode SessionEnded"))?;
        if let Err(error) = send_message(stream, &message) {
            // Nothing to tell them, and the request stands: they asked.
            log::warn(format_args!(
                "could not answer {peer} before ending its own session: {error}"
            ));
        }
        // The terminal has been sent, so nothing more is said here (§2.3).
        // The socket itself closes when the conversation returns; until then
        // it holds the caller's identity, and with it the session.
        let _ = stream.shutdown(std::net::Shutdown::Both);
        let outcome = end(&mut live, logon_session_id, found);
        log_outcome(peer, &target, &outcome);
        Ok(())
    } else {
        let first = live.holding(logon_session_id);
        let outcome = end(&mut live, logon_session_id, first);
        // Recorded before it is sent: the work is done whether or not the
        // caller is still there to hear about it.
        log_outcome(peer, &target, &outcome);
        let message = encode_session_ended(&outcome)
            .map_err(|_| io::Error::other("could not encode SessionEnded"))?;
        send_message(stream, &message)
    }
}

fn log_outcome(peer: &Sid, target: &Listed, outcome: &SessionEnded) {
    log::info(format_args!(
        "ended session {} (user={}) at the request of {peer}: {} processes ended, {} remaining",
        target.id, target.user, outcome.ended, outcome.remaining
    ));
    audit::essential("authd.session.ended", &ended_record(peer, target, outcome));
}

/// `authd.session.ended`: who asked, whose session it was, and whether
/// anything was left holding it.
fn ended_record(peer: &Sid, target: &Listed, outcome: &SessionEnded) -> audit::Record {
    let mut record = audit::Record::new();
    record
        .sid("subject.token.sid", peer.as_ref())
        .uint("object.session.id", target.id)
        .sid("object.session.user.sid", target.user.as_ref());
    if let Some(name) = audit::logon_type_name(target.logon_type) {
        record.str("object.session.logon-type", name);
    }
    record.outcome((outcome.remaining != 0).then_some("processes-remaining"));
    record
}

// ---------------------------------------------------------------------------
// The rounds
// ---------------------------------------------------------------------------

/// A signal this sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    Term,
    Kill,
}

/// What one walk found.
pub(crate) struct Holders<H> {
    /// Every process whose primary token belongs to the session.
    pub found: Vec<H>,
    /// Processes that could not be examined: they may hold the session, and
    /// nothing can be done about them if they do.
    pub unexamined: u32,
}

/// The processes of the machine, as the rounds see them. [`Live`] is the real
/// thing; the tests stand in for it.
pub(crate) trait Processes {
    type Handle;

    /// Every process whose primary token belongs to `session`.
    fn holding(&mut self, session: u64) -> Holders<Self::Handle>;
    /// The process's id, to recognise it on a later walk.
    fn pid(&self, handle: &Self::Handle) -> i32;
    /// Send `signal`. False where it could not be sent.
    fn signal(&mut self, handle: &Self::Handle, signal: Signal) -> bool;
    /// Whether the process has exited.
    fn exited(&self, handle: &Self::Handle) -> bool;
    /// Wait until every one of `handles` has exited, or `limit` has passed.
    fn wait(&mut self, handles: &[Self::Handle], limit: Duration);
}

/// End every process holding `session`, starting from the walk `first`.
///
/// Each round sends `SIGTERM` to what the last walk found, waits up to
/// [`GRACE`], sends `SIGKILL` to whatever is left, waits up to [`KILL_WAIT`],
/// and walks again — a process forked during the grace holds the session too.
/// At most [`MAX_ROUNDS`] rounds.
///
/// `ended` counts the processes signalled that the final walk no longer finds.
/// `remaining` is what the final walk does find, plus what it could not
/// examine. A zombie is in `remaining` until its parent reaps it: the kernel
/// releases a process's token at reap, not at exit.
pub(crate) fn end<P: Processes>(
    processes: &mut P,
    session: u64,
    first: Holders<P::Handle>,
) -> SessionEnded {
    let mut signalled = BTreeSet::new();
    let mut last = first;
    for _ in 0..MAX_ROUNDS {
        if last.found.is_empty() {
            break;
        }
        for handle in &last.found {
            processes.signal(handle, Signal::Term);
            signalled.insert(processes.pid(handle));
        }
        processes.wait(&last.found, GRACE);

        let survivors: Vec<P::Handle> = last
            .found
            .into_iter()
            .filter(|handle| !processes.exited(handle))
            .collect();
        for handle in &survivors {
            processes.signal(handle, Signal::Kill);
        }
        processes.wait(&survivors, KILL_WAIT);
        drop(survivors);

        last = processes.holding(session);
    }

    let still: BTreeSet<i32> = last
        .found
        .iter()
        .map(|handle| processes.pid(handle))
        .collect();
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    SessionEnded {
        ended: count(signalled.difference(&still).count()),
        remaining: count(last.found.len()).saturating_add(last.unexamined),
    }
}

// ---------------------------------------------------------------------------
// The real processes
// ---------------------------------------------------------------------------

/// A process found holding the session, by pidfd: the signal reaches the
/// process whose token was read, whatever has happened to its pid since.
pub(crate) struct Held {
    pid: i32,
    pidfd: OwnedFd,
}

/// The machine's processes, walked through `/proc` and reached by pidfd.
pub(crate) struct Live {
    own: i32,
}

/// `PF_KTHREAD`, in `/proc/<pid>/stat`'s flags field.
const PF_KTHREAD: u64 = 0x0020_0000;

impl Live {
    fn new() -> Live {
        Live {
            own: std::process::id() as i32,
        }
    }

    /// One process, if it holds `session`. `Err` says why it could not be
    /// examined; `Ok(None)` is where it does not hold it, or is gone.
    fn examine(&self, pid: i32, session: u64) -> Result<Option<Held>, String> {
        let gone = |error: &io::Error| error.raw_os_error() == Some(libc::ESRCH);

        // The pidfd first: everything after it is about this process, and the
        // signal goes to this process, even if the pid is reused meanwhile.
        let pidfd = match pidfd_open(pid) {
            Ok(fd) => fd,
            Err(error) if gone(&error) => return Ok(None),
            Err(error) => return Err(format!("{pid}: pidfd_open: {error}")),
        };
        // A kernel thread has no token of anyone's, and is nobody's to end.
        if is_kernel_thread(pid) {
            return Ok(None);
        }
        // The PRIMARY token, never a thread's: a service impersonating the
        // user for one request is not in the user's session.
        let token = match Token::open_process(pidfd.as_fd(), TokenAccess::QUERY) {
            Ok(token) => token,
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
            Err(error) => return Err(format!("{pid}: opening its token: {error}")),
        };
        let held = token
            .auth_id()
            .map_err(|error| format!("{pid}: reading its token: {error}"))?;
        // Dropped here, before anything else: a token held is a reference to
        // the session this is trying to end.
        drop(token);
        Ok((held.0 == session).then_some(Held { pid, pidfd }))
    }
}

impl Processes for Live {
    type Handle = Held;

    fn holding(&mut self, session: u64) -> Holders<Held> {
        // How many unexaminable processes are named in the log, per walk.
        const MAX_REPORTED: usize = 8;
        let mut unexaminable = Vec::new();
        let mut holders = Holders {
            found: Vec::new(),
            unexamined: 0,
        };
        let Ok(entries) = fs::read_dir("/proc") else {
            log::error(format_args!("could not walk /proc"));
            holders.unexamined = 1;
            return holders;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            if pid == self.own {
                continue;
            }
            match self.examine(pid, session) {
                Ok(Some(held)) => holders.found.push(held),
                Ok(None) => {}
                Err(why) => {
                    holders.unexamined = holders.unexamined.saturating_add(1);
                    if unexaminable.len() < MAX_REPORTED {
                        unexaminable.push(why);
                    }
                }
            }
        }
        // Each of these is counted in `remaining` whatever session it is in,
        // since authd cannot tell. Said, so that a `remaining` that never
        // reaches zero can be traced to the process responsible.
        if holders.unexamined > 0 {
            log::warn(format_args!(
                "ending session {session}: {} processes could not be examined and count as \
                 remaining: {}",
                holders.unexamined,
                unexaminable.join("; ")
            ));
        }
        holders
    }

    fn pid(&self, handle: &Held) -> i32 {
        handle.pid
    }

    fn signal(&mut self, handle: &Held, signal: Signal) -> bool {
        let signal = match signal {
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        };
        // SAFETY: a live pidfd, a valid signal, no siginfo, no flags.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                handle.pidfd.as_raw_fd(),
                signal,
                core::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        rc == 0
    }

    fn exited(&self, handle: &Held) -> bool {
        poll_exited(&[handle.pidfd.as_raw_fd()], 0) > 0
    }

    fn wait(&mut self, handles: &[Held], limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            let waiting: Vec<i32> = handles
                .iter()
                .filter(|handle| !self.exited(handle))
                .map(|handle| handle.pidfd.as_raw_fd())
                .collect();
            let left = deadline.saturating_duration_since(Instant::now());
            if waiting.is_empty() || left.is_zero() {
                return;
            }
            // Wakes when any one exits; the loop then asks about the rest.
            poll_exited(&waiting, left.as_millis().min(i32::MAX as u128) as i32);
        }
    }
}

fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
    // SAFETY: a plain syscall returning a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this descriptor, and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// How many of `pidfds` have exited, waiting up to `timeout_ms` for one to. A
/// pidfd polls readable once its process has exited.
fn poll_exited(pidfds: &[i32], timeout_ms: i32) -> usize {
    let mut polled: Vec<libc::pollfd> = pidfds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: `polled` is a live, correctly sized array of pollfds.
    let rc = unsafe {
        libc::poll(
            polled.as_mut_ptr(),
            polled.len() as libc::nfds_t,
            timeout_ms,
        )
    };
    if rc <= 0 {
        return 0;
    }
    polled.iter().filter(|fd| fd.revents != 0).count()
}

fn is_kernel_thread(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(stat_flags)
        .is_some_and(|flags| flags & PF_KTHREAD != 0)
}

/// The flags field of a `/proc/<pid>/stat` line. The command name is in
/// parentheses and may hold anything, spaces and parentheses included, so the
/// fields are counted from the last `)`.
fn stat_flags(stat: &str) -> Option<u64> {
    let (_, after) = stat.rsplit_once(')')?;
    // state ppid pgrp session tty_nr tpgid flags
    after.split_whitespace().nth(6)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    fn listed(id: u64, user: &str, logon_type: u32) -> Listed {
        Listed {
            id,
            user: sid(user),
            logon_type,
        }
    }

    const ALICE: &str = "S-1-5-21-1-2-3-1000";
    const BOB: &str = "S-1-5-21-1-2-3-1001";

    fn granted() -> bool {
        true
    }
    fn refused() -> bool {
        false
    }

    /// The record names who asked and whose session it was by SID, and a
    /// session something still holds is an end that did not finish.
    #[test]
    fn an_ended_session_is_recorded_with_who_asked() {
        let target = listed(4242, BOB, 10);
        let asker = sid(ALICE);
        log_outcome(
            &asker,
            &target,
            &SessionEnded {
                ended: 3,
                remaining: 0,
            },
        );
        log_outcome(
            &asker,
            &target,
            &SessionEnded {
                ended: 1,
                remaining: 2,
            },
        );

        let written = audit::take();
        assert_eq!(written.len(), 2);
        let (event_type, done) = &written[0];
        assert_eq!(event_type, "authd.session.ended");
        assert_eq!(
            done.get("subject.token.sid"),
            Some(&audit::Value::Bin(asker.as_ref().as_bytes().to_vec()))
        );
        assert_eq!(done.get("object.session.id"), Some(&audit::Value::Uint(4242)));
        assert_eq!(
            done.get("object.session.user.sid"),
            Some(&audit::Value::Bin(sid(BOB).as_ref().as_bytes().to_vec()))
        );
        assert_eq!(
            done.get("object.session.logon-type"),
            Some(&audit::Value::Str("remote-interactive".into()))
        );
        assert_eq!(done.get("outcome.success"), Some(&audit::Value::Bool(true)));
        assert_eq!(done.get("outcome.reason"), None);

        let (_, unfinished) = &written[1];
        assert_eq!(unfinished.get("outcome.success"), Some(&audit::Value::Bool(false)));
        assert_eq!(
            unfinished.get("outcome.reason"),
            Some(&audit::Value::Str("processes-remaining".into()))
        );
    }

    /// The context the session-end check names its descriptor with is one the
    /// kernel will accept.
    #[test]
    fn the_audit_context_is_well_formed() {
        let context = AuditContext::new(AUDIT_KIND, &[]).expect("a valid kind");
        AuditContext::from_bytes(context.as_bytes().to_vec()).expect("the kernel's rules");
    }

    #[test]
    fn a_person_may_end_their_own_session_without_a_grant() {
        for logon_type in [2, 3, 4, 8, 9, 10] {
            let target = listed(1042, ALICE, logon_type);
            assert_eq!(
                decide(sid(ALICE).as_ref(), Some(&target), || panic!(
                    "no grant needed"
                )),
                Ok(()),
                "type {logon_type}"
            );
        }
    }

    #[test]
    fn somebody_elses_session_needs_the_grant() {
        let target = listed(1042, BOB, 2);
        assert_eq!(
            decide(sid(ALICE).as_ref(), Some(&target), refused),
            Err(Denial::PermissionDenied)
        );
        assert_eq!(decide(sid(ALICE).as_ref(), Some(&target), granted), Ok(()));
    }

    /// Never SYSTEM's, Anonymous's or a service's — not even for a caller the
    /// descriptor grants, and not even as one's own.
    #[test]
    fn the_kernels_sessions_and_services_are_never_ended() {
        let system = sid("S-1-5-18");
        for target in [
            listed(SYSTEM_SESSION, "S-1-5-18", 0),
            listed(ANONYMOUS_SESSION, "S-1-5-7", 3),
            listed(2000, "S-1-5-19", SERVICE_LOGON),
            listed(2001, ALICE, SERVICE_LOGON),
        ] {
            assert_eq!(
                decide(system.as_ref(), Some(&target), granted),
                Err(Denial::PermissionDenied),
                "{target:?}"
            );
            assert_eq!(
                decide(target.user.as_ref(), Some(&target), granted),
                Err(Denial::PermissionDenied),
                "{target:?} as its own user"
            );
        }
    }

    /// "Your own" means a person's account signed in as a person. A
    /// well-known identity with a session of a person's type is not.
    #[test]
    fn a_well_known_identity_is_not_a_person_signing_out() {
        for user in ["S-1-5-19", "S-1-5-20", "S-1-5-80-1-2-3-4-5"] {
            let target = listed(3000, user, 2);
            assert_eq!(
                decide(sid(user).as_ref(), Some(&target), refused),
                Err(Denial::PermissionDenied),
                "{user}"
            );
        }
    }

    #[test]
    fn an_unknown_logon_type_is_not_a_persons() {
        let target = listed(1042, ALICE, 7);
        assert_eq!(
            decide(sid(ALICE).as_ref(), Some(&target), refused),
            Err(Denial::PermissionDenied)
        );
        assert!(!is_person_logon(99));
        assert!(!is_person_logon(SERVICE_LOGON));
    }

    /// Only a caller who could end it learns that it does not exist.
    #[test]
    fn no_such_session_is_said_only_to_who_may_end_others() {
        assert_eq!(
            decide(sid(ALICE).as_ref(), None, granted),
            Err(Denial::NoSuchSession)
        );
        assert_eq!(
            decide(sid(ALICE).as_ref(), None, refused),
            Err(Denial::PermissionDenied)
        );
    }

    #[test]
    fn the_kernels_listing_is_read() {
        let text = "logon_session_id=999 user_sid=010100000000000512000000 logon_type=0 \
                    auth_package=4b65726e656c created_at=1\n\
                    logon_session_id=1042 user_sid=010500000000000515000000010000000200000003000000e8030000 \
                    logon_type=2 auth_package=6c707364 created_at=17 future=field\n\
                    garbage line\n\
                    logon_session_id=7 user_sid=zz logon_type=2\n";
        let sessions = parse_sessions(text);
        assert_eq!(
            sessions,
            vec![listed(999, "S-1-5-18", 0), listed(1042, ALICE, 2)]
        );
    }

    #[test]
    fn a_stat_lines_flags_are_found_past_a_hostile_name() {
        let line = "42 (a) b) c) S 1 42 42 0 -1 2097216 0 0";
        assert_eq!(stat_flags(line), Some(2_097_216));
        assert!(stat_flags(line).is_some_and(|flags| flags & PF_KTHREAD != 0));
        assert_eq!(
            stat_flags("1 (init) S 0 1 1 0 -1 4194560 1"),
            Some(4_194_560)
        );
        assert_eq!(stat_flags("no paren"), None);
    }

    /// The reply waits for the rounds, so they must fit well inside the
    /// conversation's own bound.
    #[test]
    fn the_rounds_fit_inside_a_conversation() {
        assert!(ROUNDS_BOUND <= Duration::from_secs(30));
        assert!(ROUNDS_BOUND < crate::conversation::CONVERSATION_DEADLINE);
    }

    // A stand-in machine. Each process is in a session; TERM ends those that
    // don't ignore it, KILL ends everything but a zombie, and a process may
    // fork a child into its session when it is first signalled.
    #[derive(Default)]
    struct Fake {
        procs: BTreeMap<i32, FakeProc>,
        next_pid: i32,
        unexamined: u32,
        sent: Vec<(i32, Signal)>,
        walks: u32,
    }

    #[derive(Clone, Default)]
    struct FakeProc {
        session: u64,
        alive: bool,
        ignores_term: bool,
        zombie: bool,
        forks_on_term: u32,
    }

    impl Fake {
        fn add(&mut self, session: u64, proc_: FakeProc) -> i32 {
            self.next_pid += 1;
            self.procs.insert(
                self.next_pid,
                FakeProc {
                    session,
                    alive: true,
                    ..proc_
                },
            );
            self.next_pid
        }
    }

    impl Processes for Fake {
        type Handle = i32;

        fn holding(&mut self, session: u64) -> Holders<i32> {
            self.walks += 1;
            Holders {
                found: self
                    .procs
                    .iter()
                    .filter(|(_, p)| p.session == session && (p.alive || p.zombie))
                    .map(|(pid, _)| *pid)
                    .collect(),
                unexamined: self.unexamined,
            }
        }

        fn pid(&self, handle: &i32) -> i32 {
            *handle
        }

        fn signal(&mut self, handle: &i32, signal: Signal) -> bool {
            self.sent.push((*handle, signal));
            let mut children = 0;
            let session;
            {
                let p = self.procs.get_mut(handle).expect("a known process");
                session = p.session;
                if p.zombie {
                    return true;
                }
                match signal {
                    Signal::Term => {
                        children = std::mem::take(&mut p.forks_on_term);
                        if !p.ignores_term {
                            p.alive = false;
                        }
                    }
                    Signal::Kill => p.alive = false,
                }
            }
            for _ in 0..children {
                self.add(session, FakeProc::default());
            }
            true
        }

        fn exited(&self, handle: &i32) -> bool {
            let p = &self.procs[handle];
            !p.alive || p.zombie
        }

        fn wait(&mut self, _: &[i32], _: Duration) {}
    }

    fn run(fake: &mut Fake, session: u64) -> SessionEnded {
        let first = fake.holding(session);
        end(fake, session, first)
    }

    #[test]
    fn everything_in_the_session_is_ended_and_nothing_else() {
        let mut fake = Fake::default();
        let a = fake.add(1042, FakeProc::default());
        let b = fake.add(1042, FakeProc::default());
        let other = fake.add(2000, FakeProc::default());
        assert_eq!(
            run(&mut fake, 1042),
            SessionEnded {
                ended: 2,
                remaining: 0
            }
        );
        assert!(fake.sent.iter().all(|(pid, _)| *pid != other));
        assert_eq!(
            fake.sent,
            vec![(a, Signal::Term), (b, Signal::Term)],
            "TERM ends them; no KILL is needed"
        );
        assert!(fake.procs[&other].alive);
    }

    #[test]
    fn what_ignores_term_is_killed() {
        let mut fake = Fake::default();
        let stubborn = fake.add(
            1042,
            FakeProc {
                ignores_term: true,
                ..FakeProc::default()
            },
        );
        assert_eq!(
            run(&mut fake, 1042),
            SessionEnded {
                ended: 1,
                remaining: 0
            }
        );
        assert_eq!(
            fake.sent,
            vec![(stubborn, Signal::Term), (stubborn, Signal::Kill)]
        );
    }

    /// A child forked during the grace holds the session too, and the next
    /// round finds it.
    #[test]
    fn a_process_forked_during_the_grace_is_found_next_round() {
        let mut fake = Fake::default();
        fake.add(
            1042,
            FakeProc {
                forks_on_term: 2,
                ..FakeProc::default()
            },
        );
        assert_eq!(
            run(&mut fake, 1042),
            SessionEnded {
                ended: 3,
                remaining: 0
            }
        );
    }

    /// Rounds are bounded. A session whose processes keep forking reports
    /// what survives, and the walks stop.
    #[test]
    fn the_rounds_are_bounded() {
        let mut fake = Fake::default();
        fake.add(
            1042,
            FakeProc {
                forks_on_term: 1,
                ..FakeProc::default()
            },
        );
        // Every child forks again when it is signalled, forever.
        struct Forever(Fake);
        impl Processes for Forever {
            type Handle = i32;
            fn holding(&mut self, session: u64) -> Holders<i32> {
                self.0.holding(session)
            }
            fn pid(&self, handle: &i32) -> i32 {
                *handle
            }
            fn signal(&mut self, handle: &i32, signal: Signal) -> bool {
                let before = self.0.next_pid;
                let sent = self.0.signal(handle, signal);
                for pid in before + 1..=self.0.next_pid {
                    self.0.procs.get_mut(&pid).unwrap().forks_on_term = 1;
                }
                sent
            }
            fn exited(&self, handle: &i32) -> bool {
                self.0.exited(handle)
            }
            fn wait(&mut self, _: &[i32], _: Duration) {}
        }
        let mut forever = Forever(fake);
        let first = forever.holding(1042);
        let outcome = end(&mut forever, 1042, first);
        assert_eq!(
            forever.0.walks,
            1 + MAX_ROUNDS,
            "one walk, then one per round"
        );
        assert_eq!(
            outcome,
            SessionEnded {
                ended: MAX_ROUNDS,
                remaining: 1
            }
        );
    }

    /// A zombie holds its token until it is reaped and ignores every signal:
    /// it is remaining, and is not counted as ended as well.
    #[test]
    fn a_zombie_is_remaining_not_ended() {
        let mut fake = Fake::default();
        fake.add(1042, FakeProc::default());
        fake.add(
            1042,
            FakeProc {
                zombie: true,
                ..FakeProc::default()
            },
        );
        assert_eq!(
            run(&mut fake, 1042),
            SessionEnded {
                ended: 1,
                remaining: 1
            }
        );
    }

    /// What could not be examined may hold the session, and is said to.
    #[test]
    fn what_could_not_be_examined_is_remaining() {
        let mut fake = Fake {
            unexamined: 2,
            ..Fake::default()
        };
        fake.add(1042, FakeProc::default());
        assert_eq!(
            run(&mut fake, 1042),
            SessionEnded {
                ended: 1,
                remaining: 2
            }
        );
    }

    #[test]
    fn an_empty_session_needs_no_rounds() {
        let mut fake = Fake::default();
        assert_eq!(run(&mut fake, 1042), SessionEnded::default());
        assert_eq!(fake.walks, 1);
        assert!(fake.sent.is_empty());
    }
}
