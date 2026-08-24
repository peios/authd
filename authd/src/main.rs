//! **authd** — Peios' authentication daemon, and Mainline's implementation of
//! the PGSS Logon authority.
//!
//! authd is the only general-purpose minter of identity on a running system.
//! The kernel constructs the SYSTEM and Anonymous bootstrap tokens; peinit
//! mints SYSTEM service tokens directly; everything else — every user session,
//! every non-SYSTEM service — comes from here.
//!
//! It runs at `PeiosTcb` process integrity holding `SeCreateTokenPrivilege` and
//! `SeTcbPrivilege`, which makes it the most privileged userspace process on
//! the box. Two consequences shape the whole design:
//!
//! - **It stays small.** Anything that can be pushed out of this process should
//!   be. Credential verification lives in principal sources running below TCB,
//!   reached over PSI; authd forwards material it does not interpret and
//!   believes what a source tells it about *who* someone is — and nothing else.
//! - **It is never a process factory.** Callers install tokens on themselves.
//!   authd does not fork user processes and knows nothing about ttys,
//!   environments, or session leadership. That is what keeps it auditable.
//!
//! # Three sockets
//!
//! ```text
//!   login, sshd, a greeter …          lpsd, udpsd, adpsd …
//!            |                                  |
//!            | PGSS Logon                       | PSI
//!            v                                  v
//!     /run/logon.sock  ------ authd ------  /run/psi.sock
//!       (clients connect)     ^        (sources connect)
//!                             |
//!                             | PGSS Logon ch.6
//!                     /run/ident.sock
//!                    (everything connects)
//! ```
//!
//! All three are inbound. authd never dials out, which is worth preserving: a
//! process holding `SeCreateTokenPrivilege` that only ever accepts is a
//! meaningfully smaller thing than one that connects to paths named in
//! configuration.
//!
//! `/run/ident.sock` answers *who is this SID, this name, this number* — the
//! surface `getpwuid` reaches through. It is separate from the logon socket for
//! **admission**, not isolation: one authority answers both, so a second socket
//! contains no faults, but it does give the two populations of caller separate
//! accept queues. A filesystem walk issuing millions of lookups must not be able
//! to fill the queue an administrator needs in order to sign in.
//!
//! # What a token carries
//!
//! Authentication is real: a principal source verifies the credential and
//! asserts an identity, and the token carries that identity rather than SYSTEM.
//! Privileges, integrity level, owner and default DACL are decided per logon
//! from `Machine\Generic\Authn\Policy` (see [`policy::principal`]) rather
//! than taken from a flat default.
//!
//! Scope is enforced: identity confinement, membership scope and numeric scope
//! all apply, to a query result as much as to an assertion. What is *not* yet
//! real is routing — [`source::Registry::route`] ignores the identifier, so
//! more than one configured source sends every logon to the first (PEI-304).

mod conversation;
mod derive;
mod domain;
mod ident;
mod log;
mod peer;
mod policy;
mod resolve;
mod service_sid;
mod source;
mod unix_id;
mod well_known;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use libauthd::{IDENT_SOCKET_PATH, LOGON_SOCKET_PATH, PSI_SOCKET_PATH};

use crate::source::Registry;

/// How many conversations may be in flight at once.
///
/// Each is a thread and a little state. The cap is what stops a caller turning
/// "conversations are stateful" into a way to exhaust the process the whole
/// system's identity depends on.
const MAX_CONCURRENT_CONVERSATIONS: usize = 64;

/// How many PSI connections may be in flight at once.
///
/// Load-bearing rather than tidy, because `/run/psi.sock` is reachable by
/// anyone. The socket's permissions are **not** the security boundary — that is
/// the registry allowlist plus the peer's service SID, and the code must be
/// correct with the socket wide open — so this cap is what stops "connect and
/// say nothing" from exhausting threads in the daemon that mints all identity.
///
/// Comfortably above the number of sources any real system runs, since a
/// registered source holds one of these for its whole life.
const MAX_SOURCE_CONNECTIONS: usize = 32;

/// How many identity lookups may be in flight at once.
///
/// Larger than the logon cap, because the callers are: every process that
/// renders a name holds one of these, where only a handful of things ever
/// originate a logon. Separate from that cap on purpose — the two populations
/// having their own budget is the same reason they have their own socket.
const MAX_IDENT_CONNECTIONS: usize = 256;

fn main() -> ExitCode {
    log::info(format_args!(
        "starting (PGSS Logon v{}, PSI v{})",
        libauthd::wire::VERSION,
        libauthd::psi::VERSION
    ));

    let logon = match listen(Path::new(LOGON_SOCKET_PATH), 0o600) {
        Ok(listener) => listener,
        Err(error) => {
            log::error(format_args!(
                "could not listen on {LOGON_SOCKET_PATH}: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };

    // Deliberately open. A principal source is admitted by the registry
    // allowlist and the service SID on its token, not by reaching the socket,
    // and treating the permissions as a boundary would be a way to end up
    // depending on one. Anything here is denial-of-service mitigation only —
    // and that job belongs to MAX_SOURCE_CONNECTIONS, which works regardless.
    let psi = match listen(Path::new(PSI_SOCKET_PATH), 0o666) {
        Ok(listener) => listener,
        Err(error) => {
            log::error(format_args!("could not listen on {PSI_SOCKET_PATH}: {error}"));
            return ExitCode::FAILURE;
        }
    };

    // Deliberately open, and for a different reason than the PSI socket. Here
    // there is nothing to protect: a principal refused a connection would see
    // numbers where names should be, while one that can connect learns the same
    // names either way. Restriction, when authd wants it, goes on fields.
    let ident = match listen(Path::new(IDENT_SOCKET_PATH), 0o666) {
        Ok(listener) => listener,
        Err(error) => {
            log::error(format_args!(
                "could not listen on {IDENT_SOCKET_PATH}: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };

    // Read once, here, rather than per lookup. It is what tells the resolver
    // which sources *should* be present, so that a name a crashed source holds
    // answers "unavailable" rather than falling through to a different
    // principal that happens to share it.
    let registry = Arc::new(Registry::configured(&policy::sources()));

    // Sources must be able to register before the first logon arrives, so this
    // loop starts first — but nothing here waits for one. "No sources means no
    // accounts to log in to" is the honest answer, and it surfaces as a denial
    // rather than a hang. Ordering is peinit's job: `lpsd` requires authd, and
    // `login` requires lpsd.
    {
        let registry = Arc::clone(&registry);
        let spawned = thread::Builder::new()
            .name("psi".into())
            .spawn(move || accept_sources(&registry, psi));
        if let Err(error) = spawned {
            log::error(format_args!("could not start the PSI listener: {error}"));
            return ExitCode::FAILURE;
        }
    }

    {
        let registry = Arc::clone(&registry);
        let spawned = thread::Builder::new()
            .name("ident".into())
            .spawn(move || accept_lookups(&registry, ident));
        if let Err(error) = spawned {
            log::error(format_args!("could not start the ident listener: {error}"));
            return ExitCode::FAILURE;
        }
    }

    // Only once every socket exists, so a service ordered after us finds
    // something to connect to rather than racing us to create it.
    notify_ready();
    log::info(format_args!(
        "listening on {LOGON_SOCKET_PATH}, {IDENT_SOCKET_PATH} and {PSI_SOCKET_PATH}"
    ));

    accept_logons(&registry, logon);
    ExitCode::SUCCESS
}

/// Bind a socket.
///
/// The permissions here are never the access control. On the logon socket the
/// real control is a KACS security descriptor plus the peer check in [`peer`] —
/// deliberately not PIP, which would force every future caller (a graphical
/// greeter, a web console) to be signed at high trust merely to collect a
/// password. On the PSI socket it is the registry allowlist and the peer's
/// service SID.
fn listen(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    // A stale socket from an unclean shutdown would make bind() fail with
    // EADDRINUSE even though nothing is listening.
    match fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale socket at {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = UnixListener::bind(path)?;
    // Explicit rather than umask-dependent: whichever way it goes, it should be
    // a decision in the source rather than a property of how authd was started.
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

fn accept_logons(registry: &Arc<Registry>, listener: UnixListener) {
    let live = Arc::new(AtomicUsize::new(0));

    accept_loop(listener, "logon", |stream| {
        if live.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONVERSATIONS {
            // Dropping the stream is the honest answer: we cannot promise to
            // serve it, and holding it open would be worse than refusing.
            log::warn(format_args!(
                "refused a connection: {MAX_CONCURRENT_CONVERSATIONS} conversations already in flight"
            ));
            return;
        }

        live.fetch_add(1, Ordering::Relaxed);
        let held = Arc::clone(&live);
        let registry = Arc::clone(registry);
        let spawned = thread::Builder::new()
            .name("logon".into())
            .spawn(move || {
                conversation::serve(registry, stream);
                held.fetch_sub(1, Ordering::Relaxed);
            });

        if let Err(error) = spawned {
            // The thread never ran, so nothing will decrement for us.
            live.fetch_sub(1, Ordering::Relaxed);
            log::warn(format_args!("could not spawn a conversation thread: {error}"));
        }
    });
}

/// Accept identity lookups. One thread per connection, for the connection's
/// lifetime.
///
/// A separate cap from the logon socket's, which is the whole reason this is a
/// separate socket: a name resolver in every process on the system is a very
/// different population of caller from the handful of things that originate
/// logons, and neither should be able to exhaust the other.
fn accept_lookups(registry: &Arc<Registry>, listener: UnixListener) {
    let live = Arc::new(AtomicUsize::new(0));

    accept_loop(listener, "ident", |stream| {
        if live.load(Ordering::Relaxed) >= MAX_IDENT_CONNECTIONS {
            // Dropped rather than queued. A resolver that cannot get an answer
            // now will ask again, and holding it open would look like a slow
            // answer rather than a busy system.
            log::warn(format_args!(
                "ident: refused a connection: {MAX_IDENT_CONNECTIONS} already in flight"
            ));
            return;
        }

        live.fetch_add(1, Ordering::Relaxed);
        let held = Arc::clone(&live);
        let registry = Arc::clone(registry);
        let spawned = thread::Builder::new()
            .name("ident".into())
            .spawn(move || {
                ident::serve(registry, stream);
                held.fetch_sub(1, Ordering::Relaxed);
            });

        if let Err(error) = spawned {
            live.fetch_sub(1, Ordering::Relaxed);
            log::warn(format_args!("ident: could not spawn a thread: {error}"));
        }
    });
}

/// Accept principal sources. One thread per source, for the source's lifetime.
///
/// A source connection is long-lived where a logon is not, so the accounting is
/// simpler: [`Registry`](source::Registry) caps how many may be registered, and
/// a connection that never registers is dropped on a timeout.
fn accept_sources(registry: &Arc<Registry>, listener: UnixListener) {
    let live = Arc::new(AtomicUsize::new(0));

    accept_loop(listener, "psi", |stream| {
        if live.load(Ordering::Relaxed) >= MAX_SOURCE_CONNECTIONS {
            log::warn(format_args!(
                "psi: refused a connection: {MAX_SOURCE_CONNECTIONS} already in flight"
            ));
            return;
        }

        live.fetch_add(1, Ordering::Relaxed);
        let held = Arc::clone(&live);
        let registry = Arc::clone(registry);
        let spawned = thread::Builder::new()
            .name("source".into())
            .spawn(move || {
                source::serve(&registry, stream);
                held.fetch_sub(1, Ordering::Relaxed);
            });

        if let Err(error) = spawned {
            // The thread never ran, so nothing will decrement for us.
            live.fetch_sub(1, Ordering::Relaxed);
            log::warn(format_args!("could not spawn a source thread: {error}"));
        }
    });
}

/// Accept until the listener dies, logging and skipping the failures.
fn accept_loop(listener: UnixListener, what: &'static str, mut handle: impl FnMut(UnixStream)) {
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle(stream),
            Err(error) => log::warn(format_args!("{what}: accept failed: {error}")),
        }
    }
}

/// Tell peinit we are ready, systemd-style, if it gave us a notify socket.
///
/// This is what lets services be ordered after authd and find both sockets
/// already bound, instead of racing them and failing their first connect.
fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(socket) = UnixDatagram::unbound() else {
        log::warn(format_args!("could not create a notify socket"));
        return;
    };
    if let Err(error) = socket.send_to(b"READY=1", &path) {
        log::warn(format_args!("could not signal readiness: {error}"));
    }
}
