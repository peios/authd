//! **lpsd** — the Local Principal Source Daemon.
//!
//! The first principal source, and the reference implementation of the source
//! side of PSI. lpsd owns the local identity database: it holds the bytes,
//! verifies credentials against them, and tells authd *who* someone is. It has
//! no way to say anything else — no session, no token, no privileges, no
//! integrity level — because the protocol gives it no message with which to.
//!
//! # It dials in
//!
//! lpsd connects to `/run/psi.sock`; authd never connects to lpsd. That keeps
//! authd — the process holding `SeCreateTokenPrivilege` — free of any reason to
//! open an outbound connection, and it means a source restarting is the
//! source's problem rather than the authority's.
//!
//! One consequence for boot: lpsd only reports itself ready once authd has
//! *acknowledged* its registration, so "lpsd is running" and "lpsd can
//! authenticate" are the same statement. Anything ordered after lpsd —
//! `login`, a greeter, sshd — therefore finds a system that can actually
//! authenticate.
//!
//! # It drives the conversation
//!
//! authd asks lpsd to authenticate someone; everything after that is lpsd's
//! decision. It chooses what to prompt for, how many rounds to take, and when
//! to give up. authd relays without interpreting. That is what makes adding a
//! credential type — a TOTP, a passkey — a change to sources rather than a
//! change to the authority.
//!
//! # Single-threaded, on purpose
//!
//! Concurrency lives in the protocol, not in threads: one connection carries
//! many logons, tagged by conversation id, and lpsd handles each message to
//! completion as it arrives. A source that had to block — a directory lookup
//! over a network — would need threads or an event loop; a local one does not,
//! and pretending otherwise would be structure without purpose.
//!
//! # Its state is one file
//!
//! Principals, their verifiers and the machine's own domain SID live in a
//! single file replaced atomically ([`fs`]), not a database. lpsd reads it once
//! at startup and holds it: a logon must not depend on a disk that has since
//! gone away, and the store changes only when an administrator changes it.
//!
//! Provisioning is split — lpsd always generates the domain when it finds no
//! store, because a source without one can answer nothing, but it never invents
//! accounts. Those are created through [`admin`], by `lps`, including the first
//! one on a fresh image.
//!
//! # It listens, as of M4
//!
//! Two descriptors now: the outbound PSI connection, and an administrative
//! listener. They are served from one thread by polling both, which keeps the
//! store owned by the loop and needs no lock to protect a thing with exactly one
//! writer. See [`admin`] for what crosses the second one.

mod admin;
mod codec;
mod fs;
mod log;
mod random;
mod store;
mod verifier;

use std::collections::HashMap;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;

use crate::fs::RealFs;
use crate::store::{Store, StoreError};

use libauthd::psi;
use libauthd::transport::{recv_message, send_message};
use libauthd::wire::{
    CredentialRequest, CredentialType, Denial, IdentifierType, Message, MessageSeverity, Prompt,
};
use libauthd::{PSI_SOCKET_PATH, Secret};

/// What lpsd calls itself when registering.
///
/// This becomes the auth-package name on every session it authenticates, so it
/// is what `logonse` and the audit trail show as the authority that vouched for
/// a logon.
const SOURCE_NAME: &str = "lpsd";

/// The prompt reference for the password. Unique within a conversation, and
/// echoed back by the client unchanged.
const PASSWORD_REF: u32 = 1;

/// How many logons lpsd will track at once.
///
/// authd caps its own conversations, but a source should not depend on its
/// authority's bookkeeping to bound its memory.
const MAX_CONVERSATIONS: usize = 256;

/// What lpsd remembers between asking and being answered.
struct Pending {
    /// The identifier authd passed through. Held so the answer is verified
    /// against the name the conversation opened with, never against anything
    /// in the response — which the client controls.
    identifier: Vec<u8>,
}

fn main() -> ExitCode {
    log::info(format_args!("starting (PSI v{})", psi::VERSION));

    let mut store = match open_store() {
        Ok(store) => store,
        Err(error) => {
            // Deliberately fatal. A store that cannot be read must never be
            // replaced with a fresh one: that would present as every account on
            // the machine silently ceasing to exist, and then reappearing under
            // a new domain with different SIDs, orphaning every descriptor that
            // named them. Refusing to start is loud and leaves the evidence.
            log::error(format_args!(
                "could not open the principal store at {}: {error}",
                store::STORE_PATH
            ));
            return ExitCode::FAILURE;
        }
    };

    match store.domain_sid() {
        Ok(domain) => log::info(format_args!(
            "serving {} principal(s) in {domain}",
            store.len()
        )),
        Err(error) => {
            log::error(format_args!("the store has no usable domain: {error}"));
            return ExitCode::FAILURE;
        }
    }

    if store.is_empty() {
        // Not an error — a production image seeds no accounts on purpose — but
        // the symptom is a login prompt nothing can satisfy, which is confusing
        // enough to be worth naming at the moment it becomes true rather than
        // leaving someone to infer it from a failed logon.
        log::warn(format_args!(
            "no principals exist; no logon can succeed until one is created"
        ));
    }

    let stream = match connect() {
        Ok(stream) => stream,
        Err(error) => {
            log::error(format_args!(
                "could not reach an authority on {PSI_SOCKET_PATH}: {error}"
            ));
            return ExitCode::FAILURE;
        }
    };

    let registered = match register(&stream, &store) {
        Ok(registered) => registered,
        Err(error) => {
            log::error(format_args!("could not register: {error}"));
            return ExitCode::FAILURE;
        }
    };

    // Before readiness, so that a service ordered after lpsd finds both halves
    // of what lpsd offers. The first account on a fresh machine is created by
    // exactly such a service, and it would race the listener otherwise.
    let listener = match admin::listen() {
        Ok(listener) => listener,
        Err(error) => {
            log::error(format_args!(
                "could not listen on {}: {error}",
                libauthd::LPSD_ADMIN_SOCKET_PATH
            ));
            return ExitCode::FAILURE;
        }
    };

    // Only once registration is acknowledged: a service ordered after lpsd is
    // entitled to assume the system can authenticate, not merely that a process
    // exists.
    notify_ready();
    log::info(format_args!("registered as {SOURCE_NAME}"));

    match pump(&stream, &listener, &mut store, registered) {
        // The authority went away. Exiting is the honest response: peinit owns
        // supervision and restart, and reimplementing reconnection here would
        // be a second, worse copy of it.
        Ok(()) => {
            log::warn(format_args!("the authority disconnected"));
            ExitCode::FAILURE
        }
        Err(error) => {
            log::error(format_args!("connection failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn connect() -> io::Result<UnixStream> {
    UnixStream::connect(PSI_SOCKET_PATH)
}

/// Which descriptors have something for us.
struct Ready {
    logon: bool,
    admin: bool,
}

/// Block until either descriptor is readable.
///
/// `poll` rather than a thread apiece, for the reason in [`pump`]. No timeout:
/// lpsd has nothing to do on a tick, and waking up to discover that would be
/// work performed to no end on every idle machine.
fn wait(stream: &UnixStream, listener: &UnixListener) -> io::Result<Ready> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // SAFETY: `fds` is a live, exclusively borrowed array of two pollfds.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            // A signal arriving is not a failure; go back to waiting.
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        // POLLHUP and POLLERR are reported in `revents` whether or not they
        // were requested, and both must count as readable: a hung-up authority
        // is discovered by reading end-of-file from it, not by ignoring it and
        // spinning.
        let interesting = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
        return Ok(Ready {
            logon: fds[0].revents & interesting != 0,
            admin: fds[1].revents & interesting != 0,
        });
    }
}

/// Read the store, or provision one if this machine has never had a store.
///
/// The two outcomes of a failed read are kept strictly apart: *absent* is an
/// unprovisioned machine and is provisioned; anything else is an error and is
/// propagated. See [`store`] for why collapsing them would be the worst bug
/// this daemon could have.
fn open_store() -> Result<Store, StoreError> {
    let path = Path::new(store::STORE_PATH);
    if let Some(store) = Store::load(&RealFs, path)? {
        // A store written by an older lpsd was upgraded on the way in. Write it
        // back now rather than on the first administrative change, so the
        // upgrade is not silently redone on every boot until somebody happens
        // to run `lps` — and so a failure to persist it surfaces here, where it
        // can be read as an upgrade problem, rather than as a mysteriously
        // failing unrelated command later.
        if store.needs_rewrite() {
            log::info(format_args!(
                "the store is in an older format; rewriting it in the current one"
            ));
            store.save(&RealFs, path)?;
        }
        return Ok(store);
    }

    log::info(format_args!("no store at {}; provisioning", store::STORE_PATH));
    if let Some(directory) = path.parent() {
        // Durably: an atomically-replaced file inside a directory that is not
        // itself durable buys nothing, and losing the directory means losing
        // the domain. See `RealFs::create_directory`.
        RealFs.create_directory(directory).map_err(StoreError::Io)?;
    }

    let store = Store::provision()?;
    store.save(&RealFs, path)?;

    let domain = store.domain_sid()?;
    log::info(format_args!("provisioned {domain} with no principals"));
    Ok(store)
}

/// Announce ourselves and wait to be accepted.
///
/// The domain is declared here, once, and every assertion lpsd makes afterwards
/// is confined to it by authd. Declaring it is not proving it — lpsd cannot
/// prove a domain it generated itself — which is why the checks that give the
/// claim weight all live on the authority's side.
/// Returns the Unix ID range the authority assigned, which lpsd keeps only so
/// that `lps` can show an operator the uid a principal really projects to.
/// **lpsd never applies the base itself** — it asserts relative numbers and
/// authd rebases them, so adding it here would have it applied twice.
fn register(stream: &UnixStream, store: &Store) -> io::Result<psi::Registered> {
    let domain = store
        .domain_sid()
        .map_err(|error| io::Error::other(format!("no domain to register with: {error}")))?;
    let message = psi::encode_register(&psi::Register {
        source_name: SOURCE_NAME.to_string(),
        domain: domain.as_ref().as_bytes().to_vec(),
    })
    .map_err(|_| io::Error::other("could not encode a registration"))?;
    send_message(stream, &message)?;

    let received = recv_message(&psi::FRAMING, stream)?;
    let registered = psi::decode_registered(received.expose())
        .map_err(|_| io::Error::other("the authority did not acknowledge the registration"))?;

    if registered.unix_id_base == 0 {
        log::warn(format_args!(
            "the authority assigned no Unix ID range, so every principal here will project \
             to nobody; set UnixIDBase on this source in the registry"
        ));
    } else {
        log::info(format_args!(
            "Unix IDs land at {}..{}",
            registered.unix_id_base,
            registered
                .unix_id_base
                .saturating_add(registered.unix_id_count)
        ));
    }
    Ok(registered)
}

/// Serve both descriptors until the authority goes away.
///
/// One thread, polling. Threading the administrative socket separately would
/// mean a lock around the store, which is machinery to coordinate writers when
/// there is only ever one — and it would give up the property that a logon and
/// an administrative change cannot interleave halfway through either.
fn pump(
    stream: &UnixStream,
    listener: &UnixListener,
    store: &mut Store,
    registered: psi::Registered,
) -> io::Result<()> {
    let mut pending: HashMap<u64, Pending> = HashMap::new();

    loop {
        let ready = wait(stream, listener)?;

        if ready.admin {
            match listener.accept() {
                Ok((connection, _)) => admin::serve(connection, store, registered, |store| {
                    store.save(&RealFs, Path::new(store::STORE_PATH))
                }),
                Err(error) => log::warn(format_args!("admin: could not accept: {error}")),
            }
        }

        if !ready.logon {
            continue;
        }

        let received = match recv_message(&psi::FRAMING, stream) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };

        let envelope = match psi::decode_envelope(received.expose()) {
            Ok(envelope) => envelope,
            // A framing error is fatal: once a message has failed to parse
            // there is no way to know where the next one starts.
            Err(_) => return Err(io::Error::other("malformed message header")),
        };

        match envelope.msg_type {
            psi::MSG_AUTHENTICATE => {
                begin(stream, &mut pending, envelope.conversation, received.expose())?
            }
            psi::MSG_CREDENTIAL_RESPONSE => answer(
                stream,
                store,
                &mut pending,
                envelope.conversation,
                received.expose(),
            )?,
            psi::MSG_ABANDON => {
                pending.remove(&envelope.conversation);
            }
            other => {
                log::warn(format_args!("unexpected message type {other:#06x}"));
            }
        }
    }
}

/// Open a conversation: decide what to ask for.
fn begin(
    stream: &UnixStream,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    buf: &[u8],
) -> io::Result<()> {
    let Ok(request) = psi::decode_authenticate(buf) else {
        return refuse(
            stream,
            conversation,
            Denial::MalformedRequest,
            "Malformed authentication request.",
        );
    };

    if pending.len() >= MAX_CONVERSATIONS {
        return refuse(
            stream,
            conversation,
            Denial::AuthorityUnavailable,
            "Too many authentications in flight.",
        );
    }

    // lpsd knows how to identify people by name and nothing else. A source that
    // supported certificates or passkeys would accept other identifier types
    // here, or none at all.
    if request.start.identifier_type != IdentifierType::Username {
        return refuse(
            stream,
            conversation,
            Denial::AuthenticationFailed,
            "Authentication failed.",
        );
    }

    // The client must be able to render what we are about to ask for. authd
    // polices this too, and would refuse to relay a prompt the client cannot
    // handle — but the source is where the choice is actually made, so this is
    // where the capability list belongs.
    if !request
        .start
        .supported_credential_types
        .contains(&CredentialType::Password)
    {
        return refuse(
            stream,
            conversation,
            Denial::AuthenticationFailed,
            "No supported authentication method.",
        );
    }

    pending.insert(
        conversation,
        Pending {
            identifier: request.start.identifier,
        },
    );

    ask(stream, conversation)
}

/// Ask for the password.
fn ask(stream: &UnixStream, conversation: u64) -> io::Result<()> {
    let request = CredentialRequest {
        messages: vec![Message {
            severity: MessageSeverity::Info,
            text: format!("Authenticating against {SOURCE_NAME}."),
        }],
        prompts: vec![Prompt {
            credential_ref: PASSWORD_REF,
            credential_type: CredentialType::Password,
            credential_name: "Password".into(),
        }],
    };

    let message = psi::encode_credential_request(conversation, &request)
        .map_err(|_| io::Error::other("could not encode a credential request"))?;
    send_message(stream, &message)
}

/// Verify an answer and reach a terminal state.
fn answer(
    stream: &UnixStream,
    store: &Store,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    buf: &[u8],
) -> io::Result<()> {
    // Removed rather than borrowed: a conversation gets exactly one answer, and
    // taking the state out means a client that sends two cannot retry against
    // remembered context.
    let Some(state) = pending.remove(&conversation) else {
        log::warn(format_args!(
            "an answer arrived for unknown conversation {conversation}"
        ));
        return Ok(());
    };

    let Ok(response) = psi::decode_credential_response(buf) else {
        return refuse(
            stream,
            conversation,
            Denial::MalformedRequest,
            "Malformed credential response.",
        );
    };

    let empty = Secret::empty();
    let secret = response
        .answers
        .iter()
        .find(|answer| answer.credential_ref == PASSWORD_REF)
        .map(|answer| answer.data.expose())
        .unwrap_or_else(|| empty.expose());

    match store.authenticate(&state.identifier, secret) {
        Some(identity) => {
            log::info(format_args!(
                "authenticated {} as {} in {} group(s)",
                identity.name,
                identity.sid,
                identity.groups.len()
            ));
            assert_identity(stream, conversation, &identity)
        }
        None => {
            // One log line for both "no such principal" and "wrong password".
            // The distinction is a username oracle, and while it may eventually
            // be worth recording in an audit trail an administrator can read,
            // it must never reach the caller.
            log::warn(format_args!(
                "authentication failed for {}",
                String::from_utf8_lossy(&state.identifier)
            ));
            refuse(
                stream,
                conversation,
                Denial::AuthenticationFailed,
                "Authentication failed.",
            )
        }
    }
}

/// Tell the authority who this is.
fn assert_identity(
    stream: &UnixStream,
    conversation: u64,
    identity: &store::Identity,
) -> io::Result<()> {
    let message = psi::encode_assertion(
        conversation,
        &psi::Assertion {
            user_sid: identity.sid.as_ref().as_bytes().to_vec(),
            canonical_name: identity.name.clone(),
            groups: identity
                .groups
                .iter()
                .map(|group| psi::Group {
                    sid: group.sid.as_ref().as_bytes().to_vec(),
                    // `None` — a group lpsd does not own — becomes 0, which is
                    // how the protocol spells "I have no number for this". authd
                    // then uses its own, which is right: a well-known group's
                    // projection was never lpsd's to decide.
                    unix_id: group.unix_id.unwrap_or(0),
                })
                .collect(),
            // Relative. authd adds the base.
            unix_id: identity.unix_id,
            primary_group: identity.primary_group.sid.as_ref().as_bytes().to_vec(),
            profile: libauthd::wire::Profile {
                home: identity.home.clone(),
                shell: identity.shell.clone(),
                display_name: identity.display_name.clone(),
            },
            claims: identity.claims.clone(),
        },
    )
    .map_err(|_| io::Error::other("could not encode an assertion"))?;
    send_message(stream, &message)
}

fn refuse(
    stream: &UnixStream,
    conversation: u64,
    denial: Denial,
    reason: &str,
) -> io::Result<()> {
    let message = psi::encode_refusal(
        conversation,
        &psi::Refusal {
            denial,
            reason: reason.to_string(),
        },
    )
    .map_err(|_| io::Error::other("could not encode a refusal"))?;
    send_message(stream, &message)
}

/// Tell peinit we are ready, systemd-style, if it gave us a notify socket.
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
