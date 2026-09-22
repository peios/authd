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
mod query;
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

use libauthd::PSI_SOCKET_PATH;
use libauthd::psi;
use libauthd::transport::{recv_message, send_message};
use libauthd::wire::{
    CredentialRequest, CredentialResponse, CredentialType, Denial, IdentifierType, Message,
    MessageSeverity, Prompt,
};
use peios::security::SidRef;

/// What lpsd calls itself when registering.
///
/// This becomes the auth-package name on every session it authenticates, so it
/// is what `logonse` and the audit trail show as the authority that vouched for
/// a logon.
const SOURCE_NAME: &str = "lpsd";

/// The prompt reference for the password. Unique within a conversation, and
/// echoed back by the client unchanged. Also the current password's, in a
/// change: it is the same question.
const PASSWORD_REF: u32 = 1;

/// The prompt references for a new password and its confirmation.
const NEW_PASSWORD_REF: u32 = 2;
const AGAIN_REF: u32 = 3;

/// How many times a change will ask for a new password before giving up.
///
/// Each asking is a round, and authd bounds rounds too; this keeps lpsd's own
/// count well inside that, so the principal is told why it ended rather than
/// meeting authd's generic limit.
const MAX_NEW_PASSWORD_ATTEMPTS: u32 = 3;

/// How many logons lpsd will track at once.
///
/// authd caps its own conversations, but a source should not depend on its
/// authority's bookkeeping to bound its memory.
const MAX_CONVERSATIONS: usize = 256;

/// What lpsd remembers between asking and being answered.
enum Pending {
    /// A logon, waiting for its password.
    Logon {
        /// The identifier authd passed through. Held so the answer is verified
        /// against the name the conversation opened with, never against
        /// anything in the response — which the client controls.
        identifier: Vec<u8>,
    },
    /// A principal changing their own password (PSPU §2.21).
    Change(Change),
}

/// A change of a principal's own password, between rounds.
struct Change {
    /// Who, as the store resolved them from the SID authd vouched for — never
    /// from anything in a response.
    rid: u32,
    name: String,
    stage: Stage,
}

enum Stage {
    /// Asked for the current password.
    Current,
    /// The current password held; asked for the new one.
    New {
        /// What held, so the store can refuse if it has changed since.
        proof: store::Proof,
        /// How many new passwords have been refused so far.
        attempts: u32,
    },
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

    log::info(format_args!(
        "no store at {}; provisioning",
        store::STORE_PATH
    ));
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
        // Everything: the store is a few hundred records held in memory, so
        // there is no query lpsd cannot answer and no reason to decline one.
        capabilities: psi::Capabilities::QUERIES
            | psi::Capabilities::ENUMERATES
            | psi::Capabilities::MEMBERS
            | psi::Capabilities::PUSHES_CHANGES
            | psi::Capabilities::CHANGES_CREDENTIALS,
        // Zero, and correct rather than lazy: lpsd pushes an invalidation on
        // every write, so an entry stays good until it says otherwise. A time
        // limit would only make authd re-ask for answers it already knows are
        // current.
        entry_ttl: 0,
        max_batch: psi::MAX_KEYS as u32,
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
                    let saved = save_store(store);
                    if saved.is_ok() {
                        // Here rather than after `serve` returns, because a
                        // failed save rolls the store back and there is then
                        // nothing to invalidate.
                        //
                        // The ordering PSPU §2.17 requires — the notification
                        // before the new answer is observable — is structural
                        // rather than careful: one thread serves both
                        // descriptors, so no query can be answered until this
                        // returns to the poll loop.
                        notify_changed(stream);
                    }
                    saved
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

        // Source obligation 9: conversation 0 is reserved for Register,
        // Registered and Changed. An Authenticate, Query or EnumerateSource
        // arriving on it was served normally and answered on 0, which the
        // protocol does not permit — and an authority that opened one has
        // misunderstood the reserved identifier, so continuing is not a
        // kindness.
        if envelope.conversation == psi::CONVERSATION_CONTROL
            && !matches!(envelope.msg_type, psi::MSG_CHANGED)
        {
            return Err(io::Error::other(
                "the authority used the reserved conversation 0 for an ordinary message",
            ));
        }

        match envelope.msg_type {
            psi::MSG_AUTHENTICATE => begin(
                stream,
                store,
                &mut pending,
                envelope.conversation,
                received.expose(),
                registered.unix_id_count,
            )?,
            psi::MSG_CHANGE_CREDENTIAL => begin_change(
                stream,
                store,
                &mut pending,
                envelope.conversation,
                received.expose(),
            )?,
            psi::MSG_CREDENTIAL_RESPONSE => answer(
                stream,
                store,
                &mut pending,
                envelope.conversation,
                received.expose(),
                registered.unix_id_count,
                &save_store,
            )?,
            psi::MSG_ABANDON => {
                pending.remove(&envelope.conversation);
            }
            psi::MSG_QUERY => serve_query(
                stream,
                store,
                envelope.conversation,
                received.expose(),
                registered.unix_id_count,
            )?,
            psi::MSG_ENUMERATE_SOURCE => serve_enumeration(
                stream,
                store,
                envelope.conversation,
                received.expose(),
                registered.unix_id_count,
            )?,
            other => {
                log::warn(format_args!("unexpected message type {other:#06x}"));
            }
        }
    }
}

/// Write the store where it lives.
///
/// Both of lpsd's writers come through here: an administrative change, and a
/// principal changing their own password. Passed down rather than called
/// directly so that the paths reaching it can be tested without a disk.
fn save_store(store: &Store) -> Result<(), StoreError> {
    store.save(&RealFs, Path::new(store::STORE_PATH))
}

/// Answer a lookup. One message in, one message out; the conversation is over.
///
/// A query is not a logon and holds no state, so nothing goes into `pending`.
fn serve_query(
    stream: &UnixStream,
    store: &Store,
    conversation: u64,
    buf: &[u8],
    unix_id_count: u32,
) -> io::Result<()> {
    let Ok(query) = psi::decode_query(buf) else {
        return refuse_query(stream, conversation, "malformed query");
    };
    let result = query::answer(store, &query, unix_id_count);
    match psi::encode_query_result(conversation, &result) {
        Ok(message) => send_message(stream, &message),
        // The answers were correct and too large to carry. Refusing the whole
        // conversation is right: a short array would pair answers with the wrong
        // questions, which is worse than no answer.
        Err(_) => refuse_query(stream, conversation, "the answer does not fit one message"),
    }
}

/// Answer an enumeration page.
fn serve_enumeration(
    stream: &UnixStream,
    store: &Store,
    conversation: u64,
    buf: &[u8],
    unix_id_count: u32,
) -> io::Result<()> {
    let Ok(request) = psi::decode_enumerate_source(buf) else {
        return refuse_query(stream, conversation, "malformed enumeration");
    };
    let result = query::enumerate(store, &request, unix_id_count);
    match psi::encode_enumerate_result(conversation, &result) {
        Ok(message) => send_message(stream, &message),
        Err(_) => refuse_query(stream, conversation, "the page does not fit one message"),
    }
}

fn refuse_query(stream: &UnixStream, conversation: u64, reason: &str) -> io::Result<()> {
    log::warn(format_args!(
        "query: refusing conversation {conversation}: {reason}"
    ));
    let message = psi::encode_refusal(
        conversation,
        &psi::Refusal {
            denial: Denial::MalformedRequest,
            reason: reason.to_string(),
        },
    )
    .map_err(|_| io::Error::other("could not encode a refusal"))?;
    send_message(stream, &message)
}

/// Tell the authority that everything here may have changed.
///
/// Sent on every administrative write, and deliberately before the write is
/// observable through a query: an invalidation arriving *after* the new answer
/// leaves a window in which authd's cache and this store disagree while both
/// believe themselves current — which is indistinguishable, from authd's side,
/// from the notification never arriving at all.
///
/// [`psi::ChangeScope::All`] rather than naming the object. Over-invalidating
/// costs a query; under-invalidating costs correctness, and the administrative
/// protocol has calls that touch more than one principal.
fn notify_changed(stream: &UnixStream) {
    let Ok(message) = psi::encode_changed(&psi::Changed {
        scope: psi::ChangeScope::All,
        sid: Vec::new(),
    }) else {
        return;
    };
    if let Err(error) = send_message(stream, &message) {
        // §2.6 makes a failed write fatal to the connection: a partial write
        // desynchronises the stream exactly as a bad frame does, and the
        // reasoning that authd treats a lost connection as a whole-source
        // invalidation only holds if the connection actually goes.
        //
        // Tearing it down is what makes that true. Logging and carrying on left
        // a stream that may have half a message in it, and a lost invalidation
        // with nothing to fall back on — lpsd declares entry_ttl = 0, so there
        // is no backstop.
        log::error(format_args!(
            "could not notify the authority of a change: {error}; dropping the connection"
        ));
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Open a conversation: decide what to ask for, or that nothing is needed.
fn begin(
    stream: &UnixStream,
    store: &Store,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    buf: &[u8],
    unix_id_count: u32,
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

    // What this principal needs, before anything is collected. Only two answers
    // come back, and neither separates "exists" from "does not exist" — see
    // `Store::credential_requirement`.
    match store.credential_requirement(&request.start.identifier) {
        // Nothing to collect. Assert straight away: the relay carries an
        // assertion on the first inbound perfectly well (PGSS Logon §4.1 —
        // "a client that supports nothing … an authority MUST either complete
        // the logon without prompting or deny it"), so no prompt is ever
        // rendered and the client shows nothing.
        store::CredentialRequirement::None(identity) => {
            log::info(format_args!(
                "asserting {} without a credential",
                identity.name
            ));
            assert_identity(stream, conversation, &identity, unix_id_count)
        }

        store::CredentialRequirement::Password => {
            // The client must be able to render what we are about to ask for.
            // Checked *here*, after the requirement is known, rather than on the
            // way in: a client that advertises nothing is asking whether this
            // principal is passwordless, and answering "no supported method"
            // before looking would refuse the one question it came to ask.
            //
            // authd polices this too and would catch the prompt on the way out,
            // but its denial says the authority asked for something the client
            // cannot provide — which reads as an authd fault on every ordinary
            // fallback. The source is where the choice is made, so the refusal
            // belongs here.
            if !request
                .start
                .supported_credential_types
                .contains(&CredentialType::Password)
            {
                return refuse(
                    stream,
                    conversation,
                    Denial::AuthenticationFailed,
                    "Authentication failed.",
                );
            }

            // §2.7: an authority may not open a conversation with an
            // identifier already in use, and a source rejects one that does.
            // `insert` replaced the existing state and a second
            // CredentialRequest went out — obligation 13 survived, because
            // `answer` removes the entry before acting so only one terminal is
            // ever sent, but the first conversation was silently abandoned.
            if pending.contains_key(&conversation) {
                return Err(io::Error::other(
                    "the authority reused a conversation identifier that is still live",
                ));
            }
            let identifier = request.start.identifier.clone();
            pending.insert(conversation, Pending::Logon { identifier });

            ask(stream, conversation, &request.start.identifier)
        }
    }
}

/// An identifier, rendered safe to put on a terminal.
///
/// The identifier is arbitrary bytes chosen by the client, and this message is
/// displayed by `login` on a real tty. Control characters are replaced rather
/// than passed through, so a name cannot carry escape sequences that reposition
/// the cursor or clear the screen around a password prompt.
///
/// Not a security boundary — the caller is rendering its own bytes to its own
/// terminal — but a prompt is a bad place to start trusting input, and a
/// relayed identifier reaches a terminal nobody has vetted.
fn displayable(identifier: &[u8]) -> String {
    String::from_utf8_lossy(identifier)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// Ask for the password, saying who is being logged in.
///
/// The name comes back from the authority rather than being printed by the
/// client, because the client does not know the realm — a qualified
/// `name@realm` is the authority's to render once realms exist, and putting the
/// line here now means only the text changes then.
///
/// Rendered from the identifier the *client sent*, never from a store lookup.
/// Echoing a looked-up name would say this principal exists, which is exactly
/// the distinction obligation 22 forbids; echoing the caller's own bytes back
/// to the caller says nothing it did not already know.
fn ask(stream: &UnixStream, conversation: u64, identifier: &[u8]) -> io::Result<()> {
    let request = CredentialRequest {
        messages: vec![Message {
            severity: MessageSeverity::Info,
            text: format!("Logging in as {}", displayable(identifier)),
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

/// Handle an answer: verify it and reach a terminal state, or ask the next
/// question.
#[allow(clippy::too_many_arguments)]
fn answer(
    stream: &UnixStream,
    store: &mut Store,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    buf: &[u8],
    unix_id_count: u32,
    save: &dyn Fn(&Store) -> Result<(), StoreError>,
) -> io::Result<()> {
    // Removed rather than borrowed: a round gets exactly one answer, and taking
    // the state out means a client that sends two cannot retry against
    // remembered context. A change that goes on to another round puts back
    // only what that round needs.
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

    match state {
        Pending::Logon { identifier } => answer_logon(
            stream,
            store,
            conversation,
            &identifier,
            &response,
            unix_id_count,
        ),
        Pending::Change(change) => answer_change(
            stream,
            store,
            pending,
            conversation,
            change,
            &response,
            save,
        ),
    }
}

/// The material answering one prompt, or empty if it went unanswered.
///
/// PGSS §2.8: a missing answer is a failed exchange, not a protocol violation,
/// and an empty one fails every check a missing one should.
fn answered(response: &CredentialResponse, credential_ref: u32) -> &[u8] {
    response
        .answers
        .iter()
        .find(|answer| answer.credential_ref == credential_ref)
        .map_or(&[], |answer| answer.data.expose())
}

/// Verify a logon's password and reach a terminal state.
fn answer_logon(
    stream: &UnixStream,
    store: &Store,
    conversation: u64,
    identifier: &[u8],
    response: &CredentialResponse,
    unix_id_count: u32,
) -> io::Result<()> {
    let secret = answered(response, PASSWORD_REF);

    match store.authenticate(identifier, secret) {
        Some(identity) => {
            log::info(format_args!(
                "authenticated {} as {} in {} group(s)",
                identity.name,
                identity.sid,
                identity.groups.len()
            ));
            assert_identity(stream, conversation, &identity, unix_id_count)
        }
        None => {
            // One log line for both "no such principal" and "wrong password".
            // The distinction is a username oracle, and while it may eventually
            // be worth recording in an audit trail an administrator can read,
            // it must never reach the caller.
            log::warn(format_args!(
                "authentication failed for {}",
                String::from_utf8_lossy(identifier)
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

// ---------------------------------------------------------------------------
// Changing one's own password (PSPU §2.21)
// ---------------------------------------------------------------------------

/// Open a change: resolve whose password it is, and ask for the current one.
///
/// Whose is the SID authd took from the caller's token. It is the only
/// principal this conversation can touch, and nothing the client says later
/// can name another.
fn begin_change(
    stream: &UnixStream,
    store: &Store,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    buf: &[u8],
) -> io::Result<()> {
    let Ok(request) = psi::decode_change_credential(buf) else {
        return refuse(
            stream,
            conversation,
            Denial::MalformedRequest,
            "Malformed credential change.",
        );
    };

    if pending.len() >= MAX_CONVERSATIONS {
        return refuse(
            stream,
            conversation,
            Denial::AuthorityUnavailable,
            "Too many conversations in flight.",
        );
    }
    // The same rule as a logon's: an identifier still in use is the
    // authority's mistake, and continuing would abandon the first silently.
    if pending.contains_key(&conversation) {
        return Err(io::Error::other(
            "the authority reused a conversation identifier that is still live",
        ));
    }

    let Some(principal) = SidRef::from_bytes(&request.principal) else {
        return refuse(
            stream,
            conversation,
            Denial::MalformedRequest,
            "The principal is not a SID.",
        );
    };

    let target = match store.change_target(principal) {
        Ok(target) => target,
        Err(refused) => {
            log::info(format_args!(
                "refused a password change for {principal}: {refused:?}"
            ));
            return refuse_change(stream, conversation, &refused);
        }
    };

    // Checked once the principal is known, as on a logon, so the refusal says
    // what is actually wrong. Every client that can change a password at all
    // can render one; this is for the one that cannot.
    if !request
        .start
        .supported_credential_types
        .contains(&CredentialType::Password)
    {
        return refuse(
            stream,
            conversation,
            Denial::AccountRestricted,
            "This client cannot collect the password this account uses.",
        );
    }

    let message = format!("Changing the password for {}", target.name);
    pending.insert(
        conversation,
        Pending::Change(Change {
            rid: target.rid,
            name: target.name,
            stage: Stage::Current,
        }),
    );
    ask_for(
        stream,
        conversation,
        Message {
            severity: MessageSeverity::Info,
            text: message,
        },
        &[(PASSWORD_REF, "Current password")],
    )
}

/// Take one round of a change forward.
fn answer_change(
    stream: &UnixStream,
    store: &mut Store,
    pending: &mut HashMap<u64, Pending>,
    conversation: u64,
    change: Change,
    response: &CredentialResponse,
    save: &dyn Fn(&Store) -> Result<(), StoreError>,
) -> io::Result<()> {
    let Change { rid, name, stage } = change;
    match stage {
        Stage::Current => match store.prove_current(rid, answered(response, PASSWORD_REF)) {
            Ok(proof) => {
                pending.insert(
                    conversation,
                    Pending::Change(Change {
                        rid,
                        name,
                        stage: Stage::New { proof, attempts: 0 },
                    }),
                );
                ask_for_new(stream, conversation, None)
            }
            Err(refused) => {
                log::warn(format_args!(
                    "password change for {name} refused: {refused:?}"
                ));
                refuse_change(stream, conversation, &refused)
            }
        },

        Stage::New { proof, attempts } => {
            let new = answered(response, NEW_PASSWORD_REF);
            let again = answered(response, AGAIN_REF);

            // Said as an error and asked again, rather than refused, because
            // the principal has proved who they are and a typo is not worth
            // making them do it twice.
            let problem = if new.is_empty() {
                Some("An empty password is not a password.")
            } else if new != again {
                Some("The passwords do not match.")
            } else {
                None
            };
            if let Some(problem) = problem {
                let attempts = attempts + 1;
                if attempts >= MAX_NEW_PASSWORD_ATTEMPTS {
                    log::info(format_args!(
                        "password change for {name} abandoned after {attempts} attempts"
                    ));
                    return refuse(
                        stream,
                        conversation,
                        Denial::ConversationLimit,
                        "Too many attempts. The password is unchanged.",
                    );
                }
                pending.insert(
                    conversation,
                    Pending::Change(Change {
                        rid,
                        name,
                        stage: Stage::New { proof, attempts },
                    }),
                );
                return ask_for_new(stream, conversation, Some(problem));
            }

            commit_change(stream, store, conversation, rid, &name, &proof, new, save)
        }
    }
}

/// Replace the password and make it durable, or change nothing.
///
/// The same discipline as an administrative change: applied in memory, written
/// to disk, and only then reported — rolled back if the write fails, so success
/// means the next logon checks the new password and failure means it still
/// checks the old one.
///
/// No change notification follows. A password is nothing a query can observe,
/// so there is no answer an authority could be holding that this makes stale.
#[allow(clippy::too_many_arguments)]
fn commit_change(
    stream: &UnixStream,
    store: &mut Store,
    conversation: u64,
    rid: u32,
    name: &str,
    proof: &store::Proof,
    new: &[u8],
    save: &dyn Fn(&Store) -> Result<(), StoreError>,
) -> io::Result<()> {
    let snapshot = store.clone();
    if let Err(refused) = store.change_proven_password(rid, proof, new) {
        log::warn(format_args!(
            "password change for {name} refused: {refused:?}"
        ));
        return refuse_change(stream, conversation, &refused);
    }
    if let Err(error) = save(store) {
        *store = snapshot;
        log::error(format_args!(
            "could not save a password change for {name}: {error}; it was not applied"
        ));
        return refuse(
            stream,
            conversation,
            Denial::Internal,
            "The new password could not be saved. The password is unchanged.",
        );
    }

    log::info(format_args!("{name} changed their own password"));
    let message = psi::encode_credential_changed(conversation)
        .map_err(|_| io::Error::other("could not encode a credential change"))?;
    send_message(stream, &message)
}

/// Ask for a new password and its confirmation, saying what was wrong with the
/// last one if anything was.
fn ask_for_new(stream: &UnixStream, conversation: u64, problem: Option<&str>) -> io::Result<()> {
    let messages: Vec<Message> = problem
        .map(|text| Message {
            severity: MessageSeverity::Error,
            text: text.to_string(),
        })
        .into_iter()
        .collect();
    send_request(
        stream,
        conversation,
        messages,
        &[
            (NEW_PASSWORD_REF, "New password"),
            (AGAIN_REF, "Retype new password"),
        ],
    )
}

fn ask_for(
    stream: &UnixStream,
    conversation: u64,
    message: Message,
    prompts: &[(u32, &str)],
) -> io::Result<()> {
    send_request(stream, conversation, vec![message], prompts)
}

/// Send a round of password prompts.
fn send_request(
    stream: &UnixStream,
    conversation: u64,
    messages: Vec<Message>,
    prompts: &[(u32, &str)],
) -> io::Result<()> {
    let request = CredentialRequest {
        messages,
        prompts: prompts
            .iter()
            .map(|(credential_ref, name)| Prompt {
                credential_ref: *credential_ref,
                credential_type: CredentialType::Password,
                credential_name: (*name).to_string(),
            })
            .collect(),
    };
    let message = psi::encode_credential_request(conversation, &request)
        .map_err(|_| io::Error::other("could not encode a credential request"))?;
    send_message(stream, &message)
}

/// End a change with the refusal that says what stopped it.
///
/// The caller is already signed in as this principal, so none of this is an
/// existence oracle, and the reasons say plainly what is wrong — except for a
/// password that did not verify, which keeps §2.10's one wording whichever
/// password it was.
fn refuse_change(
    stream: &UnixStream,
    conversation: u64,
    refused: &store::ChangeRefused,
) -> io::Result<()> {
    let (denial, reason) = match refused {
        store::ChangeRefused::NoSuchPrincipal => {
            (Denial::AccountRestricted, "This account no longer exists.")
        }
        store::ChangeRefused::Disabled => (Denial::AccountRestricted, "This account is disabled."),
        store::ChangeRefused::NoCredential => (
            Denial::AccountRestricted,
            "This account has no password to change. An administrator can set one with lps password.",
        ),
        store::ChangeRefused::WrongPassword | store::ChangeRefused::Superseded => {
            (Denial::AuthenticationFailed, "Authentication failed.")
        }
        store::ChangeRefused::Rejected(_) => (
            Denial::Internal,
            "The new password could not be set. The password is unchanged.",
        ),
    };
    refuse(stream, conversation, denial, reason)
}

/// Tell the authority who this is.
///
/// Every relative identifier is confined to the assigned count on the way
/// out (PSI §2.20, obligation 21), exactly as on the query path: an
/// out-of-range number becomes "no number", loudly, rather than a claim
/// the authority would refuse.
fn assert_identity(
    stream: &UnixStream,
    conversation: u64,
    identity: &store::Identity,
    unix_id_count: u32,
) -> io::Result<()> {
    let confined = |unix_id: u32| {
        if unix_id != 0 && unix_id >= unix_id_count {
            log::warn(format_args!(
                "relative id {unix_id} for {} is outside the assigned count \
                 {unix_id_count}; asserting no number instead",
                identity.name
            ));
            0
        } else {
            unix_id
        }
    };
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
                    unix_id: confined(group.unix_id.unwrap_or(0)),
                })
                .collect(),
            // Relative. authd adds the base.
            unix_id: confined(identity.unix_id),
            // Stated, not enforced. lpsd holds the property because it holds
            // the principal; deciding what to do about it is the authority's,
            // which is the same division as every other field here.
            permitted_logon_types: identity.permitted_logon_types,
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

fn refuse(stream: &UnixStream, conversation: u64, denial: Denial, reason: &str) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    //! The change conversation, driven over a socketpair as authd would drive
    //! it — everything but the disk, which each test supplies.

    use super::*;
    use crate::store::NewPrincipal;
    use libauthd::Secret;
    use libauthd::wire::{Answer, CredentialChangeStart};

    const CONVERSATION: u64 = 7;

    fn saved(_: &Store) -> Result<(), StoreError> {
        Ok(())
    }

    fn unsaveable(_: &Store) -> Result<(), StoreError> {
        Err(StoreError::Io(io::Error::other("the disk is full")))
    }

    /// What lpsd sent back for one step.
    #[derive(Debug)]
    enum Sent {
        Request(CredentialRequest),
        Changed,
        Refused(Denial),
    }

    struct Harness {
        store: Store,
        pending: HashMap<u64, Pending>,
        lpsd: UnixStream,
        authd: UnixStream,
    }

    impl Harness {
        fn with(name: &str, password: Option<&[u8]>) -> Self {
            let mut store = Store::provision().expect("must provision");
            store
                .add(NewPrincipal::named(name), password)
                .expect("must add");
            let (lpsd, authd) = UnixStream::pair().expect("socketpair");
            Self {
                store,
                pending: HashMap::new(),
                lpsd,
                authd,
            }
        }

        fn sid_of(&self, name: &str) -> Vec<u8> {
            self.store
                .record(name)
                .expect("must read")
                .sid
                .as_ref()
                .as_bytes()
                .to_vec()
        }

        fn open_with(&mut self, principal: Vec<u8>, supported: Vec<CredentialType>) -> Sent {
            let message = psi::encode_change_credential(
                CONVERSATION,
                &psi::ChangeCredential {
                    start: CredentialChangeStart {
                        supported_credential_types: supported,
                    },
                    principal,
                },
            )
            .expect("encodes");
            begin_change(
                &self.lpsd,
                &self.store,
                &mut self.pending,
                CONVERSATION,
                &message,
            )
            .expect("served");
            self.sent()
        }

        fn open(&mut self, name: &str) -> Sent {
            let sid = self.sid_of(name);
            self.open_with(sid, vec![CredentialType::Password])
        }

        fn reply(
            &mut self,
            answers: &[(u32, &[u8])],
            save: &dyn Fn(&Store) -> Result<(), StoreError>,
        ) -> Sent {
            let message = psi::encode_credential_response(
                CONVERSATION,
                &CredentialResponse {
                    answers: answers
                        .iter()
                        .map(|(credential_ref, data)| Answer {
                            credential_ref: *credential_ref,
                            data: Secret::from_slice(data),
                        })
                        .collect(),
                },
            )
            .expect("encodes");
            answer(
                &self.lpsd,
                &mut self.store,
                &mut self.pending,
                CONVERSATION,
                message.expose(),
                1_000_000,
                save,
            )
            .expect("served");
            self.sent()
        }

        fn sent(&self) -> Sent {
            let received = recv_message(&psi::FRAMING, &self.authd).expect("a reply");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            assert_eq!(envelope.conversation, CONVERSATION);
            match envelope.msg_type {
                psi::MSG_CREDENTIAL_REQUEST => Sent::Request(
                    psi::decode_credential_request(received.expose()).expect("a request"),
                ),
                psi::MSG_CREDENTIAL_CHANGED => Sent::Changed,
                psi::MSG_REFUSAL => Sent::Refused(
                    psi::decode_refusal(received.expose())
                        .expect("a refusal")
                        .denial,
                ),
                other => panic!("unexpected message {other:#06x}"),
            }
        }

        fn authenticates(&self, name: &str, password: &[u8]) -> bool {
            self.store.authenticate(name.as_bytes(), password).is_some()
        }
    }

    fn refs(sent: &Sent) -> Vec<u32> {
        match sent {
            Sent::Request(request) => request.prompts.iter().map(|p| p.credential_ref).collect(),
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn a_change_proves_the_current_password_and_replaces_it() {
        let mut h = Harness::with("jack", Some(b"old"));

        let first = h.open("jack");
        assert_eq!(
            refs(&first),
            vec![PASSWORD_REF],
            "the current password first"
        );
        let Sent::Request(request) = &first else {
            unreachable!()
        };
        assert!(request.messages[0].text.contains("jack"));

        let second = h.reply(&[(PASSWORD_REF, b"old")], &saved);
        assert_eq!(refs(&second), vec![NEW_PASSWORD_REF, AGAIN_REF]);

        let last = h.reply(&[(NEW_PASSWORD_REF, b"new"), (AGAIN_REF, b"new")], &saved);
        assert!(matches!(last, Sent::Changed));
        assert!(h.authenticates("jack", b"new"));
        assert!(!h.authenticates("jack", b"old"));
        assert!(
            h.pending.is_empty(),
            "a finished change must leave nothing behind"
        );
    }

    #[test]
    fn a_wrong_current_password_ends_the_change() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        assert!(matches!(
            h.reply(&[(PASSWORD_REF, b"guess")], &saved),
            Sent::Refused(Denial::AuthenticationFailed)
        ));
        assert!(h.pending.is_empty());
        assert!(h.authenticates("jack", b"old"));
    }

    /// A typo in the new password is asked again, with the reason, rather than
    /// making the principal prove themselves twice.
    #[test]
    fn a_mismatch_is_asked_again() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        h.reply(&[(PASSWORD_REF, b"old")], &saved);

        let again = h.reply(&[(NEW_PASSWORD_REF, b"new"), (AGAIN_REF, b"nwe")], &saved);
        let Sent::Request(request) = &again else {
            panic!("expected to be asked again, got {again:?}")
        };
        assert_eq!(request.messages[0].severity, MessageSeverity::Error);
        assert_eq!(refs(&again), vec![NEW_PASSWORD_REF, AGAIN_REF]);

        assert!(matches!(
            h.reply(&[(NEW_PASSWORD_REF, b"new"), (AGAIN_REF, b"new")], &saved),
            Sent::Changed
        ));
        assert!(h.authenticates("jack", b"new"));
    }

    /// A missing answer is a failed attempt like an empty one, not a protocol
    /// violation (PGSS §2.8).
    #[test]
    fn an_empty_or_missing_new_password_is_asked_again() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        h.reply(&[(PASSWORD_REF, b"old")], &saved);
        assert!(matches!(h.reply(&[], &saved), Sent::Request(_)));
        assert!(matches!(
            h.reply(&[(NEW_PASSWORD_REF, b""), (AGAIN_REF, b"")], &saved),
            Sent::Request(_)
        ));
    }

    #[test]
    fn too_many_attempts_end_the_change_with_the_password_unchanged() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        h.reply(&[(PASSWORD_REF, b"old")], &saved);

        let mut last = None;
        for _ in 0..MAX_NEW_PASSWORD_ATTEMPTS {
            last = Some(h.reply(&[(NEW_PASSWORD_REF, b"a"), (AGAIN_REF, b"b")], &saved));
        }
        assert!(matches!(
            last,
            Some(Sent::Refused(Denial::ConversationLimit))
        ));
        assert!(h.pending.is_empty());
        assert!(h.authenticates("jack", b"old"));
    }

    /// Durable or nothing: a change the disk would not take is rolled back, and
    /// the principal is told it did not happen.
    #[test]
    fn a_change_that_cannot_be_saved_changes_nothing() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        h.reply(&[(PASSWORD_REF, b"old")], &saved);
        assert!(matches!(
            h.reply(
                &[(NEW_PASSWORD_REF, b"new"), (AGAIN_REF, b"new")],
                &unsaveable
            ),
            Sent::Refused(Denial::Internal)
        ));
        assert!(h.authenticates("jack", b"old"));
        assert!(!h.authenticates("jack", b"new"));
    }

    /// There is no current password to prove, so the account's token alone
    /// would be setting a credential for it.
    #[test]
    fn a_passwordless_principal_is_refused_before_anything_is_asked() {
        let mut h = Harness::with("kiosk", None);
        assert!(matches!(
            h.open("kiosk"),
            Sent::Refused(Denial::AccountRestricted)
        ));
        assert!(h.pending.is_empty());
    }

    #[test]
    fn a_principal_that_is_not_a_sid_is_malformed() {
        let mut h = Harness::with("jack", Some(b"old"));
        assert!(matches!(
            h.open_with(vec![1, 2, 3], vec![CredentialType::Password]),
            Sent::Refused(Denial::MalformedRequest)
        ));
    }

    #[test]
    fn a_client_that_cannot_render_a_password_is_refused() {
        let mut h = Harness::with("jack", Some(b"old"));
        let sid = h.sid_of("jack");
        assert!(matches!(
            h.open_with(sid, Vec::new()),
            Sent::Refused(Denial::AccountRestricted)
        ));
        assert!(h.pending.is_empty());
    }

    /// An abandon mid-change drops what the first round established, so a
    /// late answer cannot complete it.
    #[test]
    fn an_abandoned_change_cannot_be_completed() {
        let mut h = Harness::with("jack", Some(b"old"));
        h.open("jack");
        h.reply(&[(PASSWORD_REF, b"old")], &saved);
        h.pending.remove(&CONVERSATION);

        let message = psi::encode_credential_response(
            CONVERSATION,
            &CredentialResponse {
                answers: vec![
                    Answer {
                        credential_ref: NEW_PASSWORD_REF,
                        data: Secret::from_slice(b"new"),
                    },
                    Answer {
                        credential_ref: AGAIN_REF,
                        data: Secret::from_slice(b"new"),
                    },
                ],
            },
        )
        .expect("encodes");
        answer(
            &h.lpsd,
            &mut h.store,
            &mut h.pending,
            CONVERSATION,
            message.expose(),
            1_000_000,
            &saved,
        )
        .expect("served");
        assert!(h.authenticates("jack", b"old"));
        assert!(!h.authenticates("jack", b"new"));
    }
}
