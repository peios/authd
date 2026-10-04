//! The self socket: a principal reading their own account, and setting their
//! own display name. PSPU §10.11.
//!
//! # Who it is for
//!
//! Every authenticated principal may connect, and no request names anybody:
//! the subject is always the user of the connected peer's token, read when the
//! connection is accepted. So reaching the socket lets a caller see and change
//! exactly one account — their own — and nothing they send can point it at
//! another. A display name is not a credential, so no proof is asked; adding
//! or removing a key is, and goes through the logon socket instead (PGSS
//! §2.23), where the current password is.
//!
//! # Why it is served differently from the admin socket
//!
//! lpsd is one thread, and [`crate::admin`] blocks on its client for up to five
//! seconds — tolerable for a socket only administrators reach. This one admits
//! everybody, so a blocking read would let any signed-in principal stall every
//! logon on the machine by connecting and saying nothing. Instead each
//! connection is non-blocking and lives in a [`Table`] the poll loop drives: a
//! read or a write happens only when `poll` says it will not block, a
//! connection holds a deadline the loop wakes for, and a peer that dawdles is
//! dropped at it while everything else carries on.
//!
//! # Bounds
//!
//! At most [`MAX_CONNECTIONS`] open at once, at most [`MAX_PER_PEER`] of them
//! from any one user, at most [`lps::MAX_SELF_REQUEST_BYTES`] read from any
//! one, and [`DEADLINE`] from accept to the last byte of the answer. A caller
//! over a bound is refused with `Failed` where the socket will take it without
//! blocking, and closed.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use libauthd::lps::{self, Failed, Failure};
use libauthd::{LPSD_RUN_DIR, LPSD_SELF_SOCKET_PATH, frame};
use peios::security::{Sid, SidRef};

use crate::log;
use crate::store::{Store, StoreError};

/// How many self-socket connections may be open at once.
pub const MAX_CONNECTIONS: usize = 32;

/// How many of them one user may hold. Keyed on the token's user SID, so a
/// principal with many sessions is still one caller.
pub const MAX_PER_PEER: usize = 4;

/// From accept to the last byte of the answer.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// The socket's descriptor: SYSTEM and Administrators, and every
/// authenticated principal with what a connect needs (`FILE_WRITE_DATA`,
/// `READ_ATTRIBUTES`, `SYNCHRONIZE`) — the mask authd grants on
/// `/run/logon.sock`, for the same reason. Protected, so `/run/lpsd`'s
/// inheritance can neither widen nor narrow it.
pub const SOCKET_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100082;;;AU)";

/// Bind the self socket, non-blocking, and stamp its descriptor.
///
/// Non-blocking for accept as well as for each connection: `poll` saying the
/// listener is readable does not promise `accept` will not block, since the
/// peer may have gone in between.
pub fn listen() -> io::Result<UnixListener> {
    std::fs::create_dir_all(Path::new(LPSD_RUN_DIR))?;
    let path = Path::new(LPSD_SELF_SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {LPSD_SELF_SOCKET_PATH}")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    protect(path);
    Ok(listener)
}

/// Stamp [`SOCKET_SDDL`] and read it back.
///
/// Load-bearing: the socket would otherwise inherit `/run/lpsd`'s descriptor,
/// which admits SYSTEM, Administrators and lpsd, and nobody the socket is for.
/// Not fatal, as the admin socket's is not — a daemon that cannot
/// authenticate is worse than one whose self-service is unreachable — but
/// loud, and checked, because a stamp that silently did not take looks
/// exactly like a working socket to everyone it was meant to refuse.
fn protect(path: &Path) {
    use peios::file::SecInfo;
    use peios::security::sddl;

    let consequence = "principals will not be able to read their own accounts";
    let descriptor = match sddl::parse(SOCKET_SDDL) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            log::error(format_args!(
                "self: could not build a descriptor: {error}; {consequence}"
            ));
            return;
        }
    };
    if let Err(error) =
        peios::file::set_sd(None, path, SecInfo::DACL, &descriptor, libc::AT_SYMLINK_NOFOLLOW)
    {
        log::error(format_args!(
            "self: could not set a descriptor on {}: {error}; {consequence}",
            path.display()
        ));
        return;
    }
    let readback = peios::file::get_sd(None, path, SecInfo::DACL, libc::AT_SYMLINK_NOFOLLOW)
        .ok()
        .and_then(|actual| sddl::format(actual.as_bytes()).ok());
    let expected = sddl::format(descriptor.as_bytes()).ok();
    if readback.is_none() || readback != expected {
        log::error(format_args!(
            "self: {} does not carry the descriptor it was given ({readback:?}); {consequence}",
            path.display()
        ));
    }
}

/// Where a connection is.
enum State {
    /// Collecting the request. Never more than its header says, and never
    /// more than [`lps::MAX_SELF_REQUEST_BYTES`].
    Reading(Vec<u8>),
    /// Sending the answer, `sent` bytes in.
    Writing { reply: Vec<u8>, sent: usize },
    /// Finished, one way or another; removed at the end of the pass.
    Done,
}

struct Connection {
    stream: UnixStream,
    /// The user of the peer's token at accept. The only principal any request
    /// on this connection is about.
    peer: Sid,
    deadline: Instant,
    state: State,
}

/// The open self-socket connections, driven by lpsd's poll loop.
#[derive(Default)]
pub struct Table {
    connections: Vec<Connection>,
}

impl Table {
    pub fn new() -> Table {
        Table::default()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Accept everything waiting on `listener`, reading each peer's token.
    pub fn accept(&mut self, listener: &UnixListener, now: Instant) {
        loop {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    log::warn(format_args!("self: could not accept: {error}"));
                    return;
                }
            };
            if let Err(error) = stream.set_nonblocking(true) {
                log::warn(format_args!("self: could not make a connection non-blocking: {error}"));
                continue;
            }
            let peer = match peios::token::Token::open_peer(stream.as_fd()).and_then(|t| t.user()) {
                Ok(peer) => peer,
                Err(error) => {
                    // Without a peer there is no subject, so nothing to serve.
                    log::warn(format_args!("self: could not read a peer's token: {error}"));
                    continue;
                }
            };
            self.admit(stream, peer, now);
        }
    }

    /// Take a connection whose peer is `peer`, or refuse it if a bound says
    /// so. Separate from [`Table::accept`] so tests can name the peer.
    pub fn admit(&mut self, stream: UnixStream, peer: Sid, now: Instant) -> bool {
        let refusal = if self.connections.len() >= MAX_CONNECTIONS {
            Some("lpsd is busy. Try again shortly.")
        } else if self
            .connections
            .iter()
            .filter(|c| c.peer == peer)
            .count()
            >= MAX_PER_PEER
        {
            Some("You have too many requests open to lpsd at once.")
        } else {
            None
        };
        if let Some(reason) = refusal {
            log::warn(format_args!("self: refused {peer}: {reason}"));
            // One try, without blocking: a peer that cannot take a few dozen
            // bytes right now is not owed a wait.
            if let Ok(reply) = failed(Failure::Internal, reason) {
                let _ = (&stream).write(&reply);
            }
            return false;
        }
        self.connections.push(Connection {
            stream,
            peer,
            deadline: now + DEADLINE,
            state: State::Reading(Vec::new()),
        });
        true
    }

    /// What to poll for, one entry a connection, in table order.
    pub fn pollfds(&self) -> Vec<libc::pollfd> {
        self.connections
            .iter()
            .map(|c| libc::pollfd {
                fd: c.stream.as_raw_fd(),
                events: match c.state {
                    State::Writing { .. } => libc::POLLOUT,
                    _ => libc::POLLIN,
                },
                revents: 0,
            })
            .collect()
    }

    /// The earliest deadline, for the poll loop's timeout.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.connections.iter().map(|c| c.deadline).min()
    }

    /// Serve every connection `poll` reported ready, then drop those that
    /// finished or ran out of time. `ready` is [`Table::pollfds`]'s result,
    /// in the same order; `save` persists the store and announces the change.
    pub fn serve(
        &mut self,
        ready: &[libc::pollfd],
        now: Instant,
        store: &mut Store,
        save: &mut dyn FnMut(&Store) -> Result<(), StoreError>,
    ) {
        for (connection, polled) in self.connections.iter_mut().zip(ready) {
            debug_assert_eq!(connection.stream.as_raw_fd(), polled.fd as RawFd);
            if polled.revents == 0 {
                continue;
            }
            step(connection, store, save);
        }
        self.expire(now);
    }

    /// Drop every finished connection, and every one past its deadline.
    pub fn expire(&mut self, now: Instant) {
        self.connections.retain(|c| {
            let keep = !matches!(c.state, State::Done) && c.deadline > now;
            if !keep && !matches!(c.state, State::Done) {
                log::warn(format_args!(
                    "self: dropped a connection from {} that ran past its deadline",
                    c.peer
                ));
            }
            keep
        });
    }
}

/// Take one connection as far as it will go without blocking.
fn step(
    connection: &mut Connection,
    store: &mut Store,
    save: &mut dyn FnMut(&Store) -> Result<(), StoreError>,
) {
    if let State::Reading(buffer) = &mut connection.state {
        match read_request(&connection.stream, buffer) {
            Ok(None) => return,
            Ok(Some(Ok(()))) => {
                let reply = answer(store, connection.peer.as_ref(), buffer, save);
                connection.state = State::Writing { reply, sent: 0 };
            }
            Ok(Some(Err(reply))) => connection.state = State::Writing { reply, sent: 0 },
            Err(_) => {
                connection.state = State::Done;
                return;
            }
        }
    }
    if let State::Writing { reply, sent } = &mut connection.state {
        loop {
            match (&connection.stream).write(&reply[*sent..]) {
                Ok(0) => break,
                Ok(n) => {
                    *sent += n;
                    if *sent == reply.len() {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // All of it, or a peer that went away: one exchange a connection
        // either way.
        connection.state = State::Done;
    }
}

/// Read what is waiting. `Ok(None)`: not all here yet. `Ok(Some(Ok(())))`: the
/// request is whole in `buffer`. `Ok(Some(Err(reply)))`: refused from its
/// header, with the reply to send. `Err`: the peer went away, or the
/// connection failed.
fn read_request(stream: &UnixStream, buffer: &mut Vec<u8>) -> io::Result<Option<Result<(), Vec<u8>>>> {
    loop {
        // Never read past the header until the header has said how much
        // follows, and never past that: one request a connection, and no
        // more bytes held than it declared.
        let want = if buffer.len() < lps::HEADER_BYTES {
            lps::HEADER_BYTES
        } else {
            let total = match frame::decode_header(&lps::SELF_REQUEST_FRAMING, buffer) {
                Ok((_, total)) => total,
                Err(libauthd::WireError::TooLong) => {
                    let reply = failed(
                        Failure::Invalid,
                        "The request is larger than this socket reads.",
                    );
                    return Ok(Some(Err(reply.unwrap_or_default())));
                }
                Err(_) => {
                    let reply = failed(Failure::Invalid, "Malformed request.");
                    return Ok(Some(Err(reply.unwrap_or_default())));
                }
            };
            // At least a header, by `decode_header`'s own check.
            if buffer.len() == total {
                return Ok(Some(Ok(())));
            }
            total
        };
        let start = buffer.len();
        buffer.resize(want, 0);
        match (&*stream).read(&mut buffer[start..]) {
            Ok(0) => {
                buffer.truncate(start);
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(n) => buffer.truncate(start + n),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                buffer.truncate(start);
                return Ok(None);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => buffer.truncate(start),
            Err(error) => {
                buffer.truncate(start);
                return Err(error);
            }
        }
    }
}

fn failed(failure: Failure, reason: &str) -> Result<Vec<u8>, libauthd::WireError> {
    lps::encode_failed(&Failed {
        failure,
        reason: reason.to_string(),
    })
}

/// What a principal no source here holds is told.
const NOT_HELD: &str =
    "This account is not one this machine's local principal store holds, so it has nothing here to \
     show or change.";

/// Answer one request from `peer`. The peer is the subject of every request;
/// nothing in `request` can name another.
pub fn answer(
    store: &mut Store,
    peer: &SidRef,
    request: &[u8],
    save: &mut dyn FnMut(&Store) -> Result<(), StoreError>,
) -> Vec<u8> {
    let reply = match lps::decode_type(request) {
        Ok((lps::MSG_SHOW_SELF, _)) => match lps::decode_show_self(request) {
            Ok(()) => show(store, peer),
            Err(_) => failed(Failure::Invalid, "Malformed request."),
        },
        Ok((lps::MSG_SET_DISPLAY_NAME, _)) => match lps::decode_set_display_name(request) {
            Ok(set) => set_display_name(store, peer, &set.display_name, save),
            Err(_) => failed(Failure::Invalid, "Malformed request."),
        },
        // The admin socket's requests among them: each socket refuses the
        // other's range.
        Ok(_) => failed(Failure::Invalid, "This socket does not answer that request."),
        Err(_) => failed(Failure::Invalid, "Malformed request."),
    };
    reply.unwrap_or_else(|_| {
        failed(Failure::Internal, "lpsd could not encode its answer.").unwrap_or_default()
    })
}

fn show(store: &Store, peer: &SidRef) -> Result<Vec<u8>, libauthd::WireError> {
    let Some(own) = store.own_account(peer) else {
        return failed(Failure::NotFound, NOT_HELD);
    };
    lps::encode_self(&lps::OwnAccount {
        name: own.name,
        sid: own.sid.as_ref().as_bytes().to_vec(),
        display_name: own.display_name,
        enabled: own.enabled,
        policy: own.policy,
        has_password: own.has_password,
        keys: own
            .keys
            .iter()
            .map(|key| lps::OwnKey {
                id: key.id,
                fingerprint: crate::ssh::fingerprint(&key.blob).unwrap_or_default(),
                algorithm: crate::ssh::algorithm(&key.blob).unwrap_or_default(),
                label: key.label.clone(),
                created: key.created,
            })
            .collect(),
    })
}

/// Validated exactly as the administrative `SetProfile` validates a display
/// name — the same store call — and saved and announced as it is.
fn set_display_name(
    store: &mut Store,
    peer: &SidRef,
    display_name: &str,
    save: &mut dyn FnMut(&Store) -> Result<(), StoreError>,
) -> Result<Vec<u8>, libauthd::WireError> {
    let Some(own) = store.own_account(peer) else {
        return failed(Failure::NotFound, NOT_HELD);
    };
    // A session that outlived its account's disabling is not a way to change
    // the account.
    if !own.enabled {
        return failed(Failure::Denied, "This account is disabled.");
    }
    let snapshot = store.clone();
    match store.set_display_name(&own.name, display_name) {
        Err(error) => {
            *store = snapshot;
            failed(Failure::Invalid, &error.to_string())
        }
        Ok(false) => lps::encode_done(),
        Ok(true) => match save(store) {
            Ok(()) => {
                log::info(format_args!("self: {} set their display name", own.name));
                lps::encode_done()
            }
            Err(error) => {
                *store = snapshot;
                log::error(format_args!(
                    "self: could not save {}'s display name: {error}; rolled back",
                    own.name
                ));
                failed(
                    Failure::Internal,
                    &format!("The change could not be saved and was not applied: {error}"),
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewPrincipal;
    use libauthd::transport::{recv_message, send_message};

    fn store_with(names: &[&str]) -> Store {
        let mut store = Store::provision().expect("provisions");
        for name in names {
            store
                .add(NewPrincipal::named(name), Some(b"pw"))
                .expect("adds");
        }
        store
    }

    fn sid(store: &Store, name: &str) -> Sid {
        store.record(name).expect("a record").sid
    }

    fn saves() -> impl FnMut(&Store) -> Result<(), StoreError> {
        |_: &Store| Ok(())
    }

    fn decode_failure(reply: &[u8]) -> Failed {
        lps::decode_failed(reply).expect("a refusal")
    }

    #[test]
    fn show_self_answers_for_the_peer_only() {
        let mut store = store_with(&["alice", "bob"]);
        store.set_display_name("alice", "Alice Liddell").unwrap();
        let alice = sid(&store, "alice");
        let reply = answer(&mut store, alice.as_ref(), &lps::encode_show_self().unwrap(), &mut saves());
        let account = lps::decode_self(&reply).expect("an account");
        assert_eq!(account.name, "alice");
        assert_eq!(account.display_name, "Alice Liddell");
        assert_eq!(account.sid, alice.as_ref().as_bytes());
        assert!(account.has_password && account.enabled);
        assert_eq!(account.policy, libauthd::credential::Policy::Password);
        assert!(account.keys.is_empty());
    }

    #[test]
    fn show_self_lists_keys_with_fingerprint_and_algorithm() {
        use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
        let mut store = store_with(&["alice"]);
        let pair = Ed25519Keypair::from(Ed25519PrivateKey::from_bytes(&[5; 32]));
        let line = ssh_key::PublicKey::new(pair.public.into(), "laptop")
            .to_openssh()
            .unwrap();
        store.add_key("alice", &line, "").unwrap();
        let alice = sid(&store, "alice");
        let reply = answer(&mut store, alice.as_ref(), &lps::encode_show_self().unwrap(), &mut saves());
        let key = &lps::decode_self(&reply).unwrap().keys[0];
        assert!(key.fingerprint.starts_with("SHA256:"), "{}", key.fingerprint);
        assert_eq!(key.algorithm, "ssh-ed25519");
        assert_eq!(key.label, "laptop");
    }

    /// SYSTEM, a domain user, anyone this store does not hold: a refusal that
    /// says so, never somebody else's account.
    #[test]
    fn a_principal_the_store_does_not_hold_is_told_so() {
        let mut store = store_with(&["alice"]);
        for other in ["S-1-5-18", "S-1-5-21-9-9-9-1000"] {
            let other: Sid = other.parse().unwrap();
            let reply = answer(&mut store, other.as_ref(), &lps::encode_show_self().unwrap(), &mut saves());
            let refusal = decode_failure(&reply);
            assert_eq!(refusal.failure, Failure::NotFound);
            assert_eq!(refusal.reason, NOT_HELD);
        }
    }

    #[test]
    fn set_display_name_changes_the_peers_own_and_saves_once() {
        let mut store = store_with(&["alice", "bob"]);
        let alice = sid(&store, "alice");
        let mut saved = 0;
        let mut save = |_: &Store| {
            saved += 1;
            Ok(())
        };
        let request = lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: "  Alice  ".into(),
        })
        .unwrap();
        lps::decode_done(&answer(&mut store, alice.as_ref(), &request, &mut save)).unwrap();
        // The same again changes nothing, and saves nothing.
        lps::decode_done(&answer(&mut store, alice.as_ref(), &request, &mut save)).unwrap();
        assert_eq!(saved, 1);
        assert_eq!(store.record("alice").unwrap().display_name, "Alice", "trimmed, as SetProfile");
        assert_eq!(store.record("bob").unwrap().display_name, "");
    }

    #[test]
    fn set_display_name_validates_as_set_profile_does() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let request = lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: "a\0b".into(),
        })
        .unwrap();
        let refusal = decode_failure(&answer(&mut store, alice.as_ref(), &request, &mut saves()));
        assert_eq!(refusal.failure, Failure::Invalid);
        assert!(refusal.reason.contains("NUL"));
        assert_eq!(store.record("alice").unwrap().display_name, "");
    }

    #[test]
    fn an_unsaveable_display_name_is_rolled_back() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let request = lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: "Alice".into(),
        })
        .unwrap();
        let mut fail = |_: &Store| Err(StoreError::Io(io::Error::other("the disk is full")));
        let refusal = decode_failure(&answer(&mut store, alice.as_ref(), &request, &mut fail));
        assert_eq!(refusal.failure, Failure::Internal);
        assert_eq!(store.record("alice").unwrap().display_name, "");
    }

    #[test]
    fn a_disabled_account_cannot_change_its_display_name() {
        let mut store = store_with(&["alice", "admin"]);
        store
            .add_membership("admin", Sid::well_known(peios::security::WellKnown::Administrators))
            .unwrap();
        store.set_enabled("alice", false).unwrap();
        let alice = sid(&store, "alice");
        let request = lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: "Alice".into(),
        })
        .unwrap();
        let refusal = decode_failure(&answer(&mut store, alice.as_ref(), &request, &mut saves()));
        assert_eq!(refusal.failure, Failure::Denied);
    }

    /// The admin socket's requests are refused here: this socket is not a
    /// second way to administer the store.
    #[test]
    fn an_admin_request_is_refused() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let request = lps::encode_show(&lps::Named { name: "alice".into() }).unwrap();
        let refusal = decode_failure(&answer(&mut store, alice.as_ref(), &request, &mut saves()));
        assert_eq!(refusal.failure, Failure::Invalid);
    }

    // -- The table ----------------------------------------------------------

    /// Poll the table once, as lpsd's loop does, and serve what is ready.
    fn pump(table: &mut Table, store: &mut Store, now: Instant) {
        let mut fds = table.pollfds();
        if !fds.is_empty() {
            // SAFETY: a live, exclusively borrowed array of pollfds.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        }
        table.serve(&fds, now, store, &mut saves());
    }

    fn connection() -> (UnixStream, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (client, server)
    }

    #[test]
    fn the_table_serves_a_request_and_closes() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let mut table = Table::new();
        let (client, server) = connection();
        let now = Instant::now();
        assert!(table.admit(server, alice, now));
        send_message(&client, &lps::encode_show_self().unwrap()).unwrap();
        pump(&mut table, &mut store, now);
        let reply = recv_message(&lps::FRAMING, &client).unwrap();
        assert_eq!(lps::decode_self(reply.expose()).unwrap().name, "alice");
        assert_eq!(table.len(), 0, "one exchange a connection");
    }

    /// A request arriving a byte at a time is collected across passes.
    #[test]
    fn a_request_in_pieces_is_collected() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let mut table = Table::new();
        let (client, server) = connection();
        let now = Instant::now();
        table.admit(server, alice, now);
        let request = lps::encode_show_self().unwrap();
        for byte in &request {
            (&client).write_all(std::slice::from_ref(byte)).unwrap();
            pump(&mut table, &mut store, now);
        }
        let reply = recv_message(&lps::FRAMING, &client).unwrap();
        assert!(lps::decode_self(reply.expose()).is_ok());
    }

    /// A peer that says nothing holds its slot only until its deadline, and
    /// holds nobody else up meanwhile.
    #[test]
    fn a_silent_peer_does_not_block_another_and_is_dropped_at_its_deadline() {
        let mut store = store_with(&["alice", "bob"]);
        let (alice, bob) = (sid(&store, "alice"), sid(&store, "bob"));
        let mut table = Table::new();
        let now = Instant::now();
        let (_silent, silent_server) = connection();
        table.admit(silent_server, alice, now);
        let (client, server) = connection();
        table.admit(server, bob, now);

        send_message(&client, &lps::encode_show_self().unwrap()).unwrap();
        let started = Instant::now();
        pump(&mut table, &mut store, now);
        let reply = recv_message(&lps::FRAMING, &client).unwrap();
        assert_eq!(lps::decode_self(reply.expose()).unwrap().name, "bob");
        assert!(started.elapsed() < Duration::from_secs(1), "nothing waited on the silent peer");
        assert_eq!(table.len(), 1, "the silent one is still within its time");
        assert_eq!(table.next_deadline(), Some(now + DEADLINE));

        table.expire(now + DEADLINE);
        assert_eq!(table.len(), 0, "and gone at its deadline");
    }

    #[test]
    fn one_peer_may_hold_only_so_many_connections() {
        let store = store_with(&["alice", "bob"]);
        let (alice, bob) = (sid(&store, "alice"), sid(&store, "bob"));
        let mut table = Table::new();
        let now = Instant::now();
        let mut held = Vec::new();
        for _ in 0..MAX_PER_PEER {
            let (client, server) = connection();
            assert!(table.admit(server, alice.clone(), now));
            held.push(client);
        }
        let (refused, server) = connection();
        assert!(!table.admit(server, alice.clone(), now), "one over the per-peer bound");
        let reply = recv_message(&lps::FRAMING, &refused).unwrap();
        assert!(lps::decode_failed(reply.expose()).is_ok(), "told, not just closed");

        let (_other, server) = connection();
        assert!(table.admit(server, bob, now), "another user is not counted against alice");
    }

    #[test]
    fn the_table_is_bounded_overall() {
        let mut table = Table::new();
        let now = Instant::now();
        let mut held = Vec::new();
        for i in 0..MAX_CONNECTIONS {
            let (client, server) = connection();
            let peer: Sid = format!("S-1-5-21-1-2-3-{}", 1000 + i).parse().unwrap();
            assert!(table.admit(server, peer, now));
            held.push(client);
        }
        let (_refused, server) = connection();
        let peer: Sid = "S-1-5-21-1-2-3-9999".parse().unwrap();
        assert!(!table.admit(server, peer, now));
    }

    /// A header declaring more than the self socket reads is refused from the
    /// header, and nothing beyond it is read.
    #[test]
    fn an_oversized_request_is_refused_unread() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let mut table = Table::new();
        let (client, server) = connection();
        let now = Instant::now();
        table.admit(server, alice, now);
        let mut request = lps::encode_set_display_name(&lps::SetDisplayName {
            display_name: "x".into(),
        })
        .unwrap();
        let declared = (lps::MAX_SELF_REQUEST_BYTES + 1) as u32;
        request[8..12].copy_from_slice(&declared.to_le_bytes());
        (&client).write_all(&request).unwrap();
        pump(&mut table, &mut store, now);
        let reply = recv_message(&lps::FRAMING, &client).unwrap();
        let refusal = lps::decode_failed(reply.expose()).unwrap();
        assert_eq!(refusal.failure, Failure::Invalid);
        assert_eq!(store.record("alice").unwrap().display_name, "");
    }

    /// A peer that hangs up mid-request is dropped, not left in the table.
    #[test]
    fn a_peer_that_hangs_up_is_dropped() {
        let mut store = store_with(&["alice"]);
        let alice = sid(&store, "alice");
        let mut table = Table::new();
        let (client, server) = connection();
        let now = Instant::now();
        table.admit(server, alice, now);
        (&client).write_all(&lps::encode_show_self().unwrap()[..5]).unwrap();
        drop(client);
        pump(&mut table, &mut store, now);
        assert_eq!(table.len(), 0);
    }
}
