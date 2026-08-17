//! Principal sources: the connections on `/run/psi.sock`, and the routing over
//! them.
//!
//! A principal source owns identity — its storage, its verification, its
//! prompts. authd owns none of that; it relays. What lives here is the
//! machinery that makes relaying possible: registration, the multiplexing of
//! many concurrent logons over one persistent connection, and the table of who
//! is currently registered.
//!
//! # Why the source dials in
//!
//! The connection direction and the request direction are opposite: the source
//! connects, and authd asks. That is deliberate. It means authd — which holds
//! `SeCreateTokenPrivilege` — never initiates an outbound connection to a path
//! named in configuration. It only ever accepts. A process this privileged
//! having no reason to `connect()` anywhere is a meaningfully smaller thing
//! than one that does.
//!
//! # Multiplexing
//!
//! One connection carries every logon that source is handling, tagged by a
//! conversation id that authd allocates. A reader thread per connection
//! demultiplexes inbound messages onto per-conversation channels; the
//! conversation threads on the logon side block on those channels.
//!
//! The alternative — serialising logons behind a single connection lock — would
//! turn one slow source into a system-wide login stall.
//!
//! # What is deliberately not here yet
//!
//! A source declares nothing about *scope*: which principals it may
//! authenticate, and which groups it may assert membership in. That is the
//! check which eventually stops a network-facing source from authenticating
//! local accounts, and it must be validated against configuration rather than
//! self-declared — a trusted source lying about its scope is exactly the
//! lateral movement worth preventing. With one source and a constant SID it
//! would be theatre, so it is absent rather than faked.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use libauthd::psi;
use libauthd::transport::send_message;
use libauthd::wire::{CredentialRequest, CredentialResponse, LogonStart};
use peios::security::{Sid, SidRef};

use crate::log;
use crate::policy;
use crate::unix_id;

/// How many sources may be registered at once.
pub const MAX_SOURCES: usize = 8;

/// How many logons one source may have in flight.
///
/// Bounds the demultiplexing table, so a stuck source cannot grow authd's
/// memory without bound.
const MAX_CONVERSATIONS_PER_SOURCE: usize = 256;

/// What a source can say inside a conversation.
///
/// Note there is no variant for "here is a token" or "here is a session". A
/// source has no message with which to mint, which is what makes *backends
/// assert, never mint* a structural property rather than a convention.
#[derive(Debug)]
pub enum Inbound {
    /// Ask the user for something. Relayed outward to the client verbatim.
    Request(CredentialRequest),
    /// This is who they are. authd derives a token from it.
    Assert(psi::Assertion),
    /// Refused, with a reason to relay.
    Refuse(psi::Refusal),
}

/// One registered principal source.
pub struct Source {
    /// The source's own name for itself. Becomes the session's auth-package
    /// name, so a token's provenance records which source authenticated it.
    name: String,
    /// Whether this source may assert group memberships outside the domain of
    /// the principal it authenticated. See `policy::sources`.
    may_assert_foreign_memberships: bool,
    /// The domain this source declared at registration, verified as far as it
    /// can be. Every identity it asserts is confined to this.
    domain: Sid,
    /// The Unix ID range this source's relative numbers are rebased into.
    /// `None` when none is configured, in which case its principals project to
    /// `nobody`. The numeric counterpart of `domain`.
    unix_id_range: Option<unix_id::Range>,
    stream: UnixStream,
    /// Serialises writers. Reads need no lock: there is exactly one reader
    /// thread per connection, and reading and writing a socket are independent.
    write: Mutex<()>,
    conversations: Mutex<HashMap<u64, mpsc::Sender<Inbound>>>,
    /// Conversation ids are allocated from here. Never zero — that is reserved
    /// for connection-level messages.
    next_conversation: AtomicU64,
    live: AtomicBool,
}

impl Source {
    fn new(
        name: String,
        may_assert_foreign_memberships: bool,
        domain: Sid,
        unix_id_range: Option<unix_id::Range>,
        stream: UnixStream,
    ) -> Self {
        Self {
            name,
            may_assert_foreign_memberships,
            domain,
            unix_id_range,
            stream,
            write: Mutex::new(()),
            conversations: Mutex::new(HashMap::new()),
            next_conversation: AtomicU64::new(1),
            live: AtomicBool::new(true),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn may_assert_foreign_memberships(&self) -> bool {
        self.may_assert_foreign_memberships
    }

    /// The domain this source is authoritative for.
    pub fn domain(&self) -> &Sid {
        &self.domain
    }

    /// The Unix ID range this source's numbers are rebased into.
    pub fn unix_id_range(&self) -> Option<unix_id::Range> {
        self.unix_id_range
    }

    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    fn send(&self, message: &[u8]) -> io::Result<()> {
        let result = {
            let _guard = self.write.lock().unwrap_or_else(|e| e.into_inner());
            send_message(&self.stream, message)
        };

        if let Err(ref error) = result {
            // A failed write is very likely a *partial* one, which leaves the
            // byte stream desynchronised — the codec cannot know where the next
            // message starts. So this is not a retryable per-conversation
            // error: the connection is no longer trustworthy and is torn down.
            //
            // The write timeout set at registration is what makes this
            // reachable rather than theoretical. Without it a source that
            // stopped reading would block this thread forever with the write
            // lock held, and every other logon behind it.
            log::warn(format_args!(
                "psi: {}: write failed ({error}); dropping the connection",
                self.name
            ));
            self.fail();
        }
        result
    }

    /// Tear the connection down from the writing side.
    ///
    /// Shutting the socket down is what wakes the reader thread, which is
    /// otherwise blocked in `recv` and would never notice.
    fn fail(&self) {
        self.shut_down();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Begin a conversation with this source.
    ///
    /// `None` if the source has gone away or is already at its conversation
    /// ceiling.
    pub fn open(self: &Arc<Self>) -> Option<Conversation> {
        if !self.is_live() {
            return None;
        }

        let id = self.next_conversation.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        {
            let mut table = self.conversations.lock().unwrap_or_else(|e| e.into_inner());
            if table.len() >= MAX_CONVERSATIONS_PER_SOURCE {
                return None;
            }
            table.insert(id, tx);
        }

        Some(Conversation {
            source: Arc::clone(self),
            id,
            rx,
            terminated: false,
        })
    }

    fn close_conversation(&self, id: u64) {
        self.conversations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    /// Mark the source gone and wake everyone waiting on it.
    ///
    /// Dropping the senders is what does the waking: a conversation blocked on
    /// its channel gets a disconnect rather than sitting until its timeout.
    fn shut_down(&self) {
        self.live.store(false, Ordering::Relaxed);
        self.conversations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    fn deliver(&self, id: u64, message: Inbound) {
        let table = self.conversations.lock().unwrap_or_else(|e| e.into_inner());
        match table.get(&id) {
            // The receiver having hung up is ordinary: the client may have
            // disconnected between the source answering and us delivering.
            Some(tx) => {
                let _ = tx.send(message);
            }
            None => log::warn(format_args!(
                "{}: message for unknown conversation {id}",
                self.name
            )),
        }
    }
}

/// One logon in flight against one source.
///
/// Dropping this unregisters the conversation and, unless it reached a terminal
/// state, tells the source to abandon it — so a client that hangs up mid-prompt
/// does not leave the source holding state forever.
pub struct Conversation {
    source: Arc<Source>,
    id: u64,
    rx: mpsc::Receiver<Inbound>,
    terminated: bool,
}

impl Conversation {
    pub fn source_name(&self) -> &str {
        self.source.name()
    }

    pub fn may_assert_foreign_memberships(&self) -> bool {
        self.source.may_assert_foreign_memberships()
    }

    /// The domain the answering source is authoritative for.
    pub fn domain(&self) -> &Sid {
        self.source.domain()
    }

    /// The Unix ID range the answering source's numbers are rebased into.
    pub fn unix_id_range(&self) -> Option<unix_id::Range> {
        self.source.unix_id_range()
    }

    /// Ask the source to authenticate someone.
    pub fn authenticate(&self, start: &LogonStart, originator: &[u8]) -> io::Result<()> {
        let message = psi::encode_authenticate(
            self.id,
            &psi::Authenticate {
                // Cheap enough to rebuild rather than thread a borrow through
                // the encoder, and it keeps `LogonStart` free of Clone — which
                // it must be, since a future credential-bearing field would
                // make cloning it a way to duplicate a secret.
                start: LogonStart {
                    logon_type: start.logon_type,
                    identifier_type: start.identifier_type,
                    identifier: start.identifier.clone(),
                    tty: start.tty.clone(),
                    remote_host: start.remote_host.clone(),
                    supported_credential_types: start.supported_credential_types.clone(),
                },
                originator: originator.to_vec(),
            },
        )
        .map_err(|_| io::Error::other("could not encode an authenticate"))?;
        self.source.send(&message)
    }

    /// Relay the client's answers to the source.
    pub fn credential_response(&self, response: &CredentialResponse) -> io::Result<()> {
        let message = psi::encode_credential_response(self.id, response)
            .map_err(|_| io::Error::other("could not encode a credential response"))?;
        self.source.send(message.expose())
    }

    /// Wait for the source's next message.
    pub fn recv(&self, timeout: Duration) -> Result<Inbound, Stalled> {
        match self.rx.recv_timeout(timeout) {
            Ok(message) => Ok(message),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(Stalled::TimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(Stalled::SourceGone),
        }
    }

    /// Record that the source ended this conversation, so dropping it does not
    /// send a pointless abandon.
    pub fn finished(&mut self) {
        self.terminated = true;
    }
}

impl Drop for Conversation {
    fn drop(&mut self) {
        self.source.close_conversation(self.id);
        if !self.terminated && self.source.is_live() {
            match psi::encode_abandon(self.id) {
                Ok(message) => {
                    let _ = self.source.send(&message);
                }
                Err(_) => log::warn(format_args!("could not encode an abandon")),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stalled {
    /// The source did not answer in time.
    TimedOut,
    /// The source disconnected.
    SourceGone,
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Every source currently registered.
#[derive(Default)]
pub struct Registry {
    sources: Mutex<Vec<Arc<Source>>>,
    /// The domain each source name was *first* seen to declare, kept for the
    /// lifetime of the process — including across a source disconnecting.
    ///
    /// This is trust-on-first-use, and it is the check that survives a restart
    /// of the source. Without it, a source that is killed and comes back
    /// compromised could declare a different domain and be believed, because
    /// every other check would pass: it still holds the right service SID, its
    /// new domain is still a claimable shape, and with itself deregistered
    /// there is nothing left to collide with.
    ///
    /// It deliberately does not survive a restart of *authd*. Persisting it
    /// would mean authd writing state, which is what the optional registry pin
    /// exists to do properly, with an administrator's authority behind it.
    first_declared: Mutex<HashMap<String, Sid>>,
}

/// Why a source was not admitted.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// [`MAX_SOURCES`] are already registered.
    TooMany,
    /// A source of this name is already registered.
    AlreadyRegistered,
    /// Another registered source claims this domain.
    DomainTaken(String),
    /// This source previously declared a different domain.
    DomainChanged(Sid),
}

impl core::fmt::Display for Rejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooMany => write!(f, "{MAX_SOURCES} sources are already registered"),
            Self::AlreadyRegistered => write!(f, "a source of that name is already registered"),
            Self::DomainTaken(other) => {
                write!(f, "{other} is already registered for that domain")
            }
            Self::DomainChanged(before) => write!(
                f,
                "it previously declared {before} and may not change domain without \
                 restarting the authority"
            ),
        }
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a source, or say why not.
    ///
    /// The two domain checks here are the ones that need to see every *other*
    /// source, which is why they live on the registry rather than beside the
    /// per-connection checks in [`verify_domain`].
    fn admit(&self, source: Arc<Source>) -> Result<(), Rejected> {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let mut first_declared = self.first_declared.lock().unwrap_or_else(|e| e.into_inner());

        if sources.len() >= MAX_SOURCES {
            return Err(Rejected::TooMany);
        }
        if sources.iter().any(|s| s.name() == source.name()) {
            return Err(Rejected::AlreadyRegistered);
        }

        // Disjointness. Two sources sharing a domain means two authorities for
        // one namespace: whichever answers first decides who a name belongs to,
        // and the other's principals become impersonable by the first.
        if let Some(other) = sources
            .iter()
            .find(|s| s.domain().as_ref().as_bytes() == source.domain().as_ref().as_bytes())
        {
            return Err(Rejected::DomainTaken(other.name().to_string()));
        }

        match first_declared.get(source.name()) {
            Some(before) if before.as_ref().as_bytes() != source.domain().as_ref().as_bytes() => {
                return Err(Rejected::DomainChanged(before.clone()));
            }
            Some(_) => {}
            None => {
                first_declared.insert(source.name().to_string(), source.domain().clone());
            }
        }

        sources.push(source);
        Ok(())
    }

    fn remove(&self, source: &Arc<Source>) {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|s| !Arc::ptr_eq(s, source));
    }

    pub fn count(&self) -> usize {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Which source should answer for this identifier?
    ///
    /// **M2 is a stub**: the first live source, whatever the identifier says.
    /// The real rule is resolution in a configured order, first claim wins,
    /// with a qualified name (`CORP\jack`) going to its owning source and never
    /// falling back — because a name that can fall through to a different
    /// source when its own is unreachable lets anyone who can break the network
    /// choose which authority answers for you.
    ///
    /// Note what resolution deliberately is *not*: broadcasting the credential.
    /// Asking several sources "do you own this name?" is a resolution step with
    /// no secret in it. Trying each source in turn *with the password* — PAM and
    /// NSS stacking — hands every source the credentials of every other
    /// source's users, including on typos.
    pub fn route(&self, _identifier: &[u8]) -> Option<Arc<Source>> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|source| source.is_live())
            .map(Arc::clone)
    }
}

// ---------------------------------------------------------------------------
// Serving a connection
// ---------------------------------------------------------------------------

/// How long a connecting peer has to register before it is dropped.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a write to a source may block.
///
/// Generous — a source only has to *read*, and one that cannot keep up with
/// that is broken. What this bounds is the damage: without it a source that
/// stopped reading would block an authd thread forever holding the write lock,
/// and every logon queued behind it with it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one PSI connection for its lifetime.
///
/// Runs on its own thread: registers the peer, then demultiplexes everything it
/// sends until it goes away.
pub fn serve(registry: &Registry, stream: UnixStream) {
    // Who is this? Answered by the kernel and the registry, never by the
    // connecting process. A source's identity is the per-service SID peinit put
    // on its token, and only peinit can mint one — so a source proves nothing,
    // because peinit already did.
    //
    // Note what is deliberately *not* checked: that the peer is SYSTEM. The
    // service SID subsumes it — every TCB daemon runs as SYSTEM, so the user
    // SID could never tell lpsd from eventd — and requiring SYSTEM would
    // needlessly forbid a future source running under a lesser account.
    let entry = match crate::peer::identify_source(&stream, &policy::sources()) {
        Ok(entry) => entry,
        Err(error) => {
            log::warn(format_args!("psi: refused a connection: {error}"));
            return;
        }
    };

    let source = match register(stream, &entry) {
        Some(source) => source,
        None => return,
    };

    if let Err(rejected) = registry.admit(Arc::clone(&source)) {
        log::error(format_args!(
            "psi: refused {}: {rejected}",
            source.name()
        ));
        return;
    }

    // The acknowledgement carries the source's Unix ID range back to it. The
    // source never applies the base — authd does that — but knowing it lets an
    // administration tool show the uid a principal will really project to
    // rather than the relative number on disk.
    let range = source.unix_id_range().unwrap_or(unix_id::Range {
        base: 0,
        count: 0,
    });

    // Only once it is in the registry, so a logon racing the acknowledgement
    // cannot find a source that is not routable yet.
    if let Err(error) = source.send(
        &psi::encode_registered(&psi::Registered {
            unix_id_base: range.base,
            unix_id_count: range.count,
        })
        .expect("a registration ack has no variable-length content"),
    ) {
        log::warn(format_args!(
            "psi: could not acknowledge {}: {error}",
            source.name()
        ));
        registry.remove(&source);
        return;
    }

    log::info(format_args!(
        "psi: source {} registered ({} registered in total)",
        source.name(),
        registry.count()
    ));

    pump(&source);

    source.shut_down();
    registry.remove(&source);
    log::info(format_args!("psi: source {} disconnected", source.name()));
}

/// Read the opening `Register` and build the source from the *verified* entry.
///
/// The name in the message is a claim, cross-checked against the identity the
/// kernel attested. It contributes nothing: `entry.name` is what the source is
/// called from here on, in logs, in routing, and as the auth-package name on
/// every session it authenticates.
fn register(stream: UnixStream, entry: &policy::SourceEntry) -> Option<Arc<Source>> {
    // A peer that connects and says nothing must not hold a thread forever.
    if let Err(error) = stream.set_read_timeout(Some(REGISTRATION_TIMEOUT)) {
        log::warn(format_args!("psi: could not set a read timeout: {error}"));
        return None;
    }
    if let Err(error) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        log::warn(format_args!("psi: could not set a write timeout: {error}"));
        return None;
    }

    let received = match libauthd::transport::recv_message(&psi::FRAMING, &stream) {
        Ok(received) => received,
        Err(error) => {
            log::warn(format_args!("psi: could not read a registration: {error}"));
            return None;
        }
    };

    let envelope = match psi::decode_envelope(received.expose()) {
        Ok(envelope) => envelope,
        Err(_) => {
            log::warn(format_args!("psi: malformed header from {}", entry.name));
            return None;
        }
    };
    if envelope.msg_type != psi::MSG_REGISTER || envelope.conversation != psi::CONVERSATION_CONTROL
    {
        log::warn(format_args!(
            "psi: a connection must open with Register on conversation 0"
        ));
        return None;
    }

    let register = match psi::decode_register(received.expose()) {
        Ok(register) => register,
        Err(_) => {
            log::warn(format_args!("psi: malformed Register from {}", entry.name));
            return None;
        }
    };

    // The claim must agree with what the kernel attested. It is never *used* —
    // `entry.name` is authoritative — but a disagreement means a service is
    // registering under someone else's name, and that is worth refusing rather
    // than quietly correcting.
    if !register.source_name.eq_ignore_ascii_case(&entry.name) {
        log::error(format_args!(
            "psi: refused {}: it registered claiming to be {:?}",
            entry.name, register.source_name
        ));
        return None;
    }

    let domain = verify_domain(&register.domain, entry)?;

    // The connection is long-lived and idle most of the time; per-conversation
    // deadlines are enforced on the channels, not the socket.
    if let Err(error) = stream.set_read_timeout(None) {
        log::warn(format_args!("psi: could not clear the read timeout: {error}"));
        return None;
    }

    if entry.unix_id_range.is_none() {
        log::warn(format_args!(
            "psi: {} has no usable {}\\{}\\UnixIDBase, so every principal it asserts will \
             project to uid {}",
            entry.name,
            policy::SOURCES_KEY,
            entry.name,
            unix_id::UNMAPPED
        ));
    }

    Some(Arc::new(Source::new(
        entry.name.clone(),
        entry.may_assert_foreign_memberships,
        domain,
        entry.unix_id_range,
        stream,
    )))
}

/// Check the domain a source declared, as far as it can be checked here.
///
/// Three of the four checks that give a declaration weight are here; the fourth
/// — that no other source has claimed the same domain, and that this source has
/// not previously claimed a different one — needs the registry and lives in
/// [`Registry::admit`].
fn verify_domain(declared: &[u8], entry: &policy::SourceEntry) -> Option<Sid> {
    if declared.is_empty() {
        log::error(format_args!(
            "psi: refused {}: it declared no domain, so nothing it asserts could be \
             confined to one",
            entry.name
        ));
        return None;
    }

    let Some(domain) = SidRef::from_bytes(declared) else {
        log::error(format_args!(
            "psi: refused {}: its declared domain is not a valid SID",
            entry.name
        ));
        return None;
    };

    // The shape is what excludes BUILTIN, the well-known NT range, and every
    // other namespace nobody may claim — by construction rather than by a list.
    if !crate::domain::is_claimable(domain) {
        log::error(format_args!(
            "psi: refused {}: {domain} is not a domain any source may claim \
             (a domain is S-1-5-21-A-B-C)",
            entry.name
        ));
        return None;
    }

    if let Some(pinned) = &entry.pinned_domain {
        if pinned.as_ref().as_bytes() != domain.as_bytes() {
            log::error(format_args!(
                "psi: refused {}: it declared {domain} but {}\\{} pins {pinned}",
                entry.name,
                policy::SOURCES_KEY,
                entry.name
            ));
            return None;
        }
    }

    Some(domain.to_sid())
}

/// Read messages until the connection ends, handing each to its conversation.
fn pump(source: &Arc<Source>) {
    loop {
        let received = match libauthd::transport::recv_message(&psi::FRAMING, &source.stream) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(error) => {
                log::warn(format_args!("psi: {}: read failed: {error}", source.name()));
                return;
            }
        };

        let envelope = match psi::decode_envelope(received.expose()) {
            Ok(envelope) => envelope,
            Err(_) => {
                log::warn(format_args!(
                    "psi: {}: malformed header, dropping the connection",
                    source.name()
                ));
                return;
            }
        };

        // A framing error is fatal to the connection: the codec cannot know
        // where the next message starts once one has failed to parse.
        let message = match decode(source, &envelope, received.expose()) {
            Some(message) => message,
            None => return,
        };

        source.deliver(envelope.conversation, message);
    }
}

fn decode(source: &Arc<Source>, envelope: &psi::Envelope, buf: &[u8]) -> Option<Inbound> {
    let decoded = match envelope.msg_type {
        psi::MSG_CREDENTIAL_REQUEST => psi::decode_credential_request(buf).map(Inbound::Request),
        psi::MSG_ASSERTION => psi::decode_assertion(buf).map(Inbound::Assert),
        psi::MSG_REFUSAL => psi::decode_refusal(buf).map(Inbound::Refuse),
        other => {
            log::warn(format_args!(
                "psi: {}: unexpected message type {other:#06x}",
                source.name()
            ));
            return None;
        }
    };

    match decoded {
        Ok(message) => Some(message),
        Err(_) => {
            log::warn(format_args!(
                "psi: {}: malformed {:#06x}",
                source.name(),
                envelope.msg_type
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().expect("must parse")
    }

    fn pair() -> (Arc<Source>, UnixStream) {
        named_pair("test", "S-1-5-21-1-2-3")
    }

    fn named_pair(name: &str, domain: &str) -> (Arc<Source>, UnixStream) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        (
            Arc::new(Source::new(name.into(), false, sid(domain), None, ours)),
            theirs,
        )
    }

    fn entry(name: &str, pinned_domain: Option<&str>) -> policy::SourceEntry {
        policy::SourceEntry {
            name: name.into(),
            service_sid: sid("S-1-5-80-1-2-3-4-5"),
            may_assert_foreign_memberships: false,
            pinned_domain: pinned_domain.map(sid),
            unix_id_range: None,
        }
    }

    fn declared(text: &str) -> Vec<u8> {
        sid(text).as_ref().as_bytes().to_vec()
    }

    #[test]
    fn conversation_ids_are_never_zero() {
        // Zero is reserved for connection-level messages; allocating it for a
        // logon would collide registration with a conversation.
        let (source, _peer) = pair();
        let first = source.open().expect("open");
        assert_ne!(first.id, psi::CONVERSATION_CONTROL);
    }

    #[test]
    fn conversations_get_distinct_ids() {
        let (source, _peer) = pair();
        let a = source.open().expect("open");
        let b = source.open().expect("open");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn a_dropped_conversation_abandons_it() {
        let (source, peer) = pair();
        let conversation = source.open().expect("open");
        let id = conversation.id;
        drop(conversation);

        let received = libauthd::transport::recv_message(&psi::FRAMING, &peer).expect("recv");
        let envelope = psi::decode_envelope(received.expose()).expect("envelope");
        assert_eq!(envelope.msg_type, psi::MSG_ABANDON);
        assert_eq!(envelope.conversation, id);
    }

    /// A conversation the source terminated needs no abandon — the source has
    /// already forgotten it.
    #[test]
    fn a_finished_conversation_does_not_abandon() {
        let (source, peer) = pair();
        let mut conversation = source.open().expect("open");
        conversation.finished();
        drop(conversation);

        peer.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        assert!(
            libauthd::transport::recv_message(&psi::FRAMING, &peer).is_err(),
            "a finished conversation must send nothing on drop"
        );
    }

    #[test]
    fn dropping_a_conversation_frees_its_slot() {
        let (source, _peer) = pair();
        let conversation = source.open().expect("open");
        assert_eq!(source.conversations.lock().unwrap().len(), 1);
        drop(conversation);
        assert_eq!(source.conversations.lock().unwrap().len(), 0);
    }

    #[test]
    fn a_dead_source_opens_no_conversations() {
        let (source, _peer) = pair();
        source.shut_down();
        assert!(source.open().is_none());
    }

    /// A write that fails must take the whole connection with it, not just the
    /// one conversation: a partial write leaves the stream desynchronised, and
    /// the codec has no way to resynchronise it.
    #[test]
    fn a_failed_write_tears_the_connection_down() {
        let (source, peer) = pair();
        let conversation = source.open().expect("open");
        drop(peer);

        // Writing to a socket whose peer is gone fails (EPIPE), possibly only
        // after the buffer fills, so push until it does.
        let message = psi::encode_abandon(1).expect("encode");
        for _ in 0..10_000 {
            if source.send(&message).is_err() {
                break;
            }
        }

        assert!(!source.is_live(), "a failed write must fail the source");
        assert!(source.open().is_none());
        assert_eq!(
            conversation.recv(Duration::from_secs(1)).unwrap_err(),
            Stalled::SourceGone,
            "waiting conversations must be woken, not left to time out"
        );
    }

    /// The wake-up path: a source disconnecting must fail waiting conversations
    /// immediately rather than leaving them to time out.
    #[test]
    fn shutting_down_wakes_waiters() {
        let (source, _peer) = pair();
        let conversation = source.open().expect("open");
        source.shut_down();
        assert_eq!(
            conversation.recv(Duration::from_secs(30)).unwrap_err(),
            Stalled::SourceGone
        );
    }

    #[test]
    fn an_unanswered_conversation_times_out() {
        let (source, _peer) = pair();
        let conversation = source.open().expect("open");
        assert_eq!(
            conversation.recv(Duration::from_millis(10)).unwrap_err(),
            Stalled::TimedOut
        );
    }

    #[test]
    fn messages_reach_the_right_conversation() {
        let (source, _peer) = pair();
        let a = source.open().expect("open");
        let b = source.open().expect("open");

        source.deliver(
            b.id,
            Inbound::Assert(psi::Assertion {
                user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                canonical_name: "jack".into(),
                ..psi::Assertion::default()
            }),
        );

        assert!(matches!(
            b.recv(Duration::from_millis(50)),
            Ok(Inbound::Assert(_))
        ));
        assert_eq!(
            a.recv(Duration::from_millis(10)).unwrap_err(),
            Stalled::TimedOut,
            "a message must not be delivered to the wrong conversation"
        );
    }

    #[test]
    fn the_foreign_membership_permission_is_carried_from_configuration() {
        let (ours, _theirs) = UnixStream::pair().expect("socketpair");
        let local = Source::new("lpsd".into(), true, sid("S-1-5-21-1-2-3"), None, ours);
        assert!(local.may_assert_foreign_memberships());

        let (ours, _theirs) = UnixStream::pair().expect("socketpair");
        let directory = Source::new("udpsd".into(), false, sid("S-1-5-21-4-5-6"), None, ours);
        assert!(!directory.may_assert_foreign_memberships());
    }

    // -----------------------------------------------------------------------
    // The domain a source declares
    // -----------------------------------------------------------------------

    #[test]
    fn a_claimable_domain_is_accepted() {
        assert_eq!(
            verify_domain(&declared("S-1-5-21-1-2-3"), &entry("lpsd", None)),
            Some(sid("S-1-5-21-1-2-3"))
        );
    }

    #[test]
    fn a_source_that_declares_no_domain_is_refused() {
        // The field is appended, so an older source decodes as declaring
        // nothing. It must not register: there would be no domain to confine
        // its assertions to, which is the whole point of collecting one.
        assert_eq!(verify_domain(&[], &entry("lpsd", None)), None);
    }

    #[test]
    fn a_domain_that_is_not_a_sid_is_refused() {
        assert_eq!(verify_domain(b"not a sid", &entry("lpsd", None)), None);
    }

    #[test]
    fn a_source_may_not_claim_a_well_known_namespace() {
        // The case that matters: claiming BUILTIN would make every
        // `S-1-5-32-…` alias assertable as an identity by that source.
        for text in ["S-1-5-32", "S-1-5-32-544", "S-1-5-18", "S-1-1-0", "S-1-5-21-1-2-3-1000"] {
            assert_eq!(
                verify_domain(&declared(text), &entry("lpsd", None)),
                None,
                "{text} must not be claimable"
            );
        }
    }

    #[test]
    fn a_pinned_domain_must_match() {
        let pinned = entry("lpsd", Some("S-1-5-21-1-2-3"));
        assert_eq!(
            verify_domain(&declared("S-1-5-21-1-2-3"), &pinned),
            Some(sid("S-1-5-21-1-2-3"))
        );
        assert_eq!(
            verify_domain(&declared("S-1-5-21-9-9-9"), &pinned),
            None,
            "a declaration that contradicts the administrator's pin must be refused"
        );
    }

    #[test]
    fn the_registry_rejects_two_sources_claiming_one_domain() {
        // Two authorities for one namespace: whichever answers first decides
        // who a name belongs to, and the other's principals become
        // impersonable.
        let registry = Registry::new();
        let (first, _a) = named_pair("lpsd", "S-1-5-21-1-2-3");
        let (second, _b) = named_pair("udpsd", "S-1-5-21-1-2-3");

        assert_eq!(registry.admit(first), Ok(()));
        assert_eq!(
            registry.admit(second),
            Err(Rejected::DomainTaken("lpsd".into()))
        );
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn two_sources_with_distinct_domains_both_register() {
        let registry = Registry::new();
        let (first, _a) = named_pair("lpsd", "S-1-5-21-1-2-3");
        let (second, _b) = named_pair("udpsd", "S-1-5-21-4-5-6");
        assert_eq!(registry.admit(first), Ok(()));
        assert_eq!(registry.admit(second), Ok(()));
        assert_eq!(registry.count(), 2);
    }

    #[test]
    fn a_source_may_not_change_domain_across_a_reconnection() {
        // The check that survives the source restarting. Everything else would
        // pass: the same service SID, a claimable shape, and with itself
        // deregistered there is nothing left to collide with.
        let registry = Registry::new();
        let (first, _a) = named_pair("lpsd", "S-1-5-21-1-2-3");
        registry.admit(Arc::clone(&first)).expect("must admit");
        registry.remove(&first);
        assert_eq!(registry.count(), 0);

        let (impostor, _b) = named_pair("lpsd", "S-1-5-21-9-9-9");
        assert_eq!(
            registry.admit(impostor),
            Err(Rejected::DomainChanged(sid("S-1-5-21-1-2-3")))
        );
    }

    #[test]
    fn a_source_may_reconnect_with_the_domain_it_declared_before() {
        let registry = Registry::new();
        let (first, _a) = named_pair("lpsd", "S-1-5-21-1-2-3");
        registry.admit(Arc::clone(&first)).expect("must admit");
        registry.remove(&first);

        let (again, _b) = named_pair("lpsd", "S-1-5-21-1-2-3");
        assert_eq!(
            registry.admit(again),
            Ok(()),
            "an ordinary restart must not lock a source out"
        );
    }

    #[test]
    fn the_registry_rejects_a_duplicate_name() {
        let registry = Registry::new();
        let (first, _a) = pair();
        let (second, _b) = pair();
        assert_eq!(registry.admit(first), Ok(()));
        assert_eq!(
            registry.admit(second),
            Err(Rejected::AlreadyRegistered),
            "one name, one source"
        );
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn routing_finds_a_live_source_and_skips_a_dead_one() {
        let registry = Registry::new();
        let (source, _peer) = pair();
        registry.admit(Arc::clone(&source)).expect("must admit");
        assert!(registry.route(b"jack").is_some());

        source.shut_down();
        assert!(registry.route(b"jack").is_none());
    }

    #[test]
    fn routing_with_no_sources_is_none() {
        // Which is what makes "no sources means no accounts" an honest answer
        // rather than an outage: it becomes AuthorityUnavailable, not a hang.
        let registry = Registry::new();
        assert!(registry.route(b"jack").is_none());
    }

    #[test]
    fn a_removed_source_is_no_longer_routable() {
        let registry = Registry::new();
        let (source, _peer) = pair();
        registry.admit(Arc::clone(&source)).expect("must admit");
        registry.remove(&source);
        assert_eq!(registry.count(), 0);
        assert!(registry.route(b"jack").is_none());
    }
}
