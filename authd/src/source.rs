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
    /// Answers to a lookup, one per key, in the order they were asked.
    Results(psi::QueryResult),
    /// One page of an enumeration.
    Page(psi::EnumerateResult),
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
    /// What the source declared it can do beyond authenticating.
    ///
    /// authd sends nothing a source did not declare it answers, which is what
    /// keeps a source written against an earlier PSI working untouched: it
    /// declares nothing, and is only ever asked to authenticate.
    capabilities: psi::Capabilities,
    /// Where this source sits in the resolution order for a bare name. Lower
    /// first; ties broken by name, so the order never depends on which source
    /// happened to register first.
    search_order: u32,
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
        capabilities: psi::Capabilities,
        search_order: u32,
        stream: UnixStream,
    ) -> Self {
        Self {
            name,
            may_assert_foreign_memberships,
            domain,
            unix_id_range,
            capabilities,
            search_order,
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

    /// What this source declared it can answer.
    pub fn capabilities(&self) -> psi::Capabilities {
        self.capabilities
    }

    /// Where this source sits in the resolution order.
    pub fn search_order(&self) -> u32 {
        self.search_order
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
        if id == psi::CONVERSATION_CONTROL {
            // §2.7 reserves conversation 0 for Register, Registered and
            // Changed. A source using it for anything else has misunderstood
            // the reserved identifier, which is malformed — and §2.6 makes
            // malformed fatal to the connection. Logging and carrying on left
            // it running.
            log::error(format_args!(
                "{}: used the reserved conversation 0 for an ordinary message",
                self.name
            ));
            self.shut_down();
            return;
        }
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

    /// Ask this source about objects it holds, outside any logon.
    ///
    /// A query is a conversation like a logon, and for the same reason: it is
    /// the mechanism that already demultiplexes concurrent work over one
    /// long-lived connection.
    pub fn query(&self, query: &psi::Query) -> io::Result<()> {
        let message = psi::encode_query(self.id, query)
            .map_err(|_| io::Error::other("could not encode a query"))?;
        self.source.send(&message)
    }

    /// Ask this source to produce a page of objects.
    pub fn enumerate(&self, request: &psi::EnumerateSource) -> io::Result<()> {
        let message = psi::encode_enumerate_source(self.id, request)
            .map_err(|_| io::Error::other("could not encode an enumeration"))?;
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

/// A source this machine is configured to have, whether or not it is here.
///
/// Load-bearing for resolution rather than bookkeeping. A configured source that
/// is *absent* must still occupy its place in the search order: without that, a
/// crashed `lpsd` would make `jack` silently resolve to a directory's `jack`,
/// which is a different principal with a different SID — and every descriptor
/// granting the local one would stop applying to the person signing in under
/// that name.
#[derive(Debug, Clone)]
pub struct Configured {
    pub name: String,
    pub search_order: u32,
    pub unix_id_range: Option<unix_id::Range>,
}

/// A place in the search order, filled or not.
pub enum Slot {
    Live(Arc<Source>),
    /// Configured, and not currently registered. Everything behind it in the
    /// order is unreachable, because an answer from further down would be a
    /// different principal than the one this machine gives when it is healthy.
    Absent(String),
}

/// Every source currently registered, and every one that should be.
#[derive(Default)]
pub struct Registry {
    sources: Mutex<Vec<Arc<Source>>>,
    /// Every source the allowlist names, read once at startup.
    ///
    /// Not re-read per lookup: a name resolver in every process on the system
    /// calls this path thousands of times a second, and a registry read apiece
    /// would be the most expensive thing in it. Changing the allowlist already
    /// requires restarting authd for other reasons.
    configured: Vec<Configured>,
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
    /// A registry that knows of no configured source.
    ///
    /// Only correct where there genuinely is no allowlist. authd itself always
    /// has one — [`Self::configured`] — because a registry that does not know
    /// which sources *should* be present cannot tell an absence from an outage.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry that knows what the allowlist names.
    pub fn configured(entries: &[policy::SourceEntry]) -> Self {
        Self {
            configured: entries
                .iter()
                .map(|entry| Configured {
                    name: entry.name.clone(),
                    search_order: entry.search_order,
                    unix_id_range: entry.unix_id_range,
                })
                .collect(),
            ..Self::default()
        }
    }

    /// The range a configured source was given, whether or not it is here.
    ///
    /// The inverse arithmetic has to work for an absent source too, or a
    /// `getpwuid` for one of its principals would answer `NotFound` — a
    /// cacheable absence — the moment it went away.
    pub fn configured_range(&self, unix_id: u32) -> Option<&Configured> {
        self.configured.iter().find(|entry| {
            entry.unix_id_range.is_some_and(|range| {
                unix_id
                    .checked_sub(range.base)
                    .is_some_and(|relative| relative != 0 && relative < range.count)
            })
        })
    }

    /// Every configured source that is not currently registered.
    pub fn absent(&self) -> Vec<String> {
        let live = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        self.configured
            .iter()
            .filter(|entry| !live.iter().any(|s| s.is_live() && s.name() == entry.name))
            .map(|entry| entry.name.clone())
            .collect()
    }

    /// Whether every configured source is currently registered.
    ///
    /// What makes a `NotFound` safe to give: an absence is only authoritative
    /// when everything that could have contradicted it was asked.
    pub fn complete(&self) -> bool {
        let live = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        self.configured
            .iter()
            .all(|entry| live.iter().any(|s| s.is_live() && s.name() == entry.name))
    }

    /// Admit a source, or say why not.
    ///
    /// The two domain checks here are the ones that need to see every *other*
    /// source, which is why they live on the registry rather than beside the
    /// per-connection checks in [`verify_domain`].
    fn admit(&self, source: Arc<Source>) -> Result<(), Rejected> {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let mut first_declared = self
            .first_declared
            .lock()
            .unwrap_or_else(|e| e.into_inner());

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
        self.sources.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Every live source, in the order a bare name is resolved.
    ///
    /// Configured order first, then name. Never registration order: which source
    /// a name resolves to must not depend on which one happened to finish
    /// starting first, or a slow disk could change who `jack` is.
    pub fn ordered(&self) -> Vec<Arc<Source>> {
        let mut live: Vec<Arc<Source>> = self
            .sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|source| source.is_live())
            .map(Arc::clone)
            .collect();
        live.sort_by(|a, b| {
            a.search_order()
                .cmp(&b.search_order())
                .then_with(|| a.name().cmp(b.name()))
        });
        live
    }

    /// The search order with its gaps in it.
    ///
    /// A configured source that is not registered appears as [`Slot::Absent`]
    /// rather than being skipped, so a resolver walking this stops where the
    /// machine would have stopped if the source were here.
    pub fn slots(&self) -> Vec<Slot> {
        let live = self.ordered();
        let mut slots: Vec<(u32, &str, Option<Arc<Source>>)> = Vec::new();

        for source in &live {
            slots.push((
                source.search_order(),
                source.name(),
                Some(Arc::clone(source)),
            ));
        }
        for entry in &self.configured {
            if !live.iter().any(|s| s.name() == entry.name) {
                slots.push((entry.search_order, &entry.name, None));
            }
        }
        slots.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
        slots
            .into_iter()
            .map(|(_, name, source)| match source {
                Some(source) => Slot::Live(source),
                None => Slot::Absent(name.to_string()),
            })
            .collect()
    }

    /// A registry configured with the given sources, none of them registered.
    ///
    /// The counterpart of [`Self::admit_for_test`]: what a resolver test needs
    /// is both halves — which sources *should* be here, and which are.
    #[cfg(test)]
    pub fn for_test(configured: &[(&str, u32, Option<unix_id::Range>)]) -> Self {
        Self {
            configured: configured
                .iter()
                .map(|(name, search_order, unix_id_range)| Configured {
                    name: (*name).into(),
                    search_order: *search_order,
                    unix_id_range: *unix_id_range,
                })
                .collect(),
            ..Self::default()
        }
    }

    /// Register a source that never connected, for tests.
    ///
    /// A test seam rather than a shortcut: everything registration establishes —
    /// the peer's service SID, the allowlist, the domain checks — is tested
    /// where it lives, and what the resolver's tests need is a source that
    /// *answers*, which no amount of registration machinery provides.
    #[cfg(test)]
    pub fn admit_for_test(
        &self,
        name: &str,
        domain: Sid,
        range: Option<unix_id::Range>,
        capabilities: psi::Capabilities,
        search_order: u32,
        stream: UnixStream,
    ) -> Arc<Source> {
        self.admit_for_test_with_foreign(
            name,
            domain,
            range,
            capabilities,
            search_order,
            stream,
            false,
        )
    }

    /// [`admit_for_test`](Self::admit_for_test) with control over
    /// `MayAssertForeignMemberships` — the permission that lets a source name a
    /// group outside the principal's own domain, which lpsd ships with and a
    /// directory-backed source must not.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn admit_for_test_with_foreign(
        &self,
        name: &str,
        domain: Sid,
        range: Option<unix_id::Range>,
        capabilities: psi::Capabilities,
        search_order: u32,
        stream: UnixStream,
        may_assert_foreign_memberships: bool,
    ) -> Arc<Source> {
        let source = Arc::new(Source::new(
            name.into(),
            may_assert_foreign_memberships,
            domain,
            range,
            capabilities,
            search_order,
            stream,
        ));
        self.admit(Arc::clone(&source)).expect("must admit");
        source
    }

    /// The source authoritative for a SID, if any is.
    ///
    /// A SID names its own domain, so this needs no search: at most one source
    /// can have declared it, and identity confinement is what makes that true.
    pub fn owning(&self, sid: &SidRef) -> Option<Arc<Source>> {
        self.ordered()
            .into_iter()
            .find(|source| crate::domain::contains(source.domain().as_ref(), sid))
    }

    /// The source whose Unix ID range contains a number, and the relative
    /// identifier inside it.
    ///
    /// This is the arithmetic no source can do for itself, because no source
    /// learns its own base — which is what makes authd the only party able to
    /// answer a `getpwuid` at all.
    pub fn rebasing(&self, unix_id: u32) -> Option<(Arc<Source>, u32)> {
        self.ordered().into_iter().find_map(|source| {
            let range = source.unix_id_range()?;
            let relative = unix_id.checked_sub(range.base)?;
            // The exact inverse of `Range::rebase`: zero is not an identifier,
            // and anything at or past the count is outside the range the source
            // was given.
            (relative != 0 && relative < range.count).then_some((source, relative))
        })
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
        log::error(format_args!("psi: refused {}: {rejected}", source.name()));
        return;
    }

    // The acknowledgement carries the source's Unix ID range back to it. The
    // source never applies the base — authd does that — but knowing it lets an
    // administration tool show the uid a principal will really project to
    // rather than the relative number on disk.
    let range = source
        .unix_id_range()
        .unwrap_or(unix_id::Range { base: 0, count: 0 });

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
        log::warn(format_args!(
            "psi: could not clear the read timeout: {error}"
        ));
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

    if register
        .capabilities
        .contains(psi::Capabilities::PUSHES_CHANGES)
        && register.entry_ttl != 0
    {
        log::info(format_args!(
            "psi: {} pushes changes and bounds an entry at {}s",
            entry.name, register.entry_ttl
        ));
    }

    Some(Arc::new(Source::new(
        entry.name.clone(),
        entry.may_assert_foreign_memberships,
        domain,
        entry.unix_id_range,
        register.capabilities,
        entry.search_order,
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

/// Start the reader thread for a source that never went through [`serve`].
///
/// The resolver's tests need a source that answers, and answering means a
/// demultiplexer. Everything registration establishes is tested where it lives;
/// this supplies the one part of a live connection those tests actually use.
#[cfg(test)]
pub fn pump_for_test(source: &Arc<Source>) {
    let source = Arc::clone(source);
    std::thread::spawn(move || {
        pump(&source);
        source.shut_down();
    });
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

        // Connection-level, belonging to no conversation. Unsolicited and never
        // answered — a source telling authd that what it holds has changed.
        if envelope.msg_type == psi::MSG_CHANGED {
            match psi::decode_changed(received.expose()) {
                Ok(changed) => changed_here(source, &changed),
                Err(_) => {
                    log::warn(format_args!(
                        "psi: {}: malformed change notification, dropping the connection",
                        source.name()
                    ));
                    return;
                }
            }
            continue;
        }

        // A framing error is fatal to the connection: the codec cannot know
        // where the next message starts once one has failed to parse.
        let message = match decode(source, &envelope, received.expose()) {
            Some(message) => message,
            None => return,
        };

        source.deliver(envelope.conversation, message);
    }
}

/// Act on a source's invalidation.
///
/// Nothing to invalidate yet: authd asks a source afresh for every lookup, so
/// there is no held answer for this to discard. The message is still accepted
/// and acted on to the extent it can be — a source that declared
/// `PUSHES_CHANGES` and found authd refusing its notifications would be right to
/// consider authd broken, and a cache added later plugs in exactly here.
fn changed_here(source: &Arc<Source>, changed: &psi::Changed) {
    if !source
        .capabilities()
        .contains(psi::Capabilities::PUSHES_CHANGES)
    {
        log::warn(format_args!(
            "psi: {}: sent a change notification without declaring PushesChanges",
            source.name()
        ));
        return;
    }
    // Obligation 24: identity confinement applies to the `sid` of a Changed as
    // much as to an Assertion. Logging the byte length and acting anyway is not
    // that.
    //
    // No consequence today, because nothing is invalidated — but it becomes
    // live the moment a cache lands, and at that point an unchecked sid is a
    // source able to invalidate *another* source's entries: a cheap way to
    // force repeated queries against a source that is not answering, and, once
    // NotFound is cacheable, a way to keep somebody's account looking absent.
    // Enforcing it now means the cache plugs into a checked path.
    let scope = match changed.scope {
        psi::ChangeScope::All => "everything it holds".to_string(),
        psi::ChangeScope::Object => {
            let Some(sid) = SidRef::from_bytes(&changed.sid) else {
                log::error(format_args!(
                    "psi: {}: change notification carries {} bytes that are not a SID",
                    source.name(),
                    changed.sid.len()
                ));
                return;
            };
            if !crate::domain::contains(source.domain().as_ref(), sid) {
                log::error(format_args!(
                    "psi: {}: tried to invalidate {sid}, which is outside its domain {}",
                    source.name(),
                    source.domain()
                ));
                return;
            }
            format!("{sid}")
        }
    };
    log::info(format_args!("psi: {}: invalidated {scope}", source.name()));
}

fn decode(source: &Arc<Source>, envelope: &psi::Envelope, buf: &[u8]) -> Option<Inbound> {
    let decoded = match envelope.msg_type {
        psi::MSG_CREDENTIAL_REQUEST => psi::decode_credential_request(buf).map(Inbound::Request),
        psi::MSG_ASSERTION => psi::decode_assertion(buf).map(Inbound::Assert),
        psi::MSG_REFUSAL => psi::decode_refusal(buf).map(Inbound::Refuse),
        psi::MSG_QUERY_RESULT => psi::decode_query_result(buf).map(Inbound::Results),
        psi::MSG_ENUMERATE_RESULT => psi::decode_enumerate_result(buf).map(Inbound::Page),
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
            Arc::new(Source::new(
                name.into(),
                false,
                sid(domain),
                None,
                psi::Capabilities::QUERIES | psi::Capabilities::ENUMERATES,
                policy::sources::DEFAULT_SEARCH_ORDER,
                ours,
            )),
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
            search_order: policy::sources::DEFAULT_SEARCH_ORDER,
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
        let local = Source::new(
            "lpsd".into(),
            true,
            sid("S-1-5-21-1-2-3"),
            None,
            psi::Capabilities::empty(),
            policy::sources::DEFAULT_SEARCH_ORDER,
            ours,
        );
        assert!(local.may_assert_foreign_memberships());

        let (ours, _theirs) = UnixStream::pair().expect("socketpair");
        let directory = Source::new(
            "udpsd".into(),
            false,
            sid("S-1-5-21-4-5-6"),
            None,
            psi::Capabilities::empty(),
            policy::sources::DEFAULT_SEARCH_ORDER,
            ours,
        );
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
        for text in [
            "S-1-5-32",
            "S-1-5-32-544",
            "S-1-5-18",
            "S-1-1-0",
            "S-1-5-21-1-2-3-1000",
        ] {
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
    fn ordering_includes_a_live_source_and_drops_a_dead_one() {
        // What routing (resolve::route) builds on: a source that shut down
        // must vanish from the order, or a logon would be sent to a wire
        // nobody answers.
        let registry = Registry::new();
        let (source, _peer) = pair();
        registry.admit(Arc::clone(&source)).expect("must admit");
        assert_eq!(registry.ordered().len(), 1);

        source.shut_down();
        assert!(registry.ordered().is_empty());
    }

    #[test]
    fn a_removed_source_is_no_longer_ordered() {
        let registry = Registry::new();
        let (source, _peer) = pair();
        registry.admit(Arc::clone(&source)).expect("must admit");
        registry.remove(&source);
        assert_eq!(registry.count(), 0);
        assert!(registry.ordered().is_empty());
    }
}
