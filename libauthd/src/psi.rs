//! **PSI** — the Principal Source Interface, spoken on `/run/psi.sock`.
//!
//! PGSS Logon is a *standard*: the language `/run/logon.sock` speaks, which
//! authd merely implements. PSI is not. PSI is authd's own protocol for talking
//! to the principal sources that actually hold identity — `lpsd` locally,
//! `udpsd`/`adpsd` against a directory. It is documented well enough for a
//! third party to implement a source, but it is not part of the "if you do not
//! do this you are not Peios" bar; a system with entirely different
//! authentication infrastructure is still Peios.
//!
//! # PSI is a superset of PGSS Logon
//!
//! A principal source *is* a PGSS Logon authority for its slice of the world,
//! and authd is an authority that federates authorities. So the interrogation
//! phase is not merely similar to PGSS Logon's, it is *the same messages*:
//! [`crate::wire::CredentialRequest`] and [`crate::wire::CredentialResponse`]
//! travel over PSI with their bodies encoded by the very same code (see the
//! `body` functions in [`crate::wire`]). The source decides what to prompt for;
//! authd relays.
//!
//! That is what makes authd a relay rather than a policy engine, and it is why
//! adding a credential type does not require touching authd at all.
//!
//! # Where the two protocols diverge, deliberately
//!
//! **At the success terminal, and only there.** PGSS Logon ends a successful
//! logon with `AccessGranted { session_id }` — a session that exists, attached
//! to a token that has been minted. If PSI reused that message, sources would
//! be minting sessions.
//!
//! So PSI's success terminal is an [`Assertion`]: *this is who they are*. authd
//! turns that into a session, a token and an `AccessGranted`. The rule that
//! backends assert and never mint is therefore **structural** — a source has no
//! message with which to mint — rather than a convention someone has to
//! remember.
//!
//! # Multiplexing
//!
//! PGSS Logon is one conversation per connection: the connection *is* the
//! conversation's identity. PSI is one persistent connection carrying many
//! concurrent logons, so its header carries a `conversation` id that PGSS Logon
//! does not need.
//!
//! Conversation **0 is reserved** for connection-level messages — registration
//! and its acknowledgement. Logons use 1 upward, allocated by authd.
//!
//! The alternative — serialising every logon behind one connection lock — would
//! turn any slow source into a system-wide login stall.
//!
//! # Direction
//!
//! The source *dials in* (it connects to authd), but authd *asks* (it is the
//! requester). Connection direction and request direction are opposite, which
//! is deliberate: it means authd, the process holding `SeCreateTokenPrivilege`,
//! never initiates an outbound connection to a path named in configuration.
//!
//! Message numbering follows PGSS Logon's convention, read the same way: the
//! high bit marks a message sent *by the authority* — here, by the source.
//!
//! ```text
//!   authd                                  source
//!     |<------------- Register ---------------|   conversation 0
//!     |-------------- Registered ------------->|   conversation 0
//!     |
//!     |------------- Authenticate ------------>|   conversation N
//!     |<--------- CredentialRequest -----------|
//!     |--------- CredentialResponse ---------->|
//!     |<--------- CredentialRequest -----------|   (repeatable)
//!     |--------- CredentialResponse ---------->|
//!     |<------ Assertion | Refusal ------------|
//! ```

use crate::claim::Claim;
use crate::frame::{self, Framing, Writer};
// PGSS Logon chapter 6's vocabulary, carried unchanged. A source's answer and
// the authority's answer describe the same object, so they share the type
// rather than translating between two spellings of it.
use crate::ident::{Fields, Kind, Outcome, Value, Withheld};
use crate::secret::Secret;
use crate::wire::{
    CredentialRequest, CredentialResponse, Denial, LogonStart, Profile, MAX_REASON_BYTES, WireError,
};

/// Four literal bytes opening every message: **P**eios **P**rincipal **S**ource
/// **I**nterface.
///
/// Distinct from PGSS Logon's `PGSL` on purpose. The two protocols share
/// message bodies, so a socket plugged into the wrong daemon could otherwise
/// *partially* work — which is far worse than failing outright. This makes it a
/// hard error on the first four bytes.
pub const MAGIC: [u8; 4] = *b"PPSI";

pub const VERSION: u16 = 1;

/// PGSS Logon's twelve-byte header plus the conversation id.
pub const HEADER_BYTES: usize = frame::COMMON_HEADER_BYTES + 8;

/// Larger than PGSS Logon's ceiling, because a PSI message wraps one.
pub const MAX_MESSAGE_BYTES: usize = 80 * 1024;

pub const FRAMING: Framing = Framing {
    magic: MAGIC,
    version: VERSION,
    header_bytes: HEADER_BYTES,
    max_message_bytes: MAX_MESSAGE_BYTES,
};

/// The conversation id reserved for connection-level messages.
pub const CONVERSATION_CONTROL: u64 = 0;

// authd -> source.
pub const MSG_REGISTERED: u16 = 0x0001;
pub const MSG_AUTHENTICATE: u16 = 0x0002;
pub const MSG_CREDENTIAL_RESPONSE: u16 = 0x0003;
pub const MSG_ABANDON: u16 = 0x0004;
pub const MSG_QUERY: u16 = 0x0005;
pub const MSG_ENUMERATE_SOURCE: u16 = 0x0006;
// source -> authd. The high bit marks a message sent by the authority, as in
// PGSS Logon — here the source is the authority for its own principals.
pub const MSG_REGISTER: u16 = 0x8001;
pub const MSG_CREDENTIAL_REQUEST: u16 = 0x8002;
pub const MSG_ASSERTION: u16 = 0x8003;
pub const MSG_REFUSAL: u16 = 0x8004;
pub const MSG_QUERY_RESULT: u16 = 0x8005;
pub const MSG_ENUMERATE_RESULT: u16 = 0x8006;
pub const MSG_CHANGED: u16 = 0x8007;

/// Bounded so a source name is usable as a KACS session auth-package name.
pub const MAX_SOURCE_NAME_BYTES: usize = 32;

/// The largest a SID can be. Defined in [`frame`], because it is a property of
/// SIDs rather than of PSI.
pub const MAX_SID_BYTES: usize = frame::MAX_SID_BYTES;

pub const MAX_CANONICAL_NAME_BYTES: usize = 256;

/// How many groups one assertion may carry.
pub const MAX_GROUPS: usize = 128;

/// How many keys one [`Query`] may carry.
pub const MAX_KEYS: usize = 64;

/// How many entries one [`EnumerateResult`] may carry.
pub const MAX_ENTRIES: usize = 256;

/// How long an enumeration cursor may be.
pub const MAX_CURSOR_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// What a source can do beyond authenticating, declared at registration.
///
/// A declaration of *capability*, not of willingness: a source declaring
/// [`Self::QUERIES`] may still refuse any particular question, and one declaring
/// [`Self::ENUMERATES`] may still refuse a cursor it can no longer honour.
///
/// Like [`crate::ident::Fields`] and unlike every other enumeration in these
/// protocols, a bit may be added here without a version bump — because an
/// authority must not send a message the source did not declare it answers, so
/// an unset bit is always the safe reading in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Answers [`Query`].
    pub const QUERIES: Capabilities = Capabilities(1 << 0);
    /// Answers [`EnumerateSource`].
    pub const ENUMERATES: Capabilities = Capabilities(1 << 1);
    /// Can produce a group's membership.
    pub const MEMBERS: Capabilities = Capabilities(1 << 2);
    /// Sends [`Changed`].
    pub const PUSHES_CHANGES: Capabilities = Capabilities(1 << 3);

    pub const fn empty() -> Capabilities {
        Capabilities(0)
    }

    pub const fn contains(self, other: Capabilities) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 | other.0)
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Capabilities;
    fn bitor(self, rhs: Capabilities) -> Capabilities {
        self.union(rhs)
    }
}

/// A source announcing itself. Source to authd, on [`CONVERSATION_CONTROL`].
#[derive(Debug, Default)]
pub struct Register {
    /// Identifies the source in logs, and becomes the session's auth-package
    /// name — so a token's provenance answers "which source authenticated
    /// this?" rather than merely "authd minted it".
    pub source_name: String,
    /// The domain this source is authoritative for, as binary SID bytes.
    ///
    /// Every principal this source may assert lives under it. It is the source's
    /// *claim*, not proof of anything, and authd treats it as such — the checks
    /// that make it meaningful (a well-formed local-domain shape, disjointness
    /// from every other registered source, stability across re-registrations,
    /// and an optional administrator-written pin in the allowlist) all live in
    /// authd, because a claim is only worth what the authority does with it.
    ///
    /// Appended rather than replacing anything, so a source predating this
    /// field decodes with an empty domain — which authd refuses, since a source
    /// that cannot name its scope cannot be confined to it.
    pub domain: Vec<u8>,
    /// What this source can do beyond authenticating.
    ///
    /// authd MUST NOT send a message a source did not declare it answers, so a
    /// source predating this field declares nothing, authenticates, and keeps
    /// working untouched. That is the only reading that does not break every
    /// source written against the earlier shape.
    pub capabilities: Capabilities,
    /// How long, in seconds, authd may hold an answer from this source.
    ///
    /// **Zero means do not cache.** A source declaring neither
    /// [`Capabilities::PUSHES_CHANGES`] nor a non-zero value here has said its
    /// answers must not be held at all, and that is what silence means too — a
    /// source written against an older revision would otherwise silently serve
    /// stale identity, which is the one class of staleness that decides access.
    pub entry_ttl: u32,
    /// The most keys this source will accept in one [`Query`]. Zero means one.
    pub max_batch: u32,
}

/// authd accepting a registration. authd to source, on [`CONVERSATION_CONTROL`].
///
/// Load-bearing beyond its contents: a source must not report itself ready until
/// it has been *accepted*, so that "lpsd is running" and "lpsd can
/// authenticate" are the same statement as far as boot ordering is concerned.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    /// The bottom of the Unix ID range authd has assigned this source, and how
    /// many ids it spans — `UnixIDBase` and `UnixIDCount` from the registry.
    ///
    /// **Informational.** A source counts from 1 and asserts relative numbers;
    /// authd adds the base itself. Telling the source is what lets `lps show`
    /// print the uid a principal will actually project to rather than the "1"
    /// on disk, which is the number an operator would otherwise have to add up
    /// by hand.
    ///
    /// A source MUST NOT apply the base to what it asserts. If it did, authd
    /// would apply it again.
    pub unix_id_base: u32,
    pub unix_id_count: u32,
}

/// authd asking a source to authenticate someone. Opens a conversation.
///
/// This is PGSS Logon's [`LogonStart`] verbatim — nested, so it can grow on its
/// own schedule — plus the one thing only authd knows.
#[derive(Debug)]
pub struct Authenticate {
    pub start: LogonStart,
    /// The **verified** identity of the peer that originated this logon, as
    /// binary SID bytes, taken from the connected socket and never from a
    /// message body.
    ///
    /// A source cannot learn this for itself: it is not party to the client's
    /// connection. It matters because a source may legitimately refuse to
    /// authenticate for some originators — an account restricted to console
    /// logons, say — and that decision needs a trustworthy input.
    pub originator: Vec<u8>,
}

/// A group membership a source asserts.
///
/// **No attributes.** Owner, deny-only and enabled are decisions about how to
/// *build a token*, not claims about who someone is, so they stay with authd. A
/// source saying "jack is an administrator" is identity; a source saying "and
/// mark that group deny-only" would be reaching into derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Binary SID bytes, structurally unvalidated here.
    pub sid: Vec<u8>,
    /// The source's Unix ID for this group, **relative to the source's range**
    /// — authd adds the base. Zero means the source does not number this group,
    /// which is the honest answer for a group it does not own: a source
    /// asserting `BUILTIN\Administrators` is naming a membership, not claiming
    /// authority over what that group projects to.
    pub unix_id: u32,
}

/// The source's answer: *this is who they are*. Source to authd.
///
/// Note what remains absent. No session, no token, no privileges, no integrity
/// level — those are authd's derivation, and a source has no way to express
/// them.
///
/// # Relative, never absolute
///
/// Every Unix ID here is relative to the range authd assigned this source. A
/// source counts from 1 and knows nothing about where its range begins; authd
/// adds `UnixIDBase` and refuses anything at or past `UnixIDCount`. That is what
/// stops a source projecting its principals onto uid 0, or onto another
/// source's numbers — the numeric counterpart of confining a source to its
/// domain SID.
#[derive(Debug, Default)]
pub struct Assertion {
    /// Binary SID bytes. Structurally unvalidated here — libauthd deliberately
    /// has no dependency on the security library — so the *recipient* must
    /// validate before treating it as identity.
    pub user_sid: Vec<u8>,
    /// The source's canonical spelling of the principal's name. The client may
    /// have typed `JACK`, or a name the source normalises; this is what the
    /// principal is actually called.
    pub canonical_name: String,
    /// The groups this source says the principal belongs to.
    ///
    /// This is where scope will bite hardest when it arrives. A source's
    /// membership scope — which groups it may assert anyone into — is what
    /// stops a directory declaring its users local administrators, and it is
    /// separate from the identity scope that says whose passwords it may check.
    pub groups: Vec<Group>,
    /// The principal's own Unix ID, relative to the source's range. Zero means
    /// the source has no number for them, and authd projects them to `nobody`.
    pub unix_id: u32,
    /// Which group is primary — the one projecting to the POSIX gid. Binary SID
    /// bytes; empty means the source did not say, and authd picks a default.
    ///
    /// It need not appear in `groups`. KACS requires the primary group to be a
    /// group *on the token*, and authd keeps that invariant by adding it —
    /// naming a group as primary implies the membership.
    pub primary_group: Vec<u8>,
    /// Where the session starts, relayed onward to the client in
    /// [`AccessGranted`](crate::wire::AccessGranted).
    pub profile: Profile,
    /// Attributes for conditional ACE evaluation.
    ///
    /// The one field here that is a *trusted input to access decisions* rather
    /// than a statement of identity: a conditional ACE can turn a claim into a
    /// grant. Which claim names a source may assert is the same shape of
    /// question as which groups it may assert, and belongs with that control.
    pub claims: Vec<Claim>,
}

/// The source declining. Source to authd.
///
/// Reuses PGSS Logon's [`Denial`] vocabulary rather than inventing a parallel
/// one, so relaying a refusal outward does not require a lossy translation.
#[derive(Debug)]
pub struct Refusal {
    pub denial: Denial,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Identity queries
//
// PGSS Logon chapter 6 asks authd who a SID or a number belongs to, outside any
// logon. These are how authd asks a source. A query is an ordinary conversation:
// authd allocates the identifier, `Query` opens it, one terminal message closes
// it.
// ---------------------------------------------------------------------------

/// What to ask a source about.
///
/// **There is no variant carrying an absolute POSIX identifier**, and that is
/// the load-bearing property. PGSS Logon's lookup accepts one, because that is
/// what `getpwuid` hands a name resolver — authd locates the range containing
/// the number, subtracts the base, and asks the owning source by relative
/// identifier.
///
/// So a source is never told an absolute number here, exactly as it is never
/// told one during a logon. A source that learned its base could assert numbers
/// outside its range by arithmetic, whatever the protocol said it was allowed
/// to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Name(String),
    Sid(Vec<u8>),
    RelativeId(u32),
}

/// One question, and what kind of object would answer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryKey {
    pub key: Key,
    pub kind: Kind,
}

/// authd asking a source about objects it holds. authd to source, opens a
/// conversation.
///
/// `keys` is an array from the outset. authd may send one and always sending one
/// is conforming — but adding the array later would have broken every source
/// written against a single-key message, and a source backed by a remote
/// directory gains the difference between one query and a hundred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub fields: Fields,
    pub keys: Vec<QueryKey>,
}

/// One answer. The source's own spelling of the name, and **relative**
/// identifiers throughout.
///
/// A source does not qualify a name: qualification says which source answered,
/// and a source cannot know what it is called in an authority's search order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEntry {
    pub outcome: Outcome,
    pub sid: Vec<u8>,
    pub canonical_name: String,
    pub kind: Kind,
    pub values: Vec<Value>,
    pub withheld: Vec<Withheld>,
}

impl Default for QueryEntry {
    fn default() -> Self {
        Self {
            outcome: Outcome::NotFound,
            sid: Vec::new(),
            canonical_name: String::new(),
            kind: Kind::Principal,
            values: Vec::new(),
            withheld: Vec::new(),
        }
    }
}

impl QueryEntry {
    /// The bits this entry answers.
    pub fn present(&self) -> Fields {
        self.values
            .iter()
            .fold(Fields::empty(), |acc, value| acc.union(value.field()))
    }

    pub fn value(&self, field: Fields) -> Option<&Value> {
        self.values.iter().find(|value| value.field() == field)
    }
}

/// The source's answers, one per key, in the order the keys were sent.
///
/// A source that cannot serve a whole batch refuses the conversation rather than
/// answering part of it — a short array would silently pair answers with the
/// wrong questions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryResult {
    pub results: Vec<QueryEntry>,
}

/// authd asking a source to produce objects. authd to source, opens a
/// conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateSource {
    /// Never [`Kind::Any`].
    pub kind: Kind,
    pub fields: Fields,
    /// `None` walks everything of `kind`. `Some` names a **group** and walks its
    /// members — the continuation path for a `MEMBERS` field a source withheld
    /// as [`WithheldReason::TooLarge`].
    pub of: Option<Key>,
    /// Empty on the first request; otherwise the previous reply's `next`.
    /// **Opaque to authd**, which relays what it was given.
    pub cursor: Vec<u8>,
}

/// One page. A source that will not enumerate answers [`Outcome::Refused`] with
/// both arrays empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateResult {
    pub outcome: Outcome,
    pub entries: Vec<QueryEntry>,
    /// Empty ends the enumeration. Non-empty means there is more **even where
    /// `entries` is empty**.
    pub next: Vec<u8>,
}

/// A source telling authd that something it holds has changed. Source to authd,
/// on [`CONVERSATION_CONTROL`]. Unsolicited, and never answered.
///
/// # Why it carries no new value
///
/// It says *that* something changed, not what it changed to. Carrying the value
/// would make this a second, unsolicited path by which a source could assert
/// identity — arriving outside any conversation, with no key to check it
/// against, and no logon in progress to refuse. authd would have accepted an
/// identity assertion it never asked for.
///
/// authd discards what it holds and asks again through [`Query`], where every
/// scope check applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub scope: ChangeScope,
    /// Meaningful only for [`ChangeScope::Object`], and within the source's
    /// declared domain.
    pub sid: Vec<u8>,
}

/// How much of a source's answers an invalidation covers.
///
/// A source MAY send [`Self::All`] where it could have sent [`Self::Object`].
/// Over-invalidation costs a query; under-invalidation costs correctness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChangeScope {
    All = 1,
    /// Covers a deletion and a *creation* as well as a change — authd may be
    /// holding a cached `NotFound` for a name that now exists.
    Object = 2,
}

impl ChangeScope {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::All,
            2 => Self::Object,
            _ => return None,
        })
    }
}

/// A message's type and the conversation it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub msg_type: u16,
    pub total_len: usize,
    pub conversation: u64,
}

/// Read a PSI header.
pub fn decode_envelope(buf: &[u8]) -> Result<Envelope, WireError> {
    let (msg_type, total_len) = frame::decode_header(&FRAMING, buf)?;
    let mut r = frame::Reader::new(buf);
    r.take(frame::COMMON_HEADER_BYTES)?;
    Ok(Envelope {
        msg_type,
        total_len,
        conversation: r.u64()?,
    })
}

/// Begin a PSI message: the common header, then the conversation id.
fn begin(msg_type: u16, conversation: u64) -> Writer {
    let mut w = Writer::new(&FRAMING, msg_type);
    w.u64(conversation);
    w
}

fn open_body(buf: &[u8], expected: u16) -> Result<frame::Reader<'_>, WireError> {
    frame::open_body(&FRAMING, buf, expected)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn encode_register(register: &Register) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_REGISTER, CONVERSATION_CONTROL);
    let body = w.open();
    w.string(&register.source_name, MAX_SOURCE_NAME_BYTES)?;
    w.bytes(&register.domain, MAX_SID_BYTES)?;
    w.u32(register.capabilities.0);
    w.u32(register.entry_ttl);
    w.u32(register.max_batch);
    w.close(body);
    w.finish()
}

pub fn decode_register(buf: &[u8]) -> Result<Register, WireError> {
    let mut b = open_body(buf, MSG_REGISTER)?;
    let source_name = b.string(MAX_SOURCE_NAME_BYTES)?.to_owned();
    // Appended after the name, so a source that predates the field is decoded
    // as claiming no domain rather than as malformed. authd refuses that, but
    // it refuses it with a diagnosis rather than a framing error.
    let domain = if b.at_end() {
        Vec::new()
    } else {
        b.bytes(MAX_SID_BYTES)?.to_vec()
    };
    // Appended again, and the default is the load-bearing part: a source that
    // predates these declares no capability, so authd sends it nothing beyond a
    // logon and never caches its answers. An older source keeps working exactly
    // as it did.
    let (capabilities, entry_ttl, max_batch) = if b.at_end() {
        (Capabilities::empty(), 0, 0)
    } else {
        (Capabilities(b.u32()?), b.u32()?, b.u32()?)
    };
    Ok(Register {
        source_name,
        domain,
        capabilities,
        entry_ttl,
        max_batch,
    })
}

pub fn encode_registered(registered: &Registered) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_REGISTERED, CONVERSATION_CONTROL);
    let body = w.open();
    w.u32(registered.unix_id_base);
    w.u32(registered.unix_id_count);
    w.close(body);
    w.finish()
}

pub fn decode_registered(buf: &[u8]) -> Result<Registered, WireError> {
    let mut b = open_body(buf, MSG_REGISTERED)?;
    // Appended to a message that used to be empty: an authority predating the
    // range says nothing, and a zero base is exactly what "no range assigned"
    // means, so the default is the correct reading rather than a fallback.
    if b.at_end() {
        return Ok(Registered::default());
    }
    Ok(Registered {
        unix_id_base: b.u32()?,
        unix_id_count: b.u32()?,
    })
}

// ---------------------------------------------------------------------------
// The conversation
// ---------------------------------------------------------------------------

pub fn encode_authenticate(
    conversation: u64,
    authenticate: &Authenticate,
) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_AUTHENTICATE, conversation);
    let body = w.open();

    // Nested rather than inlined: LogonStart is PGSS Logon's struct and grows
    // on PGSS Logon's schedule. Flattening it here would mean a field appended
    // there silently displaced `originator`.
    let nested = w.open();
    crate::wire::write_logon_start_body(&mut w, &authenticate.start)?;
    w.close(nested);

    w.bytes(&authenticate.originator, MAX_SID_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_authenticate(buf: &[u8]) -> Result<Authenticate, WireError> {
    let mut b = open_body(buf, MSG_AUTHENTICATE)?;
    let start = crate::wire::read_logon_start_body(&mut b.open()?)?;
    Ok(Authenticate {
        start,
        originator: b.bytes(MAX_SID_BYTES)?.to_vec(),
    })
}

/// Relay a credential request from a source.
///
/// The body is PGSS Logon's, byte for byte — that sharing is the whole point.
pub fn encode_credential_request(
    conversation: u64,
    req: &CredentialRequest,
) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_CREDENTIAL_REQUEST, conversation);
    let body = w.open();
    crate::wire::write_credential_request_body(&mut w, req)?;
    w.close(body);
    w.finish()
}

pub fn decode_credential_request(buf: &[u8]) -> Result<CredentialRequest, WireError> {
    crate::wire::read_credential_request_body(&mut open_body(buf, MSG_CREDENTIAL_REQUEST)?)
}

/// Relay credential answers to a source.
///
/// Returns a [`Secret`] for the same reason PGSS Logon's encoder does: the
/// encoded message contains credentials in the clear, and there is no way to
/// hold that without inheriting the obligation to erase it.
pub fn encode_credential_response(
    conversation: u64,
    resp: &CredentialResponse,
) -> Result<Secret, WireError> {
    let mut w = begin(MSG_CREDENTIAL_RESPONSE, conversation);
    let body = w.open();
    crate::wire::write_credential_response_body(&mut w, resp)?;
    w.close(body);

    let encoded = w.finish()?;
    let secret = Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(secret)
}

/// Decode credential answers.
///
/// **The caller must wipe `buf` afterwards.**
pub fn decode_credential_response(buf: &[u8]) -> Result<CredentialResponse, WireError> {
    crate::wire::read_credential_response_body(&mut open_body(buf, MSG_CREDENTIAL_RESPONSE)?)
}

pub fn encode_assertion(conversation: u64, assertion: &Assertion) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_ASSERTION, conversation);
    let body = w.open();
    w.bytes(&assertion.user_sid, MAX_SID_BYTES)?;
    w.string(&assertion.canonical_name, MAX_CANONICAL_NAME_BYTES)?;

    // Each group in its own frame. That framing is what let the Unix ID be
    // appended to a group entry without breaking a decoder that predates it —
    // the case the frame was put there for.
    w.count(assertion.groups.len(), MAX_GROUPS)?;
    for group in &assertion.groups {
        let at = w.open();
        w.bytes(&group.sid, MAX_SID_BYTES)?;
        w.u32(group.unix_id);
        w.close(at);
    }

    w.u32(assertion.unix_id);
    w.bytes(&assertion.primary_group, MAX_SID_BYTES)?;

    // Nested, so PGSS Logon can grow the profile on its own schedule without
    // displacing the claims that follow it here.
    let nested = w.open();
    crate::wire::write_profile_body(&mut w, &assertion.profile)?;
    w.close(nested);

    crate::claim::write_claims(&mut w, &assertion.claims)?;

    w.close(body);
    w.finish()
}

pub fn decode_assertion(buf: &[u8]) -> Result<Assertion, WireError> {
    let mut b = open_body(buf, MSG_ASSERTION)?;
    let user_sid = b.bytes(MAX_SID_BYTES)?.to_vec();
    let canonical_name = b.string(MAX_CANONICAL_NAME_BYTES)?.to_owned();

    // Every field below is optional in the same way and for the same reason: a
    // source built against an earlier shape simply stopped writing, and what it
    // did not write it did not mean. Each default is the honest reading of
    // silence — no groups, no number, no primary group, no profile, no claims —
    // rather than a guess standing in for one.
    let groups = if b.at_end() {
        Vec::new()
    } else {
        b.array(MAX_GROUPS, |g| {
            let sid = g.bytes(MAX_SID_BYTES)?.to_vec();
            let unix_id = if g.at_end() { 0 } else { g.u32()? };
            Ok(Group { sid, unix_id })
        })?
    };
    let unix_id = if b.at_end() { 0 } else { b.u32()? };
    let primary_group = if b.at_end() {
        Vec::new()
    } else {
        b.bytes(MAX_SID_BYTES)?.to_vec()
    };
    let profile = if b.at_end() {
        Profile::default()
    } else {
        crate::wire::read_profile_body(&mut b.open()?)?
    };
    let claims = if b.at_end() {
        Vec::new()
    } else {
        crate::claim::read_claims(&mut b)?
    };

    Ok(Assertion {
        user_sid,
        canonical_name,
        groups,
        unix_id,
        primary_group,
        profile,
        claims,
    })
}

pub fn encode_refusal(conversation: u64, refusal: &Refusal) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_REFUSAL, conversation);
    let body = w.open();
    w.u32(refusal.denial as u32);
    w.string(&refusal.reason, MAX_REASON_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_refusal(buf: &[u8]) -> Result<Refusal, WireError> {
    let mut b = open_body(buf, MSG_REFUSAL)?;
    Ok(Refusal {
        denial: Denial::from_u32(b.u32()?).ok_or(WireError::UnknownValue)?,
        reason: b.string(MAX_REASON_BYTES)?.to_owned(),
    })
}

/// authd abandoning a conversation — the client hung up, or a limit was hit.
///
/// Not politeness: without it a source accumulates conversation state for
/// logons that will never terminate, which is a slow resource leak reachable by
/// anyone who can open the logon socket and walk away.
pub fn encode_abandon(conversation: u64) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_ABANDON, conversation);
    let body = w.open();
    w.close(body);
    w.finish()
}

pub fn decode_abandon(buf: &[u8]) -> Result<(), WireError> {
    open_body(buf, MSG_ABANDON)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity queries
// ---------------------------------------------------------------------------

fn write_key(w: &mut Writer, key: Option<&Key>) -> Result<(), WireError> {
    let (discriminant, name, sid, relative_id) = match key {
        None => (0, "", &[][..], 0),
        Some(Key::Name(name)) => (1, name.as_str(), &[][..], 0),
        Some(Key::Sid(sid)) => (2, "", sid.as_slice(), 0),
        Some(Key::RelativeId(id)) => (3, "", &[][..], *id),
    };
    w.u8(discriminant);
    w.string(name, MAX_CANONICAL_NAME_BYTES)?;
    w.bytes(sid, MAX_SID_BYTES)?;
    w.u32(relative_id);
    Ok(())
}

fn read_key(r: &mut frame::Reader<'_>) -> Result<Option<Key>, WireError> {
    let discriminant = r.u8()?;
    let name = r.string(MAX_CANONICAL_NAME_BYTES)?.to_owned();
    let sid = r.bytes(MAX_SID_BYTES)?.to_vec();
    let relative_id = r.u32()?;
    // Zero is "no key" — `EnumerateSource.of` meaning *everything* — rather than
    // a `Key` variant, so it is checked before the conversion.
    Ok(match discriminant {
        0 => None,
        1 => Some(Key::Name(name)),
        2 => Some(Key::Sid(sid)),
        3 => Some(Key::RelativeId(relative_id)),
        _ => return Err(WireError::UnknownValue),
    })
}

fn write_entry(w: &mut Writer, entry: &QueryEntry) -> Result<(), WireError> {
    w.u8(entry.outcome as u8);
    w.bytes(&entry.sid, MAX_SID_BYTES)?;
    w.string(&entry.canonical_name, MAX_CANONICAL_NAME_BYTES)?;
    w.u8(entry.kind as u8);
    crate::ident::write_attributes(w, &entry.values, &entry.withheld)
}

fn read_entry(r: &mut frame::Reader<'_>) -> Result<QueryEntry, WireError> {
    let outcome = Outcome::from_u8(r.u8()?).ok_or(WireError::UnknownValue)?;
    // A source answers about what it holds, so these two are its to produce and
    // neither is meaningful for it: `Unavailable` describes a source that did
    // not answer, and a message a source cannot parse is a `Refusal` for the
    // whole conversation.
    if matches!(outcome, Outcome::Unavailable | Outcome::Malformed) {
        return Err(WireError::UnknownValue);
    }
    let sid = r.bytes(MAX_SID_BYTES)?.to_vec();
    let canonical_name = r.string(MAX_CANONICAL_NAME_BYTES)?.to_owned();
    let kind = Kind::from_u8(r.u8()?).ok_or(WireError::UnknownValue)?;
    let (values, withheld) = crate::ident::read_attributes(r)?;
    Ok(QueryEntry {
        outcome,
        sid,
        canonical_name,
        kind,
        values,
        withheld,
    })
}

pub fn encode_query(conversation: u64, query: &Query) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_QUERY, conversation);
    let body = w.open();
    w.u32(query.fields.0);
    w.count(query.keys.len(), MAX_KEYS)?;
    for key in &query.keys {
        let at = w.open();
        write_key(&mut w, Some(&key.key))?;
        w.u8(key.kind as u8);
        w.close(at);
    }
    w.close(body);
    w.finish()
}

pub fn decode_query(buf: &[u8]) -> Result<Query, WireError> {
    let mut b = open_body(buf, MSG_QUERY)?;
    let fields = Fields(b.u32()?);
    let keys = b.array(MAX_KEYS, |entry| {
        Ok(QueryKey {
            key: read_key(entry)?.ok_or(WireError::UnknownValue)?,
            kind: Kind::from_u8(entry.u8()?).ok_or(WireError::UnknownValue)?,
        })
    })?;
    Ok(Query { fields, keys })
}

pub fn encode_query_result(
    conversation: u64,
    result: &QueryResult,
) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_QUERY_RESULT, conversation);
    let body = w.open();
    w.count(result.results.len(), MAX_KEYS)?;
    for entry in &result.results {
        let at = w.open();
        write_entry(&mut w, entry)?;
        w.close(at);
    }
    w.close(body);
    w.finish()
}

pub fn decode_query_result(buf: &[u8]) -> Result<QueryResult, WireError> {
    let mut b = open_body(buf, MSG_QUERY_RESULT)?;
    Ok(QueryResult {
        results: b.array(MAX_KEYS, read_entry)?,
    })
}

pub fn encode_enumerate_source(
    conversation: u64,
    request: &EnumerateSource,
) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_ENUMERATE_SOURCE, conversation);
    let body = w.open();
    w.u8(request.kind as u8);
    w.u32(request.fields.0);
    let at = w.open();
    write_key(&mut w, request.of.as_ref())?;
    w.close(at);
    w.bytes(&request.cursor, MAX_CURSOR_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_enumerate_source(buf: &[u8]) -> Result<EnumerateSource, WireError> {
    let mut b = open_body(buf, MSG_ENUMERATE_SOURCE)?;
    let kind = Kind::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let fields = Fields(b.u32()?);
    let of = read_key(&mut b.open()?)?;
    let cursor = b.bytes(MAX_CURSOR_BYTES)?.to_vec();
    Ok(EnumerateSource {
        kind,
        fields,
        of,
        cursor,
    })
}

pub fn encode_enumerate_result(
    conversation: u64,
    result: &EnumerateResult,
) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_ENUMERATE_RESULT, conversation);
    let body = w.open();
    w.u8(result.outcome as u8);
    w.count(result.entries.len(), MAX_ENTRIES)?;
    for entry in &result.entries {
        let at = w.open();
        write_entry(&mut w, entry)?;
        w.close(at);
    }
    w.bytes(&result.next, MAX_CURSOR_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_enumerate_result(buf: &[u8]) -> Result<EnumerateResult, WireError> {
    let mut b = open_body(buf, MSG_ENUMERATE_RESULT)?;
    let outcome = Outcome::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let entries = b.array(MAX_ENTRIES, read_entry)?;
    let next = b.bytes(MAX_CURSOR_BYTES)?.to_vec();
    Ok(EnumerateResult {
        outcome,
        entries,
        next,
    })
}

pub fn encode_changed(changed: &Changed) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_CHANGED, CONVERSATION_CONTROL);
    let body = w.open();
    w.u8(changed.scope as u8);
    w.bytes(&changed.sid, MAX_SID_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_changed(buf: &[u8]) -> Result<Changed, WireError> {
    let mut b = open_body(buf, MSG_CHANGED)?;
    Ok(Changed {
        scope: ChangeScope::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?,
        sid: b.bytes(MAX_SID_BYTES)?.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        Answer, CredentialType, IdentifierType, LogonType, Message, MessageSeverity, Prompt,
    };

    fn start() -> LogonStart {
        LogonStart {
            logon_type: LogonType::Interactive,
            identifier_type: IdentifierType::Username,
            identifier: b"jack".to_vec(),
            tty: Some("/dev/console".into()),
            remote_host: None,
            supported_credential_types: vec![CredentialType::Password],
        }
    }

    /// `S-1-5-21-1-2-3`, binary.
    fn domain() -> Vec<u8> {
        let mut sid = vec![1, 4, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        sid
    }

    #[test]
    fn register_round_trips() {
        let bytes = encode_register(&Register {
            source_name: "lpsd".into(),
            domain: domain(),
            ..Default::default()
        })
        .unwrap();
        let decoded = decode_register(&bytes).unwrap();
        assert_eq!(decoded.source_name, "lpsd");
        assert_eq!(decoded.domain, domain());

        let envelope = decode_envelope(&bytes).unwrap();
        assert_eq!(envelope.msg_type, MSG_REGISTER);
        assert_eq!(envelope.conversation, CONVERSATION_CONTROL);
    }

    /// The domain was appended to a message that already existed. A source
    /// built against the older shape must decode as claiming *no* domain —
    /// which authd refuses — rather than as a framing error, so the diagnosis
    /// names the real problem.
    #[test]
    fn a_register_without_a_domain_decodes_as_claiming_none() {
        let mut w = begin(MSG_REGISTER, CONVERSATION_CONTROL);
        let body = w.open();
        w.string("lpsd", MAX_SOURCE_NAME_BYTES).unwrap();
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_register(&bytes).unwrap();
        assert_eq!(decoded.source_name, "lpsd");
        assert!(decoded.domain.is_empty());
    }

    #[test]
    fn an_oversized_domain_is_rejected() {
        assert_eq!(
            encode_register(&Register {
                source_name: "lpsd".into(),
                domain: vec![0; MAX_SID_BYTES + 1],
                ..Default::default()
            })
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn registered_round_trips() {
        let registered = Registered {
            unix_id_base: 1_000_000,
            unix_id_count: 1_000_000,
        };
        let bytes = encode_registered(&registered).unwrap();
        assert_eq!(decode_registered(&bytes).unwrap(), registered);
        assert_eq!(decode_envelope(&bytes).unwrap().msg_type, MSG_REGISTERED);
    }

    /// `Registered` used to be empty. An authority built against that shape
    /// assigns no range, and a zero base is precisely what that means — so it
    /// must decode rather than fail.
    #[test]
    fn a_registered_without_a_range_decodes_as_none_assigned() {
        let mut w = begin(MSG_REGISTERED, CONVERSATION_CONTROL);
        let body = w.open();
        w.close(body);
        let bytes = w.finish().unwrap();

        assert_eq!(decode_registered(&bytes).unwrap(), Registered::default());
    }

    #[test]
    fn authenticate_carries_the_logon_start_and_the_originator() {
        let bytes = encode_authenticate(
            7,
            &Authenticate {
                start: start(),
                originator: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            },
        )
        .unwrap();

        assert_eq!(decode_envelope(&bytes).unwrap().conversation, 7);
        let decoded = decode_authenticate(&bytes).unwrap();
        assert_eq!(decoded.start.identifier, b"jack");
        assert_eq!(decoded.start.logon_type, LogonType::Interactive);
        assert_eq!(decoded.start.tty.as_deref(), Some("/dev/console"));
        assert_eq!(decoded.originator, vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    }

    /// The nesting exists so PGSS Logon can append a field to `LogonStart`
    /// without displacing PSI's own trailing fields. Simulate that: grow the
    /// nested struct and confirm `originator` still reads correctly.
    #[test]
    fn a_field_appended_to_logon_start_does_not_displace_the_originator() {
        let originator = vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut bytes = encode_authenticate(
            1,
            &Authenticate {
                start: start(),
                originator: originator.clone(),
            },
        )
        .unwrap();

        // Splice four bytes onto the end of the nested LogonStart body, as a
        // newer PGSS Logon would, fixing up each enclosing length.
        let nested_len_at = HEADER_BYTES + 4;
        let nested_len =
            u32::from_le_bytes(bytes[nested_len_at..nested_len_at + 4].try_into().unwrap()) as usize;
        let insert_at = nested_len_at + 4 + nested_len;
        for (i, byte) in [0xde, 0xad, 0xbe, 0xef].into_iter().enumerate() {
            bytes.insert(insert_at + i, byte);
        }
        let bump = |buf: &mut Vec<u8>, at: usize| {
            let old = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
            buf[at..at + 4].copy_from_slice(&(old + 4).to_le_bytes());
        };
        bump(&mut bytes, nested_len_at); // the nested LogonStart
        bump(&mut bytes, HEADER_BYTES); // the Authenticate body
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());

        let decoded = decode_authenticate(&bytes).expect("older decoder must cope");
        assert_eq!(decoded.start.identifier, b"jack");
        assert_eq!(decoded.originator, originator);
    }

    #[test]
    fn credential_request_relays_verbatim() {
        let req = CredentialRequest {
            messages: vec![Message {
                severity: MessageSeverity::Info,
                text: "Hello.".into(),
            }],
            prompts: vec![Prompt {
                credential_ref: 1,
                credential_type: CredentialType::Password,
                credential_name: "Password".into(),
            }],
        };
        let bytes = encode_credential_request(3, &req).unwrap();
        assert_eq!(decode_envelope(&bytes).unwrap().conversation, 3);

        let decoded = decode_credential_request(&bytes).unwrap();
        assert_eq!(decoded.prompts.len(), 1);
        assert_eq!(decoded.prompts[0].credential_name, "Password");
        assert_eq!(decoded.messages[0].text, "Hello.");
    }

    /// The bodies really are shared: a request encoded for PGSS Logon and one
    /// encoded for PSI must differ only in their envelopes.
    #[test]
    fn the_two_protocols_encode_identical_bodies() {
        let req = CredentialRequest {
            messages: Vec::new(),
            prompts: vec![Prompt {
                credential_ref: 9,
                credential_type: CredentialType::Password,
                credential_name: "Password".into(),
            }],
        };
        let pgss = crate::wire::encode_credential_request(&req).unwrap();
        let psi = encode_credential_request(1, &req).unwrap();
        assert_eq!(
            &pgss[crate::wire::HEADER_BYTES..],
            &psi[HEADER_BYTES..],
            "the interrogation phase must be byte-identical across the two protocols"
        );
    }

    #[test]
    fn credential_response_round_trips() {
        let resp = CredentialResponse {
            answers: vec![Answer {
                credential_ref: 1,
                data: Secret::from_slice(b"hunter2"),
            }],
        };
        let encoded = encode_credential_response(5, &resp).unwrap();
        assert_eq!(decode_envelope(encoded.expose()).unwrap().conversation, 5);

        let decoded = decode_credential_response(encoded.expose()).unwrap();
        assert_eq!(decoded.answers[0].data.expose(), b"hunter2");
    }

    fn administrators() -> Vec<u8> {
        vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
    }

    fn everyone() -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
    }

    fn assertion() -> Assertion {
        Assertion {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            canonical_name: "jack".into(),
            groups: vec![
                // A well-known group the source does not number, and a local
                // one it does — the two cases that have to be distinguishable.
                Group {
                    sid: administrators(),
                    unix_id: 0,
                },
                Group {
                    sid: everyone(),
                    unix_id: 42,
                },
            ],
            unix_id: 7,
            primary_group: everyone(),
            profile: Profile {
                home: "/home/jack".into(),
                shell: "/bin/sh".into(),
                display_name: "Jack Palfrey".into(),
            },
            claims: vec![Claim {
                name: "Department".into(),
                flags: crate::claim::FLAG_MANDATORY,
                values: crate::claim::Values::String(vec!["Engineering".into()]),
            }],
        }
    }

    #[test]
    fn assertion_round_trips() {
        let decoded = decode_assertion(&encode_assertion(2, &assertion()).unwrap()).unwrap();
        assert_eq!(decoded.canonical_name, "jack");
        assert_eq!(decoded.user_sid.len(), 12);

        assert_eq!(decoded.groups.len(), 2);
        assert_eq!(decoded.groups[0].sid, administrators());
        assert_eq!(
            decoded.groups[0].unix_id, 0,
            "a group the source does not own carries no number"
        );
        assert_eq!(decoded.groups[1].sid, everyone());
        assert_eq!(decoded.groups[1].unix_id, 42);

        assert_eq!(decoded.unix_id, 7);
        assert_eq!(decoded.primary_group, everyone());
        assert_eq!(decoded.profile.home, "/home/jack");
        assert_eq!(decoded.profile.display_name, "Jack Palfrey");
        assert_eq!(decoded.claims.len(), 1);
        assert_eq!(decoded.claims[0].name, "Department");
    }

    #[test]
    fn an_assertion_may_carry_no_groups() {
        let decoded = decode_assertion(
            &encode_assertion(
                2,
                &Assertion {
                    groups: Vec::new(),
                    ..assertion()
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(decoded.groups.is_empty());
        assert_eq!(
            decoded.unix_id, 7,
            "an empty array must not swallow what follows it"
        );
    }

    /// A source predating every field after the name asserts none of them —
    /// which is precisely what it meant, so it must decode rather than fail.
    /// Written by hand, because no encoder produces this shape any more.
    #[test]
    fn an_assertion_with_only_the_original_fields_decodes_as_empty() {
        let mut w = begin(MSG_ASSERTION, 2);
        let body = w.open();
        w.bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], MAX_SID_BYTES)
            .unwrap();
        w.string("jack", MAX_CANONICAL_NAME_BYTES).unwrap();
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_assertion(&bytes).expect("an older source must decode");
        assert_eq!(decoded.canonical_name, "jack");
        assert!(decoded.groups.is_empty());
        assert_eq!(decoded.unix_id, 0);
        assert!(decoded.primary_group.is_empty());
        assert_eq!(decoded.profile, Profile::default());
        assert!(decoded.claims.is_empty());
    }

    /// The reason each group gets its own frame — and the case it was put there
    /// for actually happened: the Unix ID was appended to a group entry. A
    /// *further* field must skip just as cleanly, and must not displace the
    /// fields that follow the array.
    #[test]
    fn a_field_appended_to_a_group_is_skipped() {
        let mut w = begin(MSG_ASSERTION, 2);
        let body = w.open();
        w.bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], MAX_SID_BYTES)
            .unwrap();
        w.string("jack", MAX_CANONICAL_NAME_BYTES).unwrap();
        w.count(1, MAX_GROUPS).unwrap();
        let at = w.open();
        w.bytes(&everyone(), MAX_SID_BYTES).unwrap();
        w.u32(42);
        w.u32(0xdead_beef); // a field this decoder does not know about
        w.close(at);
        w.u32(9); // the principal's own id, after the array
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_assertion(&bytes).expect("older decoder must cope");
        assert_eq!(decoded.groups.len(), 1);
        assert_eq!(decoded.groups[0].sid, everyone());
        assert_eq!(decoded.groups[0].unix_id, 42);
        assert_eq!(
            decoded.unix_id, 9,
            "an unknown field inside a group must not displace what follows the array"
        );
    }

    /// A group entry from before the Unix ID existed decodes as unnumbered,
    /// which is the same thing a source says about a group it does not own.
    #[test]
    fn a_group_without_a_unix_id_decodes_as_unnumbered() {
        let mut w = begin(MSG_ASSERTION, 2);
        let body = w.open();
        w.bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0], MAX_SID_BYTES)
            .unwrap();
        w.string("jack", MAX_CANONICAL_NAME_BYTES).unwrap();
        w.count(1, MAX_GROUPS).unwrap();
        let at = w.open();
        w.bytes(&everyone(), MAX_SID_BYTES).unwrap();
        w.close(at);
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_assertion(&bytes).expect("an older source must decode");
        assert_eq!(decoded.groups[0].unix_id, 0);
    }

    #[test]
    fn too_many_groups_is_rejected() {
        assert_eq!(
            encode_assertion(
                1,
                &Assertion {
                    groups: vec![
                        Group {
                            sid: everyone(),
                            unix_id: 0
                        };
                        MAX_GROUPS + 1
                    ],
                    ..assertion()
                }
            )
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn refusal_round_trips() {
        let bytes = encode_refusal(
            2,
            &Refusal {
                denial: Denial::AuthenticationFailed,
                reason: "Authentication failed.".into(),
            },
        )
        .unwrap();
        let decoded = decode_refusal(&bytes).unwrap();
        assert_eq!(decoded.denial, Denial::AuthenticationFailed);
    }

    #[test]
    fn abandon_round_trips() {
        let bytes = encode_abandon(11).unwrap();
        decode_abandon(&bytes).unwrap();
        assert_eq!(decode_envelope(&bytes).unwrap().conversation, 11);
    }

    /// The safety property the distinct magic buys: a PGSS Logon message fed to
    /// a PSI decoder must fail immediately, not decode into something plausible
    /// because the bodies happen to match.
    #[test]
    fn a_pgss_logon_message_is_not_a_psi_message() {
        let req = CredentialRequest {
            messages: Vec::new(),
            prompts: Vec::new(),
        };
        let pgss = crate::wire::encode_credential_request(&req).unwrap();
        assert_eq!(decode_envelope(&pgss).unwrap_err(), WireError::BadMagic);
        assert_eq!(
            decode_credential_request(&pgss).unwrap_err(),
            WireError::BadMagic
        );
    }

    #[test]
    fn a_psi_message_is_not_a_pgss_logon_message() {
        let bytes = encode_abandon(1).unwrap();
        assert_eq!(
            crate::wire::decode_header(&bytes).unwrap_err(),
            WireError::BadMagic
        );
    }

    #[test]
    fn oversized_source_name_is_rejected() {
        let long = "l".repeat(MAX_SOURCE_NAME_BYTES + 1);
        assert_eq!(
            encode_register(&Register {
                source_name: long,
                domain: domain(),
                ..Default::default()
            })
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn oversized_sid_is_rejected() {
        assert_eq!(
            encode_assertion(
                1,
                &Assertion {
                    user_sid: vec![0; MAX_SID_BYTES + 1],
                    canonical_name: "x".into(),
                    groups: Vec::new(),
                    ..Assertion::default()
                }
            )
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn an_oversized_group_sid_is_rejected() {
        assert_eq!(
            encode_assertion(
                1,
                &Assertion {
                    groups: vec![Group {
                        sid: vec![0; MAX_SID_BYTES + 1],
                        unix_id: 0,
                    }],
                    ..assertion()
                }
            )
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let messages: Vec<Vec<u8>> = vec![
            encode_register(&Register {
                source_name: "lpsd".into(),
                domain: domain(),
                ..Default::default()
            })
            .unwrap(),
            encode_registered(&Registered {
                unix_id_base: 1_000_000,
                unix_id_count: 1_000_000,
            })
            .unwrap(),
            encode_authenticate(
                1,
                &Authenticate {
                    start: start(),
                    originator: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                },
            )
            .unwrap(),
            encode_assertion(1, &assertion()).unwrap(),
            encode_refusal(
                1,
                &Refusal {
                    denial: Denial::Internal,
                    reason: "x".into(),
                },
            )
            .unwrap(),
            encode_abandon(1).unwrap(),
        ];
        for message in &messages {
            for cut in 0..message.len() {
                let prefix = &message[..cut];
                let _ = decode_envelope(prefix);
                let _ = decode_register(prefix);
                let _ = decode_registered(prefix);
                let _ = decode_authenticate(prefix);
                let _ = decode_credential_request(prefix);
                let _ = decode_credential_response(prefix);
                let _ = decode_assertion(prefix);
                let _ = decode_refusal(prefix);
                let _ = decode_abandon(prefix);
            }
        }
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;
    use crate::ident::WithheldReason;

    fn sid(sub: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, 5];
        for value in sub {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn entry() -> QueryEntry {
        QueryEntry {
            outcome: Outcome::Found,
            sid: sid(&[21, 1, 2, 3, 1000]),
            canonical_name: "jack".into(),
            kind: Kind::Principal,
            values: vec![
                // Relative, not rebased — the source counts inside its range and
                // authd adds the base.
                Value::UnixId(1000),
                Value::Home("/home/jack".into()),
                Value::Shell("/bin/sh".into()),
            ],
            withheld: vec![Withheld {
                field: Fields::MEMBERS,
                reason: WithheldReason::Absent,
            }],
        }
    }

    #[test]
    fn a_query_survives_a_round_trip() {
        let query = Query {
            fields: Fields::PASSWD,
            keys: vec![
                QueryKey {
                    key: Key::Name("jack".into()),
                    kind: Kind::Principal,
                },
                QueryKey {
                    key: Key::RelativeId(1000),
                    kind: Kind::Any,
                },
                QueryKey {
                    key: Key::Sid(sid(&[21, 1, 2, 3, 1001])),
                    kind: Kind::Group,
                },
            ],
        };
        assert_eq!(decode_query(&encode_query(7, &query).unwrap()).unwrap(), query);
    }

    #[test]
    fn a_query_result_survives_a_round_trip() {
        let result = QueryResult {
            results: vec![
                entry(),
                QueryEntry {
                    outcome: Outcome::NotFound,
                    ..QueryEntry::default()
                },
            ],
        };
        let decoded = decode_query_result(&encode_query_result(7, &result).unwrap()).unwrap();
        assert_eq!(decoded, result);
    }

    /// A source is answering, so nothing was unavailable to *it*. Letting it say
    /// so would record a working source as a broken one.
    #[test]
    fn a_source_may_not_claim_unavailable_or_malformed() {
        for outcome in [Outcome::Unavailable, Outcome::Malformed] {
            let result = QueryResult {
                results: vec![QueryEntry {
                    outcome,
                    ..QueryEntry::default()
                }],
            };
            let bytes = encode_query_result(1, &result).unwrap();
            assert!(
                matches!(decode_query_result(&bytes), Err(WireError::UnknownValue)),
                "{outcome:?} must be refused from a source"
            );
        }
    }

    #[test]
    fn a_source_may_refuse_a_principal_it_holds() {
        let result = QueryResult {
            results: vec![QueryEntry {
                outcome: Outcome::Refused,
                ..QueryEntry::default()
            }],
        };
        let decoded = decode_query_result(&encode_query_result(1, &result).unwrap()).unwrap();
        assert_eq!(decoded.results[0].outcome, Outcome::Refused);
    }

    #[test]
    fn an_enumeration_request_survives_a_round_trip() {
        for of in [None, Some(Key::Name("developers".into()))] {
            let request = EnumerateSource {
                kind: Kind::Principal,
                fields: Fields::PASSWD,
                of: of.clone(),
                cursor: vec![1, 2, 3],
            };
            let decoded =
                decode_enumerate_source(&encode_enumerate_source(2, &request).unwrap()).unwrap();
            assert_eq!(decoded, request, "of = {of:?}");
        }
    }

    #[test]
    fn an_enumeration_result_survives_a_round_trip() {
        let result = EnumerateResult {
            outcome: Outcome::Found,
            entries: vec![entry(), entry()],
            next: vec![7, 7],
        };
        let decoded =
            decode_enumerate_result(&encode_enumerate_result(2, &result).unwrap()).unwrap();
        assert_eq!(decoded, result);
    }

    /// A non-empty cursor means there is more even where the page was empty.
    #[test]
    fn an_empty_page_with_a_cursor_is_not_the_end() {
        let result = EnumerateResult {
            outcome: Outcome::Found,
            entries: vec![],
            next: vec![1],
        };
        let decoded =
            decode_enumerate_result(&encode_enumerate_result(2, &result).unwrap()).unwrap();
        assert!(decoded.entries.is_empty());
        assert!(!decoded.next.is_empty());
    }

    #[test]
    fn a_source_that_will_not_enumerate_refuses() {
        let result = EnumerateResult {
            outcome: Outcome::Refused,
            entries: vec![],
            next: vec![],
        };
        let decoded =
            decode_enumerate_result(&encode_enumerate_result(2, &result).unwrap()).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn a_change_notification_survives_a_round_trip() {
        for changed in [
            Changed {
                scope: ChangeScope::All,
                sid: vec![],
            },
            Changed {
                scope: ChangeScope::Object,
                sid: sid(&[21, 1, 2, 3, 1000]),
            },
        ] {
            let decoded = decode_changed(&encode_changed(&changed).unwrap()).unwrap();
            assert_eq!(decoded, changed);
        }
    }

    /// Connection-level, like registration — it belongs to no conversation.
    #[test]
    fn a_change_notification_rides_the_control_conversation() {
        let bytes = encode_changed(&Changed {
            scope: ChangeScope::All,
            sid: vec![],
        })
        .unwrap();
        assert_eq!(
            decode_envelope(&bytes).unwrap().conversation,
            CONVERSATION_CONTROL
        );
    }

    /// A source predating capabilities declares none, so authd sends it nothing
    /// beyond a logon and never caches it. Anything else would break it.
    #[test]
    fn a_register_without_capabilities_declares_none() {
        let mut w = begin(MSG_REGISTER, CONVERSATION_CONTROL);
        let body = w.open();
        w.string("lpsd", MAX_SOURCE_NAME_BYTES).unwrap();
        w.bytes(&sid(&[21, 1, 2, 3]), MAX_SID_BYTES).unwrap();
        w.close(body);
        let decoded = decode_register(&w.finish().unwrap()).unwrap();
        assert_eq!(decoded.capabilities, Capabilities::empty());
        assert_eq!(decoded.entry_ttl, 0, "and so must not be cached");
        assert_eq!(decoded.max_batch, 0);
    }

    #[test]
    fn capabilities_survive_a_round_trip() {
        let register = Register {
            source_name: "lpsd".into(),
            domain: sid(&[21, 1, 2, 3]),
            capabilities: Capabilities::QUERIES
                | Capabilities::ENUMERATES
                | Capabilities::MEMBERS
                | Capabilities::PUSHES_CHANGES,
            entry_ttl: 0,
            max_batch: 64,
        };
        let decoded = decode_register(&encode_register(&register).unwrap()).unwrap();
        assert_eq!(decoded.capabilities, register.capabilities);
        assert_eq!(decoded.max_batch, 64);
        assert!(decoded.capabilities.contains(Capabilities::MEMBERS));
        assert!(!Capabilities::QUERIES.contains(Capabilities::MEMBERS));
    }

    /// A source's answer and the authority's describe the same object, so the
    /// attribute encoding is shared rather than translated between two spellings.
    #[test]
    fn psi_and_ident_encode_attributes_identically() {
        let values = vec![Value::UnixId(1000), Value::Shell("/bin/sh".into())];
        let withheld = vec![Withheld {
            field: Fields::MEMBERS,
            reason: WithheldReason::Declined,
        }];

        // `begin` writes PSI's conversation id after the common header, which is
        // what makes `HEADER_BYTES` the right place to cut.
        let mut psi = begin(MSG_QUERY_RESULT, CONVERSATION_CONTROL);
        crate::ident::write_attributes(&mut psi, &values, &withheld).unwrap();

        let mut ident = Writer::new(&crate::wire::FRAMING, crate::ident::MSG_LOOKUP_REPLY);
        crate::ident::write_attributes(&mut ident, &values, &withheld).unwrap();

        let psi = psi.finish().unwrap();
        let ident = ident.finish().unwrap();
        assert_eq!(
            psi[HEADER_BYTES..],
            ident[crate::wire::HEADER_BYTES..],
            "the shared body must be byte-identical in both protocols"
        );
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let messages: Vec<Vec<u8>> = vec![
            encode_query(
                1,
                &Query {
                    fields: Fields::PASSWD,
                    keys: vec![QueryKey {
                        key: Key::Name("jack".into()),
                        kind: Kind::Principal,
                    }],
                },
            )
            .unwrap(),
            encode_query_result(
                1,
                &QueryResult {
                    results: vec![entry()],
                },
            )
            .unwrap(),
            encode_enumerate_source(
                1,
                &EnumerateSource {
                    kind: Kind::Principal,
                    fields: Fields::PASSWD,
                    of: Some(Key::RelativeId(1000)),
                    cursor: vec![1],
                },
            )
            .unwrap(),
            encode_enumerate_result(
                1,
                &EnumerateResult {
                    outcome: Outcome::Found,
                    entries: vec![entry()],
                    next: vec![2],
                },
            )
            .unwrap(),
            encode_changed(&Changed {
                scope: ChangeScope::Object,
                sid: sid(&[21, 1, 2, 3, 1000]),
            })
            .unwrap(),
        ];
        for message in &messages {
            for cut in 0..message.len() {
                let prefix = &message[..cut];
                let _ = decode_envelope(prefix);
                let _ = decode_query(prefix);
                let _ = decode_query_result(prefix);
                let _ = decode_enumerate_source(prefix);
                let _ = decode_enumerate_result(prefix);
                let _ = decode_changed(prefix);
            }
        }
    }
}
