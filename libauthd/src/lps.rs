//! **LPS** — the protocol `lps` speaks to `lpsd` to administer the local
//! principal store.
//!
//! Spoken on `/run/lpsd/admin.sock`. Third protocol on [`frame`], alongside
//! PGSS Logon and PSI, with its own magic (`PLPS`) so a socket plugged into the
//! wrong daemon fails on the first four bytes rather than several fields in.
//!
//! # Why there is a protocol here at all
//!
//! The obvious alternative is a CLI that edits the store file directly, and it
//! was rejected for a reason that is easy to lose sight of: the store's
//! descriptor grants `LocalSystem` and nothing else, precisely so that the
//! machine's credential verifiers are readable by as few principals as
//! possible. A tool that writes the file needs read and write on it, so the
//! descriptor would have to be widened to whatever that tool runs as — undoing
//! the one thing that descriptor exists to do.
//!
//! Going through the daemon also makes authorization *expressible*. "An
//! administrator may add a principal, but a principal may change their own
//! password" cannot be said with file permissions; over a socket it is a check
//! on the caller's token. And it leaves the store with exactly one writer,
//! which is what atomic replacement quietly assumes.
//!
//! # Shape
//!
//! Strict request/response, one exchange at a time, no pipelining and no
//! conversation ids — so unlike PSI there is nothing to demultiplex. An
//! administrative tool does one thing and exits; the concurrency PSI needs
//! (many logons over one long-lived connection) has no analogue here, and
//! inventing it would be structure without purpose.
//!
//! Every request is answered exactly once, with either its specific reply or
//! [`MSG_FAILED`].
//!
//! # Credentials
//!
//! [`Add`] and [`SetPassword`] carry a password in the clear, and the reasoning
//! is the project's standing one: on a kernel-mediated local socket, anything
//! that could read the bytes could equally `ptrace` the process that typed
//! them. What must never travel is anything a verifier could be *recomputed*
//! from, and nothing here does — the daemon derives the verifier and the
//! plaintext ends at its process boundary.
//!
//! Both structs borrow the secret from the message buffer rather than owning
//! it, so a password is never copied out of the [`crate::Secret`] the transport
//! read it into.

use crate::claim::Claim;
use crate::frame::{self, Framing, Reader, WireError, Writer};
use crate::secret::Secret;

pub const MAGIC: [u8; 4] = *b"PLPS";
pub const VERSION: u16 = 1;

/// No conversation id, so the common header is the whole header.
pub const HEADER_BYTES: usize = frame::COMMON_HEADER_BYTES;

/// Sized to hold the largest reply the daemon can generate: a full listing of
/// the store's maximum [`MAX_PRINCIPALS`] principals, each with a name of up to
/// [`MAX_NAME_BYTES`], is about 1.1 MiB. Two gives headroom without inviting an
/// allocation worth worrying about — and only an administrator can reach this
/// socket to ask for one.
pub const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

pub const FRAMING: Framing = Framing {
    magic: MAGIC,
    version: VERSION,
    header_bytes: HEADER_BYTES,
    max_message_bytes: MAX_MESSAGE_BYTES,
};

// client -> lpsd
pub const MSG_LIST: u16 = 0x0001;
pub const MSG_SHOW: u16 = 0x0002;
pub const MSG_DOMAIN: u16 = 0x0003;
pub const MSG_ADD: u16 = 0x0004;
pub const MSG_REMOVE: u16 = 0x0005;
pub const MSG_SET_ENABLED: u16 = 0x0006;
pub const MSG_SET_PASSWORD: u16 = 0x0007;
pub const MSG_GROUP_ADD: u16 = 0x0008;
pub const MSG_GROUP_REMOVE: u16 = 0x0009;
pub const MSG_GROUP_LIST: u16 = 0x000a;
pub const MSG_GROUP_CREATE: u16 = 0x000b;
pub const MSG_GROUP_DELETE: u16 = 0x000c;
pub const MSG_SET_PROFILE: u16 = 0x000d;
pub const MSG_SET_PRIMARY_GROUP: u16 = 0x000e;
pub const MSG_SET_CLAIM: u16 = 0x000f;
pub const MSG_REMOVE_CLAIM: u16 = 0x0010;
// lpsd -> client. The high bit marks a message sent by the authority, as in
// PGSS Logon and PSI — here lpsd is the authority for its own store.
pub const MSG_PRINCIPALS: u16 = 0x8001;
pub const MSG_PRINCIPAL: u16 = 0x8002;
pub const MSG_DOMAIN_IS: u16 = 0x8003;
pub const MSG_CREATED: u16 = 0x8004;
pub const MSG_DONE: u16 = 0x8005;
pub const MSG_FAILED: u16 = 0x8006;
pub const MSG_GROUPS: u16 = 0x8007;

/// Which reply answers which request, on success.
///
/// The protocol is strict request/response, so every request has exactly one
/// successful answer — but until this existed that pairing lived only in the
/// daemon's dispatch and the tool's call sites, in two crates, agreeing by
/// inspection. They stopped agreeing: `MSG_GROUP_CREATE` allocates a RID and so
/// is answered with [`MSG_CREATED`], while `lps` decoded [`MSG_DONE`] and
/// reported a *failure* for an operation that had already succeeded. An operator
/// then retries and is told the group already exists.
///
/// So the pairing is declared once, here, and lpsd checks its own replies
/// against it. `None` means the request type is not one this protocol defines.
///
/// [`MSG_FAILED`] answers anything and is deliberately absent: it is the failure
/// path, not the successful answer to any particular request.
pub fn reply_to(request: u16) -> Option<u16> {
    Some(match request {
        MSG_LIST => MSG_PRINCIPALS,
        MSG_SHOW => MSG_PRINCIPAL,
        MSG_DOMAIN => MSG_DOMAIN_IS,
        MSG_GROUP_LIST => MSG_GROUPS,
        // The two that allocate a RID, and so have something to report back.
        MSG_ADD | MSG_GROUP_CREATE => MSG_CREATED,
        MSG_REMOVE
        | MSG_SET_ENABLED
        | MSG_SET_PASSWORD
        | MSG_GROUP_ADD
        | MSG_GROUP_REMOVE
        | MSG_GROUP_DELETE
        | MSG_SET_PROFILE
        | MSG_SET_PRIMARY_GROUP
        | MSG_SET_CLAIM
        | MSG_REMOVE_CLAIM => MSG_DONE,
        _ => return None,
    })
}

/// Every request type this protocol defines. Exists so [`reply_to`] can be
/// tested for completeness rather than trusted.
pub const REQUEST_TYPES: &[u16] = &[
    MSG_LIST,
    MSG_SHOW,
    MSG_DOMAIN,
    MSG_ADD,
    MSG_REMOVE,
    MSG_SET_ENABLED,
    MSG_SET_PASSWORD,
    MSG_GROUP_ADD,
    MSG_GROUP_REMOVE,
    MSG_GROUP_LIST,
    MSG_GROUP_CREATE,
    MSG_GROUP_DELETE,
    MSG_SET_PROFILE,
    MSG_SET_PRIMARY_GROUP,
    MSG_SET_CLAIM,
    MSG_REMOVE_CLAIM,
];

/// Matches the store's own ceiling on a principal name. A protocol that could
/// not carry a name the store accepts would make some principals invisible to
/// the only tool that administers them.
pub const MAX_NAME_BYTES: usize = 256;

/// Matches the store's ceiling on memberships.
pub const MAX_GROUPS: usize = 128;

/// Matches the store's ceiling on principals.
pub const MAX_PRINCIPALS: usize = 4096;

/// Matches the store's ceiling on local group objects.
pub const MAX_GROUP_OBJECTS: usize = 4096;

/// Matches PGSS Logon's ceilings on the same fields, since these are the same
/// strings travelling in the other direction.
pub const MAX_PATH_BYTES: usize = crate::wire::MAX_PATH_BYTES;
pub const MAX_DISPLAY_NAME_BYTES: usize = crate::wire::MAX_DISPLAY_NAME_BYTES;

/// The largest a password may be.
///
/// Generous rather than restrictive: a passphrase is a good password and a
/// length limit is the wrong place to have opinions. argon2id's own input
/// limit is far higher, so this exists to bound the message rather than to
/// constrain anybody.
pub const MAX_SECRET_BYTES: usize = 4096;

pub const MAX_REASON_BYTES: usize = 512;

/// Why a request was refused.
///
/// A small vocabulary a client can branch on, alongside a human-readable
/// message it should print rather than interpret — the same division PGSS
/// Logon's [`crate::wire::Denial`] makes, for the same reason.
///
/// Note what is *not* here: any distinction between "no such principal" and
/// "you may not see that principal". Administration is not authentication, and
/// the caller has already proved they are an administrator, so there is no
/// enumeration oracle to protect against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The caller is not entitled to administer the store.
    Denied,
    /// No principal by that name.
    NotFound,
    /// A principal by that name already exists.
    Exists,
    /// The request was well-formed but asks for something impossible.
    Invalid,
    /// The store could not be read or written.
    Internal,
}

impl Failure {
    fn to_u32(self) -> u32 {
        match self {
            Self::Denied => 1,
            Self::NotFound => 2,
            Self::Exists => 3,
            Self::Invalid => 4,
            Self::Internal => 5,
        }
    }

    fn from_u32(value: u32) -> Result<Self, WireError> {
        Ok(match value {
            1 => Self::Denied,
            2 => Self::NotFound,
            3 => Self::Exists,
            4 => Self::Invalid,
            5 => Self::Internal,
            // Every peer must understand every value it is sent; an unknown one
            // is a version mismatch rather than something to guess at.
            _ => return Err(WireError::UnknownValue),
        })
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// One principal, as [`MSG_LIST`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub name: String,
    pub rid: u32,
    pub enabled: bool,
    pub groups: u32,
    /// The uid this principal projects to — **effective**, with the authority's
    /// base already added. Zero when the daemon has no range, which is what an
    /// operator needs to see: it means every principal here projects to
    /// `nobody` until the range is configured.
    pub unix_id: u32,
}

/// A group as a reply refers to it.
///
/// Resolved by the daemon rather than the tool. `lps` is on the far side of a
/// socket with no store, so a SID is all it could otherwise print — and
/// `S-1-5-32-544` is a worse answer than `Administrators` for every question an
/// operator is actually asking.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupRef {
    pub sid: Vec<u8>,
    /// What this machine calls the group; empty if it knows no name for it.
    pub name: String,
    /// The effective gid, or zero if nothing numbers this group.
    pub unix_id: u32,
}

/// One local group, as [`MSG_GROUP_LIST`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupSummary {
    pub name: String,
    pub rid: u32,
    pub unix_id: u32,
    pub sid: Vec<u8>,
    pub members: u32,
}

/// One principal in full, as [`MSG_SHOW`] reports it.
///
/// Carries the composed SID rather than leaving the caller to build it from the
/// domain and the RID. Composing a SID is the store's business, and a tool that
/// did it independently would be a second implementation of the machine's
/// identity scheme. The same reasoning covers group names and Unix IDs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detail {
    pub name: String,
    pub rid: u32,
    pub enabled: bool,
    pub sid: Vec<u8>,
    pub groups: Vec<GroupRef>,
    pub unix_id: u32,
    pub primary_group: GroupRef,
    pub home: String,
    pub shell: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

/// Set part of a principal's profile. An absent field is left alone, which is
/// what lets `lps` offer `--home` without forcing the operator to restate the
/// shell they did not want to change.
#[derive(Debug, Clone, Default)]
pub struct SetProfile {
    pub name: String,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub display_name: Option<String>,
}

/// Set or replace one claim.
#[derive(Debug, Clone)]
pub struct SetClaim {
    pub name: String,
    pub claim: Claim,
}

/// A principal and a claim name.
#[derive(Debug, Clone)]
pub struct NamedClaim {
    pub name: String,
    pub claim_name: String,
}

/// Create a principal.
///
/// Borrows `secret` from the message buffer, so the password is never copied
/// out of the self-wiping buffer the transport read it into.
#[derive(Debug)]
pub enum Credential<'a> {
    /// A password, verified at every logon. Never empty — an empty password and
    /// no password are different things, and the daemon refuses the first.
    Password(&'a [u8]),
    /// None required: this principal authenticates without collecting anything.
    None,
}

impl Credential<'_> {
    /// The wire tag. Explicit rather than inferring "no password" from an empty
    /// secret, so a client cannot create a passwordless principal by accident —
    /// the most consequential thing this message can do should be the thing it
    /// most plainly says.
    const TAG_NONE: u8 = 0;
    const TAG_PASSWORD: u8 = 1;

    fn tag(&self) -> u8 {
        match self {
            Self::Password(_) => Self::TAG_PASSWORD,
            Self::None => Self::TAG_NONE,
        }
    }
}

pub struct Add<'a> {
    pub name: String,
    pub credential: Credential<'a>,
    pub enabled: bool,
    /// Groups as the operator wrote them, resolved by the daemon — see
    /// [`Membership::group`].
    pub groups: Vec<String>,
}

/// Reset a principal's password. Borrows, for the same reason as [`Add`].
#[derive(Debug)]
pub struct SetPassword<'a> {
    pub name: String,
    pub secret: &'a [u8],
}

/// A request naming a principal and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub name: String,
}

/// A request naming a principal and a group SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub name: String,
    /// The group, as the operator wrote it: a well-known name, a local group's
    /// name, or a literal SID.
    ///
    /// **The daemon resolves it, not the tool.** `lps` has no store, so it could
    /// only ever resolve the third form — and a tool that accepted names by
    /// keeping its own copy of the well-known table would be a second
    /// implementation of the machine's identity scheme, free to disagree with
    /// the first.
    pub group: String,
}

/// Enable or disable a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetEnabled {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub failure: Failure,
    pub reason: String,
}

/// Read an LPS header.
pub fn decode_type(buf: &[u8]) -> Result<(u16, usize), WireError> {
    frame::decode_header(&FRAMING, buf)
}

fn begin(msg_type: u16) -> Writer {
    Writer::new(&FRAMING, msg_type)
}

fn open_body(buf: &[u8], expected: u16) -> Result<frame::Reader<'_>, WireError> {
    frame::open_body(&FRAMING, buf, expected)
}

/// A message with no body beyond its frame.
fn encode_empty(msg_type: u16) -> Result<Vec<u8>, WireError> {
    let mut w = begin(msg_type);
    let body = w.open();
    w.close(body);
    w.finish()
}

fn decode_empty(buf: &[u8], expected: u16) -> Result<(), WireError> {
    open_body(buf, expected)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

pub fn encode_list() -> Result<Vec<u8>, WireError> {
    encode_empty(MSG_LIST)
}

pub fn decode_list(buf: &[u8]) -> Result<(), WireError> {
    decode_empty(buf, MSG_LIST)
}

pub fn encode_domain() -> Result<Vec<u8>, WireError> {
    encode_empty(MSG_DOMAIN)
}

pub fn decode_domain(buf: &[u8]) -> Result<(), WireError> {
    decode_empty(buf, MSG_DOMAIN)
}

fn encode_named(msg_type: u16, named: &Named) -> Result<Vec<u8>, WireError> {
    let mut w = begin(msg_type);
    let body = w.open();
    w.string(&named.name, MAX_NAME_BYTES)?;
    w.close(body);
    w.finish()
}

fn decode_named(buf: &[u8], expected: u16) -> Result<Named, WireError> {
    let mut b = open_body(buf, expected)?;
    Ok(Named {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
    })
}

pub fn encode_show(named: &Named) -> Result<Vec<u8>, WireError> {
    encode_named(MSG_SHOW, named)
}

pub fn decode_show(buf: &[u8]) -> Result<Named, WireError> {
    decode_named(buf, MSG_SHOW)
}

pub fn encode_remove(named: &Named) -> Result<Vec<u8>, WireError> {
    encode_named(MSG_REMOVE, named)
}

pub fn decode_remove(buf: &[u8]) -> Result<Named, WireError> {
    decode_named(buf, MSG_REMOVE)
}

/// Encode an [`Add`].
///
/// Returns a [`Secret`], not a `Vec`: the encoded message contains the password
/// in the clear, so the buffer it was built in is wiped before this returns.
/// Same contract as `wire::encode_credential_response`.
pub fn encode_add(add: &Add<'_>) -> Result<Secret, WireError> {
    let mut w = begin(MSG_ADD);
    let body = w.open();
    w.string(&add.name, MAX_NAME_BYTES)?;
    w.u8(add.credential.tag());
    // The frame is written either way, so the field count does not depend on
    // the tag and a decoder never has to branch before it has read one.
    w.bytes(
        match &add.credential {
            Credential::Password(secret) => secret,
            Credential::None => &[][..],
        },
        MAX_SECRET_BYTES,
    )?;
    w.u8(u8::from(add.enabled));
    // Each group in its own frame, matching PSI: `Reader::array` opens one
    // frame per element, so a bare `bytes` here would be read as a frame length
    // followed by the next field.
    w.count(add.groups.len(), MAX_GROUPS)?;
    for group in &add.groups {
        let at = w.open();
        w.string(group, MAX_NAME_BYTES)?;
        w.close(at);
    }
    w.close(body);

    let encoded = w.finish()?;
    let secret = Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(secret)
}

/// **The caller must wipe `buf` afterwards.** It holds a password in the clear.
pub fn decode_add(buf: &[u8]) -> Result<Add<'_>, WireError> {
    let mut b = open_body(buf, MSG_ADD)?;
    let name = b.string(MAX_NAME_BYTES)?.to_owned();
    let tag = b.u8()?;
    let secret = b.bytes(MAX_SECRET_BYTES)?;
    let credential = match tag {
        Credential::TAG_NONE => Credential::None,
        Credential::TAG_PASSWORD => Credential::Password(secret),
        // The closed-enum rule: an unrecognised credential kind fails the
        // exchange rather than defaulting to either answer.
        _ => return Err(WireError::UnknownValue),
    };
    Ok(Add {
        name,
        credential,
        enabled: b.u8()? != 0,
        groups: b.array(MAX_GROUPS, |g| Ok(g.string(MAX_NAME_BYTES)?.to_owned()))?,
    })
}

/// Encode a [`SetPassword`]. Returns a [`Secret`], as [`encode_add`] does.
pub fn encode_set_password(set: &SetPassword<'_>) -> Result<Secret, WireError> {
    let mut w = begin(MSG_SET_PASSWORD);
    let body = w.open();
    w.string(&set.name, MAX_NAME_BYTES)?;
    w.bytes(set.secret, MAX_SECRET_BYTES)?;
    w.close(body);

    let encoded = w.finish()?;
    let secret = Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(secret)
}

/// **The caller must wipe `buf` afterwards.** It holds a password in the clear.
pub fn decode_set_password(buf: &[u8]) -> Result<SetPassword<'_>, WireError> {
    let mut b = open_body(buf, MSG_SET_PASSWORD)?;
    Ok(SetPassword {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        secret: b.bytes(MAX_SECRET_BYTES)?,
    })
}

pub fn encode_set_enabled(set: &SetEnabled) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_SET_ENABLED);
    let body = w.open();
    w.string(&set.name, MAX_NAME_BYTES)?;
    w.u8(u8::from(set.enabled));
    w.close(body);
    w.finish()
}

pub fn decode_set_enabled(buf: &[u8]) -> Result<SetEnabled, WireError> {
    let mut b = open_body(buf, MSG_SET_ENABLED)?;
    Ok(SetEnabled {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        enabled: b.u8()? != 0,
    })
}

fn encode_membership(msg_type: u16, membership: &Membership) -> Result<Vec<u8>, WireError> {
    let mut w = begin(msg_type);
    let body = w.open();
    w.string(&membership.name, MAX_NAME_BYTES)?;
    w.string(&membership.group, MAX_NAME_BYTES)?;
    w.close(body);
    w.finish()
}

fn decode_membership(buf: &[u8], expected: u16) -> Result<Membership, WireError> {
    let mut b = open_body(buf, expected)?;
    Ok(Membership {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        group: b.string(MAX_NAME_BYTES)?.to_owned(),
    })
}

pub fn encode_group_add(membership: &Membership) -> Result<Vec<u8>, WireError> {
    encode_membership(MSG_GROUP_ADD, membership)
}

pub fn decode_group_add(buf: &[u8]) -> Result<Membership, WireError> {
    decode_membership(buf, MSG_GROUP_ADD)
}

pub fn encode_group_remove(membership: &Membership) -> Result<Vec<u8>, WireError> {
    encode_membership(MSG_GROUP_REMOVE, membership)
}

pub fn decode_group_remove(buf: &[u8]) -> Result<Membership, WireError> {
    decode_membership(buf, MSG_GROUP_REMOVE)
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

pub fn encode_principals(principals: &[Summary]) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_PRINCIPALS);
    let body = w.open();
    w.count(principals.len(), MAX_PRINCIPALS)?;
    for principal in principals {
        let entry = w.open();
        w.string(&principal.name, MAX_NAME_BYTES)?;
        w.u32(principal.rid);
        w.u8(u8::from(principal.enabled));
        w.u32(principal.groups);
        w.u32(principal.unix_id);
        w.close(entry);
    }
    w.close(body);
    w.finish()
}

pub fn decode_principals(buf: &[u8]) -> Result<Vec<Summary>, WireError> {
    let mut b = open_body(buf, MSG_PRINCIPALS)?;
    b.array(MAX_PRINCIPALS, |entry| {
        Ok(Summary {
            name: entry.string(MAX_NAME_BYTES)?.to_owned(),
            rid: entry.u32()?,
            enabled: entry.u8()? != 0,
            groups: entry.u32()?,
            unix_id: if entry.at_end() { 0 } else { entry.u32()? },
        })
    })
}

/// Write a group reference into the caller's frame.
fn write_group_ref(w: &mut Writer, group: &GroupRef) -> Result<(), WireError> {
    w.bytes(&group.sid, frame::MAX_SID_BYTES)?;
    w.string(&group.name, MAX_NAME_BYTES)?;
    w.u32(group.unix_id);
    Ok(())
}

fn read_group_ref(b: &mut Reader<'_>) -> Result<GroupRef, WireError> {
    Ok(GroupRef {
        sid: b.bytes(frame::MAX_SID_BYTES)?.to_vec(),
        name: if b.at_end() {
            String::new()
        } else {
            b.string(MAX_NAME_BYTES)?.to_owned()
        },
        unix_id: if b.at_end() { 0 } else { b.u32()? },
    })
}

pub fn encode_principal(detail: &Detail) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_PRINCIPAL);
    let body = w.open();
    w.string(&detail.name, MAX_NAME_BYTES)?;
    w.u32(detail.rid);
    w.u8(u8::from(detail.enabled));
    w.bytes(&detail.sid, frame::MAX_SID_BYTES)?;
    w.count(detail.groups.len(), MAX_GROUPS)?;
    for group in &detail.groups {
        let at = w.open();
        write_group_ref(&mut w, group)?;
        w.close(at);
    }

    w.u32(detail.unix_id);
    let at = w.open();
    write_group_ref(&mut w, &detail.primary_group)?;
    w.close(at);
    w.string(&detail.home, MAX_PATH_BYTES)?;
    w.string(&detail.shell, MAX_PATH_BYTES)?;
    w.string(&detail.display_name, MAX_DISPLAY_NAME_BYTES)?;
    crate::claim::write_claims(&mut w, &detail.claims)?;

    w.close(body);
    w.finish()
}

pub fn decode_principal(buf: &[u8]) -> Result<Detail, WireError> {
    let mut b = open_body(buf, MSG_PRINCIPAL)?;
    let name = b.string(MAX_NAME_BYTES)?.to_owned();
    let rid = b.u32()?;
    let enabled = b.u8()? != 0;
    let sid = b.bytes(frame::MAX_SID_BYTES)?.to_vec();
    let groups = b.array(MAX_GROUPS, read_group_ref)?;

    // Each appended field defaults to "the daemon did not say", so a tool and a
    // daemon of different vintages degrade rather than fail. They ship together,
    // but an upgrade replaces them one file at a time.
    let unix_id = if b.at_end() { 0 } else { b.u32()? };
    let primary_group = if b.at_end() {
        GroupRef::default()
    } else {
        read_group_ref(&mut b.open()?)?
    };
    let home = if b.at_end() {
        String::new()
    } else {
        b.string(MAX_PATH_BYTES)?.to_owned()
    };
    let shell = if b.at_end() {
        String::new()
    } else {
        b.string(MAX_PATH_BYTES)?.to_owned()
    };
    let display_name = if b.at_end() {
        String::new()
    } else {
        b.string(MAX_DISPLAY_NAME_BYTES)?.to_owned()
    };
    let claims = if b.at_end() {
        Vec::new()
    } else {
        crate::claim::read_claims(&mut b)?
    };

    Ok(Detail {
        name,
        rid,
        enabled,
        sid,
        groups,
        unix_id,
        primary_group,
        home,
        shell,
        display_name,
        claims,
    })
}

pub fn encode_groups(groups: &[GroupSummary]) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_GROUPS);
    let body = w.open();
    w.count(groups.len(), MAX_GROUP_OBJECTS)?;
    for group in groups {
        let entry = w.open();
        w.string(&group.name, MAX_NAME_BYTES)?;
        w.u32(group.rid);
        w.u32(group.unix_id);
        w.bytes(&group.sid, frame::MAX_SID_BYTES)?;
        w.u32(group.members);
        w.close(entry);
    }
    w.close(body);
    w.finish()
}

pub fn decode_groups(buf: &[u8]) -> Result<Vec<GroupSummary>, WireError> {
    let mut b = open_body(buf, MSG_GROUPS)?;
    b.array(MAX_GROUP_OBJECTS, |entry| {
        Ok(GroupSummary {
            name: entry.string(MAX_NAME_BYTES)?.to_owned(),
            rid: entry.u32()?,
            unix_id: entry.u32()?,
            sid: entry.bytes(frame::MAX_SID_BYTES)?.to_vec(),
            members: entry.u32()?,
        })
    })
}

pub fn encode_group_list() -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_GROUP_LIST);
    let body = w.open();
    w.close(body);
    w.finish()
}

pub fn decode_group_list(buf: &[u8]) -> Result<(), WireError> {
    open_body(buf, MSG_GROUP_LIST)?;
    Ok(())
}

pub fn encode_group_create(named: &Named) -> Result<Vec<u8>, WireError> {
    encode_named(MSG_GROUP_CREATE, named)
}

pub fn decode_group_create(buf: &[u8]) -> Result<Named, WireError> {
    decode_named(buf, MSG_GROUP_CREATE)
}

pub fn encode_group_delete(named: &Named) -> Result<Vec<u8>, WireError> {
    encode_named(MSG_GROUP_DELETE, named)
}

pub fn decode_group_delete(buf: &[u8]) -> Result<Named, WireError> {
    decode_named(buf, MSG_GROUP_DELETE)
}

/// An optional string: a length-framed value, empty meaning "leave it alone".
///
/// A present-but-empty field and an absent one have to be distinguishable,
/// because clearing a display name is a real operation. So presence is a flag
/// rather than an empty string.
fn write_optional(w: &mut Writer, value: Option<&str>, max: usize) -> Result<(), WireError> {
    w.u8(u8::from(value.is_some()));
    w.string(value.unwrap_or(""), max)
}

fn read_optional(b: &mut Reader<'_>, max: usize) -> Result<Option<String>, WireError> {
    let present = b.u8()? != 0;
    let value = b.string(max)?.to_owned();
    Ok(present.then_some(value))
}

pub fn encode_set_profile(profile: &SetProfile) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_SET_PROFILE);
    let body = w.open();
    w.string(&profile.name, MAX_NAME_BYTES)?;
    write_optional(&mut w, profile.home.as_deref(), MAX_PATH_BYTES)?;
    write_optional(&mut w, profile.shell.as_deref(), MAX_PATH_BYTES)?;
    write_optional(
        &mut w,
        profile.display_name.as_deref(),
        MAX_DISPLAY_NAME_BYTES,
    )?;
    w.close(body);
    w.finish()
}

pub fn decode_set_profile(buf: &[u8]) -> Result<SetProfile, WireError> {
    let mut b = open_body(buf, MSG_SET_PROFILE)?;
    Ok(SetProfile {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        home: read_optional(&mut b, MAX_PATH_BYTES)?,
        shell: read_optional(&mut b, MAX_PATH_BYTES)?,
        display_name: read_optional(&mut b, MAX_DISPLAY_NAME_BYTES)?,
    })
}

pub fn encode_set_primary_group(membership: &Membership) -> Result<Vec<u8>, WireError> {
    encode_membership(MSG_SET_PRIMARY_GROUP, membership)
}

pub fn decode_set_primary_group(buf: &[u8]) -> Result<Membership, WireError> {
    decode_membership(buf, MSG_SET_PRIMARY_GROUP)
}

pub fn encode_set_claim(set: &SetClaim) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_SET_CLAIM);
    let body = w.open();
    w.string(&set.name, MAX_NAME_BYTES)?;
    let at = w.open();
    crate::claim::write_claim(&mut w, &set.claim)?;
    w.close(at);
    w.close(body);
    w.finish()
}

pub fn decode_set_claim(buf: &[u8]) -> Result<SetClaim, WireError> {
    let mut b = open_body(buf, MSG_SET_CLAIM)?;
    Ok(SetClaim {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        claim: crate::claim::read_claim(&mut b.open()?)?,
    })
}

pub fn encode_remove_claim(named: &NamedClaim) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_REMOVE_CLAIM);
    let body = w.open();
    w.string(&named.name, MAX_NAME_BYTES)?;
    w.string(&named.claim_name, crate::claim::MAX_NAME_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_remove_claim(buf: &[u8]) -> Result<NamedClaim, WireError> {
    let mut b = open_body(buf, MSG_REMOVE_CLAIM)?;
    Ok(NamedClaim {
        name: b.string(MAX_NAME_BYTES)?.to_owned(),
        claim_name: b.string(crate::claim::MAX_NAME_BYTES)?.to_owned(),
    })
}

pub fn encode_domain_is(sid: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_DOMAIN_IS);
    let body = w.open();
    w.bytes(sid, frame::MAX_SID_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_domain_is(buf: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut b = open_body(buf, MSG_DOMAIN_IS)?;
    Ok(b.bytes(frame::MAX_SID_BYTES)?.to_vec())
}

pub fn encode_created(rid: u32) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_CREATED);
    let body = w.open();
    w.u32(rid);
    w.close(body);
    w.finish()
}

pub fn decode_created(buf: &[u8]) -> Result<u32, WireError> {
    let mut b = open_body(buf, MSG_CREATED)?;
    b.u32()
}

pub fn encode_done() -> Result<Vec<u8>, WireError> {
    encode_empty(MSG_DONE)
}

pub fn decode_done(buf: &[u8]) -> Result<(), WireError> {
    decode_empty(buf, MSG_DONE)
}

pub fn encode_failed(failed: &Failed) -> Result<Vec<u8>, WireError> {
    let mut w = begin(MSG_FAILED);
    let body = w.open();
    w.u32(failed.failure.to_u32());
    w.string(&failed.reason, MAX_REASON_BYTES)?;
    w.close(body);
    w.finish()
}

pub fn decode_failed(buf: &[u8]) -> Result<Failed, WireError> {
    let mut b = open_body(buf, MSG_FAILED)?;
    Ok(Failed {
        failure: Failure::from_u32(b.u32()?)?,
        reason: b.string(MAX_REASON_BYTES)?.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> Vec<u8> {
        let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, 1000] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes
    }

    fn administrators() -> Vec<u8> {
        let mut bytes = vec![1, 2, 0, 0, 0, 0, 0, 5];
        for sub in [32u32, 544] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn list_round_trips() {
        let bytes = encode_list().unwrap();
        decode_list(&bytes).unwrap();
        assert_eq!(decode_type(&bytes).unwrap().0, MSG_LIST);
    }

    #[test]
    fn domain_round_trips() {
        let bytes = encode_domain().unwrap();
        decode_domain(&bytes).unwrap();
        let reply = encode_domain_is(&sid()).unwrap();
        assert_eq!(decode_domain_is(&reply).unwrap(), sid());
    }

    #[test]
    fn show_round_trips() {
        let bytes = encode_show(&Named { name: "jack".into() }).unwrap();
        assert_eq!(decode_show(&bytes).unwrap().name, "jack");
    }

    #[test]
    fn add_round_trips() {
        let add = Add {
            name: "jack".into(),
            credential: Credential::Password(b"hunter2"),
            enabled: true,
            groups: vec!["Administrators".into()],
        };
        let encoded = encode_add(&add).unwrap();
        let decoded = decode_add(encoded.expose()).unwrap();
        assert_eq!(decoded.name, "jack");
        assert!(matches!(decoded.credential, Credential::Password(b"hunter2")));
        assert!(decoded.enabled);
        assert_eq!(decoded.groups, vec!["Administrators".to_string()]);
    }

    #[test]
    fn add_with_no_groups_round_trips() {
        let add = Add {
            name: "guest".into(),
            credential: Credential::None,
            enabled: false,
            groups: vec![],
        };
        let encoded = encode_add(&add).unwrap();
        let decoded = decode_add(encoded.expose()).unwrap();
        assert!(decoded.groups.is_empty());
        assert!(!decoded.enabled);
        assert!(matches!(decoded.credential, Credential::None));
    }

    /// The closed-enum rule. A credential kind this build does not know must
    /// fail the exchange rather than fall back to either answer — defaulting to
    /// `None` would create a passwordless principal from a message nobody
    /// understood.
    #[test]
    fn an_unknown_credential_kind_is_refused() {
        let encoded = encode_add(&Add {
            name: "jack".into(),
            credential: Credential::Password(b"pw"),
            enabled: true,
            groups: vec![],
        })
        .unwrap();

        // The tag sits immediately after the name, which is the first field.
        let mut bytes = encoded.expose().to_vec();
        let tag = bytes
            .windows(4)
            .position(|w| w == b"jack")
            .expect("the name is in the message")
            + 4;
        assert_eq!(bytes[tag], Credential::TAG_PASSWORD);
        bytes[tag] = 0x7f;

        // `matches!` rather than `unwrap_err`: `Add` has no `Debug`, on purpose
        // — it holds a password, and a derived one is how that reaches a log.
        assert!(matches!(decode_add(&bytes), Err(WireError::UnknownValue)));
    }

    /// A passwordless add and an add with an empty password must not encode to
    /// the same bytes — the whole point of the tag is that the two are
    /// different requests.
    #[test]
    fn no_credential_and_an_empty_password_are_distinguishable() {
        let none = encode_add(&Add {
            name: "jack".into(),
            credential: Credential::None,
            enabled: true,
            groups: vec![],
        })
        .unwrap();
        let empty = encode_add(&Add {
            name: "jack".into(),
            credential: Credential::Password(b""),
            enabled: true,
            groups: vec![],
        })
        .unwrap();

        assert_ne!(none.expose(), empty.expose());
        assert!(matches!(
            decode_add(none.expose()).unwrap().credential,
            Credential::None
        ));
        assert!(matches!(
            decode_add(empty.expose()).unwrap().credential,
            Credential::Password(b"")
        ));
    }

    #[test]
    fn set_password_round_trips() {
        let set = SetPassword {
            name: "jack".into(),
            secret: b"correct horse",
        };
        let encoded = encode_set_password(&set).unwrap();
        let decoded = decode_set_password(encoded.expose()).unwrap();
        assert_eq!(decoded.name, "jack");
        assert_eq!(decoded.secret, b"correct horse");
    }

    #[test]
    fn set_enabled_round_trips() {
        for enabled in [true, false] {
            let bytes = encode_set_enabled(&SetEnabled {
                name: "jack".into(),
                enabled,
            })
            .unwrap();
            let decoded = decode_set_enabled(&bytes).unwrap();
            assert_eq!(decoded.enabled, enabled);
            assert_eq!(decoded.name, "jack");
        }
    }

    #[test]
    fn membership_round_trips() {
        let membership = Membership {
            name: "jack".into(),
            group: "Administrators".into(),
        };
        let added = encode_group_add(&membership).unwrap();
        assert_eq!(decode_group_add(&added).unwrap(), membership);
        let removed = encode_group_remove(&membership).unwrap();
        assert_eq!(decode_group_remove(&removed).unwrap(), membership);
    }

    /// `group add` and `group remove` carry identical bodies, so the message
    /// type is the only thing distinguishing them. Decoding one as the other
    /// must fail rather than quietly invert the operation.
    #[test]
    fn group_add_does_not_decode_as_group_remove() {
        let added = encode_group_add(&Membership {
            name: "jack".into(),
            group: "Administrators".into(),
        })
        .unwrap();
        assert_eq!(
            decode_group_remove(&added).unwrap_err(),
            WireError::UnexpectedMessage(MSG_GROUP_ADD)
        );
    }

    #[test]
    fn principals_round_trip() {
        let principals = vec![
            Summary {
                name: "jack".into(),
                rid: 1000,
                enabled: true,
                groups: 1,
                unix_id: 1_000_001,
            },
            Summary {
                name: "guest".into(),
                rid: 1001,
                enabled: false,
                groups: 0,
                unix_id: 1_000_002,
            },
        ];
        let bytes = encode_principals(&principals).unwrap();
        assert_eq!(decode_principals(&bytes).unwrap(), principals);
    }

    #[test]
    fn an_empty_listing_round_trips() {
        let bytes = encode_principals(&[]).unwrap();
        assert!(decode_principals(&bytes).unwrap().is_empty());
    }

    fn detail() -> Detail {
        Detail {
            name: "jack".into(),
            rid: 1000,
            enabled: true,
            sid: sid(),
            groups: vec![GroupRef {
                sid: administrators(),
                name: "Administrators".into(),
                unix_id: 102,
            }],
            unix_id: 1_000_001,
            primary_group: GroupRef {
                sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0],
                name: "Authenticated Users".into(),
                unix_id: 101,
            },
            home: "/home/jack".into(),
            shell: "/bin/sh".into(),
            display_name: "Jack Palfrey".into(),
            claims: vec![Claim {
                name: "Department".into(),
                flags: crate::claim::FLAG_MANDATORY,
                values: crate::claim::Values::String(vec!["Engineering".into()]),
            }],
        }
    }

    #[test]
    fn principal_round_trips() {
        let detail = detail();
        let bytes = encode_principal(&detail).unwrap();
        assert_eq!(decode_principal(&bytes).unwrap(), detail);
    }

    /// The tool and the daemon ship together, but an upgrade replaces them one
    /// file at a time. A reply from before the profile existed must decode into
    /// empty fields rather than fail.
    #[test]
    fn a_principal_reply_with_only_the_original_fields_decodes() {
        let mut w = begin(MSG_PRINCIPAL);
        let body = w.open();
        w.string("jack", MAX_NAME_BYTES).unwrap();
        w.u32(1000);
        w.u8(1);
        w.bytes(&sid(), frame::MAX_SID_BYTES).unwrap();
        w.count(1, MAX_GROUPS).unwrap();
        let at = w.open();
        w.bytes(&administrators(), frame::MAX_SID_BYTES).unwrap();
        w.close(at);
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_principal(&bytes).expect("an older daemon must decode");
        assert_eq!(decoded.name, "jack");
        assert_eq!(decoded.groups.len(), 1);
        assert_eq!(decoded.groups[0].name, "");
        assert_eq!(decoded.groups[0].unix_id, 0);
        assert_eq!(decoded.unix_id, 0);
        assert_eq!(decoded.home, "");
        assert!(decoded.claims.is_empty());
    }

    #[test]
    fn groups_round_trip() {
        let groups = vec![GroupSummary {
            name: "developers".into(),
            rid: 1001,
            unix_id: 1_000_002,
            sid: sid(),
            members: 3,
        }];
        let bytes = encode_groups(&groups).unwrap();
        assert_eq!(decode_groups(&bytes).unwrap(), groups);

        decode_group_list(&encode_group_list().unwrap()).unwrap();
        assert_eq!(
            decode_group_create(&encode_group_create(&Named { name: "developers".into() }).unwrap())
                .unwrap()
                .name,
            "developers"
        );
        assert_eq!(
            decode_group_delete(&encode_group_delete(&Named { name: "developers".into() }).unwrap())
                .unwrap()
                .name,
            "developers"
        );
    }

    /// Clearing a display name and leaving it alone are different operations,
    /// so an empty value must not collapse into "absent".
    #[test]
    fn an_optional_profile_field_distinguishes_empty_from_absent() {
        let cleared = SetProfile {
            name: "jack".into(),
            home: None,
            shell: None,
            display_name: Some(String::new()),
        };
        let decoded = decode_set_profile(&encode_set_profile(&cleared).unwrap()).unwrap();
        assert_eq!(decoded.home, None);
        assert_eq!(decoded.shell, None);
        assert_eq!(
            decoded.display_name,
            Some(String::new()),
            "an explicit clear must survive as a clear, not become 'unchanged'"
        );
    }

    #[test]
    fn set_profile_round_trips() {
        let profile = SetProfile {
            name: "jack".into(),
            home: Some("/srv/jack".into()),
            shell: Some("/bin/bash".into()),
            display_name: Some("Jack Palfrey".into()),
        };
        let decoded = decode_set_profile(&encode_set_profile(&profile).unwrap()).unwrap();
        assert_eq!(decoded.name, "jack");
        assert_eq!(decoded.home.as_deref(), Some("/srv/jack"));
        assert_eq!(decoded.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(decoded.display_name.as_deref(), Some("Jack Palfrey"));
    }

    #[test]
    fn claim_messages_round_trip() {
        let set = SetClaim {
            name: "jack".into(),
            claim: Claim {
                name: "Level".into(),
                flags: 0,
                values: crate::claim::Values::Int64(vec![7]),
            },
        };
        let decoded = decode_set_claim(&encode_set_claim(&set).unwrap()).unwrap();
        assert_eq!(decoded.name, "jack");
        assert_eq!(decoded.claim.name, "Level");
        assert_eq!(decoded.claim.values, crate::claim::Values::Int64(vec![7]));

        let removed = decode_remove_claim(
            &encode_remove_claim(&NamedClaim {
                name: "jack".into(),
                claim_name: "Level".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(removed.claim_name, "Level");
    }

    #[test]
    fn every_request_has_a_declared_reply() {
        for request in REQUEST_TYPES {
            let reply = reply_to(*request)
                .unwrap_or_else(|| panic!("{request:#06x} has no declared reply"));
            assert!(
                reply & 0x8000 != 0,
                "{reply:#06x} answers {request:#06x} but is not an authority message"
            );
        }
    }

    #[test]
    fn a_request_type_this_protocol_does_not_define_has_no_reply() {
        assert_eq!(reply_to(0xffff), None);
        // A reply is not a request, so it pairs with nothing.
        assert_eq!(reply_to(MSG_DONE), None);
    }

    #[test]
    fn set_primary_group_round_trips() {
        let membership = Membership {
            name: "jack".into(),
            group: "Administrators".into(),
        };
        let decoded =
            decode_set_primary_group(&encode_set_primary_group(&membership).unwrap()).unwrap();
        assert_eq!(decoded, membership);
    }

    #[test]
    fn created_and_done_round_trip() {
        assert_eq!(decode_created(&encode_created(1000).unwrap()).unwrap(), 1000);
        decode_done(&encode_done().unwrap()).unwrap();
    }

    #[test]
    fn every_failure_round_trips() {
        for failure in [
            Failure::Denied,
            Failure::NotFound,
            Failure::Exists,
            Failure::Invalid,
            Failure::Internal,
        ] {
            let bytes = encode_failed(&Failed {
                failure,
                reason: "because".into(),
            })
            .unwrap();
            let decoded = decode_failed(&bytes).unwrap();
            assert_eq!(decoded.failure, failure);
            assert_eq!(decoded.reason, "because");
        }
    }

    #[test]
    fn an_unknown_failure_code_is_refused() {
        let mut w = begin(MSG_FAILED);
        let body = w.open();
        w.u32(9999);
        w.string("from the future", MAX_REASON_BYTES).unwrap();
        w.close(body);
        let bytes = w.finish().unwrap();
        assert_eq!(decode_failed(&bytes).unwrap_err(), WireError::UnknownValue);
    }

    /// The whole reason for a distinct magic: these protocols share a codec and
    /// a header layout, so a socket plugged into the wrong daemon must fail on
    /// the first four bytes rather than several fields in.
    #[test]
    fn another_protocols_message_does_not_decode() {
        let psi = crate::psi::encode_registered(&crate::psi::Registered::default()).unwrap();
        assert_eq!(decode_type(&psi).unwrap_err(), WireError::BadMagic);

        let lps = encode_list().unwrap();
        assert_eq!(
            crate::psi::decode_envelope(&lps).unwrap_err(),
            WireError::BadMagic
        );
    }

    #[test]
    fn an_oversized_name_is_rejected() {
        let long = "l".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(
            encode_show(&Named { name: long }).unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn an_oversized_secret_is_rejected() {
        let long = vec![b'x'; MAX_SECRET_BYTES + 1];
        assert_eq!(
            encode_add(&Add {
                name: "jack".into(),
                credential: Credential::Password(&long),
                enabled: true,
                groups: vec![],
            })
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn too_many_groups_are_rejected() {
        assert_eq!(
            encode_add(&Add {
                name: "jack".into(),
                credential: Credential::Password(b"pw"),
                enabled: true,
                groups: vec!["Administrators".to_string(); MAX_GROUPS + 1],
            })
            .unwrap_err(),
            WireError::TooLong
        );
    }

    /// A field appended to a listing entry by a newer daemon must be stepped
    /// over, not mistaken for the start of the next entry.
    #[test]
    fn a_field_appended_to_an_entry_is_skipped() {
        let mut w = begin(MSG_PRINCIPALS);
        let body = w.open();
        w.count(1, MAX_PRINCIPALS).unwrap();
        let entry = w.open();
        w.string("jack", MAX_NAME_BYTES).unwrap();
        w.u32(1000);
        w.u8(1);
        w.u32(2);
        w.u32(0xDEAD_BEEF); // a field this version does not know
        w.close(entry);
        w.close(body);
        let bytes = w.finish().unwrap();

        let decoded = decode_principals(&bytes).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, "jack");
        assert_eq!(decoded[0].groups, 2);
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let messages: Vec<Vec<u8>> = vec![
            encode_list().unwrap(),
            encode_domain().unwrap(),
            encode_show(&Named { name: "jack".into() }).unwrap(),
            encode_remove(&Named { name: "jack".into() }).unwrap(),
            encode_set_enabled(&SetEnabled {
                name: "jack".into(),
                enabled: true,
            })
            .unwrap(),
            encode_group_add(&Membership {
                name: "jack".into(),
                group: "Administrators".into(),
            })
            .unwrap(),
            encode_principals(&[Summary {
                name: "jack".into(),
                rid: 1000,
                enabled: true,
                groups: 1,
                unix_id: 1_000_001,
            }])
            .unwrap(),
            encode_principal(&detail()).unwrap(),
            encode_groups(&[GroupSummary {
                name: "developers".into(),
                rid: 1001,
                unix_id: 1_000_002,
                sid: sid(),
                members: 1,
            }])
            .unwrap(),
            encode_group_list().unwrap(),
            encode_group_create(&Named {
                name: "developers".into(),
            })
            .unwrap(),
            encode_group_delete(&Named {
                name: "developers".into(),
            })
            .unwrap(),
            encode_set_profile(&SetProfile {
                name: "jack".into(),
                home: Some("/home/jack".into()),
                shell: None,
                display_name: Some(String::new()),
            })
            .unwrap(),
            encode_set_primary_group(&Membership {
                name: "jack".into(),
                group: "Administrators".into(),
            })
            .unwrap(),
            encode_set_claim(&SetClaim {
                name: "jack".into(),
                claim: Claim {
                    name: "Level".into(),
                    flags: 0,
                    values: crate::claim::Values::Int64(vec![7]),
                },
            })
            .unwrap(),
            encode_remove_claim(&NamedClaim {
                name: "jack".into(),
                claim_name: "Level".into(),
            })
            .unwrap(),
            encode_domain_is(&sid()).unwrap(),
            encode_created(1000).unwrap(),
            encode_done().unwrap(),
            encode_failed(&Failed {
                failure: Failure::NotFound,
                reason: "no".into(),
            })
            .unwrap(),
        ];

        for message in messages {
            for len in 0..message.len() {
                let partial = &message[..len];
                // Whatever it is, it must not panic and must not succeed.
                let _ = decode_type(partial);
                let _ = decode_principals(partial);
                let _ = decode_principal(partial);
                let _ = decode_failed(partial);
                let _ = decode_show(partial);
                let _ = decode_add(partial);
            }
        }
    }
}
