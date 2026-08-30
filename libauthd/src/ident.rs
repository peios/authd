//! PGSS Logon chapter 6 — identity lookup, on `/run/ident.sock`.
//!
//! Same standard as [`crate::wire`], same framing, same magic, disjoint message
//! types. The separation is a *socket*, not a protocol: PGSS §2.14 is explicit
//! that it buys no isolation, since one authority answers both and a defect in
//! either reaches the other regardless.
//!
//! What it buys is admission. A listening socket has one accept queue, and a
//! filesystem walk is millions of lookups where logons are a handful per boot.
//! Sharing a socket would let an ordinary `find` fill the queue an administrator
//! needs in order to sign in and stop it.
//!
//! # Not a conversation
//!
//! A logon connection *is* its conversation, so PGSS Logon needs no correlation
//! identifier. A lookup connection carries as many independent requests as a
//! caller cares to send, and replies may come back out of order — so every
//! request carries a [`tag`](Lookup::tag) its reply echoes.
//!
//! The tag is in the body rather than the header, which is what leaves the
//! twelve bytes of [`crate::frame`] untouched.
//!
//! # The shape of the answer
//!
//! Identity is never optional: a found record always carries the SID, the
//! canonical qualified name, and the kind actually found. A caller cannot
//! decline them, because without them it cannot tell what it got.
//!
//! Everything else is requested by bit and answered by bit. Each requested
//! field comes back in one of three states — present with a value, withheld with
//! a reason, or in neither, meaning this authority does not implement it. That
//! third state is what makes [`Fields`] the one bitmask in these protocols that
//! may gain a value without a version bump: an older authority ignoring a newer
//! bit is *reported* rather than silently omitting something the caller believed
//! it had asked for.
//!
//! # What is not here
//!
//! Privileges, integrity levels, owner and default DACL. They are not identity —
//! nothing stores them, and an authority computes them from local policy at the
//! moment it derives a token.
//!
//! They are reserved rather than excluded. PGSS §2.13 names the shape a future
//! revision is expected to take (`Evaluate { key, logon_type }`, a token derived
//! and discarded) and forbids adding them as fields here, because a field of a
//! record describes something a source holds and this does not.

use crate::claim::Claim;
use crate::frame::{self, MAX_SID_BYTES, Reader, WireError, Writer};
use crate::wire::{FRAMING, MAX_DISPLAY_NAME_BYTES, MAX_PATH_BYTES};

pub const MSG_LOOKUP: u16 = 0x0010;
pub const MSG_ENUMERATE: u16 = 0x0011;

pub const MSG_LOOKUP_REPLY: u16 = 0x8010;
pub const MSG_ENUMERATE_REPLY: u16 = 0x8011;

/// A name as a caller may type it. Matches PSI's `canonical_name` bound, since
/// what a source can hold is what can be looked up.
pub const MAX_NAME_BYTES: usize = 256;

/// A name with a realm on it. Twice the bare bound, leaving room for the
/// qualified form before any realm syntax exists to produce one.
pub const MAX_QUALIFIED_NAME_BYTES: usize = 512;

pub const MAX_WITHHELD: usize = 32;
pub const MAX_VALUES: usize = 32;
pub const MAX_GROUPS: usize = 128;
pub const MAX_MEMBERS: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_ENTRIES: usize = 256;
pub const MAX_INCOMPLETE: usize = 32;
pub const MAX_SOURCE_NAME_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Which of a [`Key`]'s three spellings is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Name = 1,
    Sid = 2,
    UnixId = 3,
}

impl KeyType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Name,
            2 => Self::Sid,
            3 => Self::UnixId,
            _ => return None,
        })
    }
}

/// What a caller is looking for, and what it found.
///
/// POSIX keeps users and groups in separate namespaces, so `getpwnam` and
/// `getgrnam` may be asked the same string and expect different objects.
/// Carrying the kind on the request is what serves both correctly without
/// requiring an authority to forbid the collision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Any = 0,
    Principal = 1,
    Group = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Any,
            1 => Self::Principal,
            2 => Self::Group,
            _ => return None,
        })
    }

    /// Whether an object of this kind satisfies a request for `wanted`.
    pub fn satisfies(self, wanted: Kind) -> bool {
        wanted == Kind::Any || wanted == self
    }
}

/// How a request turned out.
///
/// Unlike [`Denial`](crate::wire::Denial) these are not a security boundary.
/// `NotFound` reveals that a name is unused, which is what a name lookup is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    Found = 1,
    /// No such object, and **every** source that could have said so was asked.
    NotFound = 2,
    /// A source that could have answered did not. Never cacheable — see the
    /// module docs of [`crate::ident`] and PGSS §2.18.
    Unavailable = 3,
    /// The caller may not make this request at all. A caller refused a single
    /// *field* gets [`WithheldReason::Restricted`] instead.
    Refused = 4,
    Malformed = 5,
}

impl Outcome {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Found,
            2 => Self::NotFound,
            3 => Self::Unavailable,
            4 => Self::Refused,
            5 => Self::Malformed,
            _ => return None,
        })
    }
}

/// Why a requested field carries no value.
///
/// Distinguishing these is the point of the structure. An empty member list and
/// a source that refuses to enumerate members are the same bytes to a POSIX
/// caller, and an administrator diagnosing a system needs to know which happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WithheldReason {
    /// The field has no value. For a group, that its membership is a *rule* an
    /// authority applies rather than anything a source records.
    Absent = 1,
    /// The caller may not have this field.
    Restricted = 2,
    /// The source will not produce it.
    Declined = 3,
    /// It exists and exceeds one reply. Continue with [`Enumerate`].
    TooLarge = 4,
}

impl WithheldReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Absent,
            2 => Self::Restricted,
            3 => Self::Declined,
            4 => Self::TooLarge,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

/// The attributes a reply may carry, as a bitmask.
///
/// Identity is not among them — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fields(pub u32);

impl Fields {
    pub const UNIX_ID: Fields = Fields(1 << 0);
    pub const PRIMARY_GROUP: Fields = Fields(1 << 1);
    pub const HOME: Fields = Fields(1 << 2);
    pub const SHELL: Fields = Fields(1 << 3);
    pub const DISPLAY_NAME: Fields = Fields(1 << 4);
    pub const GROUPS: Fields = Fields(1 << 5);
    pub const MEMBERS: Fields = Fields(1 << 6);
    pub const CLAIMS: Fields = Fields(1 << 7);
    pub const ENABLED: Fields = Fields(1 << 8);
    /// Which kinds of sign-on this principal may be used for. See
    /// [`LogonTypes`](crate::wire::LogonTypes).
    pub const LOGON_TYPES: Fields = Fields(1 << 9);

    /// Everything this build implements.
    ///
    /// A peer may set bits outside this; they are ignored rather than refused,
    /// which is the exception to the closed-enum rule that the module docs set
    /// out.
    pub const KNOWN: Fields = Fields(0x03ff);

    /// What a `passwd` record needs, in one request.
    pub const PASSWD: Fields = Fields(
        Self::UNIX_ID.0
            | Self::PRIMARY_GROUP.0
            | Self::HOME.0
            | Self::SHELL.0
            | Self::DISPLAY_NAME.0,
    );

    /// What a `group` record needs, in one request.
    pub const GROUP: Fields = Fields(Self::UNIX_ID.0 | Self::MEMBERS.0);

    pub const fn empty() -> Fields {
        Fields(0)
    }

    pub const fn contains(self, other: Fields) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Fields) -> Fields {
        Fields(self.0 | other.0)
    }

    pub const fn difference(self, other: Fields) -> Fields {
        Fields(self.0 & !other.0)
    }

    pub const fn intersection(self, other: Fields) -> Fields {
        Fields(self.0 & other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The bits set, one at a time, in ascending order.
    ///
    /// The order values appear in on the wire.
    pub fn iter(self) -> impl Iterator<Item = Fields> {
        (0..u32::BITS).map(Fields::bit).filter(move |b| self.contains(*b))
    }

    const fn bit(index: u32) -> Fields {
        Fields(1 << index)
    }
}

impl core::ops::BitOr for Fields {
    type Output = Fields;
    fn bitor(self, rhs: Fields) -> Fields {
        self.union(rhs)
    }
}

/// A named principal or group, carried wherever a reply refers to one.
///
/// Carrying the name is what keeps `getgrnam` to a single round trip: a reply of
/// bare SIDs would make one request into one per member.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reference {
    pub sid: Vec<u8>,
    /// Empty where the authority has no name for this SID — an ordinary answer
    /// for one belonging to no source on this machine.
    pub name: String,
    /// Zero where it has no number for it.
    pub unix_id: u32,
}

/// One attribute of a record.
///
/// The variants are in bit order, which is the order they appear on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    UnixId(u32),
    PrimaryGroup(Reference),
    Home(String),
    Shell(String),
    DisplayName(String),
    Groups(Vec<Reference>),
    Members(Vec<Reference>),
    Claims(Vec<Claim>),
    Enabled(bool),
    LogonTypes(crate::wire::LogonTypes),
}

impl Value {
    /// Which bit this value answers.
    pub fn field(&self) -> Fields {
        match self {
            Self::UnixId(_) => Fields::UNIX_ID,
            Self::PrimaryGroup(_) => Fields::PRIMARY_GROUP,
            Self::Home(_) => Fields::HOME,
            Self::Shell(_) => Fields::SHELL,
            Self::DisplayName(_) => Fields::DISPLAY_NAME,
            Self::Groups(_) => Fields::GROUPS,
            Self::Members(_) => Fields::MEMBERS,
            Self::Claims(_) => Fields::CLAIMS,
            Self::Enabled(_) => Fields::ENABLED,
            Self::LogonTypes(_) => Fields::LOGON_TYPES,
        }
    }
}

/// A requested field that carries no value, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withheld {
    pub field: Fields,
    pub reason: WithheldReason,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// What to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// A name as a caller typed it. **Opaque** — a client forwards what it was
    /// given and the authority does all the parsing, so that a name cannot
    /// resolve differently depending on which client asked.
    Name(String),
    Sid(Vec<u8>),
    /// An *absolute* POSIX identifier. The authority inverts its own range
    /// arithmetic to reach a source; no source is ever asked one.
    UnixId(u32),
}

impl Key {
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Name(_) => KeyType::Name,
            Self::Sid(_) => KeyType::Sid,
            Self::UnixId(_) => KeyType::UnixId,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// Echoed by the reply. A client must not reuse one while a request bearing
    /// it is outstanding, and must not assume replies arrive in request order.
    pub tag: u32,
    pub key: Key,
    pub kind: Kind,
    pub fields: Fields,
}

/// A found object, and whatever of it was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    pub sid: Vec<u8>,
    /// The canonical name, qualified. Bare name in, qualified answer out — so a
    /// caller can always tell which principal it got, whatever it asked with.
    pub qualified_name: String,
    pub kind_found: Kind,
    /// In ascending field order.
    pub values: Vec<Value>,
    pub withheld: Vec<Withheld>,
}

impl Default for Kind {
    fn default() -> Self {
        Kind::Principal
    }
}

impl Record {
    /// The bits this record answers.
    pub fn present(&self) -> Fields {
        self.values
            .iter()
            .fold(Fields::empty(), |acc, v| acc | v.field())
    }

    pub fn value(&self, field: Fields) -> Option<&Value> {
        self.values.iter().find(|v| v.field() == field)
    }

    pub fn reason(&self, field: Fields) -> Option<WithheldReason> {
        self.withheld
            .iter()
            .find(|w| w.field == field)
            .map(|w| w.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupReply {
    pub tag: u32,
    pub outcome: Outcome,
    /// Present exactly when `outcome` is [`Outcome::Found`].
    pub record: Option<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumerate {
    pub tag: u32,
    /// Never [`Kind::Any`]: a caller enumerating is filling a `passwd` or a
    /// `group` table, and the two are separate.
    pub kind: Kind,
    pub fields: Fields,
    /// `None` walks everything of `kind`. `Some` names a **group**, and walks
    /// its members — the continuation path for a `MEMBERS` field withheld as
    /// [`WithheldReason::TooLarge`].
    pub of: Option<Key>,
    /// Empty on the first request; otherwise the previous reply's `next`.
    /// Opaque: a client must not construct, parse or modify one.
    pub cursor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateReply {
    pub tag: u32,
    pub outcome: Outcome,
    pub entries: Vec<Record>,
    /// Empty when the enumeration is complete. A non-empty value means there is
    /// more **even where `entries` is empty**.
    pub next: Vec<u8>,
    /// Sources that did not contribute — declined, or unreachable. A short list
    /// that looks complete is what this exists to prevent.
    pub incomplete: Vec<String>,
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

fn write_key(w: &mut Writer, key: Option<&Key>) -> Result<(), WireError> {
    match key {
        None => {
            w.u8(0);
            w.string("", MAX_NAME_BYTES)?;
            w.bytes(&[], MAX_SID_BYTES)?;
            w.u32(0);
        }
        Some(key) => {
            w.u8(key.key_type() as u8);
            match key {
                Key::Name(name) => {
                    w.string(name, MAX_NAME_BYTES)?;
                    w.bytes(&[], MAX_SID_BYTES)?;
                    w.u32(0);
                }
                Key::Sid(sid) => {
                    w.string("", MAX_NAME_BYTES)?;
                    w.bytes(sid, MAX_SID_BYTES)?;
                    w.u32(0);
                }
                Key::UnixId(id) => {
                    w.string("", MAX_NAME_BYTES)?;
                    w.bytes(&[], MAX_SID_BYTES)?;
                    w.u32(*id);
                }
            }
        }
    }
    Ok(())
}

fn read_key(r: &mut Reader<'_>) -> Result<Option<Key>, WireError> {
    let discriminant = r.u8()?;
    let name = r.string(MAX_NAME_BYTES)?.to_owned();
    let sid = r.bytes(MAX_SID_BYTES)?.to_vec();
    let unix_id = r.u32()?;

    // Zero means "no key" — used by `Enumerate.of` to mean *everything*. It is
    // not a `KeyType`, so it is checked before the enum conversion rather than
    // becoming a value of it.
    if discriminant == 0 {
        return Ok(None);
    }
    Ok(Some(
        match KeyType::from_u8(discriminant).ok_or(WireError::UnknownValue)? {
            KeyType::Name => Key::Name(name),
            KeyType::Sid => Key::Sid(sid),
            KeyType::UnixId => Key::UnixId(unix_id),
        },
    ))
}

fn write_reference(w: &mut Writer, reference: &Reference) -> Result<(), WireError> {
    let at = w.open();
    w.bytes(&reference.sid, MAX_SID_BYTES)?;
    w.string(&reference.name, MAX_QUALIFIED_NAME_BYTES)?;
    w.u32(reference.unix_id);
    w.close(at);
    Ok(())
}

fn read_reference(r: &mut Reader<'_>) -> Result<Reference, WireError> {
    Ok(Reference {
        sid: r.bytes(MAX_SID_BYTES)?.to_vec(),
        name: r.string(MAX_QUALIFIED_NAME_BYTES)?.to_owned(),
        unix_id: r.u32()?,
    })
}

fn write_references(w: &mut Writer, refs: &[Reference], max: usize) -> Result<(), WireError> {
    w.count(refs.len(), max)?;
    for reference in refs {
        write_reference(w, reference)?;
    }
    Ok(())
}

fn read_references(r: &mut Reader<'_>, max: usize) -> Result<Vec<Reference>, WireError> {
    r.array(max, read_reference)
}

fn write_value(w: &mut Writer, value: &Value) -> Result<(), WireError> {
    // Every value is length-framed so a peer can step over one whose field it
    // does not recognise — the property that lets a bit be added later.
    let at = w.open();
    match value {
        Value::UnixId(id) => w.u32(*id),
        Value::PrimaryGroup(reference) => write_reference(w, reference)?,
        Value::Home(path) => w.string(path, MAX_PATH_BYTES)?,
        Value::Shell(path) => w.string(path, MAX_PATH_BYTES)?,
        Value::DisplayName(name) => w.string(name, MAX_DISPLAY_NAME_BYTES)?,
        Value::Groups(refs) => write_references(w, refs, MAX_GROUPS)?,
        Value::Members(refs) => write_references(w, refs, MAX_MEMBERS)?,
        Value::Claims(claims) => crate::claim::write_claims(w, claims)?,
        Value::Enabled(enabled) => w.u8(u8::from(*enabled)),
        Value::LogonTypes(types) => w.u32(types.bits()),
    }
    w.close(at);
    Ok(())
}

fn read_value(r: &mut Reader<'_>, field: Fields) -> Result<Option<Value>, WireError> {
    let mut b = r.open()?;
    Ok(Some(match field {
        Fields::UNIX_ID => Value::UnixId(b.u32()?),
        Fields::PRIMARY_GROUP => Value::PrimaryGroup(read_reference(&mut b.open()?)?),
        Fields::HOME => Value::Home(b.string(MAX_PATH_BYTES)?.to_owned()),
        Fields::SHELL => Value::Shell(b.string(MAX_PATH_BYTES)?.to_owned()),
        Fields::DISPLAY_NAME => Value::DisplayName(b.string(MAX_DISPLAY_NAME_BYTES)?.to_owned()),
        Fields::GROUPS => Value::Groups(read_references(&mut b, MAX_GROUPS)?),
        Fields::MEMBERS => Value::Members(read_references(&mut b, MAX_MEMBERS)?),
        Fields::CLAIMS => Value::Claims(crate::claim::read_claims(&mut b)?),
        Fields::ENABLED => Value::Enabled(b.u8()? != 0),
        Fields::LOGON_TYPES => Value::LogonTypes(crate::wire::LogonTypes(b.u32()?)),
        // A bit this build does not implement. Its value was length-framed, so
        // `open` has already stepped over it and the fields after it are intact.
        _ => return Ok(None),
    }))
}

/// The attributes of a record: which fields are present, which were withheld,
/// and the values themselves.
///
/// Shared with PSI, which nests exactly this inside a `QueryResult` entry.
/// Sharing the *code* is what keeps that from being a claim in a comment
/// somewhere that quietly stops being true — the same reason
/// [`crate::wire`] exports its bodies.
pub(crate) fn write_attributes(
    w: &mut Writer,
    values: &[Value],
    withheld: &[Withheld],
) -> Result<(), WireError> {
    let present = values
        .iter()
        .fold(Fields::empty(), |acc, value| acc | value.field());
    w.u32(present.0);

    w.count(withheld.len(), MAX_WITHHELD)?;
    for entry in withheld {
        let at = w.open();
        w.u32(entry.field.0);
        w.u8(entry.reason as u8);
        w.close(at);
    }

    w.count(values.len(), MAX_VALUES)?;
    // Ascending field order, which is what lets a reader pair each value with a
    // bit without the value carrying its own tag.
    let mut sorted: Vec<&Value> = values.iter().collect();
    sorted.sort_by_key(|value| value.field().0);
    for value in sorted {
        write_value(w, value)?;
    }
    Ok(())
}

pub(crate) fn read_attributes(
    r: &mut Reader<'_>,
) -> Result<(Vec<Value>, Vec<Withheld>), WireError> {
    let present = Fields(r.u32()?);

    let withheld = r.array(MAX_WITHHELD, |entry| {
        Ok(Withheld {
            field: Fields(entry.u32()?),
            reason: WithheldReason::from_u8(entry.u8()?).ok_or(WireError::UnknownValue)?,
        })
    })?;

    let count = r.u32()? as usize;
    if count > MAX_VALUES {
        return Err(WireError::TooLong);
    }
    // One value per bit set in `present`, in ascending bit order — which is what
    // lets a value be paired with its field without carrying its own tag. A
    // disagreement between the two is a desynchronised reader rather than
    // something to muddle through, so it fails here.
    if count != present.0.count_ones() as usize {
        return Err(WireError::Truncated);
    }
    // A bit outside `KNOWN` still consumes its value; `read_value` steps over
    // the length frame and returns nothing.
    let mut values = Vec::with_capacity(count);
    for field in present.iter() {
        if let Some(value) = read_value(r, field)? {
            values.push(value);
        }
    }
    Ok((values, withheld))
}

fn write_record(w: &mut Writer, record: &Record) -> Result<(), WireError> {
    w.bytes(&record.sid, MAX_SID_BYTES)?;
    w.string(&record.qualified_name, MAX_QUALIFIED_NAME_BYTES)?;
    w.u8(record.kind_found as u8);
    write_attributes(w, &record.values, &record.withheld)
}

fn read_record(r: &mut Reader<'_>) -> Result<Record, WireError> {
    let sid = r.bytes(MAX_SID_BYTES)?.to_vec();
    let qualified_name = r.string(MAX_QUALIFIED_NAME_BYTES)?.to_owned();
    let kind_found = Kind::from_u8(r.u8()?).ok_or(WireError::UnknownValue)?;
    let (values, withheld) = read_attributes(r)?;

    Ok(Record {
        sid,
        qualified_name,
        kind_found,
        values,
        withheld,
    })
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

/// Read a PGSS Logon header, returning `(msg_type, total_len)`.
///
/// The same header as [`crate::wire`], because it is the same protocol.
pub fn decode_header(buf: &[u8]) -> Result<(u16, usize), WireError> {
    frame::decode_header(&FRAMING, buf)
}

pub fn encode_lookup(lookup: &Lookup) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_LOOKUP);
    let at = w.open();
    w.u32(lookup.tag);
    write_key(&mut w, Some(&lookup.key))?;
    w.u8(lookup.kind as u8);
    w.u32(lookup.fields.0);
    w.close(at);
    w.finish()
}

pub fn decode_lookup(buf: &[u8]) -> Result<Lookup, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_LOOKUP)?;
    let tag = b.u32()?;
    let key = read_key(&mut b)?.ok_or(WireError::UnknownValue)?;
    let kind = Kind::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let fields = Fields(b.u32()?);
    Ok(Lookup {
        tag,
        key,
        kind,
        fields,
    })
}

pub fn encode_lookup_reply(reply: &LookupReply) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_LOOKUP_REPLY);
    let at = w.open();
    w.u32(reply.tag);
    w.u8(reply.outcome as u8);
    match &reply.record {
        Some(record) => write_record(&mut w, record)?,
        // Everything after a non-`Found` outcome is empty, and a reader must not
        // look at it.
        None => write_record(&mut w, &Record::default())?,
    }
    w.close(at);
    w.finish()
}

pub fn decode_lookup_reply(buf: &[u8]) -> Result<LookupReply, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_LOOKUP_REPLY)?;
    let tag = b.u32()?;
    let outcome = Outcome::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let record = read_record(&mut b)?;
    Ok(LookupReply {
        tag,
        outcome,
        record: (outcome == Outcome::Found).then_some(record),
    })
}

pub fn encode_enumerate(request: &Enumerate) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_ENUMERATE);
    let at = w.open();
    w.u32(request.tag);
    w.u8(request.kind as u8);
    w.u32(request.fields.0);
    write_key(&mut w, request.of.as_ref())?;
    w.bytes(&request.cursor, MAX_CURSOR_BYTES)?;
    w.close(at);
    w.finish()
}

pub fn decode_enumerate(buf: &[u8]) -> Result<Enumerate, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_ENUMERATE)?;
    let tag = b.u32()?;
    let kind = Kind::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let fields = Fields(b.u32()?);
    let of = read_key(&mut b)?;
    let cursor = b.bytes(MAX_CURSOR_BYTES)?.to_vec();
    Ok(Enumerate {
        tag,
        kind,
        fields,
        of,
        cursor,
    })
}

pub fn encode_enumerate_reply(reply: &EnumerateReply) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_ENUMERATE_REPLY);
    let at = w.open();
    w.u32(reply.tag);
    w.u8(reply.outcome as u8);

    w.count(reply.entries.len(), MAX_ENTRIES)?;
    for entry in &reply.entries {
        let at = w.open();
        write_record(&mut w, entry)?;
        w.close(at);
    }

    w.bytes(&reply.next, MAX_CURSOR_BYTES)?;

    w.count(reply.incomplete.len(), MAX_INCOMPLETE)?;
    for source in &reply.incomplete {
        let at = w.open();
        w.string(source, MAX_SOURCE_NAME_BYTES)?;
        w.close(at);
    }

    w.close(at);
    w.finish()
}

pub fn decode_enumerate_reply(buf: &[u8]) -> Result<EnumerateReply, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_ENUMERATE_REPLY)?;
    let tag = b.u32()?;
    let outcome = Outcome::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let entries = b.array(MAX_ENTRIES, read_record)?;
    let next = b.bytes(MAX_CURSOR_BYTES)?.to_vec();
    let incomplete = b.array(MAX_INCOMPLETE, |s| {
        Ok(s.string(MAX_SOURCE_NAME_BYTES)?.to_owned())
    })?;
    Ok(EnumerateReply {
        tag,
        outcome,
        entries,
        next,
        incomplete,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{FLAG_MANDATORY, Values};

    fn sid(sub: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, 5];
        for value in sub {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn reference(name: &str, unix_id: u32) -> Reference {
        Reference {
            sid: sid(&[21, 1, 2, 3, unix_id]),
            name: name.into(),
            unix_id,
        }
    }

    fn record() -> Record {
        Record {
            sid: sid(&[21, 1, 2, 3, 1000]),
            qualified_name: "jack".into(),
            kind_found: Kind::Principal,
            values: vec![
                Value::UnixId(1_001_000),
                Value::PrimaryGroup(reference("Authenticated Users", 101)),
                Value::Home("/home/jack".into()),
                Value::Shell("/bin/sh".into()),
                Value::DisplayName("Jack".into()),
                Value::Groups(vec![reference("Administrators", 102)]),
                Value::Claims(vec![crate::Claim {
                    name: "Department".into(),
                    flags: FLAG_MANDATORY,
                    values: Values::String(vec!["Engineering".into()]),
                }]),
                Value::Enabled(true),
            ],
            withheld: vec![Withheld {
                field: Fields::MEMBERS,
                reason: WithheldReason::Absent,
            }],
        }
    }

    #[test]
    fn every_field_survives_a_round_trip() {
        let reply = LookupReply {
            tag: 7,
            outcome: Outcome::Found,
            record: Some(record()),
        };
        let decoded = decode_lookup_reply(&encode_lookup_reply(&reply).unwrap()).unwrap();
        assert_eq!(decoded, reply);
    }

    #[test]
    fn each_key_spelling_survives_a_round_trip() {
        for key in [
            Key::Name("jack".into()),
            Key::Sid(sid(&[21, 1, 2, 3, 1000])),
            Key::UnixId(1_001_000),
        ] {
            let lookup = Lookup {
                tag: 1,
                key: key.clone(),
                kind: Kind::Principal,
                fields: Fields::PASSWD,
            };
            let decoded = decode_lookup(&encode_lookup(&lookup).unwrap()).unwrap();
            assert_eq!(decoded, lookup, "{key:?} must survive");
        }
    }

    #[test]
    fn the_tag_comes_back_unchanged() {
        let lookup = Lookup {
            tag: 0xdead_beef,
            key: Key::Name("jack".into()),
            kind: Kind::Any,
            fields: Fields::empty(),
        };
        assert_eq!(
            decode_lookup(&encode_lookup(&lookup).unwrap()).unwrap().tag,
            0xdead_beef
        );
    }

    /// Bare name in, qualified answer out — a caller must always be able to tell
    /// which principal it got, whatever it asked with.
    #[test]
    fn a_found_reply_always_carries_identity() {
        let mut record = record();
        record.values.clear();
        let reply = LookupReply {
            tag: 1,
            outcome: Outcome::Found,
            record: Some(record),
        };
        let decoded = decode_lookup_reply(&encode_lookup_reply(&reply).unwrap()).unwrap();
        let decoded = decoded.record.expect("a Found reply carries a record");
        assert!(!decoded.sid.is_empty());
        assert_eq!(decoded.qualified_name, "jack");
        assert_eq!(decoded.kind_found, Kind::Principal);
    }

    #[test]
    fn a_reply_that_is_not_found_carries_no_record() {
        for outcome in [
            Outcome::NotFound,
            Outcome::Unavailable,
            Outcome::Refused,
            Outcome::Malformed,
        ] {
            let reply = LookupReply {
                tag: 1,
                outcome,
                record: None,
            };
            let decoded = decode_lookup_reply(&encode_lookup_reply(&reply).unwrap()).unwrap();
            assert_eq!(decoded, reply, "{outcome:?} must carry nothing");
        }
    }

    /// The three states of a requested field. A bit in neither `present` nor
    /// `withheld` means the authority does not implement it, which is what makes
    /// adding a bit later safe.
    #[test]
    fn a_requested_field_is_present_withheld_or_unimplemented() {
        let requested = Fields::UNIX_ID | Fields::MEMBERS | Fields::CLAIMS;
        let record = Record {
            sid: sid(&[21, 1, 2, 3, 1000]),
            qualified_name: "developers".into(),
            kind_found: Kind::Group,
            values: vec![Value::UnixId(1_001_001)],
            withheld: vec![Withheld {
                field: Fields::MEMBERS,
                reason: WithheldReason::Declined,
            }],
        };
        let reply = LookupReply {
            tag: 1,
            outcome: Outcome::Found,
            record: Some(record),
        };
        let decoded = decode_lookup_reply(&encode_lookup_reply(&reply).unwrap()).unwrap();
        let decoded = decoded.record.unwrap();

        assert!(decoded.value(Fields::UNIX_ID).is_some());
        assert_eq!(decoded.reason(Fields::MEMBERS), Some(WithheldReason::Declined));
        assert!(decoded.value(Fields::CLAIMS).is_none());
        assert!(decoded.reason(Fields::CLAIMS).is_none());
        assert!(
            requested.difference(decoded.present()).contains(Fields::CLAIMS),
            "an unanswered field must be distinguishable from an answered one"
        );
    }

    /// The exception to the closed-enum rule: a newer peer may set a bit this
    /// build has never heard of, and the fields after it must survive.
    #[test]
    fn an_unknown_field_bit_is_stepped_over() {
        let unknown = Fields(1 << 20);
        let mut w = Writer::new(&FRAMING, MSG_LOOKUP_REPLY);
        let at = w.open();
        w.u32(1);
        w.u8(Outcome::Found as u8);
        w.bytes(&sid(&[21, 1, 2, 3, 1000]), MAX_SID_BYTES).unwrap();
        w.string("jack", MAX_QUALIFIED_NAME_BYTES).unwrap();
        w.u8(Kind::Principal as u8);
        // UNIX_ID, then a bit from the future, then ENABLED.
        w.u32((Fields::UNIX_ID | unknown | Fields::ENABLED).0);
        w.count(0, MAX_WITHHELD).unwrap();
        w.count(3, MAX_VALUES).unwrap();
        write_value(&mut w, &Value::UnixId(1_001_000)).unwrap();
        let future = w.open();
        w.u64(0xffff_ffff_ffff_ffff);
        w.close(future);
        write_value(&mut w, &Value::Enabled(true)).unwrap();
        w.close(at);

        let decoded = decode_lookup_reply(&w.finish().unwrap()).unwrap();
        let decoded = decoded.record.unwrap();
        assert_eq!(decoded.value(Fields::UNIX_ID), Some(&Value::UnixId(1_001_000)));
        assert_eq!(
            decoded.value(Fields::ENABLED),
            Some(&Value::Enabled(true)),
            "a field after an unknown one must not be displaced by it"
        );
    }

    #[test]
    fn a_value_count_disagreeing_with_the_present_mask_is_refused() {
        let mut w = Writer::new(&FRAMING, MSG_LOOKUP_REPLY);
        let at = w.open();
        w.u32(1);
        w.u8(Outcome::Found as u8);
        w.bytes(&sid(&[21, 1, 2, 3, 1000]), MAX_SID_BYTES).unwrap();
        w.string("jack", MAX_QUALIFIED_NAME_BYTES).unwrap();
        w.u8(Kind::Principal as u8);
        w.u32((Fields::UNIX_ID | Fields::ENABLED).0);
        w.count(0, MAX_WITHHELD).unwrap();
        w.count(1, MAX_VALUES).unwrap(); // two bits, one value
        write_value(&mut w, &Value::UnixId(1)).unwrap();
        w.close(at);
        assert!(decode_lookup_reply(&w.finish().unwrap()).is_err());
    }

    #[test]
    fn an_enumeration_survives_a_round_trip() {
        let reply = EnumerateReply {
            tag: 3,
            outcome: Outcome::Found,
            entries: vec![record(), record()],
            next: vec![9, 9, 9],
            incomplete: vec!["udpsd".into()],
        };
        let decoded = decode_enumerate_reply(&encode_enumerate_reply(&reply).unwrap()).unwrap();
        assert_eq!(decoded, reply);
    }

    /// A non-empty cursor means there is more even where the page was empty, so
    /// a client must not infer completion from an empty page.
    #[test]
    fn an_empty_page_with_a_cursor_is_not_the_end() {
        let reply = EnumerateReply {
            tag: 1,
            outcome: Outcome::Found,
            entries: vec![],
            next: vec![1],
            incomplete: vec![],
        };
        let decoded = decode_enumerate_reply(&encode_enumerate_reply(&reply).unwrap()).unwrap();
        assert!(decoded.entries.is_empty());
        assert!(!decoded.next.is_empty());
    }

    #[test]
    fn enumerating_a_group_carries_the_group_it_is_of() {
        let request = Enumerate {
            tag: 1,
            kind: Kind::Principal,
            fields: Fields::PASSWD,
            of: Some(Key::Name("developers".into())),
            cursor: vec![4, 5, 6],
        };
        let decoded = decode_enumerate(&encode_enumerate(&request).unwrap()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn enumerating_everything_carries_no_group() {
        let request = Enumerate {
            tag: 1,
            kind: Kind::Group,
            fields: Fields::GROUP,
            of: None,
            cursor: vec![],
        };
        let decoded = decode_enumerate(&encode_enumerate(&request).unwrap()).unwrap();
        assert_eq!(decoded.of, None);
        assert_eq!(decoded, request);
    }

    #[test]
    fn a_message_of_the_wrong_type_is_refused() {
        let lookup = encode_lookup(&Lookup {
            tag: 1,
            key: Key::Name("jack".into()),
            kind: Kind::Any,
            fields: Fields::empty(),
        })
        .unwrap();
        assert!(matches!(
            decode_enumerate(&lookup),
            Err(WireError::UnexpectedMessage(MSG_LOOKUP))
        ));
    }

    /// Ident shares PGSS Logon's magic, so a message sent to the wrong socket is
    /// a clean "not served here" rather than a parse failure several fields in.
    #[test]
    fn ident_and_logon_share_a_header() {
        let lookup = encode_lookup(&Lookup {
            tag: 1,
            key: Key::Name("jack".into()),
            kind: Kind::Any,
            fields: Fields::empty(),
        })
        .unwrap();
        let (msg_type, _) = crate::wire::decode_header(&lookup).unwrap();
        assert_eq!(msg_type, MSG_LOOKUP);
        assert!(matches!(
            crate::wire::decode_logon_start(&lookup),
            Err(WireError::UnexpectedMessage(MSG_LOOKUP))
        ));
    }

    #[test]
    fn field_bits_iterate_in_ascending_order() {
        let bits: Vec<u32> = Fields::KNOWN.iter().map(|f| f.0).collect();
        assert_eq!(bits.len(), 10);
        assert!(bits.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(bits[0], Fields::UNIX_ID.0);
        assert_eq!(*bits.last().unwrap(), Fields::LOGON_TYPES.0);
    }

    #[test]
    fn a_kind_request_is_satisfied_only_by_that_kind() {
        assert!(Kind::Principal.satisfies(Kind::Any));
        assert!(Kind::Principal.satisfies(Kind::Principal));
        assert!(!Kind::Principal.satisfies(Kind::Group));
        assert!(!Kind::Group.satisfies(Kind::Principal));
    }

    #[test]
    fn an_oversized_field_is_refused() {
        let mut record = record();
        record.values = vec![Value::Home("/".repeat(MAX_PATH_BYTES + 1))];
        assert!(matches!(
            encode_lookup_reply(&LookupReply {
                tag: 1,
                outcome: Outcome::Found,
                record: Some(record),
            }),
            Err(WireError::TooLong)
        ));
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let messages: Vec<Vec<u8>> = vec![
            encode_lookup(&Lookup {
                tag: 1,
                key: Key::Name("jack".into()),
                kind: Kind::Principal,
                fields: Fields::PASSWD,
            })
            .unwrap(),
            encode_lookup_reply(&LookupReply {
                tag: 1,
                outcome: Outcome::Found,
                record: Some(record()),
            })
            .unwrap(),
            encode_enumerate(&Enumerate {
                tag: 1,
                kind: Kind::Principal,
                fields: Fields::PASSWD,
                of: Some(Key::Sid(sid(&[21, 1, 2, 3, 1000]))),
                cursor: vec![1, 2, 3],
            })
            .unwrap(),
            encode_enumerate_reply(&EnumerateReply {
                tag: 1,
                outcome: Outcome::Found,
                entries: vec![record()],
                next: vec![1],
                incomplete: vec!["udpsd".into()],
            })
            .unwrap(),
        ];
        for message in &messages {
            for cut in 0..message.len() {
                let prefix = &message[..cut];
                let _ = decode_header(prefix);
                let _ = decode_lookup(prefix);
                let _ = decode_lookup_reply(prefix);
                let _ = decode_enumerate(prefix);
                let _ = decode_enumerate_reply(prefix);
            }
        }
    }
}
