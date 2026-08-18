//! The local principal store: who this machine knows, what it will accept as
//! proof, and everything a token needs to say about them.
//!
//! # A store file, not a database
//!
//! Serialised whole and replaced atomically ([`crate::fs::replace`]). A few
//! hundred principals, rewritten when an administrator changes an account, is
//! not a workload that needs a write-ahead log — and the absence of one means
//! there is no recovery path to get wrong. The full reasoning, including why
//! neither SQLite nor `udd`'s persistence layer was taken, is on PEI-166.
//!
//! # Absent and corrupt are opposite outcomes
//!
//! - **Absent** is an unprovisioned machine. lpsd provisions a fresh store.
//! - **Corrupt** is fatal, and lpsd refuses to start.
//!
//! Collapsing those two would be the worst bug this file could have. "Cannot
//! read the store, so make a new one" turns a flipped bit into *every account on
//! the machine silently ceasing to exist* — and then, because provisioning
//! creates a fresh domain, into every one of them coming back with different
//! SIDs, orphaning every security descriptor that named them. Refusing to start
//! is loud, reversible, and leaves the evidence intact.
//!
//! An **older** store is neither: it is upgraded in place. See [`Store::load`].
//!
//! # The domain is the store's, and it is generated here
//!
//! A principal's SID is `S-1-5-21-{A}-{B}-{C}-{RID}`, where the domain is drawn
//! from the kernel's CSPRNG when the store is provisioned and persisted
//! alongside the principals numbered under it. Keeping it *in the store* rather
//! than in the registry is what makes it impossible for the domain to disagree
//! with the accounts it numbers: there is one file, written once, containing
//! both.
//!
//! The `S-1-5-21` prefix is structural rather than a convention this code
//! follows. [`Store::domain_sid`] and [`Store::sid_of`] build every SID from
//! three stored `u32`s under that fixed prefix, so a store *cannot express* a
//! domain of any other shape — it cannot claim `S-1-5-32` (BUILTIN), or the NT
//! authority's well-known range, or another source's namespace. That is a
//! property of the representation, not a check someone has to remember to run.
//!
//! # One counter: a Unix ID is the RID
//!
//! RIDs name principals and local groups inside the domain, and the counter is
//! shared between them so a group can never collide with a user's SID. A
//! principal's Unix ID is simply *its RID*.
//!
//! That satisfies PSD-004 §12.1 — which requires one counter across all
//! principal types, so an id issued to a user is never issued again to a group —
//! and it buys something the specification does not ask for: **one object has
//! one number.** With two counters `jack` was RID 1000 and uid 1, two
//! identifiers with no relationship, so reading a uid out of a log meant
//! consulting a mapping table. Tied together, the RID reads straight out of the
//! uid.
//!
//! It is still a *stored attribute*, not a computation. §12.1 is explicit that
//! the number comes from the directory's `uidNumber` rather than an algorithmic
//! mapping, and importing an account from another system means pinning the
//! number it already had. The RID is the default, not the definition.
//!
//! # Unix IDs here are relative, always
//!
//! This store knows nothing of where its range sits: authd adds a base from the
//! registry (`UnixIDBase`) before the number reaches a token. That is what lets
//! a second principal source exist without either one knowing about the other,
//! and it makes rebasing a source a policy edit rather than a rewrite of every
//! record here.
//!
//! Nothing in this file may add that base. If a number leaves here already
//! rebased, authd would rebase it again.
//!
//! # Groups are objects now
//!
//! A membership used to be a bare SID stapled to a principal. It cannot stay
//! that way, because a supplementary GID needs a `gidNumber` and a bare SID has
//! nowhere to keep one. So a *local* group is an object: a RID, a name, and a
//! Unix ID.
//!
//! Well-known groups — `BUILTIN\Administrators`, `Everyone` — are deliberately
//! **not** stored. Their SIDs are constants, and a stored copy could drift from
//! the system's. They resolve through [`well_known_group`], a table in code, and
//! their Unix IDs belong to authd, which owns every id below its sources'
//! ranges. lpsd holding one would be lpsd numbering a group it does not own.

use std::io;
use std::path::Path;

use libauthd::claim::{self, Claim, Values};
use peios::security::{Sid, SidRef, WellKnown};

use crate::codec::{self, CodecError, Reader, Writer};
use crate::fs::Fs;
use crate::random;
use crate::verifier::{Verifier, VerifierError};

/// Where the store lives. `/var/state/<daemon>/` is the convention peinit,
/// loregd and peipkg already follow for daemon-owned state.
pub const STORE_PATH: &str = "/var/state/lpsd/principals";

/// `S-1-5-21-…` — NT authority, non-unique (i.e. locally issued) domain.
const NT_AUTHORITY: u64 = 5;
const NON_UNIQUE: u32 = 21;

/// The first RID handed to a principal or a local group.
///
/// Below 1000 is reserved by convention for built-in accounts, the same
/// convention Windows and Unix both keep. Nothing enforces it; starting here
/// means nothing has to.
const FIRST_RID: u32 = 1000;

/// A Unix ID can never be zero, because [`FIRST_RID`] is 1000 and a Unix ID
/// defaults to the RID.
///
/// That matters twice over. Zero is root — and it is authd's, since `peinit`
/// already projects the SYSTEM token to uid 0 and KACS refuses a token
/// projecting uid 0 for any user SID that is not SYSTEM. It also leaves 0 free
/// to mean "no id" in every message that carries one, which is why
/// [`GroupRef::unix_id`] can be an `Option` with no separate presence flag on
/// the wire.
const NO_UNIX_ID: u32 = 0;

/// Bounds on what a store may contain.
///
/// These are not policy limits — no machine is expected to approach them. They
/// bound the work done decoding a file that has been corrupted or tampered
/// with, before any of it is believed. The name and membership ceilings match
/// what PSI will carry, so a store cannot hold a principal it would be unable to
/// assert.
const MAX_PRINCIPALS: usize = 4096;
const MAX_GROUP_OBJECTS: usize = 4096;
const MAX_NAME_BYTES: usize = 256;
const MAX_GROUPS: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// Characters a principal or group name may not contain.
///
/// Every one of these is a separator somewhere a name is going to end up, and
/// the damage is done by the reader rather than by us:
///
/// - `@` is reserved for the qualified-name syntax (`jack@local`) that realms
///   will use. Nothing parses it yet, which is precisely why it has to be
///   reserved now: an account literally named `jack@local` created today would
///   collide with the syntax the day it arrives, and unpicking that means
///   renaming principals that already exist.
/// - `\` is the other spelling of a qualified name (`DOMAIN\jack`), reserved on
///   the same grounds — and already given meaning by [`well_known_group`],
///   which strips a `BUILTIN\` prefix.
/// - `/` is a path separator, and a name becomes path components in
///   [`default_home`].
/// - `:` separates the fields of `/etc/passwd` and `/etc/group`.
/// - `,` separates a group's members in `/etc/group`, and the subfields of
///   GECOS.
///
/// Control characters — NUL, newline, carriage return, tab — are refused by the
/// printable-ASCII rule in [`check_name`] rather than listed here. Those are the
/// record separators, and a name carrying one could forge a whole line in any of
/// those files, or in a log.
const RESERVED_IN_NAME: &[u8] = b"@\\/:,";

/// The shell a principal gets when nobody chose one.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Where a principal's home directory goes when nobody chose one.
///
/// `/home` exists on a Peios image and is packaged by `fsbase` for humans
/// specifically — services have no entry there. Note that lpsd only records the
/// path; nothing here creates the directory.
fn default_home(name: &str) -> String {
    format!("/home/{name}")
}

/// The primary group a principal gets when nobody chose one.
///
/// `S-1-5-11`, Authenticated Users. Peios deliberately has **no per-user
/// group**: that convention exists in Linux so that a file's *group ownership*
/// means something, and under KACS it means nothing — every managed credential
/// carries `CAP_DAC_OVERRIDE`, so a Unix mode decides nothing at all. A group
/// per user would be ceremony with a RID attached.
///
/// Authenticated Users is a derived membership rather than an asserted one:
/// authd adds it to every token it mints. Naming it here says which of the
/// token's groups is *primary*, not that lpsd is vouching for the membership.
fn default_primary_group() -> Sid {
    Sid::well_known(WellKnown::AuthenticatedUsers)
}

/// Groups that exist on every Peios machine, by name.
///
/// A table in code rather than rows in the store, because these SIDs are
/// constants: a stored copy could drift from the system's idea of them, and
/// provisioning would bake in whatever the table said on the day. Their Unix IDs
/// are **not** here — those belong to authd, which numbers everything below its
/// sources' ranges.
///
/// Matched case-insensitively, and a `BUILTIN\` qualifier is accepted and
/// ignored, since that is how an administrator is likely to write the two that
/// carry it.
const WELL_KNOWN_GROUPS: &[(&str, u64, &[u32])] = &[
    ("Everyone", 1, &[0]),
    ("Authenticated Users", 5, &[11]),
    ("Administrators", 5, &[32, 544]),
    ("Users", 5, &[32, 545]),
    ("Guests", 5, &[32, 546]),
];

/// Resolve a well-known group name to its SID.
pub fn well_known_group(name: &str) -> Option<Sid> {
    let name = name
        .strip_prefix("BUILTIN\\")
        .or_else(|| name.strip_prefix("builtin\\"))
        .unwrap_or(name);
    WELL_KNOWN_GROUPS
        .iter()
        .find(|(known, _, _)| known.eq_ignore_ascii_case(name))
        .and_then(|(_, authority, subs)| Sid::build(*authority, subs).ok())
}

/// Groups the authority staples onto every token it mints.
///
/// Nothing records who is in them. `Everyone` and `Authenticated Users` are not
/// memberships anyone stores; they are a rule authd applies at derivation, so
/// "who is in this group" has no answer a store could give.
///
/// The distinction is not well-known-versus-local: `BUILTIN\Administrators` is
/// equally well-known and lpsd holds real memberships into it. What matters is
/// whether anything records an edge.
///
/// lpsd could return every principal it holds for these, and it would be a wrong
/// answer rather than a partial one — it knows nothing of other sources'
/// principals, and the group is a property of a token rather than of an account.
const STAPLED_GROUPS: &[(u64, &[u32])] = &[
    (1, &[0]),  // Everyone
    (5, &[11]), // Authenticated Users
];

fn is_stapled(sid: &SidRef) -> bool {
    STAPLED_GROUPS.iter().any(|(authority, subs)| {
        Sid::build(*authority, subs).is_ok_and(|built| built.as_ref().as_bytes() == sid.as_bytes())
    })
}

/// The name of a well-known group, if this is one.
pub fn well_known_group_name(sid: &SidRef) -> Option<&'static str> {
    WELL_KNOWN_GROUPS.iter().find_map(|(name, authority, subs)| {
        let built = Sid::build(*authority, subs).ok()?;
        (built.as_ref().as_bytes() == sid.as_bytes()).then_some(*name)
    })
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// The file exists but is not a store this lpsd can believe.
    Corrupt(CodecError),
    /// Structurally decodable, semantically impossible.
    Invalid(String),
    /// No principal by that name.
    NotFound(String),
    /// No group by that name, and it does not parse as a SID either.
    NoSuchGroup(String),
    Verifier(VerifierError),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Corrupt(e) => write!(f, "{e}"),
            Self::Invalid(what) => write!(f, "{what}"),
            Self::NotFound(name) => write!(f, "there is no principal named {name}"),
            Self::NoSuchGroup(name) => {
                write!(f, "there is no group named {name}, and it is not a SID")
            }
            Self::Verifier(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CodecError> for StoreError {
    fn from(error: CodecError) -> Self {
        Self::Corrupt(error)
    }
}

impl From<VerifierError> for StoreError {
    fn from(error: VerifierError) -> Self {
        Self::Verifier(error)
    }
}

/// Someone lpsd is authoritative for, as stored.
#[derive(Debug, Clone)]
struct Principal {
    rid: u32,
    /// This principal's Unix ID, relative to lpsd's range. Never rebased here.
    unix_id: u32,
    /// The canonical spelling. A client may type `JACK`; this is what the
    /// principal is actually called.
    name: String,
    enabled: bool,
    /// `None` means this principal authenticates with no credential at all.
    ///
    /// Distinct from a verifier over an empty password, which is why the empty
    /// password is rejected outright ([`Store::add`]): two encodings of "type
    /// nothing" that behave differently — one prompting, one not — is the kind
    /// of ambiguity an administrator discovers at the worst moment.
    ///
    /// Whether the account *has* one is deliberately not derivable from
    /// [`Store::authenticate`], which runs one derivation either way. The
    /// distinction is drawn by [`Store::credential_requirement`], before any
    /// credential is asked for, and only ever separates "passwordless" from
    /// everything else — never "exists" from "does not exist".
    verifier: Option<Verifier>,
    /// Groups lpsd says this principal belongs to.
    ///
    /// SIDs only. Whether a group is enabled, owner-marked or deny-only is a
    /// question about building a token, and lpsd has no business answering it.
    groups: Vec<Sid>,
    /// Which group is primary — the one that projects to the POSIX gid.
    primary_group: Sid,
    home: String,
    shell: String,
    /// Empty when unset. Not GECOS: that field is a comma-separated
    /// `/etc/passwd` artefact, and storing one would make anything that wants
    /// the name parse it back out. An NSS shim renders GECOS from this.
    display_name: String,
    /// Attributes fed to conditional ACE evaluation.
    claims: Vec<Claim>,
}

impl Principal {
    const FLAG_ENABLED: u8 = 1 << 0;

    /// ASCII case-insensitive, as principal names are throughout Peios — which
    /// is what makes the canonical name in an assertion worth carrying.
    fn matches(&self, identifier: &[u8]) -> bool {
        identifier.len() == self.name.len() && identifier.eq_ignore_ascii_case(self.name.as_bytes())
    }
}

/// A group this machine owns: one that lives under lpsd's domain.
#[derive(Debug, Clone)]
struct Group {
    rid: u32,
    unix_id: u32,
    name: String,
}

impl Group {
    fn matches(&self, name: &str) -> bool {
        name.len() == self.name.len() && name.eq_ignore_ascii_case(&self.name)
    }
}

/// A group as something else refers to it.
///
/// Carries the name and the Unix ID alongside the SID because the two callers
/// that matter cannot work them out for themselves: `lps` is on the far side of
/// a socket, and authd knows nothing of lpsd's group table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    pub sid: Sid,
    /// The name, if this machine knows one — a local group or a well-known
    /// alias. `None` for a SID from somewhere else entirely.
    pub name: Option<String>,
    /// The group's Unix ID, **relative to lpsd's range**. `None` when lpsd does
    /// not own the group, in which case authd's own table decides the number —
    /// applying lpsd's base to a `BUILTIN` group would put it inside lpsd's
    /// range, where it does not belong.
    pub unix_id: Option<u32>,
}

/// One principal, as a listing shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub name: String,
    pub rid: u32,
    pub unix_id: u32,
    pub enabled: bool,
    pub groups: usize,
}

/// One local group, as a listing shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub name: String,
    pub rid: u32,
    pub unix_id: u32,
    pub sid: Sid,
    pub members: usize,
}

/// What a lookup key resolved to.
///
/// One enum rather than two lookups because principals and groups share a RID
/// counter here: a relative identifier names at most one object, whichever kind
/// it turns out to be.
#[derive(Debug, Clone)]
pub enum Object {
    Principal(Record),
    Group(GroupRecord),
}

/// A group this machine can name — one of its own, or a well-known one.
#[derive(Debug, Clone)]
pub struct GroupRecord {
    pub sid: Sid,
    pub name: String,
    /// `None` for a well-known group, which lpsd does not number.
    pub unix_id: Option<u32>,
    /// Whether anything records membership edges into it. False for a group the
    /// authority staples onto tokens — see [`STAPLED_GROUPS`].
    pub enumerable: bool,
}

/// A principal in a group's membership list.
#[derive(Debug, Clone)]
pub struct Member {
    pub sid: Sid,
    pub name: String,
    /// Relative to lpsd's range, like every other number it states.
    pub unix_id: u32,
    /// The paging cursor: RIDs are never reused, so resuming after one is stable
    /// across a store that changed in between.
    pub rid: u32,
}

/// One principal in full, as administration sees them.
///
/// Carries composed SIDs rather than the domain and RIDs separately, so no
/// caller has to reimplement how this machine numbers its principals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rid: u32,
    pub unix_id: u32,
    pub enabled: bool,
    pub sid: Sid,
    pub groups: Vec<GroupRef>,
    pub primary_group: GroupRef,
    pub home: String,
    pub shell: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

/// What lpsd tells authd when a credential holds.
///
/// Everything here is *asserted* — a claim about who someone is. Nothing about
/// how much this machine trusts them: no privileges, no integrity level, no
/// group attributes. Those are authd's derivation, and a source has no way to
/// express them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub sid: Sid,
    pub unix_id: u32,
    pub groups: Vec<GroupRef>,
    pub primary_group: GroupRef,
    pub home: String,
    pub shell: String,
    pub display_name: String,
    pub claims: Vec<Claim>,
}

/// What the store needs before it can authenticate a given identifier.
///
/// Deliberately two variants and not three. There is no `NoSuchPrincipal`,
/// because a source that answered one would hand an unauthenticated caller an
/// account-existence oracle over the logon channel — which PGSS Logon
/// obligation 22 forbids, and which the decoy verifier in
/// [`Store::authenticate`] exists to prevent.
#[derive(Debug)]
pub enum CredentialRequirement {
    /// Collect a password and call [`Store::authenticate`]. Also the answer for
    /// a principal who does not exist, and for a disabled one.
    Password,
    /// Nothing to collect: this principal is already identified. Boxed because
    /// an `Identity` is far larger than the other variant and this type is
    /// returned by value on every logon.
    None(Box<Identity>),
}

/// Refuse an empty password.
///
/// An empty password and no password are two spellings of "type nothing" that
/// behave differently — one prompts and fails on anything else, the other never
/// prompts — so the store admits exactly one of them. `lps add name --no-password`
/// says it; `lps add name ""` is a mistake.
fn refuse_empty_password(credential: Option<&[u8]>) -> Result<(), StoreError> {
    if credential.is_some_and(<[u8]>::is_empty) {
        return Err(StoreError::Invalid(
            "an empty password is not a password: use --no-password to create a principal that \
             authenticates without one"
                .into(),
        ));
    }
    Ok(())
}

/// Everything an administrator may choose when creating a principal.
///
/// A struct rather than nine positional arguments, and the password is
/// deliberately *not* in it: a secret does not belong in a type that can be
/// cloned, defaulted and logged alongside a home directory.
#[derive(Debug, Clone)]
pub struct NewPrincipal {
    pub name: String,
    pub enabled: bool,
    pub groups: Vec<Sid>,
    /// `None` takes [`default_primary_group`].
    pub primary_group: Option<Sid>,
    /// `None` takes `/home/<name>`.
    pub home: Option<String>,
    /// `None` takes [`DEFAULT_SHELL`].
    pub shell: Option<String>,
    pub display_name: Option<String>,
}

impl NewPrincipal {
    /// A principal with nothing chosen but the name.
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enabled: true,
            groups: Vec::new(),
            primary_group: None,
            home: None,
            shell: None,
            display_name: None,
        }
    }
}

/// Cloneable so an administrative change can be rolled back if it cannot be
/// written to disk — see [`crate::admin`]. At a few hundred records that is far
/// cheaper than any scheme for keeping memory and disk in step after a failed
/// write, and it means the failure path is a single assignment rather than an
/// inverse for every operation.
#[derive(Clone)]
pub struct Store {
    /// The three sub-authorities under `S-1-5-21`.
    domain: [u32; 3],
    next_rid: u32,
    principals: Vec<Principal>,
    groups: Vec<Group>,
    /// A verifier for a password nobody knows — see [`Store::authenticate`].
    decoy: Verifier,
    /// Set when this store was read from an older format and upgraded in
    /// memory. Not persisted: it is a fact about *this load*, and the next
    /// write is what makes it false.
    upgraded: bool,
}

impl Store {
    /// A fresh store for a machine that has never had one: a new domain, drawn
    /// from the kernel's CSPRNG, and nothing in it.
    pub fn provision() -> Result<Self, StoreError> {
        let bytes = random::array::<12>().map_err(StoreError::Io)?;
        let domain = [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        ];
        Ok(Self {
            domain,
            next_rid: FIRST_RID,
            principals: Vec::new(),
            groups: Vec::new(),
            decoy: Verifier::decoy()?,
            upgraded: false,
        })
    }

    /// This machine's domain SID.
    pub fn domain_sid(&self) -> Result<Sid, StoreError> {
        Sid::build(
            NT_AUTHORITY,
            &[NON_UNIQUE, self.domain[0], self.domain[1], self.domain[2]],
        )
        .map_err(|error| StoreError::Invalid(format!("the domain SID is unbuildable: {error}")))
    }

    /// A principal's or local group's SID: the domain, plus their RID.
    fn sid_of(&self, rid: u32) -> Result<Sid, StoreError> {
        Sid::build(
            NT_AUTHORITY,
            &[
                NON_UNIQUE,
                self.domain[0],
                self.domain[1],
                self.domain[2],
                rid,
            ],
        )
        .map_err(|error| StoreError::Invalid(format!("a principal SID is unbuildable: {error}")))
    }

    /// The RID a SID carries, if the SID is one of ours.
    ///
    /// Decided by rebuilding the SID this store *would* issue for that RID and
    /// comparing bytes, rather than by picking the domain apart. That is exact:
    /// it settles the authority, the sub-authority count and every intermediate
    /// word in one comparison, so a SID with our domain words but a different
    /// shape cannot slip through.
    fn rid_in_domain(&self, sid: &SidRef) -> Option<u32> {
        let rid = sid.rid();
        let expected = self.sid_of(rid).ok()?;
        (expected.as_ref().as_bytes() == sid.as_bytes()).then_some(rid)
    }

    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }

    pub fn len(&self) -> usize {
        self.principals.len()
    }

    /// Whether this store was upgraded from an older format on load and should
    /// be written back.
    pub fn needs_rewrite(&self) -> bool {
        self.upgraded
    }

    #[cfg(test)]
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.principals.iter().map(|p| p.name.as_str())
    }

    // -----------------------------------------------------------------------
    // Reading, for administration
    // -----------------------------------------------------------------------

    /// Every principal, in the order they were created.
    pub fn summaries(&self) -> Vec<Summary> {
        self.principals
            .iter()
            .map(|principal| Summary {
                name: principal.name.clone(),
                rid: principal.rid,
                unix_id: principal.unix_id,
                enabled: principal.enabled,
                groups: principal.groups.len(),
            })
            .collect()
    }

    /// Every local group, in the order they were created.
    ///
    /// Well-known groups are absent by construction — this store does not hold
    /// them. `members` counts principals in *this* store, which is the only
    /// count lpsd can answer for.
    pub fn group_summaries(&self) -> Result<Vec<GroupSummary>, StoreError> {
        let mut out = Vec::with_capacity(self.groups.len());
        for group in &self.groups {
            let sid = self.sid_of(group.rid)?;
            out.push(GroupSummary {
                name: group.name.clone(),
                rid: group.rid,
                unix_id: group.unix_id,
                members: self
                    .principals
                    .iter()
                    .filter(|p| p.groups.iter().any(|g| *g == sid))
                    .count(),
                sid,
            });
        }
        Ok(out)
    }

    /// One principal in full, by name.
    pub fn record(&self, name: &str) -> Result<Record, StoreError> {
        let principal = self.find(name)?;
        Ok(Record {
            name: principal.name.clone(),
            rid: principal.rid,
            unix_id: principal.unix_id,
            enabled: principal.enabled,
            sid: self.sid_of(principal.rid)?,
            groups: principal
                .groups
                .iter()
                .map(|sid| self.group_ref(sid))
                .collect(),
            primary_group: self.group_ref(&principal.primary_group),
            home: principal.home.clone(),
            shell: principal.shell.clone(),
            display_name: principal.display_name.clone(),
            claims: principal.claims.clone(),
        })
    }

    /// Describe a group SID as fully as this machine can.
    // -----------------------------------------------------------------------
    // Lookup: answering about principals outside a logon
    //
    // PSI's `Query` (PSD-013 §5.5) asks about objects by name, by SID, or by
    // *relative* identifier — never by an absolute Unix ID, because lpsd does
    // not know its base and must not be able to act on one.
    // -----------------------------------------------------------------------

    /// Resolve a name to whatever this machine calls by it.
    ///
    /// Groups win over principals for a well-known name, which cannot collide in
    /// practice: [`check_name`] refuses those names at creation.
    pub fn lookup_name(&self, name: &str) -> Option<Object> {
        if let Some(sid) = well_known_group(name) {
            return self.group_record(sid.as_ref()).map(Object::Group);
        }
        if let Some(group) = self.groups.iter().find(|g| g.matches(name)) {
            return self.group_record_of(group).map(Object::Group);
        }
        let principal = self
            .principals
            .iter()
            .find(|p| p.matches(name.as_bytes()))?;
        self.record(&principal.name).ok().map(Object::Principal)
    }

    /// Resolve a relative identifier — a RID — to the object holding it.
    ///
    /// Principals and groups share one counter (see the module docs), so a RID
    /// names at most one of them and no disambiguation is needed.
    pub fn lookup_relative_id(&self, rid: u32) -> Option<Object> {
        if let Some(group) = self.groups.iter().find(|g| g.rid == rid) {
            return self.group_record_of(group).map(Object::Group);
        }
        let principal = self.principals.iter().find(|p| p.rid == rid)?;
        self.record(&principal.name).ok().map(Object::Principal)
    }

    /// Resolve a SID, which may be one of this domain's or a well-known group's.
    pub fn lookup_sid(&self, sid: &SidRef) -> Option<Object> {
        if let Some(rid) = self.rid_in_domain(sid) {
            return self.lookup_relative_id(rid);
        }
        self.group_record(sid).map(Object::Group)
    }

    /// A group this machine can name, local or well-known.
    pub fn group_record(&self, sid: &SidRef) -> Option<GroupRecord> {
        if let Some(rid) = self.rid_in_domain(sid) {
            let group = self.groups.iter().find(|g| g.rid == rid)?;
            return self.group_record_of(group);
        }
        let name = well_known_group_name(sid)?;
        Some(GroupRecord {
            sid: sid.to_owned(),
            name: name.to_string(),
            // lpsd does not number what it does not own — applying its base to a
            // `BUILTIN` group would land it inside lpsd's range.
            unix_id: None,
            enumerable: !is_stapled(sid),
        })
    }

    fn group_record_of(&self, group: &Group) -> Option<GroupRecord> {
        Some(GroupRecord {
            sid: self.sid_of(group.rid).ok()?,
            name: group.name.clone(),
            unix_id: Some(group.unix_id),
            enumerable: true,
        })
    }

    /// Who is in a group, in RID order.
    ///
    /// `after` resumes a walk: only principals with a **higher** RID are
    /// returned. RIDs are never reused, so a cursor stays meaningful across a
    /// store that changed underneath it — a deletion is skipped and an addition
    /// lands past the end. That is what lets lpsd page a membership without
    /// holding per-cursor state or ever refusing a cursor it issued.
    ///
    /// `None` where nothing records edges into the group. See [`is_stapled`].
    pub fn members_of(&self, sid: &SidRef, after: Option<u32>) -> Option<Vec<Member>> {
        if is_stapled(sid) {
            return None;
        }
        let owned = self.rid_in_domain(sid).is_some();
        if !owned && well_known_group_name(sid).is_none() {
            return None;
        }
        let sid = sid.to_owned();
        Some(
            self.principals
                .iter()
                .filter(|p| after.is_none_or(|rid| p.rid > rid))
                .filter(|p| {
                    p.groups.iter().any(|g| g.as_ref().as_bytes() == sid.as_ref().as_bytes())
                        // A primary group is a membership claim (PSD-013 §5.3),
                        // but only where lpsd owns the group. Every principal
                        // defaults to `Authenticated Users`, and listing them
                        // all as its members would be an answer this machine is
                        // in no position to give.
                        || (owned
                            && p.primary_group.as_ref().as_bytes() == sid.as_ref().as_bytes())
                })
                .filter_map(|p| {
                    Some(Member {
                        sid: self.sid_of(p.rid).ok()?,
                        name: p.name.clone(),
                        unix_id: p.unix_id,
                        rid: p.rid,
                    })
                })
                .collect(),
        )
    }

    /// Every principal after `after`, in RID order.
    pub fn principals_after(&self, after: Option<u32>) -> Vec<Record> {
        self.principals
            .iter()
            .filter(|p| after.is_none_or(|rid| p.rid > rid))
            .filter_map(|p| self.record(&p.name).ok())
            .collect()
    }

    /// Every local group after `after`, in RID order.
    ///
    /// Well-known groups are **not** included. They exist on every Peios machine
    /// whether or not this store mentions them, so they are the authority's to
    /// enumerate, not a source's — a source listing them would have every source
    /// on the system claim the same handful of objects.
    pub fn groups_after(&self, after: Option<u32>) -> Vec<GroupRecord> {
        self.groups
            .iter()
            .filter(|g| after.is_none_or(|rid| g.rid > rid))
            .filter_map(|g| self.group_record_of(g))
            .collect()
    }

    fn group_ref(&self, sid: &Sid) -> GroupRef {
        if let Some(rid) = self.rid_in_domain(sid.as_ref()) {
            if let Some(group) = self.groups.iter().find(|g| g.rid == rid) {
                return GroupRef {
                    sid: sid.clone(),
                    name: Some(group.name.clone()),
                    unix_id: Some(group.unix_id),
                };
            }
        }
        GroupRef {
            sid: sid.clone(),
            name: well_known_group_name(sid.as_ref()).map(str::to_string),
            unix_id: None,
        }
    }

    /// Turn what an administrator typed into a group SID.
    ///
    /// Three spellings, tried in that order: a well-known name, a local group's
    /// name, then a literal SID. One entry point rather than three means `lps`
    /// sends a string and never has to guess which kind it holds.
    ///
    /// Well-known names win over local ones, so creating a local group called
    /// `Administrators` cannot shadow `BUILTIN\Administrators` for anyone who
    /// types the short form — the reading that would quietly grant less than the
    /// administrator believed they had granted.
    pub fn resolve_group(&self, name: &str) -> Result<Sid, StoreError> {
        if let Some(sid) = well_known_group(name) {
            return Ok(sid);
        }
        if let Some(group) = self.groups.iter().find(|g| g.matches(name)) {
            return self.sid_of(group.rid);
        }
        name.parse::<Sid>()
            .map_err(|_| StoreError::NoSuchGroup(name.to_string()))
    }

    fn find(&self, name: &str) -> Result<&Principal, StoreError> {
        self.principals
            .iter()
            .find(|principal| principal.matches(name.as_bytes()))
            .ok_or_else(|| StoreError::NotFound(name.to_string()))
    }

    fn position(&self, name: &str) -> Result<usize, StoreError> {
        self.principals
            .iter()
            .position(|principal| principal.matches(name.as_bytes()))
            .ok_or_else(|| StoreError::NotFound(name.to_string()))
    }

    // -----------------------------------------------------------------------
    // Not locking everyone out
    // -----------------------------------------------------------------------

    /// Whether `principal` can currently administer the machine.
    fn administers(principal: &Principal) -> bool {
        let administrators = Sid::well_known(WellKnown::Administrators);
        principal.enabled
            && principal
                .groups
                .iter()
                .any(|group| group.as_ref().as_bytes() == administrators.as_ref().as_bytes())
    }

    /// Whether `name` is the only principal left who can administer the machine.
    ///
    /// Every operation that could take away the last administrator consults
    /// this and refuses. That is a policy decision living in the store, which is
    /// worth justifying: **there is no offline repair.** `lps` reaches the store
    /// only through lpsd, and lpsd only authenticates — so a machine with no
    /// enabled administrator has no path back short of editing the disk from
    /// another system. A guard against an unrecoverable mistake belongs at the
    /// point the mistake would be made.
    ///
    /// It is deliberately about `BUILTIN\Administrators` specifically, rather
    /// than "the last principal". An ordinary user is not a way back in.
    fn is_last_administrator(&self, name: &str) -> bool {
        let mut administrators = self
            .principals
            .iter()
            .filter(|principal| Self::administers(principal));
        match (administrators.next(), administrators.next()) {
            (Some(only), None) => only.matches(name.as_bytes()),
            _ => false,
        }
    }

    fn refuse_if_last_administrator(&self, name: &str, what: &str) -> Result<(), StoreError> {
        if self.is_last_administrator(name) {
            return Err(StoreError::Invalid(format!(
                "{name} is the only principal who can administer this machine; \
                 {what} would leave no way back in"
            )));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Allocation
    // -----------------------------------------------------------------------

    /// Take the next RID.
    ///
    /// RIDs are never reused: the counter only advances, and it advances even
    /// across deletions. A reused RID would give a new principal the SID of an
    /// old one, silently inheriting every access the descriptors on this machine
    /// still grant them — the one identity mistake that cannot be undone by
    /// fixing the account.
    fn allocate_rid(&mut self) -> Result<u32, StoreError> {
        let rid = self.next_rid;
        self.next_rid = rid
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("this store has exhausted its RID space".into()))?;
        Ok(rid)
    }

    // -----------------------------------------------------------------------
    // Mutation: principals
    // -----------------------------------------------------------------------

    /// Add a principal, returning the RID allocated to them.
    ///
    /// `credential` of `None` creates a principal that authenticates without
    /// one. An empty password is refused rather than accepted as a synonym —
    /// see [`Principal::verifier`].
    pub fn add(&mut self, new: NewPrincipal, credential: Option<&[u8]>) -> Result<u32, StoreError> {
        let name = check_name(&new.name, "principal")?;
        refuse_empty_password(credential)?;
        if new.groups.len() > MAX_GROUPS {
            return Err(StoreError::Invalid(format!(
                "{name} is in more than {MAX_GROUPS} groups"
            )));
        }
        if self.principals.len() >= MAX_PRINCIPALS {
            return Err(StoreError::Invalid(format!(
                "the store already holds {MAX_PRINCIPALS} principals"
            )));
        }
        if self.principals.iter().any(|p| p.matches(name.as_bytes())) {
            return Err(StoreError::Invalid(format!("{name} already exists")));
        }

        let home = match new.home {
            Some(home) => check_path(&home, "home directory")?,
            None => default_home(&name),
        };
        let shell = match new.shell {
            Some(shell) => check_path(&shell, "shell")?,
            None => DEFAULT_SHELL.to_string(),
        };
        let display_name = check_display_name(new.display_name.as_deref().unwrap_or(""))?;

        let rid = self.allocate_rid()?;

        self.principals.push(Principal {
            rid,
            // The RID is the default, not the definition — see the module
            // docs. Stored so that an account imported from another system can
            // keep the number it already had.
            unix_id: rid,
            name,
            enabled: new.enabled,
            verifier: credential.map(Verifier::create).transpose()?,
            groups: new.groups,
            primary_group: new.primary_group.unwrap_or_else(default_primary_group),
            home,
            shell,
            display_name,
            claims: Vec::new(),
        });
        Ok(rid)
    }

    /// Delete a principal.
    ///
    /// The RID is not reclaimed — see [`Store::allocate_rid`]. Files the
    /// principal owned keep naming a SID that now resolves to nobody, which is
    /// the correct outcome: the alternative is a future principal silently
    /// inheriting them.
    pub fn remove(&mut self, name: &str) -> Result<(), StoreError> {
        let at = self.position(name)?;
        self.refuse_if_last_administrator(name, "removing them")?;
        self.principals.remove(at);
        Ok(())
    }

    /// Enable or disable a principal. Returns whether anything changed.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<bool, StoreError> {
        let at = self.position(name)?;
        if !enabled {
            self.refuse_if_last_administrator(name, "disabling them")?;
        }
        if self.principals[at].enabled == enabled {
            return Ok(false);
        }
        self.principals[at].enabled = enabled;
        Ok(true)
    }

    /// Replace a principal's verifier.
    ///
    /// Always a change, even if the password is the one already set: the salt is
    /// fresh, so the record differs regardless and there is nothing to compare
    /// against without verifying — which would turn this into a password oracle
    /// for anyone entitled to call it.
    pub fn set_password(&mut self, name: &str, password: &[u8]) -> Result<(), StoreError> {
        refuse_empty_password(Some(password))?;
        let at = self.position(name)?;
        self.principals[at].verifier = Some(Verifier::create(password)?);
        Ok(())
    }

    /// Set the home directory. Returns whether anything changed.
    pub fn set_home(&mut self, name: &str, home: &str) -> Result<bool, StoreError> {
        let home = check_path(home, "home directory")?;
        let at = self.position(name)?;
        Ok(core::mem::replace(&mut self.principals[at].home, home) != self.principals[at].home)
    }

    /// Set the login shell. Returns whether anything changed.
    pub fn set_shell(&mut self, name: &str, shell: &str) -> Result<bool, StoreError> {
        let shell = check_path(shell, "shell")?;
        let at = self.position(name)?;
        Ok(core::mem::replace(&mut self.principals[at].shell, shell) != self.principals[at].shell)
    }

    /// Set the display name; empty clears it. Returns whether anything changed.
    pub fn set_display_name(&mut self, name: &str, display: &str) -> Result<bool, StoreError> {
        let display = check_display_name(display)?;
        let at = self.position(name)?;
        Ok(
            core::mem::replace(&mut self.principals[at].display_name, display)
                != self.principals[at].display_name,
        )
    }

    /// Set which group is primary. Returns whether anything changed.
    ///
    /// Membership is *not* required. PSD-004 §4.4 does require the primary group
    /// to be a group on the token, but that is authd's invariant to keep, and
    /// authd keeps it by adding the group if it is missing — naming a group as
    /// primary implies the membership. Requiring it here would make the order of
    /// two administrative commands matter for no reason.
    pub fn set_primary_group(&mut self, name: &str, group: Sid) -> Result<bool, StoreError> {
        let at = self.position(name)?;
        if self.principals[at].primary_group == group {
            return Ok(false);
        }
        self.principals[at].primary_group = group;
        Ok(true)
    }

    /// Add a group membership. Returns whether anything changed.
    pub fn add_membership(&mut self, name: &str, group: Sid) -> Result<bool, StoreError> {
        let at = self.position(name)?;
        if self.principals[at].groups.iter().any(|g| *g == group) {
            return Ok(false);
        }
        if self.principals[at].groups.len() >= MAX_GROUPS {
            return Err(StoreError::Invalid(format!(
                "{name} is already in the maximum of {MAX_GROUPS} groups"
            )));
        }
        self.principals[at].groups.push(group);
        Ok(true)
    }

    /// Remove a group membership. Returns whether anything changed.
    pub fn remove_membership(&mut self, name: &str, group: &SidRef) -> Result<bool, StoreError> {
        let at = self.position(name)?;
        let administrators = Sid::well_known(WellKnown::Administrators);
        if group.as_bytes() == administrators.as_ref().as_bytes() {
            self.refuse_if_last_administrator(name, "taking that group away")?;
        }

        let before = self.principals[at].groups.len();
        self.principals[at]
            .groups
            .retain(|existing| existing.as_ref().as_bytes() != group.as_bytes());
        Ok(self.principals[at].groups.len() != before)
    }

    /// Set a claim, replacing any with the same name. Returns whether anything
    /// changed.
    ///
    /// Names match case-insensitively, following KACS' own comparison rules for
    /// attribute names, so `Department` and `department` are one claim rather
    /// than two that a conditional ACE would see inconsistently.
    pub fn set_claim(&mut self, name: &str, claim: Claim) -> Result<bool, StoreError> {
        claim
            .validate()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let at = self.position(name)?;

        let claims = &mut self.principals[at].claims;
        if let Some(existing) = claims
            .iter_mut()
            .find(|c| c.name.eq_ignore_ascii_case(&claim.name))
        {
            if *existing == claim {
                return Ok(false);
            }
            *existing = claim;
            return Ok(true);
        }
        if claims.len() >= claim::MAX_CLAIMS {
            return Err(StoreError::Invalid(format!(
                "{name} already carries the maximum of {} claims",
                claim::MAX_CLAIMS
            )));
        }
        claims.push(claim);
        Ok(true)
    }

    /// Remove a claim by name. Returns whether anything changed.
    pub fn remove_claim(&mut self, name: &str, claim_name: &str) -> Result<bool, StoreError> {
        let at = self.position(name)?;
        let claims = &mut self.principals[at].claims;
        let before = claims.len();
        claims.retain(|c| !c.name.eq_ignore_ascii_case(claim_name));
        Ok(claims.len() != before)
    }

    // -----------------------------------------------------------------------
    // Mutation: groups
    // -----------------------------------------------------------------------

    /// Create a local group, returning the RID allocated to it.
    pub fn create_group(&mut self, name: &str) -> Result<u32, StoreError> {
        let name = check_name(name, "group")?;
        if self.groups.iter().any(|g| g.matches(&name)) {
            return Err(StoreError::Invalid(format!("the group {name} already exists")));
        }
        if self.groups.len() >= MAX_GROUP_OBJECTS {
            return Err(StoreError::Invalid(format!(
                "the store already holds {MAX_GROUP_OBJECTS} groups"
            )));
        }

        let rid = self.allocate_rid()?;
        self.groups.push(Group {
            rid,
            unix_id: rid,
            name,
        });
        Ok(rid)
    }

    /// Delete a local group.
    ///
    /// Refused while anyone is still a member. Deleting it out from under them
    /// would leave a SID on their record that resolves to nothing — the same
    /// dangling reference that makes RID reuse dangerous, except reachable by an
    /// ordinary administrative command.
    pub fn delete_group(&mut self, name: &str) -> Result<(), StoreError> {
        let at = self
            .groups
            .iter()
            .position(|g| g.matches(name))
            .ok_or_else(|| StoreError::NoSuchGroup(name.to_string()))?;
        let sid = self.sid_of(self.groups[at].rid)?;

        let members = self
            .principals
            .iter()
            .filter(|p| p.groups.iter().any(|g| *g == sid))
            .count();
        if members > 0 {
            return Err(StoreError::Invalid(format!(
                "{name} still has {members} member(s); remove them before deleting the group"
            )));
        }
        // A group nobody is *in* may still be somebody's primary group, which
        // would leave them projecting a gid that names nothing.
        if let Some(principal) = self
            .principals
            .iter()
            .find(|p| p.primary_group == sid)
        {
            return Err(StoreError::Invalid(format!(
                "{name} is the primary group of {}; give them another before deleting it",
                principal.name
            )));
        }

        self.groups.remove(at);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// Verify a credential and, if it holds, say who the principal is.
    ///
    /// # One code path, whether or not the name exists
    ///
    /// Lookup and verification are deliberately not separable. An unknown name
    /// is verified against [`Store::decoy`] — a real verifier over a password
    /// nobody knows — so both outcomes run exactly one argon2id derivation.
    ///
    /// This matters far more than it did when the comparison was a `memcmp`.
    /// argon2id at the configured cost takes tens of milliseconds; returning
    /// early for an unknown name would make "does this account exist?"
    /// answerable over the network by anyone who can time a login, which is
    /// precisely the distinction PGSS Logon's denial codes refuse to make.
    ///
    /// The residual: a principal whose verifier predates a parameter change
    /// costs what *those* parameters cost, which the decoy does not match. That
    /// distinguishes "old account" from "no account", not "account" from "no
    /// account", and it is inherent to keeping old verifiers working at all.
    pub fn authenticate(&self, identifier: &[u8], secret: &[u8]) -> Option<Identity> {
        let found = self.principals.iter().find(|p| p.matches(identifier));
        // A passwordless principal takes the decoy too. It is not authenticable
        // by password at all, and giving it its own early return would cost a
        // different amount of time from an unknown name — reintroducing exactly
        // the distinction the decoy exists to erase. The passwordless path does
        // not come through here; see `credential_requirement`.
        let verifier = found
            .and_then(|principal| principal.verifier.as_ref())
            .unwrap_or(&self.decoy);

        // Unconditional, and before any decision is taken on `found`.
        let correct = verifier.verify(secret);

        let principal = found?;
        if !correct || !principal.enabled || principal.verifier.is_none() {
            return None;
        }
        self.identity_of(principal)
    }

    /// What must be collected before [`Store::authenticate`] can be called for
    /// `identifier`.
    ///
    /// # This is the only place the store answers a question before a credential
    ///
    /// So it is the only place that could leak one, and what it may separate is
    /// therefore narrow: [`CredentialRequirement::None`] for a principal that
    /// exists, is enabled and has no verifier, and [`CredentialRequirement::Password`]
    /// for *everything else* — a principal with a password, a disabled one, and
    /// a name that does not exist, all alike.
    ///
    /// That keeps PGSS Logon obligation 22 (never distinguish an unknown
    /// principal from a bad credential) intact. The one thing an unauthenticated
    /// caller can learn here is that a name is passwordless — which is a name
    /// they could have logged in as anyway, so there is nothing left to protect.
    ///
    /// Existence on its own is a question for the identity-lookup channel
    /// (PSD-012 §6), which answers it plainly and by design.
    pub fn credential_requirement(&self, identifier: &[u8]) -> CredentialRequirement {
        let Some(principal) = self.principals.iter().find(|p| p.matches(identifier)) else {
            return CredentialRequirement::Password;
        };
        if !principal.enabled || principal.verifier.is_some() {
            return CredentialRequirement::Password;
        }
        match self.identity_of(principal) {
            Some(identity) => CredentialRequirement::None(Box::new(identity)),
            // The SID could not be built. Fall back to asking, which fails —
            // rather than granting on a half-built identity.
            None => CredentialRequirement::Password,
        }
    }

    /// The assertion this principal produces once authenticated.
    fn identity_of(&self, principal: &Principal) -> Option<Identity> {
        Some(Identity {
            name: principal.name.clone(),
            sid: self.sid_of(principal.rid).ok()?,
            unix_id: principal.unix_id,
            groups: principal
                .groups
                .iter()
                .map(|sid| self.group_ref(sid))
                .collect(),
            primary_group: self.group_ref(&principal.primary_group),
            home: principal.home.clone(),
            shell: principal.shell.clone(),
            display_name: principal.display_name.clone(),
            claims: principal.claims.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Read the store, if there is one.
    ///
    /// `Ok(None)` means no store exists — an unprovisioned machine. Every other
    /// failure is an error, and the caller must not treat it as absence.
    ///
    /// A store written by an **older** lpsd is upgraded in memory and flagged
    /// with [`Store::needs_rewrite`], so the caller writes it back once. Every
    /// field added since has a defensible default, and the alternative — refuse
    /// to start — would strand a machine whose only administrator is inside the
    /// file it is refusing to read.
    pub fn load<F: Fs>(fs: &F, path: &Path) -> Result<Option<Self>, StoreError> {
        let Some(file) = fs.read(path)? else {
            return Ok(None);
        };
        let (version, body) = codec::open(file.expose())?;
        Ok(Some(Self::decode(version, body)?))
    }

    /// Write the store, replacing any previous one atomically.
    pub fn save<F: Fs>(&self, fs: &F, path: &Path) -> Result<(), StoreError> {
        let sd = store_descriptor().map_err(|error| {
            StoreError::Invalid(format!("could not build the store's descriptor: {error}"))
        })?;
        let file = codec::seal(&self.encode());
        crate::fs::replace(fs, path, &file, &sd)?;
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.domain[0]);
        w.u32(self.domain[1]);
        w.u32(self.domain[2]);
        w.u32(self.next_rid);

        // Groups first: a principal's memberships name them, so a reader that
        // wants to resolve a membership while decoding has them already.
        w.u32(self.groups.len() as u32);
        for group in &self.groups {
            w.u32(group.rid);
            w.u32(group.unix_id);
            w.str(&group.name);
        }

        w.u32(self.principals.len() as u32);
        for principal in &self.principals {
            w.u32(principal.rid);
            w.u32(principal.unix_id);
            w.u8(if principal.enabled {
                Principal::FLAG_ENABLED
            } else {
                0
            });
            w.str(&principal.name);

            // The verifier goes in its own length frame so its format can grow
            // — a new KDF with more parameters — without displacing the groups
            // that follow it. Same discipline as PSI nesting `LogonStart`.
            //
            // An *empty* frame is a principal with no verifier at all. That
            // needs no format version: every store ever written held a real
            // verifier here, whose encoding starts with an algorithm byte and
            // is never zero-length, so the empty frame was unreachable until it
            // was given this meaning.
            let mut inner = Writer::new();
            if let Some(verifier) = &principal.verifier {
                verifier.encode(&mut inner);
            }
            w.bytes(&inner.finish());

            w.u32(principal.groups.len() as u32);
            for group in &principal.groups {
                w.bytes(group.as_ref().as_bytes());
            }

            w.bytes(principal.primary_group.as_ref().as_bytes());
            w.str(&principal.home);
            w.str(&principal.shell);
            w.str(&principal.display_name);

            w.u32(principal.claims.len() as u32);
            for claim in &principal.claims {
                // Framed for the same reason the verifier is: the claim format
                // is KACS', and KACS may grow it.
                let mut inner = Writer::new();
                encode_claim(&mut inner, claim);
                w.bytes(&inner.finish());
            }
        }
        w.finish()
    }

    fn decode(version: u16, body: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader::new(body);
        let domain = [r.u32()?, r.u32()?, r.u32()?];
        let next_rid = r.u32()?;

        // What each older layout is missing, and how it is filled in.
        //
        // Version 1 had no groups and no profile at all. Version 2 had both,
        // plus a separate Unix ID counter that allocated 1, 2, 3… — which is
        // what version 3 replaced with "the Unix ID is the RID".
        //
        // **Both are renumbered on the way in**, so every store ends up with
        // one rule rather than a stratum per vintage. That changes a
        // principal's uid across the upgrade, which on an ordinary Unix would
        // be reckless — it would orphan every file they own. Here it is safe,
        // and for a reason specific to this system: under KACS a uid decides
        // nothing. Access is decided by the SID, and the SID is untouched.
        let has_groups = version >= 2;
        let has_profile = version >= 2;
        let upgraded = version < codec::VERSION;

        // Version 2's Unix ID counter. Read and discarded: version 3 allocates
        // no Unix IDs, so there is no counter to carry forward.
        if version == 2 {
            let _ = r.u32()?;
        }

        let groups = if !has_groups {
            Vec::new()
        } else {
            let count = bounded(r.u32()?, MAX_GROUP_OBJECTS, "groups")?;
            let mut groups = Vec::with_capacity(count);
            for _ in 0..count {
                let rid = r.u32()?;
                // Version 2 allocated this separately; version 3 stores it, and
                // it defaults to the RID.
                let stored = r.u32()?;
                let name = r.str()?;
                if name.is_empty() || name.len() > MAX_NAME_BYTES {
                    return Err(StoreError::Invalid(
                        "the store contains a group with an unusable name".into(),
                    ));
                }
                groups.push(Group {
                    rid,
                    unix_id: if version == 2 { rid } else { stored },
                    name: name.to_string(),
                });
            }
            groups
        };

        let count = bounded(r.u32()?, MAX_PRINCIPALS, "principals")?;
        let mut principals = Vec::with_capacity(count);
        for _ in 0..count {
            let rid = r.u32()?;
            let unix_id = match version {
                // No such field: version 1 had no concept of one.
                1 => rid,
                // Present, but separately allocated (1, 2, 3…). Read so the
                // cursor advances, then discarded in favour of the RID.
                2 => {
                    let _ = r.u32()?;
                    rid
                }
                // A stored attribute, which defaults to the RID but need not
                // equal it — an imported account keeps the number it had.
                _ => r.u32()?,
            };
            let flags = r.u8()?;
            let name = r.str()?;
            if name.is_empty() || name.len() > MAX_NAME_BYTES {
                return Err(StoreError::Invalid(
                    "the store contains a principal with an unusable name".into(),
                ));
            }

            let verifier_frame = r.bytes()?;
            let verifier = if verifier_frame.is_empty() {
                None
            } else {
                Some(Verifier::decode(&mut Reader::new(verifier_frame))?)
            };

            let group_count = bounded(r.u32()?, MAX_GROUPS, "group memberships")?;
            let mut memberships = Vec::with_capacity(group_count);
            for _ in 0..group_count {
                let bytes = r.bytes()?;
                let sid = SidRef::from_bytes(bytes).ok_or_else(|| {
                    StoreError::Invalid(format!("{name} has a group that is not a valid SID"))
                })?;
                memberships.push(sid.to_sid());
            }

            let (primary_group, home, shell, display_name, claims) = if !has_profile {
                (
                    default_primary_group(),
                    default_home(name),
                    DEFAULT_SHELL.to_string(),
                    String::new(),
                    Vec::new(),
                )
            } else {
                let primary = SidRef::from_bytes(r.bytes()?)
                    .ok_or_else(|| {
                        StoreError::Invalid(format!(
                            "{name} has a primary group that is not a valid SID"
                        ))
                    })?
                    .to_sid();
                let home = r.str()?.to_string();
                let shell = r.str()?.to_string();
                let display_name = r.str()?.to_string();

                let claim_count = bounded(r.u32()?, claim::MAX_CLAIMS, "claims")?;
                let mut claims = Vec::with_capacity(claim_count);
                for _ in 0..claim_count {
                    let frame = r.bytes()?;
                    let claim = decode_claim(&mut Reader::new(frame))?;
                    claim.validate().map_err(|error| {
                        StoreError::Invalid(format!("{name} has an unusable claim: {error}"))
                    })?;
                    claims.push(claim);
                }
                (primary, home, shell, display_name, claims)
            };

            principals.push(Principal {
                rid,
                unix_id,
                name: name.to_string(),
                enabled: flags & Principal::FLAG_ENABLED != 0,
                verifier,
                groups: memberships,
                primary_group,
                home,
                shell,
                display_name,
                claims,
            });
        }

        if !r.at_end() {
            // The body is exactly what this version writes, or it is not this
            // version's body. Trailing bytes that survived the checksum mean a
            // newer lpsd wrote fields here, and guessing at their meaning is
            // how a store silently loses data on a downgrade.
            return Err(StoreError::Invalid(
                "the store has trailing data this lpsd does not understand".into(),
            ));
        }

        let store = Self {
            domain,
            next_rid,
            principals,
            groups,
            decoy: Verifier::decoy()?,
            upgraded,
        };
        store.check_consistent()?;
        Ok(store)
    }

    /// Everything a decoded store must be true of, checked once it is assembled.
    ///
    /// None of these are reachable through this module's own API — every one of
    /// them means the file was edited, or written by something that is not this
    /// program. They are checked anyway because the consequences run from
    /// "ambiguous" to "two principals share an identity".
    fn check_consistent(&self) -> Result<(), StoreError> {
        for (index, principal) in self.principals.iter().enumerate() {
            if self.principals[..index]
                .iter()
                .any(|earlier| earlier.matches(principal.name.as_bytes()))
            {
                return Err(StoreError::Invalid(format!(
                    "the store contains two principals named {}",
                    principal.name
                )));
            }
            if principal.rid >= self.next_rid {
                return Err(StoreError::Invalid(format!(
                    "{} holds RID {} at or beyond the next to be allocated ({})",
                    principal.name, principal.rid, self.next_rid
                )));
            }
            // Zero is root. Nothing here can produce it — the RID floor is
            // 1000 — so a file carrying one was edited, and this is the edit
            // that matters most.
            if principal.unix_id == NO_UNIX_ID {
                return Err(StoreError::Invalid(format!(
                    "{} holds Unix ID 0, which projects to root",
                    principal.name
                )));
            }
        }

        for (index, group) in self.groups.iter().enumerate() {
            if self.groups[..index].iter().any(|earlier| earlier.matches(&group.name)) {
                return Err(StoreError::Invalid(format!(
                    "the store contains two groups named {}",
                    group.name
                )));
            }
            if group.rid >= self.next_rid {
                return Err(StoreError::Invalid(format!(
                    "the group {} holds RID {} at or beyond the next to be allocated ({})",
                    group.name, group.rid, self.next_rid
                )));
            }
            if group.unix_id == NO_UNIX_ID {
                return Err(StoreError::Invalid(format!(
                    "the group {} holds Unix ID 0, which projects to root",
                    group.name
                )));
            }
        }

        // The two counters are shared across principals and groups precisely so
        // that neither a SID nor a projected id can be issued twice. A file
        // claiming otherwise breaks the property every descriptor depends on.
        let mut rids: Vec<u32> = self
            .principals
            .iter()
            .map(|p| p.rid)
            .chain(self.groups.iter().map(|g| g.rid))
            .collect();
        rids.sort_unstable();
        if rids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StoreError::Invalid(
                "the store issues one RID to two different objects".into(),
            ));
        }

        let mut ids: Vec<u32> = self
            .principals
            .iter()
            .map(|p| p.unix_id)
            .chain(self.groups.iter().map(|g| g.unix_id))
            .collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(StoreError::Invalid(
                "the store issues one Unix ID to two different objects".into(),
            ));
        }

        Ok(())
    }
}

/// Refuse an absurd count before allocating for it.
fn bounded(count: u32, max: usize, what: &str) -> Result<usize, StoreError> {
    let count = count as usize;
    if count > max {
        return Err(StoreError::Invalid(format!(
            "the store claims {count} {what}, more than the {max} permitted"
        )));
    }
    Ok(count)
}

/// Check a path an administrator supplied for a home directory or a shell.
///
/// Absolute, bounded, and free of interior NULs. Nothing checks that the path
/// *exists*: a home directory is routinely created after the account, and a
/// shell may live on a filesystem that is not mounted yet at the moment an
/// administrator types the command.
fn check_path(path: &str, what: &str) -> Result<String, StoreError> {
    let path = path.trim();
    if path.is_empty() {
        return Err(StoreError::Invalid(format!("a {what} cannot be empty")));
    }
    if !path.starts_with('/') {
        return Err(StoreError::Invalid(format!(
            "a {what} must be an absolute path, and {path:?} is not"
        )));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(StoreError::Invalid(format!(
            "a {what} may not exceed {MAX_PATH_BYTES} bytes"
        )));
    }
    if path.as_bytes().contains(&0) {
        return Err(StoreError::Invalid(format!(
            "a {what} may not contain a NUL"
        )));
    }
    Ok(path.to_string())
}

/// A principal or group name, canonicalised.
///
/// Trimmed, non-empty, bounded, printable ASCII, free of [`RESERVED_IN_NAME`],
/// and not the name of a well-known group.
///
/// Surrounding whitespace is stripped rather than refused. It is nearly always a
/// typo, and stripping it is what stops a name differing from another only by a
/// trailing space ever reaching the store — which would render identically
/// everywhere an operator could look at it.
///
/// **ASCII, deliberately.** Unicode names bring confusables — `jack` with a
/// Cyrillic `а` renders identically and is a different principal — and
/// normalisation, where NFC and NFD spell one name in two byte sequences that a
/// byte comparison calls two people. Matching here is `eq_ignore_ascii_case`, so
/// admitting Unicode would also mean defining what case means across the whole
/// of it, and freezing that definition for as long as the accounts live.
/// Restricting now and relaxing later is backward compatible; the reverse means
/// renaming principals that already exist.
///
/// Interior spaces are allowed. Well-known groups have them (`Authenticated
/// Users`), and a local group called `Backup Operators` is a reasonable thing to
/// want.
fn check_name(name: &str, what: &str) -> Result<String, StoreError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StoreError::Invalid(format!("a {what} needs a name")));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(StoreError::Invalid(format!(
            "the name {name:?} is longer than {MAX_NAME_BYTES} bytes"
        )));
    }
    if let Some(byte) = name.bytes().find(|byte| !(0x20..=0x7e).contains(byte)) {
        return Err(StoreError::Invalid(format!(
            "the name {name:?} contains {byte:#04x}; a {what} name is printable ASCII"
        )));
    }
    if let Some(byte) = name.bytes().find(|byte| RESERVED_IN_NAME.contains(byte)) {
        return Err(StoreError::Invalid(format!(
            "a {what} name may not contain {:?}",
            char::from(byte)
        )));
    }
    // A name that shadows a well-known group is unreachable: `resolve_group`
    // prefers the well-known spelling, and the resolver in authd will do the
    // same. Creating one produces an object nothing can ever name.
    if well_known_group(name).is_some() {
        return Err(StoreError::Invalid(format!(
            "{name} is a well-known group, and that name is reserved"
        )));
    }
    Ok(name.to_string())
}

fn check_display_name(display: &str) -> Result<String, StoreError> {
    let display = display.trim();
    if display.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(StoreError::Invalid(format!(
            "a display name may not exceed {MAX_DISPLAY_NAME_BYTES} bytes"
        )));
    }
    if display.as_bytes().contains(&0) {
        return Err(StoreError::Invalid(
            "a display name may not contain a NUL".into(),
        ));
    }
    Ok(display.to_string())
}

// ---------------------------------------------------------------------------
// Claims, in the store's own codec
// ---------------------------------------------------------------------------
//
// Deliberately not the wire encoding. `libauthd` frames a claim for a protocol
// that has to survive a peer of a different vintage; the store has a version
// number on the file and refuses anything it does not recognise, so it can use
// the simpler codec the rest of this file uses. The *type* is shared, which is
// what stops a claim meaning one thing on disk and another on the wire.

fn encode_claim(w: &mut Writer, claim: &Claim) {
    w.str(&claim.name);
    w.u32(claim.flags);
    w.u32(claim.values.type_code());
    w.u32(claim.values.len() as u32);
    match &claim.values {
        Values::Int64(values) => values.iter().for_each(|v| w.u64(*v as u64)),
        Values::Uint64(values) => values.iter().for_each(|v| w.u64(*v)),
        Values::Boolean(values) => values.iter().for_each(|v| w.u64(u64::from(*v))),
        Values::String(values) => values.iter().for_each(|v| w.str(v)),
        Values::Sid(values) => values.iter().for_each(|v| w.bytes(v)),
        Values::Octet(values) => values.iter().for_each(|v| w.bytes(v)),
    }
}

fn decode_claim(r: &mut Reader<'_>) -> Result<Claim, StoreError> {
    let name = r.str()?.to_string();
    let flags = r.u32()?;
    let type_code = r.u32()?;
    let count = bounded(r.u32()?, claim::MAX_VALUES, "claim values")?;

    let mut read = |kind: u32| -> Result<Values, StoreError> {
        Ok(match kind {
            claim::TYPE_INT64 => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(r.u64()? as i64);
                }
                Values::Int64(v)
            }
            claim::TYPE_UINT64 => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(r.u64()?);
                }
                Values::Uint64(v)
            }
            claim::TYPE_BOOLEAN => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    // Any non-zero is true, as KACS normalises it.
                    v.push(r.u64()? != 0);
                }
                Values::Boolean(v)
            }
            claim::TYPE_STRING => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(r.str()?.to_string());
                }
                Values::String(v)
            }
            claim::TYPE_SID => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(r.bytes()?.to_vec());
                }
                Values::Sid(v)
            }
            claim::TYPE_OCTET => {
                let mut v = Vec::with_capacity(count);
                for _ in 0..count {
                    v.push(r.bytes()?.to_vec());
                }
                Values::Octet(v)
            }
            other => {
                return Err(StoreError::Invalid(format!(
                    "the store contains a claim of unsupported type {other:#06x}"
                )))
            }
        })
    };

    let values = read(type_code)?;
    Ok(Claim {
        name,
        flags,
        values,
    })
}

/// The security descriptor the store file is written with.
///
/// `LocalSystem` alone: owner, group, and the only ACE. Not
/// `BUILTIN\Administrators`, which the rest of the system's descriptors do
/// grant — an administrator can take ownership if they genuinely need the file,
/// and that is an act that leaves a trail, where a read granted by the DACL
/// does not. This is the machine's password material; the list of principals
/// entitled to read it should be as close to empty as the system permits.
///
/// No inheritance flags. It is a file, nothing is created under it, and an
/// inheritable ACE here would be a claim about children that cannot exist.
///
/// **This is coupled to lpsd running as SYSTEM.** If lpsd is ever given a
/// dedicated account, this descriptor has to name it or lpsd will lock itself
/// out of its own store. The tighter descriptor — lpsd's *service* SID rather
/// than SYSTEM, so that not every SYSTEM process on the machine can read the
/// verifiers — needs the service-SID derivation that currently exists twice
/// (peinit and authd) and should exist once in libpeios. Flagged on PEI-166
/// rather than adding a third copy here.
pub fn store_descriptor() -> peios::Result<peios::security::SecurityDescriptor> {
    use peios::security::{AccessMask, AceFlags, AclBuilder, SdBuilder, WellKnown};

    let system = Sid::well_known(WellKnown::System);
    let dacl = AclBuilder::new()
        .allow(
            system.as_ref(),
            AccessMask::GENERIC_ALL.bits(),
            AceFlags::empty(),
        )
        .build()?;
    SdBuilder::new()
        .owner(system.as_ref())
        .group(system.as_ref())
        .dacl(&dacl)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FaultyFs;
    use peios::security::WellKnown;

    fn path() -> &'static Path {
        Path::new("/var/state/lpsd/principals")
    }

    fn administrators() -> Sid {
        Sid::well_known(WellKnown::Administrators)
    }

    fn new(name: &str, groups: Vec<Sid>) -> NewPrincipal {
        NewPrincipal {
            groups,
            ..NewPrincipal::named(name)
        }
    }

    /// A store with one account. Argon2id is deliberately slow, so tests that
    /// do not care about the credential share this.
    fn seeded() -> Store {
        let mut store = Store::provision().expect("must provision");
        store
            .add(new("jack", vec![administrators()]), Some(b"password"))
            .expect("must add");
        store
    }

    // -----------------------------------------------------------------------
    // Passwordless principals
    // -----------------------------------------------------------------------

    fn requirement(store: &Store, name: &str) -> CredentialRequirement {
        store.credential_requirement(name.as_bytes())
    }

    fn needs_a_password(store: &Store, name: &str) -> bool {
        matches!(requirement(store, name), CredentialRequirement::Password)
    }

    #[test]
    fn a_passwordless_principal_needs_no_credential() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("kiosk", vec![]), None).expect("must add");

        let CredentialRequirement::None(identity) = requirement(&store, "kiosk") else {
            panic!("a principal with no verifier must need nothing collected");
        };
        assert_eq!(identity.name, "kiosk");
    }

    /// The canonical name comes from the store, not from what the caller typed
    /// — the same rule an assertion follows after a password logon.
    #[test]
    fn a_passwordless_assertion_carries_the_canonical_name() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("Kiosk", vec![]), None).expect("must add");

        let CredentialRequirement::None(identity) = requirement(&store, "KIOSK") else {
            panic!("names are case-insensitive");
        };
        assert_eq!(identity.name, "Kiosk");
    }

    /// The heart of it. A caller that asks whether a name is passwordless must
    /// not be able to read an account-existence answer out of the reply —
    /// PGSS Logon obligation 22. "Has a password" and "does not exist" are one
    /// answer here, as they are everywhere else.
    #[test]
    fn an_unknown_principal_is_indistinguishable_from_one_with_a_password() {
        let store = seeded();

        assert!(needs_a_password(&store, "jack"));
        assert!(needs_a_password(&store, "nobody"));
        assert!(needs_a_password(&store, ""));
    }

    /// A disabled account must not become *easier* to use by having no
    /// password. It takes the same branch as a nonexistent one.
    #[test]
    fn a_disabled_passwordless_principal_still_needs_a_credential() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("kiosk", vec![]), None).expect("must add");
        store
            .add(new("root", vec![administrators()]), Some(b"pw"))
            .expect("must add");
        store.set_enabled("kiosk", false).expect("must disable");

        assert!(needs_a_password(&store, "kiosk"));
    }

    /// A passwordless principal is not authenticable *by password* — including
    /// by the empty one. Otherwise "no password" would quietly mean "the
    /// password is empty", which is the ambiguity the store refuses to store.
    #[test]
    fn a_passwordless_principal_cannot_be_password_authenticated() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("kiosk", vec![]), None).expect("must add");

        assert!(store.authenticate(b"kiosk", b"").is_none());
        assert!(store.authenticate(b"kiosk", b"anything").is_none());
    }

    #[test]
    fn an_empty_password_is_refused_on_add() {
        let mut store = Store::provision().expect("must provision");

        assert!(matches!(
            store.add(new("jack", vec![]), Some(b"")),
            Err(StoreError::Invalid(_))
        ));
        assert!(store.is_empty(), "a refused add must not create anything");
    }

    #[test]
    fn an_empty_password_is_refused_on_set_password() {
        let mut store = seeded();

        assert!(matches!(
            store.set_password("jack", b""),
            Err(StoreError::Invalid(_))
        ));
        // And the old one still works, so a refused change is not a lockout.
        assert!(store.authenticate(b"jack", b"password").is_some());
    }

    /// Giving a passwordless principal a password is a one-way door only
    /// because nothing exposes the reverse — but it must at least work.
    #[test]
    fn a_passwordless_principal_can_be_given_a_password() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("kiosk", vec![]), None).expect("must add");
        store.set_password("kiosk", b"pw").expect("must set");

        assert!(needs_a_password(&store, "kiosk"));
        assert!(store.authenticate(b"kiosk", b"pw").is_some());
    }

    /// The empty verifier frame survives a write and a read. If it did not, a
    /// passwordless account would come back as a corrupt store — or worse, as
    /// an account with an unknown password.
    #[test]
    fn a_passwordless_principal_round_trips_through_the_codec() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("kiosk", vec![]), None).expect("must add");
        store
            .add(new("jack", vec![administrators()]), Some(b"password"))
            .expect("must add");

        let body = store.encode();
        let back = Store::decode(codec::VERSION, &body).expect("must decode");

        assert!(matches!(
            back.credential_requirement(b"kiosk"),
            CredentialRequirement::None(_)
        ));
        assert!(needs_a_password(&back, "jack"));
        assert!(back.authenticate(b"jack", b"password").is_some());
    }

    #[test]
    fn a_fresh_store_has_a_domain_and_no_principals() {
        let store = Store::provision().expect("must provision");
        assert!(store.is_empty());
        let domain = store.domain_sid().expect("must build").to_string();
        assert!(
            domain.starts_with("S-1-5-21-"),
            "a local domain must be S-1-5-21-…, got {domain}"
        );
    }

    #[test]
    fn two_machines_do_not_share_a_domain() {
        let a = Store::provision().expect("must provision");
        let b = Store::provision().expect("must provision");
        assert_ne!(
            a.domain_sid().unwrap().to_string(),
            b.domain_sid().unwrap().to_string(),
            "colliding domains would make one machine's descriptors grant the other's users"
        );
    }

    #[test]
    fn the_domain_cannot_be_a_well_known_namespace() {
        // The shape is structural: three stored u32s under a fixed S-1-5-21
        // prefix. There is no representation of BUILTIN or the NT authority's
        // own range, whatever the stored words happen to be.
        let mut store = Store::provision().expect("must provision");
        store.domain = [32, 0, 0];
        let domain = store.domain_sid().unwrap().to_string();
        assert_eq!(domain, "S-1-5-21-32-0-0");
        assert_ne!(domain, "S-1-5-32");
    }

    #[test]
    fn a_principal_gets_a_sid_in_the_domain() {
        let store = seeded();
        let identity = store
            .authenticate(b"jack", b"password")
            .expect("must authenticate");
        let domain = store.domain_sid().unwrap().to_string();
        assert_eq!(identity.sid.to_string(), format!("{domain}-1000"));
    }

    #[test]
    fn the_first_rid_is_1000() {
        let store = seeded();
        assert!(store
            .authenticate(b"jack", b"password")
            .unwrap()
            .sid
            .to_string()
            .ends_with("-1000"));
    }

    #[test]
    fn rids_are_not_reused() {
        let mut store = Store::provision().expect("must provision");
        assert_eq!(store.add(new("a", vec![]), Some(b"pw")).unwrap(), 1000);
        assert_eq!(store.add(new("b", vec![]), Some(b"pw")).unwrap(), 1001);
        // Even after a removal, which the format permits, the counter only
        // advances — a reissued RID inherits the old holder's access.
        store.principals.retain(|p| p.name != "b");
        assert_eq!(store.add(new("c", vec![]), Some(b"pw")).unwrap(), 1002);
    }

    #[test]
    fn the_right_password_authenticates() {
        let store = seeded();
        let identity = store
            .authenticate(b"jack", b"password")
            .expect("must authenticate");
        assert_eq!(identity.name, "jack");
        assert_eq!(
            identity
                .groups
                .iter()
                .map(|g| g.sid.to_string())
                .collect::<Vec<_>>(),
            vec!["S-1-5-32-544"]
        );
    }

    #[test]
    fn the_wrong_password_does_not() {
        let store = seeded();
        assert!(store.authenticate(b"jack", b"hunter2").is_none());
        assert!(store.authenticate(b"jack", b"").is_none());
        assert!(store.authenticate(b"jack", b"password ").is_none());
    }

    #[test]
    fn an_unknown_principal_does_not_authenticate() {
        let store = seeded();
        assert!(store.authenticate(b"root", b"password").is_none());
        assert!(store.authenticate(b"", b"").is_none());
    }

    #[test]
    fn names_are_case_insensitive_and_canonicalised() {
        let store = seeded();
        let identity = store
            .authenticate(b"JACK", b"password")
            .expect("must authenticate");
        assert_eq!(
            identity.name, "jack",
            "the assertion carries the canonical spelling, not what was typed"
        );
    }

    #[test]
    fn a_prefix_of_the_name_is_not_the_name() {
        let store = seeded();
        assert!(store.authenticate(b"jac", b"password").is_none());
        assert!(store.authenticate(b"jackx", b"password").is_none());
    }

    #[test]
    fn a_disabled_principal_does_not_authenticate() {
        let mut store = seeded();
        store.principals[0].enabled = false;
        assert!(
            store.authenticate(b"jack", b"password").is_none(),
            "the right password must not admit a disabled account"
        );
    }

    #[test]
    fn duplicate_names_are_refused() {
        let mut store = seeded();
        assert!(matches!(
            store.add(new("JACK", vec![]), Some(b"other")),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn an_unnamed_principal_is_refused() {
        let mut store = Store::provision().expect("must provision");
        assert!(matches!(
            store.add(new("   ", vec![]), Some(b"pw")),
            Err(StoreError::Invalid(_))
        ));
    }

    /// A principal created disabled must be created disabled, not created and
    /// then disabled: on an empty store the second step would trip the
    /// last-administrator guard and leave a half-made account behind.
    #[test]
    fn a_principal_can_be_created_disabled() {
        let mut store = Store::provision().expect("must provision");
        store
            .add(
                NewPrincipal {
                    enabled: false,
                    groups: vec![administrators()],
                    ..NewPrincipal::named("standby")
                },
                Some(b"pw"),
            )
            .expect("must add");
        assert!(!store.record("standby").unwrap().enabled);
        assert!(store.authenticate(b"standby", b"pw").is_none());
    }

    // -----------------------------------------------------------------------
    // Unix IDs
    // -----------------------------------------------------------------------

    #[test]
    fn unix_ids_start_at_the_first_rid_and_never_reach_zero() {
        // Zero is root, and root is authd's. Nothing here can issue it, because
        // a Unix ID is the RID and RIDs begin at 1000 — so the property holds
        // by construction rather than by a check somebody has to remember.
        let mut store = Store::provision().expect("must provision");
        store.add(new("first", vec![]), Some(b"pw")).unwrap();
        assert_eq!(store.record("first").unwrap().unix_id, FIRST_RID);
    }

    #[test]
    fn principals_and_groups_share_one_unix_id_counter() {
        // PSD-004 §12.1: SIDs are one namespace, uid and gid are two, so a
        // number issued to a principal must never be issued to a group.
        let mut store = Store::provision().expect("must provision");
        store.add(new("a", vec![]), Some(b"pw")).unwrap();
        store.create_group("developers").unwrap();
        store.add(new("b", vec![]), Some(b"pw")).unwrap();

        let a = store.record("a").unwrap().unix_id;
        let b = store.record("b").unwrap().unix_id;
        let group = store.group_summaries().unwrap()[0].unix_id;

        let mut all = vec![a, b, group];
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 3, "every object must hold a distinct Unix ID");
    }

    #[test]
    fn principals_and_groups_share_one_rid_counter() {
        let mut store = Store::provision().expect("must provision");
        let a = store.add(new("a", vec![]), Some(b"pw")).unwrap();
        let group = store.create_group("developers").unwrap();
        let b = store.add(new("b", vec![]), Some(b"pw")).unwrap();
        assert_eq!((a, group, b), (1000, 1001, 1002));
    }

    #[test]
    fn a_unix_id_is_never_reused_after_a_removal() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("keeper", vec![administrators()]), Some(b"pw")).unwrap();
        store.add(new("doomed", vec![]), Some(b"pw")).unwrap();
        let doomed = store.record("doomed").unwrap().unix_id;
        store.remove("doomed").unwrap();
        store.add(new("replacement", vec![]), Some(b"pw")).unwrap();
        assert!(store.record("replacement").unwrap().unix_id > doomed);
    }

    // -----------------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------------

    #[test]
    fn a_local_group_gets_a_sid_in_the_domain() {
        let mut store = Store::provision().expect("must provision");
        let rid = store.create_group("developers").unwrap();
        let domain = store.domain_sid().unwrap().to_string();
        let sid = store.resolve_group("developers").unwrap();
        assert_eq!(sid.to_string(), format!("{domain}-{rid}"));
    }

    #[test]
    fn a_group_resolves_by_well_known_name_local_name_or_sid() {
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();

        assert_eq!(
            store.resolve_group("Administrators").unwrap(),
            administrators()
        );
        assert_eq!(
            store.resolve_group("BUILTIN\\Administrators").unwrap(),
            administrators()
        );
        assert_eq!(
            store.resolve_group("administrators").unwrap(),
            administrators(),
            "names are matched case-insensitively"
        );
        assert_eq!(
            store.resolve_group("S-1-5-32-544").unwrap(),
            administrators()
        );
        assert_eq!(
            store.resolve_group("DEVELOPERS").unwrap(),
            store.resolve_group("developers").unwrap()
        );
    }

    #[test]
    fn an_unknown_group_name_is_refused_rather_than_invented() {
        let store = Store::provision().expect("must provision");
        assert!(matches!(
            store.resolve_group("nonesuch"),
            Err(StoreError::NoSuchGroup(_))
        ));
    }

    #[test]
    fn a_local_group_may_not_shadow_a_well_known_one() {
        // `resolve_group` prefers the well-known spelling, so such a group would
        // be unreachable — created, and impossible to add anyone to.
        let mut store = Store::provision().expect("must provision");
        assert!(matches!(
            store.create_group("Administrators"),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.create_group("administrators"),
            Err(StoreError::Invalid(_))
        ));
    }

    /// The same reservation, from the other side of the shared RID counter.
    /// Principals and groups are one object space here, so a principal called
    /// `Everyone` would be just as unreachable by name as a group would.
    #[test]
    fn a_principal_may_not_shadow_a_well_known_group_either() {
        let mut store = Store::provision().expect("must provision");
        assert!(matches!(
            store.add(new("Everyone", vec![]), Some(b"pw")),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.add(new("authenticated users", vec![]), Some(b"pw")),
            Err(StoreError::Invalid(_))
        ));
    }

    /// Each of these is a separator in something that will one day read a name
    /// back — the realm syntax, a path, `/etc/passwd`, `/etc/group`. Reserved
    /// before any account can be created holding one, because the fix
    /// afterwards is renaming live principals.
    #[test]
    fn a_reserved_character_is_refused_in_a_name() {
        for name in ["jack@local", "PEIOS\\jack", "jack/x", "jack:x", "jack,x"] {
            let mut store = Store::provision().expect("must provision");
            assert!(
                matches!(store.add(new(name, vec![]), Some(b"pw")), Err(StoreError::Invalid(_))),
                "{name} must not be creatable as a principal"
            );
            assert!(
                matches!(store.create_group(name), Err(StoreError::Invalid(_))),
                "{name} must not be creatable as a group"
            );
        }
    }

    /// The record separators. A name carrying one could forge a whole line in a
    /// passwd-format file or in a log.
    #[test]
    fn a_control_character_is_refused_in_a_name() {
        for name in ["jack\nroot", "jack\rroot", "jack\tx", "jack\u{0}x", "jack\u{7f}"] {
            let mut store = Store::provision().expect("must provision");
            assert!(
                matches!(store.add(new(name, vec![]), Some(b"pw")), Err(StoreError::Invalid(_))),
                "{name:?} must not be creatable"
            );
        }
    }

    /// Confusables and normalisation, refused at the door rather than reasoned
    /// about. The second name here renders identically to the first.
    #[test]
    fn a_non_ascii_name_is_refused() {
        let mut store = Store::provision().expect("must provision");
        assert!(matches!(
            store.add(new("jack\u{301}", vec![]), Some(b"pw")),
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.add(new("j\u{430}ck", vec![]), Some(b"pw")),
            Err(StoreError::Invalid(_))
        ));
    }

    /// The reservation must not have swallowed the ordinary case: well-known
    /// groups have interior spaces, so local ones must be allowed them too.
    #[test]
    fn an_interior_space_is_allowed_in_a_name() {
        let mut store = Store::provision().expect("must provision");
        store
            .create_group("Backup Operators")
            .expect("an ordinary group name must still be creatable");
    }

    #[test]
    fn surrounding_whitespace_is_stripped_rather_than_stored() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("  jack  ", vec![]), Some(b"pw")).expect("must add");
        let identity = store
            .authenticate(b"jack", b"pw")
            .expect("the stored name must be the trimmed one");
        assert_eq!(identity.name, "jack");
    }

    #[test]
    fn duplicate_group_names_are_refused() {
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        assert!(matches!(
            store.create_group("DEVELOPERS"),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn a_group_carries_its_name_and_unix_id_into_an_identity() {
        // The reason group objects exist: authd cannot project a supplementary
        // GID from a bare SID.
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        let developers = store.resolve_group("developers").unwrap();
        store
            .add(new("jack", vec![developers.clone(), administrators()]), Some(b"pw"))
            .unwrap();

        let identity = store.authenticate(b"jack", b"pw").unwrap();
        let local = identity
            .groups
            .iter()
            .find(|g| g.sid == developers)
            .expect("the local group must be present");
        assert_eq!(local.name.as_deref(), Some("developers"));
        assert!(local.unix_id.is_some(), "lpsd owns this group's number");

        let builtin = identity
            .groups
            .iter()
            .find(|g| g.sid == administrators())
            .expect("the well-known group must be present");
        assert_eq!(builtin.name.as_deref(), Some("Administrators"));
        assert_eq!(
            builtin.unix_id, None,
            "authd numbers well-known groups; lpsd must not claim to"
        );
    }

    #[test]
    fn a_foreign_sid_is_carried_without_a_name_or_a_number() {
        let mut store = Store::provision().expect("must provision");
        let foreign: Sid = "S-1-5-21-9-9-9-1000".parse().unwrap();
        store.add(new("jack", vec![foreign.clone()]), Some(b"pw")).unwrap();
        let identity = store.authenticate(b"jack", b"pw").unwrap();
        assert_eq!(identity.groups[0].sid, foreign);
        assert_eq!(identity.groups[0].name, None);
        assert_eq!(identity.groups[0].unix_id, None);
    }

    #[test]
    fn a_group_with_members_cannot_be_deleted() {
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        let developers = store.resolve_group("developers").unwrap();
        store.add(new("jack", vec![developers]), Some(b"pw")).unwrap();

        assert!(matches!(
            store.delete_group("developers"),
            Err(StoreError::Invalid(_))
        ));

        store
            .remove_membership("jack", store.resolve_group("developers").unwrap().as_ref())
            .unwrap();
        store.delete_group("developers").expect("now it may go");
    }

    #[test]
    fn a_group_that_is_somebodys_primary_cannot_be_deleted() {
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        let developers = store.resolve_group("developers").unwrap();
        store.add(new("jack", vec![]), Some(b"pw")).unwrap();
        store.set_primary_group("jack", developers).unwrap();

        assert!(
            matches!(store.delete_group("developers"), Err(StoreError::Invalid(_))),
            "deleting it would leave jack projecting a gid that names nothing"
        );
    }

    #[test]
    fn deleting_a_group_that_is_not_there_says_so() {
        let mut store = Store::provision().expect("must provision");
        assert!(matches!(
            store.delete_group("nonesuch"),
            Err(StoreError::NoSuchGroup(_))
        ));
    }

    #[test]
    fn group_summaries_count_members() {
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        let developers = store.resolve_group("developers").unwrap();
        store.add(new("a", vec![developers.clone()]), Some(b"pw")).unwrap();
        store.add(new("b", vec![developers]), Some(b"pw")).unwrap();
        store.add(new("c", vec![]), Some(b"pw")).unwrap();

        let summaries = store.group_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "developers");
        assert_eq!(summaries[0].members, 2);
    }

    // -----------------------------------------------------------------------
    // Profile
    // -----------------------------------------------------------------------

    #[test]
    fn a_principal_gets_a_default_home_shell_and_primary_group() {
        let store = seeded();
        let record = store.record("jack").unwrap();
        assert_eq!(record.home, "/home/jack");
        assert_eq!(record.shell, "/bin/sh");
        assert_eq!(record.display_name, "");
        assert_eq!(record.primary_group.sid, default_primary_group());
        assert_eq!(
            record.primary_group.name.as_deref(),
            Some("Authenticated Users")
        );
    }

    #[test]
    fn the_profile_can_be_chosen_at_creation_and_changed_afterwards() {
        let mut store = Store::provision().expect("must provision");
        store
            .add(
                NewPrincipal {
                    home: Some("/srv/jack".into()),
                    shell: Some("/bin/bash".into()),
                    display_name: Some("Jack Palfrey".into()),
                    ..NewPrincipal::named("jack")
                },
                Some(b"pw"),
            )
            .unwrap();

        let record = store.record("jack").unwrap();
        assert_eq!(record.home, "/srv/jack");
        assert_eq!(record.shell, "/bin/bash");
        assert_eq!(record.display_name, "Jack Palfrey");

        assert!(store.set_home("jack", "/home/jack").unwrap());
        assert!(!store.set_home("jack", "/home/jack").unwrap());
        assert!(store.set_shell("jack", "/bin/sh").unwrap());
        assert!(store.set_display_name("jack", "").unwrap());
        assert_eq!(store.record("jack").unwrap().display_name, "");
    }

    #[test]
    fn a_relative_or_empty_path_is_refused() {
        let mut store = seeded();
        for bad in ["", "   ", "home/jack", "../etc"] {
            assert!(
                matches!(store.set_home("jack", bad), Err(StoreError::Invalid(_))),
                "{bad:?} must be refused as a home directory"
            );
            assert!(matches!(
                store.set_shell("jack", bad),
                Err(StoreError::Invalid(_))
            ));
        }
    }

    #[test]
    fn the_primary_group_need_not_be_a_membership() {
        // authd adds it to the token if it is missing; requiring it here would
        // make the order of two administrative commands matter.
        let mut store = seeded();
        let developers = {
            store.create_group("developers").unwrap();
            store.resolve_group("developers").unwrap()
        };
        assert!(store.set_primary_group("jack", developers.clone()).unwrap());
        assert!(!store.set_primary_group("jack", developers.clone()).unwrap());

        let record = store.record("jack").unwrap();
        assert_eq!(record.primary_group.sid, developers);
        assert!(!record.groups.iter().any(|g| g.sid == developers));
    }

    // -----------------------------------------------------------------------
    // Claims
    // -----------------------------------------------------------------------

    fn claim(name: &str, value: &str) -> Claim {
        Claim {
            name: name.into(),
            flags: claim::FLAG_MANDATORY,
            values: Values::String(vec![value.into()]),
        }
    }

    #[test]
    fn a_claim_can_be_set_replaced_and_removed() {
        let mut store = seeded();
        assert!(store.set_claim("jack", claim("Department", "Engineering")).unwrap());
        assert!(
            !store.set_claim("jack", claim("Department", "Engineering")).unwrap(),
            "setting a claim to what it already is must not force a write"
        );

        assert!(store.set_claim("jack", claim("department", "Platform")).unwrap());
        let claims = store.record("jack").unwrap().claims;
        assert_eq!(claims.len(), 1, "the name matched case-insensitively");
        assert_eq!(claims[0].values, Values::String(vec!["Platform".into()]));

        assert!(store.remove_claim("jack", "DEPARTMENT").unwrap());
        assert!(!store.remove_claim("jack", "Department").unwrap());
        assert!(store.record("jack").unwrap().claims.is_empty());
    }

    #[test]
    fn an_unusable_claim_is_refused_at_the_point_it_is_set() {
        let mut store = seeded();
        assert!(matches!(
            store.set_claim(
                "jack",
                Claim {
                    name: "Bad\0Name".into(),
                    ..claim("x", "y")
                }
            ),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn claims_reach_an_identity() {
        let mut store = seeded();
        store.set_claim("jack", claim("Department", "Engineering")).unwrap();
        let identity = store.authenticate(b"jack", b"password").unwrap();
        assert_eq!(identity.claims.len(), 1);
        assert_eq!(identity.claims[0].name, "Department");
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    #[test]
    fn a_store_survives_a_save_and_load() {
        let fs = FaultyFs::new();
        let store = seeded();
        let domain = store.domain_sid().unwrap().to_string();
        store.save(&fs, path()).expect("must save");

        let loaded = Store::load(&fs, path())
            .expect("must load")
            .expect("must be present");
        assert_eq!(loaded.domain_sid().unwrap().to_string(), domain);
        assert_eq!(loaded.len(), 1);
        assert!(!loaded.needs_rewrite());

        let identity = loaded
            .authenticate(b"jack", b"password")
            .expect("must authenticate");
        assert_eq!(identity.sid.to_string(), format!("{domain}-1000"));
        assert_eq!(
            identity
                .groups
                .iter()
                .map(|g| g.sid.to_string())
                .collect::<Vec<_>>(),
            vec!["S-1-5-32-544"]
        );
    }

    #[test]
    fn everything_a_principal_carries_survives_a_round_trip() {
        let fs = FaultyFs::new();
        let mut store = Store::provision().expect("must provision");
        store.create_group("developers").unwrap();
        let developers = store.resolve_group("developers").unwrap();
        store
            .add(
                NewPrincipal {
                    groups: vec![developers.clone(), administrators()],
                    primary_group: Some(developers.clone()),
                    home: Some("/srv/jack".into()),
                    shell: Some("/bin/bash".into()),
                    display_name: Some("Jack Palfrey".into()),
                    ..NewPrincipal::named("jack")
                },
                Some(b"password"),
            )
            .unwrap();
        store
            .set_claim(
                "jack",
                Claim {
                    name: "Level".into(),
                    flags: claim::FLAG_CASE_SENSITIVE,
                    values: Values::Int64(vec![-3, 7]),
                },
            )
            .unwrap();
        store.set_claim("jack", claim("Department", "Engineering")).unwrap();

        let before = store.record("jack").unwrap();
        store.save(&fs, path()).expect("must save");
        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert_eq!(loaded.record("jack").unwrap(), before);
        assert_eq!(loaded.group_summaries().unwrap(), store.group_summaries().unwrap());
    }

    #[test]
    fn every_claim_value_type_survives_a_round_trip() {
        let fs = FaultyFs::new();
        let mut store = seeded();
        let values = [
            Values::Int64(vec![i64::MIN, 0, i64::MAX]),
            Values::Uint64(vec![0, u64::MAX]),
            Values::Boolean(vec![true, false]),
            Values::String(vec!["a".into(), String::new()]),
            Values::Sid(vec![administrators().as_ref().as_bytes().to_vec()]),
            Values::Octet(vec![vec![0xde, 0xad], Vec::new()]),
        ];
        for (index, value) in values.iter().enumerate() {
            store
                .set_claim(
                    "jack",
                    Claim {
                        name: format!("Claim{index}"),
                        flags: 0,
                        values: value.clone(),
                    },
                )
                .unwrap();
        }

        store.save(&fs, path()).expect("must save");
        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert_eq!(loaded.record("jack").unwrap().claims, store.record("jack").unwrap().claims);
    }

    #[test]
    fn the_sids_are_stable_across_a_reload() {
        // The whole point of persisting the domain: a principal's SID is the
        // same after a restart, so the descriptors naming it still mean what
        // they meant.
        let fs = FaultyFs::new();
        let before = {
            let store = seeded();
            store.save(&fs, path()).expect("must save");
            store
                .authenticate(b"jack", b"password")
                .unwrap()
                .sid
                .to_string()
        };
        let after = Store::load(&fs, path())
            .unwrap()
            .unwrap()
            .authenticate(b"jack", b"password")
            .unwrap()
            .sid
            .to_string();
        assert_eq!(before, after);
    }

    #[test]
    fn the_unix_ids_are_stable_across_a_reload() {
        let fs = FaultyFs::new();
        let store = seeded();
        let before = store.record("jack").unwrap().unix_id;
        store.save(&fs, path()).expect("must save");
        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert_eq!(loaded.record("jack").unwrap().unix_id, before);
    }

    #[test]
    fn an_absent_store_is_not_an_error() {
        let fs = FaultyFs::new();
        assert!(
            Store::load(&fs, path())
                .expect("absence is not failure")
                .is_none(),
            "an unprovisioned machine has no store, and that is a normal state"
        );
    }

    #[test]
    fn a_corrupt_store_is_refused_rather_than_read_as_empty() {
        let fs = FaultyFs::new();
        seeded().save(&fs, path()).expect("must save");

        let mut bytes = fs.read_now(path()).expect("must exist");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs.preload(path(), &bytes);

        assert!(
            matches!(
                Store::load(&fs, path()),
                Err(StoreError::Corrupt(CodecError::BadChecksum))
            ),
            "a corrupt store must be refused, never read as an empty one"
        );
    }

    #[test]
    fn a_truncated_store_is_refused() {
        let fs = FaultyFs::new();
        seeded().save(&fs, path()).expect("must save");
        let bytes = fs.read_now(path()).expect("must exist");
        fs.preload(path(), &bytes[..bytes.len() / 2]);

        assert!(
            matches!(Store::load(&fs, path()), Err(StoreError::Corrupt(_))),
            "half a store is not an empty store"
        );
    }

    #[test]
    fn an_empty_file_is_refused_rather_than_read_as_no_accounts() {
        // The most dangerous corruption to get wrong: a zero-length file is
        // exactly what a crash between rename and fsync can leave, and reading
        // it as "no principals" would silently delete every account.
        let fs = FaultyFs::new();
        fs.preload(path(), b"");
        assert!(matches!(
            Store::load(&fs, path()),
            Err(StoreError::Corrupt(CodecError::Truncated))
        ));
    }

    #[test]
    fn the_store_is_written_with_a_system_only_descriptor() {
        let fs = FaultyFs::new();
        seeded().save(&fs, path()).expect("must save");
        let stamped = fs
            .descriptor_of(path())
            .expect("the store must carry a descriptor");
        assert_eq!(
            stamped,
            store_descriptor().unwrap().as_bytes(),
            "the store must be written with its own descriptor, not an inherited one"
        );
    }

    #[test]
    fn a_failed_save_leaves_the_previous_store_readable() {
        let fs = FaultyFs::new();
        let first = seeded();
        first.save(&fs, path()).expect("must save");

        let mut second = Store::provision().expect("must provision");
        second
            .add(new("someone-else", vec![]), Some(b"pw"))
            .expect("must add");
        fs.fail_next(crate::fs::Op::Sync);
        second
            .save(&fs, path())
            .expect_err("the injected failure must surface");

        let recovered = Store::load(&fs, path())
            .expect("the previous store must still load")
            .expect("must be present");
        assert_eq!(recovered.names().collect::<Vec<_>>(), vec!["jack"]);
    }

    #[test]
    fn a_store_with_two_principals_round_trips() {
        let fs = FaultyFs::new();
        let mut store = Store::provision().expect("must provision");
        store
            .add(new("jack", vec![administrators()]), Some(b"password"))
            .unwrap();
        store.add(new("guest", vec![]), Some(b"guest")).unwrap();
        store.save(&fs, path()).expect("must save");

        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert_eq!(loaded.names().collect::<Vec<_>>(), vec!["jack", "guest"]);
        assert!(loaded.authenticate(b"jack", b"password").is_some());
        assert!(loaded.authenticate(b"guest", b"guest").is_some());
        assert!(loaded.authenticate(b"guest", b"password").is_none());

        let jack = loaded.authenticate(b"jack", b"password").unwrap();
        let guest = loaded.authenticate(b"guest", b"guest").unwrap();
        assert_ne!(jack.sid, guest.sid);
        assert_ne!(jack.unix_id, guest.unix_id);
        assert!(guest.groups.is_empty());
    }

    #[test]
    fn a_store_with_no_principals_round_trips() {
        let fs = FaultyFs::new();
        let store = Store::provision().expect("must provision");
        let domain = store.domain_sid().unwrap().to_string();
        store.save(&fs, path()).expect("must save");

        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert!(loaded.is_empty());
        assert_eq!(
            loaded.domain_sid().unwrap().to_string(),
            domain,
            "an empty store still carries the machine's identity"
        );
    }

    #[test]
    fn duplicate_names_in_a_file_are_refused() {
        // Not reachable through `add`; reachable by editing the file.
        let mut store = seeded();
        let clone = store.principals[0].clone();
        store.principals.push(clone);
        let body = store.encode();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn a_rid_beyond_the_allocator_is_refused() {
        let mut store = seeded();
        store.principals[0].rid = store.next_rid + 1;
        let body = store.encode();
        assert!(
            matches!(
                Store::decode(codec::VERSION, &body),
                Err(StoreError::Invalid(_))
            ),
            "a RID past the allocator would be handed out again"
        );
    }

    #[test]
    fn a_unix_id_defaults_to_the_rid() {
        // One object, one number: the RID reads straight out of the uid rather
        // than needing a mapping table.
        let mut store = Store::provision().expect("must provision");
        let rid = store.add(new("jack", vec![]), Some(b"pw")).unwrap();
        let record = store.record("jack").unwrap();
        assert_eq!(record.rid, rid);
        assert_eq!(record.unix_id, rid);

        let group_rid = store.create_group("developers").unwrap();
        let group = &store.group_summaries().unwrap()[0];
        assert_eq!(group.rid, group_rid);
        assert_eq!(group.unix_id, group_rid);
    }

    /// It is still an attribute rather than a computation, so a store that
    /// carries a different number keeps it — which is what an account imported
    /// from another system needs.
    #[test]
    fn a_stored_unix_id_that_is_not_the_rid_survives_a_round_trip() {
        let fs = FaultyFs::new();
        let mut store = seeded();
        store.principals[0].unix_id = 4242;
        store.save(&fs, path()).expect("must save");

        let loaded = Store::load(&fs, path()).unwrap().unwrap();
        assert_eq!(loaded.record("jack").unwrap().unix_id, 4242);
        assert_eq!(loaded.record("jack").unwrap().rid, 1000);
    }

    #[test]
    fn a_zero_unix_id_is_refused() {
        // Zero projects to root. Nothing in this module can produce it — the
        // RID floor is 1000 — so a file carrying one was edited, and this is
        // the edit that matters most.
        let mut store = seeded();
        store.principals[0].unix_id = 0;
        let body = store.encode();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn two_objects_sharing_a_unix_id_are_refused() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("jack", vec![]), Some(b"pw")).unwrap();
        store.create_group("developers").unwrap();
        store.groups[0].unix_id = store.principals[0].unix_id;
        let body = store.encode();
        assert!(
            matches!(
                Store::decode(codec::VERSION, &body),
                Err(StoreError::Invalid(_))
            ),
            "one number projecting two SIDs breaks the property §12.1 requires"
        );
    }

    #[test]
    fn two_objects_sharing_a_rid_are_refused() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("jack", vec![]), Some(b"pw")).unwrap();
        store.create_group("developers").unwrap();
        store.groups[0].rid = store.principals[0].rid;
        let body = store.encode();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn trailing_data_is_refused() {
        let store = seeded();
        let mut body = store.encode();
        body.push(0);
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn an_absurd_principal_count_is_refused_without_allocating_for_it() {
        let mut w = Writer::new();
        w.u32(1);
        w.u32(2);
        w.u32(3);
        w.u32(1000);
        w.u32(0); // no groups
        w.u32(u32::MAX);
        let body = w.finish();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn an_absurd_group_count_is_refused_without_allocating_for_it() {
        let mut w = Writer::new();
        w.u32(1);
        w.u32(2);
        w.u32(3);
        w.u32(1000);
        w.u32(u32::MAX);
        let body = w.finish();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn a_group_that_is_not_a_sid_is_refused() {
        let mut store = seeded();
        let mut w = Writer::new();
        w.u32(store.domain[0]);
        w.u32(store.domain[1]);
        w.u32(store.domain[2]);
        w.u32(store.next_rid);
        w.u32(0); // no group objects
        w.u32(1);
        w.u32(1000); // rid
        w.u32(1000); // unix id
        w.u8(Principal::FLAG_ENABLED);
        w.str("jack");
        let mut inner = Writer::new();
        store
            .principals
            .remove(0)
            .verifier
            .expect("the fixture principal has a password")
            .encode(&mut inner);
        w.bytes(&inner.finish());
        w.u32(1);
        w.bytes(b"not a sid");
        let body = w.finish();
        assert!(matches!(
            Store::decode(codec::VERSION, &body),
            Err(StoreError::Invalid(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Upgrading a version 1 store
    // -----------------------------------------------------------------------

    /// A version 1 body: no Unix ID counter, no groups, and no profile or
    /// claims on a principal. Written by hand because no code produces it any
    /// more, which is exactly why the upgrade path needs a test.
    fn version_1_body(domain: [u32; 3], next_rid: u32, principals: &[(u32, &str, Verifier)]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(domain[0]);
        w.u32(domain[1]);
        w.u32(domain[2]);
        w.u32(next_rid);
        w.u32(principals.len() as u32);
        for (rid, name, verifier) in principals {
            w.u32(*rid);
            w.u8(Principal::FLAG_ENABLED);
            w.str(name);
            let mut inner = Writer::new();
            verifier.encode(&mut inner);
            w.bytes(&inner.finish());
            w.u32(1);
            w.bytes(Sid::well_known(WellKnown::Administrators).as_ref().as_bytes());
        }
        w.finish()
    }

    #[test]
    fn a_version_1_store_is_upgraded_rather_than_refused() {
        let verifier = Verifier::create(b"password").unwrap();
        let body = version_1_body([1, 2, 3], 1001, &[(1000, "jack", verifier)]);

        let store = Store::decode(1, &body).expect("an older store must be readable");
        assert!(
            store.needs_rewrite(),
            "the caller has to know to write it back in the new format"
        );

        let record = store.record("jack").unwrap();
        assert_eq!(record.rid, 1000);
        assert_eq!(record.unix_id, 1000, "numbered on the way in, from the RID");
        assert_eq!(record.home, "/home/jack");
        assert_eq!(record.shell, "/bin/sh");
        assert_eq!(record.primary_group.sid, default_primary_group());
        assert!(record.claims.is_empty());

        // The credential still works, which is the whole point.
        assert!(store.authenticate(b"jack", b"password").is_some());
    }

    #[test]
    fn an_upgraded_store_numbers_every_principal_distinctly() {
        let body = version_1_body(
            [1, 2, 3],
            1002,
            &[
                (1000, "jack", Verifier::create(b"a").unwrap()),
                (1001, "guest", Verifier::create(b"b").unwrap()),
            ],
        );
        let store = Store::decode(1, &body).expect("must upgrade");
        assert_eq!(store.record("jack").unwrap().unix_id, 1000);
        assert_eq!(store.record("guest").unwrap().unix_id, 1001);
    }

    /// Version 2 allocated Unix IDs from a counter of its own — 1, 2, 3… — so
    /// upgrading renumbers them onto the RID rather than leaving one store
    /// carrying two conventions.
    ///
    /// That changes a principal's uid, which on an ordinary Unix would orphan
    /// every file they own. It is safe here for a reason particular to this
    /// system: under KACS a uid decides nothing. Access is decided by the SID,
    /// and the SID does not move.
    #[test]
    fn a_version_2_store_is_renumbered_onto_the_rid() {
        let mut w = Writer::new();
        w.u32(1);
        w.u32(2);
        w.u32(3);
        w.u32(1002); // next_rid
        w.u32(3); // version 2's Unix ID counter
        w.u32(1); // one group
        w.u32(1001); // its rid
        w.u32(2); // its separately-allocated unix id
        w.str("developers");
        w.u32(1); // one principal
        w.u32(1000); // rid
        w.u32(1); // its separately-allocated unix id
        w.u8(Principal::FLAG_ENABLED);
        w.str("jack");
        let mut inner = Writer::new();
        Verifier::create(b"password").unwrap().encode(&mut inner);
        w.bytes(&inner.finish());
        w.u32(0); // no memberships
        w.bytes(default_primary_group().as_ref().as_bytes());
        w.str("/home/jack");
        w.str("/bin/sh");
        w.str("");
        w.u32(0); // no claims
        let body = w.finish();

        let store = Store::decode(2, &body).expect("a version 2 store must be readable");
        assert!(store.needs_rewrite());
        assert_eq!(store.record("jack").unwrap().unix_id, 1000);
        assert_eq!(store.group_summaries().unwrap()[0].unix_id, 1001);
        assert!(store.authenticate(b"jack", b"password").is_some());
    }

    #[test]
    fn an_upgraded_store_writes_back_in_the_current_format() {
        let fs = FaultyFs::new();
        let body = version_1_body([1, 2, 3], 1001, &[(1000, "jack", Verifier::create(b"pw").unwrap())]);
        let store = Store::decode(1, &body).expect("must upgrade");
        store.save(&fs, path()).expect("must save");

        let reloaded = Store::load(&fs, path()).unwrap().unwrap();
        assert!(
            !reloaded.needs_rewrite(),
            "once written back it is a current store, not an upgraded one"
        );
        assert_eq!(reloaded.record("jack").unwrap(), store.record("jack").unwrap());
    }

    // -----------------------------------------------------------------------
    // Mutation
    // -----------------------------------------------------------------------

    #[test]
    fn a_removed_principal_is_gone() {
        let mut store = seeded();
        store.add(new("guest", vec![]), Some(b"pw")).unwrap();
        store.remove("guest").expect("must remove");
        assert_eq!(store.names().collect::<Vec<_>>(), vec!["jack"]);
        assert!(store.authenticate(b"guest", b"pw").is_none());
    }

    #[test]
    fn removing_someone_who_is_not_there_says_so() {
        let mut store = seeded();
        assert!(matches!(
            store.remove("nobody"),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn a_removed_principals_rid_is_not_handed_out_again() {
        // The property that makes `remove` safe to offer at all: a reissued RID
        // would give a new person the SID of an old one, silently inheriting
        // every access the descriptors on this machine still grant them.
        let mut store = Store::provision().expect("must provision");
        store
            .add(new("first", vec![administrators()]), Some(b"pw"))
            .unwrap();
        let doomed = store.add(new("doomed", vec![]), Some(b"pw")).unwrap();
        store.remove("doomed").expect("must remove");
        let next = store.add(new("replacement", vec![]), Some(b"pw")).unwrap();
        assert!(next > doomed, "{next} must not reuse {doomed}");
    }

    #[test]
    fn disabling_reports_whether_anything_changed() {
        let mut store = seeded();
        store.add(new("guest", vec![]), Some(b"pw")).unwrap();
        assert!(store.set_enabled("guest", false).expect("must set"));
        assert!(
            !store.set_enabled("guest", false).expect("must set"),
            "disabling a disabled principal changes nothing, and must not force a write"
        );
        assert!(store.set_enabled("guest", true).expect("must set"));
    }

    #[test]
    fn a_disabled_principal_cannot_authenticate_and_an_enabled_one_can_again() {
        let mut store = seeded();
        store.add(new("guest", vec![]), Some(b"pw")).unwrap();
        store.set_enabled("guest", false).unwrap();
        assert!(store.authenticate(b"guest", b"pw").is_none());
        store.set_enabled("guest", true).unwrap();
        assert!(store.authenticate(b"guest", b"pw").is_some());
    }

    #[test]
    fn a_new_password_replaces_the_old_one() {
        let mut store = seeded();
        store.set_password("jack", b"different").expect("must set");
        assert!(store.authenticate(b"jack", b"password").is_none());
        assert!(store.authenticate(b"jack", b"different").is_some());
    }

    #[test]
    fn setting_a_password_does_not_disturb_anything_else() {
        let mut store = seeded();
        let before = store.record("jack").expect("must read");
        store.set_password("jack", b"different").expect("must set");
        let after = store.record("jack").expect("must read");
        assert_eq!(before, after);
    }

    #[test]
    fn memberships_can_be_granted_and_revoked() {
        let mut store = Store::provision().expect("must provision");
        store.add(new("jack", vec![]), Some(b"pw")).unwrap();

        assert!(store.add_membership("jack", administrators()).expect("must add"));
        assert!(
            !store.add_membership("jack", administrators()).expect("must add"),
            "granting a membership twice changes nothing"
        );
        assert_eq!(store.record("jack").unwrap().groups.len(), 1);

        // Now the only administrator, so revoking is refused — add a second one
        // first. That is the guard doing its job, not an accident of ordering.
        store
            .add(new("other", vec![administrators()]), Some(b"pw"))
            .unwrap();
        assert!(store
            .remove_membership("jack", administrators().as_ref())
            .expect("must remove"));
        assert!(store.record("jack").unwrap().groups.is_empty());
    }

    #[test]
    fn revoking_a_membership_nobody_has_changes_nothing() {
        let mut store = seeded();
        let everyone: Sid = "S-1-1-0".parse().unwrap();
        assert!(!store
            .remove_membership("jack", everyone.as_ref())
            .expect("must not fail"));
    }

    #[test]
    fn mutating_an_absent_principal_is_not_found_rather_than_a_silent_no_op() {
        let mut store = seeded();
        assert!(matches!(
            store.set_enabled("nobody", false),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_password("nobody", b"pw"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.add_membership("nobody", administrators()),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.remove_membership("nobody", administrators().as_ref()),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_home("nobody", "/home/nobody"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_shell("nobody", "/bin/sh"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_display_name("nobody", "Nobody"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_primary_group("nobody", administrators()),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.set_claim("nobody", claim("Department", "Engineering")),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.remove_claim("nobody", "Department"),
            Err(StoreError::NotFound(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Not locking everyone out
    // -----------------------------------------------------------------------
    //
    // There is no offline repair: `lps` reaches the store only through lpsd,
    // and lpsd only authenticates. A machine with no enabled administrator has
    // no way back short of editing the disk from another system, so every
    // operation that could produce one refuses.

    #[test]
    fn the_last_administrator_cannot_be_removed() {
        let mut store = seeded();
        assert!(matches!(store.remove("jack"), Err(StoreError::Invalid(_))));
        assert_eq!(store.len(), 1, "the refusal must leave the store untouched");
    }

    #[test]
    fn the_last_administrator_cannot_be_disabled() {
        let mut store = seeded();
        assert!(matches!(
            store.set_enabled("jack", false),
            Err(StoreError::Invalid(_))
        ));
        assert!(
            store.authenticate(b"jack", b"password").is_some(),
            "the refusal must leave them able to log on"
        );
    }

    #[test]
    fn the_last_administrator_cannot_be_de_administered() {
        let mut store = seeded();
        assert!(matches!(
            store.remove_membership("jack", administrators().as_ref()),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(store.record("jack").unwrap().groups.len(), 1);
    }

    #[test]
    fn a_second_administrator_makes_the_first_removable() {
        let mut store = seeded();
        store
            .add(new("root", vec![administrators()]), Some(b"pw"))
            .unwrap();
        store
            .remove("jack")
            .expect("with two administrators, either may go");
        assert_eq!(store.names().collect::<Vec<_>>(), vec!["root"]);
    }

    #[test]
    fn a_disabled_administrator_does_not_count_as_a_way_back_in() {
        // The subtle case: two administrators, but one is disabled, so removing
        // the other really would lock the machine.
        let mut store = seeded();
        store
            .add(new("standby", vec![administrators()]), Some(b"pw"))
            .unwrap();
        store.set_enabled("standby", false).unwrap();
        assert!(
            matches!(store.remove("jack"), Err(StoreError::Invalid(_))),
            "a disabled administrator cannot let anyone back in"
        );
    }

    #[test]
    fn an_ordinary_principal_does_not_count_as_a_way_back_in() {
        let mut store = seeded();
        store.add(new("guest", vec![]), Some(b"pw")).unwrap();
        assert!(matches!(store.remove("jack"), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn the_guard_does_not_block_an_ordinary_principal() {
        let mut store = seeded();
        store.add(new("guest", vec![]), Some(b"pw")).unwrap();
        store
            .remove("guest")
            .expect("a non-administrator is freely removable");
    }
}
