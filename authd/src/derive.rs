//! Turning "this principal authenticated, this way, from here" into a token.
//!
//! This is the part of authd the kernel cannot do for us. KACS validates a
//! token's *structure* and then trusts it: it does not decide integrity levels,
//! it does not choose privilege sets, and — the one worth dwelling on — it does
//! not add the `S-1-5-4` / `S-1-5-2` / `S-1-5-6` group SIDs that ACLs across
//! the whole system are written against. Those come from here.
//!
//! So every semantic claim a running Peios system makes about identity
//! originates in this module. It is small, and it should stay small enough to
//! read in one sitting.
//!
//! # Assert versus derive
//!
//! A principal source says *who* someone is: the user SID, the memberships, the
//! POSIX numbers, the primary group, the claims. Everything else on the token is
//! derived here, from the logon type and from local policy.
//!
//! The line is not where it first appears. `Everyone`, `AuthenticatedUsers`,
//! `Local` and the logon-type SID are all added below and none of them come from
//! a source, because they are properties of *how* this logon happened rather
//! than of who the principal is — a source could not assert them meaningfully
//! even if the protocol let it. Group *attributes* are on the same side of the
//! line: whether a membership is enabled, owner-marked or deny-only is a
//! decision about building a token, so PSI carries SIDs and numbers and no
//! attributes at all.
//!
//! # Where the last two fields come from
//!
//! Privileges and the integrity level are **local policy** — a statement about
//! how much this machine trusts a principal, keyed on the SIDs it ends up
//! carrying — and neither will ever come from a source. Both are read per logon
//! from `Machine\Generic\Authn\Policy`, alongside the owner and the default
//! DACL; see [`crate::policy::principal`].

use peios::security::{GroupAttributes, Sid, SidRef};
use peios::token::{
    Claim, ClaimAttr, ClaimValues, ImpersonationLevel, LogonType as KacsLogonType, MandatoryPolicy,
    Session, SessionId, Token, TokenBuilder, TokenType,
};

use libauthd::wire::LogonType;

use crate::log;
use crate::policy;
use crate::unix_id::Projection;

/// The `source` name stamped into every token this authority mints, so
/// provenance is answerable from the token alone. Eight bytes at most.
///
/// Distinct from the session's auth-package name, which is the *principal
/// source* that authenticated the logon. The split is worth keeping: the token
/// records who minted it, the session records who vouched for it.
const SOURCE_NAME: &str = "authd";

/// What a successful logon produced.
pub struct Grant {
    pub session: SessionId,
    pub token: Token,
}

/// Map PGSS Logon's logon type onto the KACS one.
///
/// They are deliberately separate types. PGSS Logon is a standard that outlives
/// any one kernel; KACS is this kernel. That they currently agree value-for-value
/// is a convenience, not a contract, and collapsing them would bake the kernel's
/// numbering into the protocol.
fn kacs_logon_type(logon_type: LogonType) -> KacsLogonType {
    match logon_type {
        LogonType::Interactive => KacsLogonType::Interactive,
        LogonType::Network => KacsLogonType::Network,
        LogonType::Batch => KacsLogonType::Batch,
        LogonType::Service => KacsLogonType::Service,
        LogonType::NetworkCleartext => KacsLogonType::NetworkCleartext,
        LogonType::NewCredentials => KacsLogonType::NewCredentials,
    }
}

/// The well-known group SID a logon type confers, if any.
///
/// This is the derivation rule that makes `logon_type` load-bearing rather than
/// merely descriptive: AccessCheck never reads the logon type, so an ACE that
/// wants to distinguish console users from network users matches on the SID
/// this function returns. Getting it wrong silently changes who can reach what.
///
/// - `NetworkCleartext` confers the same SID as `Network`. The type exists to
///   record that the credential crossed the wire in the clear, which is an
///   audit distinction, not an access-control one.
/// - `NewCredentials` confers nothing: the local identity is deliberately
///   unchanged, and only outbound credentials differ.
fn logon_type_sid(logon_type: LogonType) -> Option<Sid> {
    let sub_authority = match logon_type {
        LogonType::Network | LogonType::NetworkCleartext => 2,
        LogonType::Batch => 3,
        LogonType::Interactive => 4,
        LogonType::Service => 6,
        LogonType::NewCredentials => return None,
    };
    // NT Authority (5), one sub-authority.
    Sid::build(5, &[sub_authority]).ok()
}

/// A SID's index in the token's SID array.
///
/// The convention is the wire format's: **0 is the user SID**, and 1..N is the
/// Nth group. `groups` already carries the user SID at position 0 — it is added
/// as a group as well as being the user field — so a group at `groups[i]` is
/// index `i + 1`, and index 0 and index 1 both name the principal.
///
/// `None` when the SID is not on the token at all, which every caller has to
/// handle rather than defaulting silently: KACS refuses a token whose index
/// points past its array, so a wrong answer here fails the whole logon.
fn index_of(groups: &[(Sid, u32)], sid: &SidRef) -> Option<u32> {
    groups
        .iter()
        .position(|(group, _)| group.as_ref().as_bytes() == sid.as_bytes())
        .map(|at| at as u32 + 1)
}

/// Append a group unless it is already present.
///
/// The first mention wins, which matters because the principal's own SID is
/// added first and carries `OWNER`: a source redundantly asserting the user as
/// a group must not silently strip that attribute back off.
fn add_unique(groups: &mut Vec<(Sid, u32)>, sid: Sid, attributes: u32) {
    if !groups.iter().any(|(existing, _)| *existing == sid) {
        groups.push((sid, attributes));
    }
}

/// Whether a SID is a logon SID (`S-1-5-5-X-Y`).
///
/// No principal source is authoritative for one: logon SIDs are minted by the
/// kernel, per session, at the moment a session is created. A source could not
/// know this session's — it does not exist when the source answers — so a
/// source asserting one is either buggy or reaching for a *different* session's
/// SID, which would forge membership of someone else's logon for any ACE keyed
/// on it.
///
/// Tested on the binary form: revision, count, then a six-byte big-endian
/// authority, then little-endian sub-authorities. NT Authority (5) with a first
/// sub-authority of 5 is the logon-SID namespace, whatever follows.
pub(crate) fn is_logon_sid(sid: &SidRef) -> bool {
    let bytes = sid.as_bytes();
    bytes.len() >= 12
        && bytes[2..8] == [0, 0, 0, 0, 0, 5]
        && bytes[8..12] == 5u32.to_le_bytes()
}

/// Everything a mint needs. A struct rather than seven positional arguments,
/// several of which are SIDs and would otherwise be interchangeable at a call
/// site by mistake.
/// Every SID the token will carry, with its attributes, in the order the
/// builder will see them.
///
/// Split out of [`mint`] because **local policy has to be evaluated against
/// this exact set** — including the SIDs derived here rather than asserted.
/// Evaluating against only the asserted memberships would mean `Everyone`'s
/// policy record never applied, and would silently remove the ability to write
/// policy against *how* a logon happened rather than who it was.
///
/// `asserted` are the memberships the source claimed. They are believed — a
/// source is authoritative for its own principals, and that is the entire point
/// of having one — but they are *filtered*, not pasted in:
///
/// - A logon SID is dropped (see [`is_logon_sid`]). The kernel adds the correct
///   one itself and refuses a token that already carries it, so passing one
///   through would fail every logon behind a buggy source.
/// - Duplicates are dropped, including against the derived set. A source
///   asserting `Everyone` is not wrong, merely redundant.
pub fn token_groups(
    user: &SidRef,
    asserted: &[&SidRef],
    logon_type: LogonType,
) -> Vec<(Sid, u32)> {
    let enabled = (GroupAttributes::MANDATORY
        | GroupAttributes::ENABLED_BY_DEFAULT
        | GroupAttributes::ENABLED)
        .bits();

    // OWNER marks the SID that becomes the default owner of objects this token
    // creates. It belongs on the principal: a file jack creates should be owned
    // by jack.
    let mut groups: Vec<(Sid, u32)> =
        vec![(user.to_sid(), enabled | GroupAttributes::OWNER.bits())];

    // Asserted: who the source says they are.
    for asserted in asserted {
        if is_logon_sid(asserted) {
            log::error(format_args!(
                "dropping asserted logon SID {asserted}: logon SIDs are the kernel's to mint"
            ));
            continue;
        }
        add_unique(&mut groups, asserted.to_sid(), enabled);
    }

    // Derived: how this logon happened, rather than who they are. A source
    // could not assert these meaningfully even if the protocol let it.
    add_unique(
        &mut groups,
        Sid::well_known(peios::security::WellKnown::Everyone),
        enabled,
    );
    add_unique(
        &mut groups,
        Sid::well_known(peios::security::WellKnown::AuthenticatedUsers),
        enabled,
    );
    add_unique(
        &mut groups,
        Sid::well_known(peios::security::WellKnown::Local),
        enabled,
    );

    // The logon-type SID. This is the derivation that matters most here.
    if let Some(sid) = logon_type_sid(logon_type) {
        add_unique(&mut groups, sid, enabled);
    }

    groups
}

/// How strong the evidence behind a logon is.
///
/// This fixes the impersonation level of the token, and through the ratchet the
/// ceiling on everything derived from it. The rule is that **the level tracks
/// the strength of the evidence**, rather than every logon starting at the top:
///
/// - A credential a principal source verified is evidence another machine could
///   in principle check too, so the token may be delegated.
/// - A local process's attestation is evidence only here. peinit vouching for a
///   service it is launching says nothing a second machine has any reason to
///   believe, so the token must not leave this one.
///
/// Stated as a rule rather than a carve-out for services, it survives the
/// arrival of a domain: a domain-issued service credential would be
/// independently verifiable and would sit at [`Verified`](Self::Verified),
/// and the reasoning already says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// A credential, verified by a principal source.
    Verified,
    /// A trusted local process's word, with no credential behind it.
    Attested,
}

impl Evidence {
    /// The impersonation level this evidence supports.
    fn impersonation_level(self) -> ImpersonationLevel {
        match self {
            Self::Verified => ImpersonationLevel::Delegation,
            Self::Attested => ImpersonationLevel::Impersonation,
        }
    }
}

pub struct Minting<'a> {
    pub user: &'a SidRef,
    /// Every SID the token will carry, from [`token_groups`].
    pub groups: &'a [(Sid, u32)],
    /// Which group projects to the POSIX gid and becomes the default group of
    /// objects this token creates.
    pub primary_group: &'a SidRef,
    /// The POSIX numbers, computed by [`crate::unix_id`].
    pub projection: &'a Projection,
    /// The principal's claims, already converted by [`kacs_claims`].
    pub claims: &'a [Claim],
    pub logon_type: LogonType,
    pub auth_package: &'a str,
    /// What local policy decided this principal gets. Never from a source.
    pub policy: policy::Outcome,
    /// What satisfied the authority that this logon should happen, which sets
    /// the token's impersonation level. See [`Evidence`].
    pub evidence: Evidence,
}

/// Convert a source's claims into the form the kernel takes.
///
/// `None` if any of them cannot be carried — which currently means only a claim
/// value that is not a structurally valid SID. Refusing the whole set rather
/// than dropping the offender is deliberate, and matches how a malformed group
/// SID is handled: a claim is an *input to access decisions*, so silently losing
/// one signs somebody in against a different policy than the one the source
/// stated, with nothing anywhere to point at.
///
/// # The two flags that do not survive
///
/// §3.9 defines five claim flags; KACS carries three on a token. `MANDATORY`
/// governs whether `kacs_set_sd` will let an unprivileged caller remove the
/// attribute, and `NON_INHERITABLE` governs SD inheritance — both are about a
/// claim living in a *security descriptor*, and neither has any meaning for one
/// living on a token. Dropping them here is the correct mapping rather than a
/// loss, but it is stated because the alternative reading is that it is a bug.
pub fn kacs_claims(claims: &[libauthd::claim::Claim]) -> Option<Vec<Claim>> {
    claims.iter().map(kacs_claim).collect()
}

fn kacs_claim(claim: &libauthd::claim::Claim) -> Option<Claim> {
    use libauthd::claim::Values;

    let values = match &claim.values {
        Values::Int64(v) => ClaimValues::Int64(v.clone()),
        Values::Uint64(v) => ClaimValues::Uint64(v.clone()),
        Values::Boolean(v) => ClaimValues::Boolean(v.clone()),
        Values::String(v) => ClaimValues::String(v.clone()),
        Values::Octet(v) => ClaimValues::Octet(v.clone()),
        // The only fallible arm: libauthd carries SIDs as opaque bytes, since
        // it has no dependency on the security library, so this is where they
        // are first held to being SIDs at all.
        Values::Sid(v) => ClaimValues::Sid(
            v.iter()
                .map(|bytes| SidRef::from_bytes(bytes).map(SidRef::to_sid))
                .collect::<Option<Vec<_>>>()?,
        ),
    };

    Some(Claim {
        name: claim.name.clone(),
        flags: ClaimAttr::from_bits_truncate(claim.flags),
        values,
    })
}

/// Create the logon session and mint the token for it.
///
/// `groups` are the memberships the principal source claimed. They are
/// believed — a source is authoritative for its own principals, and that is the
/// entire point of having one — but they are *filtered*, not pasted in:
///
/// - A logon SID is dropped (see [`is_logon_sid`]). The kernel adds the correct
///   one itself and refuses a token that already carries it, so passing one
///   through would fail every logon behind a buggy source.
/// - Duplicates are dropped, including against the derived set. A source
///   asserting `Everyone` is not wrong, merely redundant.
///
/// `auth_package` is the name of the principal source that authenticated this
/// logon; it lands on the session, where `logonse` and every audit record can
/// answer "which authority vouched for this?".
///
/// Ordering matters and is not arbitrary: the session is created first so the
/// token can reference it. If the mint then fails the session is left with no
/// tokens, which the kernel reaps after a grace period — that grace exists
/// precisely because this two-step is unavoidable.
pub fn mint(minting: Minting<'_>) -> peios::Result<Grant> {
    let Minting {
        user,
        groups,
        primary_group,
        projection,
        claims,
        logon_type,
        auth_package,
        policy,
        evidence,
    } = minting;

    let session = Session::create(kacs_logon_type(logon_type), auth_package, user)?;

    // Which entry the primary group is.
    //
    // Falling back to 0 — the user SID — rather than failing is deliberate.
    // KACS requires the primary group to be the user SID or a group on the
    // token, so an index that is not there would be refused outright, taking
    // the whole logon with it. The caller ensures the primary group is in
    // `asserted_groups`; this is what happens if that ever stops being true,
    // and a principal whose primary group is themselves is odd but harmless.
    let primary_group_index = index_of(groups, primary_group).unwrap_or(0);

    // Which SID owns the objects this token creates. Policy names a principal;
    // the token wants an index into `[user_sid, groups...]`, which only authd
    // can compute and which means something different on every logon.
    //
    // Falling back to the user is right for every failure here: a policy naming
    // a principal this token does not carry is a misconfiguration, and "owned by
    // their creator" is both the ordinary case and always valid.
    let owner_index = match &policy.owner {
        None => 0,
        Some(owner) => match index_of(groups, owner.as_ref()) {
            Some(index) => index,
            None => {
                log::warn(format_args!(
                    "policy names {owner} as the owner for {user}, who does not carry \
                     that SID; objects will be owned by their creator"
                ));
                0
            }
        },
    };

    let mut builder = TokenBuilder::new();
    builder.user(user);
    for (position, (sid, attributes)) in groups.iter().enumerate() {
        // KACS refuses a token outright (-EINVAL) whose owner index names a
        // group without SE_GROUP_OWNER, so marking it is not decoration — it is
        // the difference between this policy working and every logon for the
        // principal failing. The user SID is already marked in `token_groups`.
        let attributes = if owner_index as usize == position + 1 {
            attributes | GroupAttributes::OWNER.bits()
        } else {
            *attributes
        };
        builder.add_group(sid.as_ref(), attributes);
    }
    builder.owner_index(owner_index);

    // The DACL an object created by this token gets when nothing else supplies
    // one. Left unset, the kernel applies its own default; policy overrides it
    // rather than the other way round, so an unconfigured machine keeps
    // whatever the kernel considers safe.
    if let Some(dacl) = &policy.default_dacl {
        builder.default_dacl(dacl);
    }

    // Claims are fixed at creation, like every other identity field: a token
    // carries the claims its principal held at the moment of the logon, and a
    // claim set afterwards reaches them at their next one.
    for claim in claims {
        builder.add_user_claim(claim);
    }

    builder
        .primary_group_index(primary_group_index)
        // The impersonation level is a ratchet on every token: nothing captured
        // from, conveyed by, or duplicated out of this token can act above it.
        // A client may lower it further per connection with
        // KACS_SO_IMPERSONATION_LEVEL. (Kernel TRM §3.5.1)
        //
        // Where it *starts* is set by how the authority was satisfied, not by
        // what was asked for -- see `Evidence`. A credentialled logon starts at
        // the top; an attested one starts a rung below, so nothing derived from
        // it can be forwarded off this machine on the strength of a local
        // process's word.
        .token_type(TokenType::Primary, evidence.impersonation_level())
        // Both from local policy, keyed on the SIDs this token ends up
        // carrying. A principal source has no way to influence either and
        // should not: how much this machine trusts someone is not a fact about
        // them that a directory could know.
        .integrity(policy.integrity)
        // Without NO_WRITE_UP the integrity level is decorative — `apply_mic`
        // returns with no enforcement at all unless the token carries this bit,
        // so a token would hold a level that nothing checked. Setting the level
        // and not setting this was the state every token authd minted before
        // M6.
        .mandatory_policy(MandatoryPolicy::NO_WRITE_UP)
        // Enabled as well as present: a granted privilege that a caller had to
        // enable before it worked would be a grant in name only.
        .privileges(policy.privileges, policy.privileges)
        // Computed once, here, and carried on the token: KACS must not resolve
        // a SID to a number at runtime (PSD-004 §12.1), so what a Linux program
        // sees from `getuid` is decided at this line and nowhere else.
        .projected_ids(projection.uid, projection.gid)
        .supplementary_gids(&projection.supplementary)
        .session(session)
        .source(SOURCE_NAME, 0);

    match builder.create() {
        Ok(token) => Ok(Grant { session, token }),
        Err(error) => {
            // Roll the session back rather than leaving a stranded one behind.
            // It has no tokens, so this is the one destroy the kernel permits.
            let _ = Session::destroy_empty(session);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_types_confer_the_documented_sids() {
        let sid_of = |t| logon_type_sid(t).map(|s| s.to_string());
        assert_eq!(sid_of(LogonType::Interactive).as_deref(), Some("S-1-5-4"));
        assert_eq!(sid_of(LogonType::Network).as_deref(), Some("S-1-5-2"));
        assert_eq!(sid_of(LogonType::Batch).as_deref(), Some("S-1-5-3"));
        assert_eq!(sid_of(LogonType::Service).as_deref(), Some("S-1-5-6"));
    }

    #[test]
    fn cleartext_network_is_indistinguishable_for_access_control() {
        // The distinction is recorded on the session for audit; it must not
        // change what the token can reach.
        assert_eq!(
            logon_type_sid(LogonType::NetworkCleartext).map(|s| s.to_string()),
            logon_type_sid(LogonType::Network).map(|s| s.to_string())
        );
    }

    #[test]
    fn every_group_stapled_onto_a_token_is_numbered() {
        // The contract PEI-206 found broken from the other end. `token_groups`
        // adds these to every token regardless of what a source said, so each
        // needs a number in `well_known` -- otherwise `getgroups` reports a
        // membership short and `id`/`groups` under-report every principal on
        // the machine.
        //
        // The logon-type SID is excluded deliberately and tested for below:
        // it says how the logon happened rather than who the principal is.
        let user: Sid = "S-1-5-21-1-2-3-1000".parse().expect("a well-formed SID");
        let groups = token_groups(user.as_ref(), &[], LogonType::Interactive);

        for text in ["S-1-1-0", "S-1-5-11", "S-1-2-0"] {
            let wanted: Sid = text.parse().expect("a well-formed SID");
            assert!(
                groups
                    .iter()
                    .any(|(sid, _)| sid.as_ref().as_bytes() == wanted.as_ref().as_bytes()),
                "{text} is no longer stapled onto every token"
            );
            assert!(
                crate::unix_id::built_in(wanted.as_ref()).is_some(),
                "{text} is stapled onto every token but carries no number"
            );
        }

        let interactive: Sid = "S-1-5-4".parse().expect("a well-formed SID");
        assert!(
            crate::unix_id::built_in(interactive.as_ref()).is_none(),
            "a logon-type SID must stay unnumbered"
        );
    }

    #[test]
    fn new_credentials_confers_no_group() {
        assert!(logon_type_sid(LogonType::NewCredentials).is_none());
    }

    #[test]
    fn a_logon_sid_is_recognised() {
        // Whatever the session id, and whatever its length.
        for session in [0u64, 1, 1000, u64::MAX] {
            let sid = Sid::logon(session);
            assert!(
                is_logon_sid(sid.as_ref()),
                "{sid} must be recognised as a logon SID"
            );
        }
        assert!(is_logon_sid(Sid::build(5, &[5]).unwrap().as_ref()));
        assert!(is_logon_sid(Sid::build(5, &[5, 7, 7, 7]).unwrap().as_ref()));
    }

    #[test]
    fn an_ordinary_sid_is_not_a_logon_sid() {
        let not_logon = [
            Sid::well_known(peios::security::WellKnown::System),
            Sid::well_known(peios::security::WellKnown::Everyone),
            Sid::well_known(peios::security::WellKnown::Administrators),
            Sid::well_known(peios::security::WellKnown::AuthenticatedUsers),
            "S-1-5-21-0-0-0-1000".parse().unwrap(),
            // S-1-5-4 (Interactive) — NT Authority, but not sub-authority 5.
            Sid::build(5, &[4]).unwrap(),
            // Sub-authority 5 under a *different* authority is not a logon SID.
            Sid::build(1, &[5, 1, 2]).unwrap(),
        ];
        for sid in not_logon {
            assert!(!is_logon_sid(sid.as_ref()), "{sid} is not a logon SID");
        }
    }

    fn wire_claim(values: libauthd::claim::Values) -> libauthd::claim::Claim {
        libauthd::claim::Claim {
            name: "Department".into(),
            flags: 0,
            values,
        }
    }

    #[test]
    fn every_claim_value_type_converts() {
        use libauthd::claim::Values;

        let converted = |values| kacs_claims(&[wire_claim(values)]).map(|mut c| c.remove(0).values);

        assert_eq!(
            converted(Values::Int64(vec![-3, 7])),
            Some(ClaimValues::Int64(vec![-3, 7]))
        );
        assert_eq!(
            converted(Values::Uint64(vec![u64::MAX])),
            Some(ClaimValues::Uint64(vec![u64::MAX]))
        );
        assert_eq!(
            converted(Values::Boolean(vec![true, false])),
            Some(ClaimValues::Boolean(vec![true, false]))
        );
        assert_eq!(
            converted(Values::String(vec!["Engineering".into()])),
            Some(ClaimValues::String(vec!["Engineering".into()]))
        );
        assert_eq!(
            converted(Values::Octet(vec![vec![0xde, 0xad]])),
            Some(ClaimValues::Octet(vec![vec![0xde, 0xad]]))
        );

        let administrators = Sid::well_known(peios::security::WellKnown::Administrators);
        assert_eq!(
            converted(Values::Sid(vec![
                administrators.as_ref().as_bytes().to_vec()
            ])),
            Some(ClaimValues::Sid(vec![administrators]))
        );
    }

    /// libauthd carries SIDs as opaque bytes, so this is the first point one is
    /// held to being a SID at all. Refusing the whole set rather than dropping
    /// the offender matters: a claim is an input to access decisions, so losing
    /// one signs somebody in against a policy nobody stated.
    #[test]
    fn a_claim_carrying_something_that_is_not_a_sid_refuses_the_whole_set() {
        use libauthd::claim::Values;

        let good = wire_claim(Values::String(vec!["Engineering".into()]));
        let bad = wire_claim(Values::Sid(vec![b"not a sid".to_vec()]));

        assert!(kacs_claims(core::slice::from_ref(&good)).is_some());
        assert_eq!(kacs_claims(&[bad.clone()]), None);
        assert_eq!(
            kacs_claims(&[good, bad]),
            None,
            "one unusable claim must not leave the others to be believed"
        );
    }

    #[test]
    fn the_flags_kacs_carries_on_a_token_survive() {
        use libauthd::claim::{self, Values};

        let with = |flags| {
            kacs_claims(&[libauthd::claim::Claim {
                flags,
                ..wire_claim(Values::Int64(Vec::new()))
            }])
            .map(|mut c| c.remove(0).flags)
        };

        assert_eq!(
            with(claim::FLAG_CASE_SENSITIVE),
            Some(ClaimAttr::CASE_SENSITIVE)
        );
        assert_eq!(
            with(claim::FLAG_USE_FOR_DENY_ONLY),
            Some(ClaimAttr::USE_FOR_DENY_ONLY)
        );
        assert_eq!(with(claim::FLAG_DISABLED), Some(ClaimAttr::DISABLED));

        // MANDATORY and NON_INHERITABLE govern a claim living in a *security
        // descriptor* — removal by an unprivileged caller, and inheritance to
        // children. Neither has meaning on a token, so KACS does not carry
        // them and dropping them is the correct mapping rather than a loss.
        assert_eq!(with(claim::FLAG_MANDATORY), Some(ClaimAttr::empty()));
        assert_eq!(with(claim::FLAG_NON_INHERITABLE), Some(ClaimAttr::empty()));
    }

    #[test]
    fn no_claims_converts_to_no_claims() {
        assert_eq!(kacs_claims(&[]), Some(Vec::new()));
    }

    #[test]
    fn add_unique_keeps_the_first_mention() {
        let user: Sid = "S-1-5-21-0-0-0-1000".parse().unwrap();
        let mut groups = vec![(user.clone(), 0xf0)];

        // A source redundantly asserting the user must not strip OWNER back
        // off by re-adding it with plain attributes.
        add_unique(&mut groups, user.clone(), 0x01);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1, 0xf0);

        add_unique(&mut groups, Sid::well_known(peios::security::WellKnown::Everyone), 0x01);
        assert_eq!(groups.len(), 2);
    }
}
