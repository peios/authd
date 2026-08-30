//! Service attestation: a token for a service, with no credential behind it.
//!
//! Implements PGSS Logon §2.19; the obligations are §2.20 items 51-60.
//!
//! A service identity has no credential and must never acquire one. A machine
//! that could authenticate its own services would have to hold their secret,
//! and a store of service passwords is a thing to design out rather than to
//! protect — it is the single most-attacked structure in the system this design
//! otherwise follows.
//!
//! What stands in for the credential is *attestation*. The service manager asks
//! for a token, the authority satisfies itself about **who is asking**, and
//! takes the service name on that peer's word because no other component is in
//! a position to know it.
//!
//! # What the authority can and cannot check
//!
//! It can check the peer exactly. It cannot check the claim.
//!
//! [`crate::peer::identify_source`] authenticates a principal source by asking
//! the kernel whether the peer's token carries the service SID peinit stamped —
//! peinit's assertion is *verified* there, not trusted. That does not work
//! here, because the process this request is about **does not exist yet**:
//! there is no token to interrogate, so `service` is taken on the peer's word.
//!
//! That trust is not removable. peinit holds the service registry, launches the
//! process and stamps its SID; it is inherently the attester for "which service
//! is this". What the split buys is that the *policy* — what privileges and
//! integrity an identity carries — is decided here, by
//! [`crate::policy::principal`], rather than in a second place that could
//! silently disagree.
//!
//! # Two facts, from two places
//!
//! Both are required, and neither is sufficient:
//!
//! 1. **The peer is SYSTEM**, from its token via [`crate::peer::identity`].
//! 2. **The peer is PID 1**, from `SO_PEERCRED` via [`crate::peer::is_init`].
//!
//! The second is doing real work rather than belt-and-braces. SYSTEM alone is
//! every platform daemon on the box — lpsd, login, eventd, atriumd, netd — so
//! with only the first, compromising any one of them mints any service identity
//! on the machine. And peinit is the one peer that *cannot* be identified the
//! way a source is: nothing launched it, so it carries no service SID to match
//! against. PID 1 is the discriminator available.
//!
//! # Evidence, and why these tokens are weaker
//!
//! An attested token is minted at [`derive::Evidence::Attested`], so it starts
//! one rung below a credentialled logon on the impersonation ratchet. peinit's
//! word is evidence here and nowhere else, and a token that could be forwarded
//! to another machine on the strength of it would let one box's PID 1 act as an
//! arbitrary account across the network.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use libauthd::transport::{send_message, send_message_with_fd};
use libauthd::wire::{
    AccessDenied, AccessGranted, Denial, LogonType, Profile, ServiceAttest, encode_access_denied,
    encode_access_granted,
};
use peios::security::{Sid, SidRef};

use crate::unix_id::Projection;
use crate::{derive, log, peer, policy, service_sid};

/// The identities the authority mints without consulting any source.
///
/// These are `NT AUTHORITY` principals — no domain SID, no record anywhere, and
/// nothing for a principal source to hold. They belong to the authority for the
/// same reason the well-known *groups* do: a source that owned them would mean
/// every source claiming the same handful of objects, and "which LocalService"
/// would become a question with more than one answer.
///
/// Spelled as the service manager spells them in a service definition's
/// `Identity`, matched without regard to case.
const SERVICE_IDENTITIES: &[(&str, u32)] = &[
    ("SYSTEM", 18),
    ("LocalService", 19),
    ("NetworkService", 20),
];

/// Whether a peer may attest a service identity — obtain a token with no
/// credential behind it.
///
/// See the module documentation for why both facts are load-bearing.
pub fn may_attest(peer: &Sid, peer_is_init: bool) -> bool {
    peer::is_system(peer) && peer_is_init
}

/// Serve one `ServiceAttest`, having already established the peer's identity.
pub fn serve(stream: &UnixStream, peer: &Sid, attest: &ServiceAttest) -> io::Result<()> {
    if !may_attest(peer, peer::is_init(stream)) {
        log::warn(format_args!(
            "refused attestation from {peer}: not the service manager"
        ));
        return deny(
            stream,
            Denial::PermissionDenied,
            "Caller may not attest service identities.",
        );
    }

    // The service name becomes a SID that goes on the token, so it is validated
    // before anything else uses it. An empty name would derive the SHA-1 of the
    // empty string — a perfectly well-formed SID naming nothing, which would be
    // shared by every service that made the same mistake.
    if attest.service.trim().is_empty() {
        return deny(
            stream,
            Denial::MalformedRequest,
            "A service attestation must name a service.",
        );
    }
    let Some(service) = service_sid::of(&attest.service) else {
        log::warn(format_args!(
            "attestation for service {:?}: name does not derive a usable SID",
            attest.service
        ));
        return deny(
            stream,
            Denial::MalformedRequest,
            "That service name does not derive a usable identity.",
        );
    };

    let Some(user) = well_known_identity(&attest.identity) else {
        // Everything that is not a well-known service identity — a principal
        // name, a literal SID — needs the principal's own record to say it may
        // be used for a service logon, and that field does not exist yet. Until
        // it does, the honest answer is no: accepting a bare name here would
        // make the service manager an oracle that mints a token for any
        // principal on the machine with no credential.
        log::warn(format_args!(
            "refused attestation of {:?} for service {:?}: not a well-known service identity",
            attest.identity, attest.service
        ));
        return deny(
            stream,
            Denial::AccountRestricted,
            "That identity may not be used for a service logon.",
        );
    };

    mint_and_send(stream, user.as_ref(), &service, &attest.service)
}

/// Resolve one of the authority's own service identities, or `None`.
fn well_known_identity(identity: &str) -> Option<Sid> {
    let sub_authority = SERVICE_IDENTITIES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(identity))
        .map(|(_, sub_authority)| *sub_authority)?;
    // NT Authority (5), one sub-authority.
    Sid::build(5, &[sub_authority]).ok()
}

fn mint_and_send(
    stream: &UnixStream,
    user: &SidRef,
    service: &Sid,
    service_name: &str,
) -> io::Result<()> {
    // The service SID is asserted rather than derived, in the sense that
    // `token_groups` takes it alongside anything a source would have claimed.
    // It is what keeps two services running as the same identity
    // distinguishable in an ACL, which is the whole reason a virtual account is
    // usually enough and a real one usually is not.
    let asserted: Vec<&SidRef> = vec![service.as_ref()];
    let token_groups = derive::token_groups(user, &asserted, LogonType::Service);
    let token_sids: Vec<&SidRef> = token_groups.iter().map(|(sid, _)| sid.as_ref()).collect();

    // Local policy, evaluated against the SIDs this token actually ends up
    // carrying — exactly as for a credentialled logon. This is the reason the
    // minting moved here: privileges and integrity for an identity are a
    // statement about how much this machine trusts it, and a second component
    // deciding that in parallel is a disagreement waiting to happen.
    let outcome = policy::principal::evaluate(user, &token_sids);

    // These principals are numbered by the authority's own table rather than by
    // a source, so there is no range to rebase through. A SID with no number
    // projects to `nobody`, which grants nothing and is the honest answer.
    let projection = Projection {
        uid: crate::unix_id::built_in(user).unwrap_or(crate::unix_id::UNMAPPED),
        gid: crate::unix_id::built_in(user).unwrap_or(crate::unix_id::UNMAPPED),
        supplementary: token_groups
            .iter()
            .filter_map(|(sid, _)| crate::unix_id::built_in(sid.as_ref()))
            .collect(),
    };

    let granted = match derive::mint(derive::Minting {
        user,
        groups: &token_groups,
        primary_group: user,
        projection: &projection,
        claims: &[],
        logon_type: LogonType::Service,
        // What vouched for this logon, which is what an audit record needs in
        // order not to read as though a source verified something.
        auth_package: "attested",
        policy: outcome.clone(),
        evidence: derive::Evidence::Attested,
    }) {
        Ok(granted) => granted,
        Err(error) => {
            log::warn(format_args!("could not mint service token: {error}"));
            return deny(
                stream,
                Denial::Internal,
                "The authority could not issue a token.",
            );
        }
    };

    // A service has no profile. Every field is already optional and every
    // client already falls back, so saying nothing is both correct and what an
    // authority that knows nothing is required to do.
    let message = encode_access_granted(&AccessGranted {
        session_id: granted.session.0,
        profile: Profile::default(),
    })
    .map_err(|_| io::Error::other("could not encode grant"))?;

    send_message_with_fd(stream, &message, granted.token.as_fd())?;

    log::info(format_args!(
        "service token granted: user={user} service={service_name} service_sid={service} \
         session={} groups={} uid={} integrity={} privileges={}",
        granted.session.0,
        token_groups.len(),
        projection.uid,
        policy::principal::tier_name(outcome.integrity)
            .map_or_else(|| outcome.integrity.0.to_string(), str::to_string),
        outcome
            .privileges
            .canonical_names()
            .collect::<Vec<_>>()
            .join(",")
    ));

    Ok(())
}

fn deny(stream: &UnixStream, denial: Denial, reason: &str) -> io::Result<()> {
    let message = encode_access_denied(&AccessDenied {
        denial,
        reason: reason.to_string(),
    })
    .map_err(|_| io::Error::other("could not encode denial"))?;
    send_message(stream, &message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    #[test]
    fn both_facts_are_required() {
        let system = sid("S-1-5-18");
        let other = sid("S-1-5-21-1-2-3-1000");

        assert!(may_attest(&system, true));
        // SYSTEM but not PID 1 — every other platform daemon on the box.
        assert!(!may_attest(&system, false));
        // PID 1 but not SYSTEM, which should not be reachable, and is refused
        // anyway rather than relying on that.
        assert!(!may_attest(&other, true));
        assert!(!may_attest(&other, false));
    }

    #[test]
    fn the_three_service_identities_resolve() {
        assert_eq!(well_known_identity("SYSTEM"), Some(sid("S-1-5-18")));
        assert_eq!(well_known_identity("LocalService"), Some(sid("S-1-5-19")));
        assert_eq!(well_known_identity("NetworkService"), Some(sid("S-1-5-20")));
    }

    /// peinit canonicalises identity spellings without regard to case, so an
    /// authority that did not would refuse a definition peinit accepted.
    #[test]
    fn service_identities_are_matched_without_case() {
        assert_eq!(well_known_identity("localservice"), Some(sid("S-1-5-19")));
        assert_eq!(well_known_identity("SYSTEM"), well_known_identity("system"));
    }

    /// The property the whole design rests on: a service cannot be an ordinary
    /// principal. Until a record can say it permits a service logon, nothing
    /// outside the authority's own table is attestable at all.
    #[test]
    fn an_ordinary_principal_is_not_a_service_identity() {
        assert_eq!(well_known_identity("jack"), None);
        assert_eq!(well_known_identity("S-1-5-21-1-2-3-1000"), None);
        assert_eq!(well_known_identity("Administrators"), None);
        assert_eq!(well_known_identity(""), None);
    }

    /// The service SID is not decoration: two services sharing an identity are
    /// told apart by it, so it must differ per service and agree with what
    /// peinit derives.
    #[test]
    fn distinct_services_get_distinct_sids() {
        let a = service_sid::of("resolvd").expect("a usable SID");
        let b = service_sid::of("lpsd").expect("a usable SID");
        assert_ne!(a, b);
        assert_eq!(a, service_sid::of("RESOLVD").expect("a usable SID"));
    }
}
