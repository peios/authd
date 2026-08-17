//! One connection, one logon conversation — relayed to a principal source.
//!
//! Establishes who is calling, finds the source that should answer for them,
//! and then gets out of the way: the source decides what to ask for, and this
//! module carries messages between it and the client until one side reaches a
//! terminal state.
//!
//! # authd is a relay in the middle and an authority at both ends
//!
//! Because PSI is a superset of PGSS Logon, the interrogation phase is the same
//! messages on both sides and relaying is nearly a memcpy. What authd adds is
//! at the edges:
//!
//! - **Peer verification**, on both sockets.
//! - **Routing** — which source answers for this identifier.
//! - **Constraint** — whether this peer may originate this logon type.
//! - **Policing** — a source must not prompt for a credential type the client
//!   never advertised, which is the one thing a relay must refuse to carry.
//! - **Limits** — how many rounds, and how long each may take.
//! - **Derivation and minting**, which no source can do.
//!
//! # The peer check is correctness, not hardening
//!
//! It is tempting to read peer verification as defence in depth on top of the
//! socket's DACL. It is not — it is load-bearing for *correctness*, because the
//! peer's identity is an input to derivation. Only the caller knows whether an
//! sshd connection is an interactive shell or a batch command, so PGSS Logon
//! lets the client propose a logon type; but if that proposal were accepted
//! unchecked, anything able to reach the socket could claim `Interactive` and
//! collect the `S-1-5-4` group SID that ACLs across the system are written
//! against.
//!
//! So the client proposes and the authority constrains, against a peer identity
//! taken from the connected socket and never from the message body. That
//! identity is then forwarded to the source, which cannot learn it for itself.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use libauthd::transport::{recv_message, send_message, send_message_with_fd};
use libauthd::wire::{
    self, AccessDenied, AccessGranted, CredentialRequest, CredentialResponse, Denial, LogonStart,
    LogonType, MSG_CREDENTIAL_RESPONSE, MSG_LOGON_START, decode_credential_response, decode_header,
    decode_logon_start, encode_access_denied, encode_access_granted, encode_credential_request,
};
use peios::security::{Sid, SidRef};

use crate::derive;
use crate::log;
use crate::peer;
use crate::policy;
use crate::unix_id;
use crate::source::{Conversation, Inbound, Registry, Stalled};

/// How many prompt/answer rounds a single logon may take.
///
/// The conversational shape exists for choosing between authentication paths
/// and for chained requirements, not for unbounded interrogation. Without a
/// ceiling a source could hold a client in a prompt loop forever.
const MAX_ROUNDS: u32 = 8;

/// How long a single conversation may sit waiting for the client.
///
/// [`MAX_ROUNDS`] bounds how *many* exchanges happen; this bounds how long each
/// may take. Without it a client can hold a conversation slot open indefinitely
/// without ever being rude enough to be disconnected.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the source has to answer.
///
/// Generous because a directory-backed source may be doing network work, but
/// finite because a wedged source must not wedge every logon behind it.
const SOURCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve one connection to completion.
pub fn serve(registry: Arc<Registry>, stream: UnixStream) {
    if let Err(error) = stream.set_read_timeout(Some(CLIENT_TIMEOUT)) {
        log::warn(format_args!("could not set read timeout: {error}"));
        return;
    }

    match run(&registry, &stream) {
        Ok(()) => {}
        Err(error) => log::warn(format_args!("conversation ended: {error}")),
    }
}

fn run(registry: &Registry, stream: &UnixStream) -> io::Result<()> {
    // Who is actually calling? From the socket, never from the message.
    let peer = match peer::identity(stream) {
        Ok(peer) => peer,
        Err(error) => {
            log::warn(format_args!("could not identify peer: {error}"));
            return deny(
                stream,
                Denial::PermissionDenied,
                "Caller identity could not be established.",
            );
        }
    };

    let start = match read_logon_start(stream) {
        Ok(start) => start,
        Err(denial) => return deny(stream, denial.0, denial.1),
    };

    if !may_originate(&peer) {
        log::warn(format_args!(
            "refused logon from {peer}: not a permitted originator"
        ));
        return deny(
            stream,
            Denial::PermissionDenied,
            "Caller may not originate logons.",
        );
    }

    if !may_request(&peer, start.logon_type) {
        log::warn(format_args!(
            "refused {:?} logon from {peer}: not permitted for this originator",
            start.logon_type
        ));
        return deny(
            stream,
            Denial::LogonTypeNotPermitted,
            "Caller may not request that logon type.",
        );
    }

    log::info(format_args!(
        "logon started: peer={peer} type={:?} identifier={}",
        start.logon_type,
        String::from_utf8_lossy(&start.identifier)
    ));

    let Some(source) = registry.route(&start.identifier) else {
        log::warn(format_args!(
            "no principal source can answer for {}",
            String::from_utf8_lossy(&start.identifier)
        ));
        return deny(
            stream,
            Denial::AuthorityUnavailable,
            "No authority is available for that principal.",
        );
    };

    let Some(mut conversation) = source.open() else {
        log::warn(format_args!(
            "source {} could not accept another conversation",
            source.name()
        ));
        return deny(
            stream,
            Denial::AuthorityUnavailable,
            "The authority is busy. Try again shortly.",
        );
    };

    if let Err(error) = conversation.authenticate(&start, peer.as_ref().as_bytes()) {
        log::warn(format_args!(
            "could not reach source {}: {error}",
            source.name()
        ));
        return deny(
            stream,
            Denial::AuthorityUnavailable,
            "The authority could not be reached.",
        );
    }

    relay(stream, &start, &mut conversation)
}

/// Carry messages between the client and the source until one of them finishes.
fn relay(
    stream: &UnixStream,
    start: &LogonStart,
    conversation: &mut Conversation,
) -> io::Result<()> {
    for _ in 0..MAX_ROUNDS {
        let inbound = match conversation.recv(SOURCE_TIMEOUT) {
            Ok(inbound) => inbound,
            Err(Stalled::TimedOut) => {
                log::warn(format_args!(
                    "source {} did not answer in time",
                    conversation.source_name()
                ));
                return deny(
                    stream,
                    Denial::AuthorityUnavailable,
                    "The authority did not respond.",
                );
            }
            Err(Stalled::SourceGone) => {
                log::warn(format_args!(
                    "source {} disconnected mid-logon",
                    conversation.source_name()
                ));
                return deny(
                    stream,
                    Denial::AuthorityUnavailable,
                    "The authority became unavailable.",
                );
            }
        };

        match inbound {
            Inbound::Request(request) => {
                if let Some(offending) = unrenderable_prompt(start, &request) {
                    // The source asked for something this client told us it
                    // cannot render. Relaying it would force the client to
                    // hard-fail — and a client that guessed instead might echo
                    // a secret to the screen. So the relay refuses to carry it.
                    log::error(format_args!(
                        "source {} asked for credential type {offending:?}, which the client did \
                         not advertise; refusing to relay",
                        conversation.source_name()
                    ));
                    return deny(
                        stream,
                        Denial::Internal,
                        "The authority asked for something this client cannot provide.",
                    );
                }

                let answers = match ask_client(stream, &request) {
                    Ok(answers) => answers,
                    Err(ClientFailed::Protocol(denial, reason)) => {
                        return deny(stream, denial, reason);
                    }
                    Err(ClientFailed::Io(error)) => return Err(error),
                };

                conversation.credential_response(&answers)?;
            }

            Inbound::Assert(assertion) => {
                conversation.finished();
                return grant(stream, start, conversation, &assertion);
            }

            Inbound::Refuse(refusal) => {
                conversation.finished();
                log::info(format_args!(
                    "logon denied by {}: {:?}",
                    conversation.source_name(),
                    refusal.denial
                ));
                return deny(stream, refusal.denial, &refusal.reason);
            }
        }
    }

    log::warn(format_args!(
        "source {} exceeded {MAX_ROUNDS} rounds",
        conversation.source_name()
    ));
    deny(
        stream,
        Denial::ConversationLimit,
        "The logon took too many steps.",
    )
}

/// The first group a source may not assert for this principal, if any.
///
/// An ordinary source vouches for its own users and its own groups, and nothing
/// else — a directory must not be able to declare its users administrators of
/// this machine. The local source is exempt, because local group membership of
/// *any* principal, domain ones included, is a local decision.
fn foreign_membership<'a>(user: &SidRef, groups: &[&'a SidRef]) -> Option<&'a SidRef> {
    groups
        .iter()
        .copied()
        .find(|group| !crate::domain::siblings(user, group))
}

/// The first prompt asking for something the client cannot render, if any.
fn unrenderable_prompt(
    start: &LogonStart,
    request: &CredentialRequest,
) -> Option<wire::CredentialType> {
    request
        .prompts
        .iter()
        .map(|prompt| prompt.credential_type)
        .find(|wanted| !start.supported_credential_types.contains(wanted))
}

enum ClientFailed {
    Protocol(Denial, &'static str),
    Io(io::Error),
}

/// Put a request to the client and read back its answers.
fn ask_client(
    stream: &UnixStream,
    request: &CredentialRequest,
) -> Result<CredentialResponse, ClientFailed> {
    let encoded = encode_credential_request(request)
        .map_err(|_| ClientFailed::Io(io::Error::other("could not encode credential request")))?;
    send_message(stream, &encoded).map_err(ClientFailed::Io)?;

    let received = recv_message(&wire::FRAMING, stream).map_err(ClientFailed::Io)?;
    let (msg_type, _) = decode_header(received.expose())
        .map_err(|_| ClientFailed::Protocol(Denial::MalformedRequest, "Malformed message header."))?;
    if msg_type != MSG_CREDENTIAL_RESPONSE {
        return Err(ClientFailed::Protocol(
            Denial::MalformedRequest,
            "Expected a credential response.",
        ));
    }

    decode_credential_response(received.expose()).map_err(|_| {
        ClientFailed::Protocol(Denial::MalformedRequest, "Malformed credential response.")
    })
}

/// Mint and hand over the token.
fn grant(
    stream: &UnixStream,
    start: &LogonStart,
    conversation: &Conversation,
    assertion: &libauthd::psi::Assertion,
) -> io::Result<()> {
    let source_name = conversation.source_name();
    // A source's assertion is bytes until proven otherwise. Validating the SID
    // here — before it becomes identity — is why libauthd carries it untyped:
    // the codec has no business knowing what a SID is, and the process that
    // mints tokens has every business checking.
    let Some(user) = SidRef::from_bytes(&assertion.user_sid) else {
        log::error(format_args!(
            "source {source_name} asserted {} bytes that are not a valid SID",
            assertion.user_sid.len()
        ));
        return deny(
            stream,
            Denial::Internal,
            "The authority returned an unusable identity.",
        );
    };

    // **Identity confinement.** A source is authoritative for its own domain and
    // no other, whatever else it is permitted. This is not the same restriction
    // as the membership one below, and no flag lifts it: a source that could
    // assert identities outside its domain could hand out a *different
    // authority's* principals to anyone who satisfied *its* credential check —
    // so the local source, which holds no domain credential, could mint a
    // domain administrator for anyone who knew a local password.
    //
    // Confining it keeps a compromised source at "authority over its own
    // domain", which is what it already was, rather than "authority over
    // everyone".
    if !crate::domain::contains(conversation.domain().as_ref(), user) {
        log::error(format_args!(
            "source {source_name} asserted {user}, which is outside the domain it \
             registered for ({})",
            conversation.domain()
        ));
        return deny(
            stream,
            Denial::Internal,
            "The authority returned an identity it is not entitled to assert.",
        );
    }

    // Group SIDs get the same treatment, and a malformed one fails the logon
    // rather than being skipped. Dropping it would silently sign someone in
    // with less authority than the source granted them, which is a confusing
    // way to be wrong; a source that cannot encode a SID is broken, and saying
    // so is more useful than half-believing it.
    let mut memberships: Vec<(Sid, u32)> = Vec::with_capacity(assertion.groups.len() + 1);
    for group in &assertion.groups {
        let Some(sid) = SidRef::from_bytes(&group.sid) else {
            log::error(format_args!(
                "source {source_name} asserted a group of {} bytes that is not a valid SID",
                group.sid.len()
            ));
            return deny(
                stream,
                Denial::Internal,
                "The authority returned an unusable group membership.",
            );
        };
        memberships.push((sid.to_sid(), group.unix_id));
    }

    // The primary group. Empty means the source did not say, and Authenticated
    // Users is the answer: it is a membership authd derives for every principal
    // anyway, so naming it as primary asserts nothing new.
    //
    // Peios deliberately has no per-user group. That Linux convention exists so
    // a file's *group ownership* means something, and under KACS it means
    // nothing — every managed credential carries `CAP_DAC_OVERRIDE`.
    let primary_group = if assertion.primary_group.is_empty() {
        Sid::well_known(peios::security::WellKnown::AuthenticatedUsers)
    } else {
        match SidRef::from_bytes(&assertion.primary_group) {
            Some(sid) => sid.to_sid(),
            None => {
                log::error(format_args!(
                    "source {source_name} asserted a primary group of {} bytes that is not a \
                     valid SID",
                    assertion.primary_group.len()
                ));
                return deny(
                    stream,
                    Denial::Internal,
                    "The authority returned an unusable primary group.",
                );
            }
        }
    };

    // KACS requires the primary group to be a group on the token, so a source
    // naming one it did not list is taken to be asserting the membership too.
    // Added *before* the check below rather than after, which matters: naming a
    // group as primary is as much a membership claim as listing it, and a
    // source must not be able to reach `BUILTIN\Administrators` through the one
    // field that skipped the scope check.
    if !memberships.iter().any(|(sid, _)| *sid == primary_group) {
        memberships.push((primary_group.clone(), 0));
    }

    let groups: Vec<&SidRef> = memberships.iter().map(|(sid, _)| sid.as_ref()).collect();

    // A source vouches for its own users and its own groups. Asserting a group
    // from another domain — a BUILTIN alias, or another directory's — is the
    // local source's privilege alone, because local membership is a local
    // decision and a directory must not be able to make its users
    // administrators of this machine.
    if !conversation.may_assert_foreign_memberships() {
        if let Some(foreign) = foreign_membership(user, &groups) {
            log::error(format_args!(
                "source {source_name} asserted {foreign} for {user}, which is outside that \
                 principal's domain, and it may not assert foreign memberships"
            ));
            return deny(
                stream,
                Denial::Internal,
                "The authority returned a membership it is not permitted to assert.",
            );
        }
    }

    // The POSIX numbers. Every id a source sends is *relative* to the range the
    // registry assigned it; this is where the base is added, and it is the only
    // place that may add it.
    let numbered: Vec<unix_id::Numbered<'_>> = memberships
        .iter()
        .map(|(sid, relative)| unix_id::Numbered {
            sid: sid.as_ref(),
            relative: *relative,
        })
        .collect();
    let projection = unix_id::project(
        conversation.unix_id_range().as_ref(),
        assertion.unix_id,
        primary_group.as_ref(),
        &numbered,
    );

    // Claims are the one asserted field that is a *trusted input to access
    // decisions* rather than a statement of identity — a conditional ACE can
    // turn one into a grant. So they are held to the same standard as a group
    // SID: checked here, and a source that cannot produce a usable one fails
    // the logon rather than having it quietly dropped.
    for claim in &assertion.claims {
        if let Err(error) = claim.validate() {
            log::error(format_args!(
                "source {source_name} asserted an unusable claim for {user}: {error}"
            ));
            return deny(
                stream,
                Denial::Internal,
                "The authority returned an unusable claim.",
            );
        }
    }
    let Some(claims) = derive::kacs_claims(&assertion.claims) else {
        log::error(format_args!(
            "source {source_name} asserted a claim for {user} carrying a value that is not a \
             valid SID"
        ));
        return deny(
            stream,
            Denial::Internal,
            "The authority returned an unusable claim.",
        );
    };

    // The SID set the token will carry, derived SIDs included. Built before
    // minting because local policy is evaluated against *this* set: a record
    // for `Everyone`, or for a logon-type SID, would otherwise never apply.
    let token_groups = derive::token_groups(user, &groups, start.logon_type);
    let token_sids: Vec<&SidRef> = token_groups.iter().map(|(sid, _)| sid.as_ref()).collect();

    // Read per logon rather than cached at startup, so a policy change takes
    // effect on the next sign-on rather than on the next restart of the one
    // daemon that is most disruptive to restart.
    let outcome = policy::principal::evaluate(user, &token_sids);

    let granted = match derive::mint(derive::Minting {
        user,
        groups: &token_groups,
        primary_group: primary_group.as_ref(),
        projection: &projection,
        claims: &claims,
        logon_type: start.logon_type,
        auth_package: source_name,
        policy: outcome.clone(),
    }) {
        Ok(granted) => granted,
        Err(error) => {
            log::warn(format_args!("could not mint token: {error}"));
            return deny(
                stream,
                Denial::Internal,
                "The authority could not issue a token.",
            );
        }
    };

    // The profile is relayed exactly as the source gave it. It is not identity
    // and decides no access — a home directory appears in no ACL — so there is
    // nothing here for authd to check that the client should not check itself.
    let message = encode_access_granted(&AccessGranted {
        session_id: granted.session.0,
        profile: assertion.profile.clone(),
    })
    .map_err(|_| io::Error::other("could not encode grant"))?;

    send_message_with_fd(stream, &message, granted.token.as_fd())?;

    log::info(format_args!(
        "logon granted: user={user} name={} session={} type={:?} source={source_name} \
         groups={} uid={} gid={} claims={} integrity={} privileges={}",
        assertion.canonical_name,
        granted.session.0,
        start.logon_type,
        token_groups.len(),
        projection.uid,
        projection.gid,
        claims.len(),
        policy::principal::tier_name(outcome.integrity)
            .map_or_else(|| outcome.integrity.0.to_string(), str::to_string),
        outcome
            .privileges
            .canonical_names()
            .collect::<Vec<_>>()
            .join(",")
    ));

    // `granted.token` drops here, closing authd's descriptor. The kernel keeps
    // the token alive for the copy the client now holds — authd does not retain
    // a handle on an identity it has handed away.
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

/// Read and validate the opening message.
fn read_logon_start(stream: &UnixStream) -> Result<LogonStart, (Denial, &'static str)> {
    let received = recv_message(&wire::FRAMING, stream)
        .map_err(|_| (Denial::MalformedRequest, "Could not read the opening message."))?;

    let (msg_type, _) = decode_header(received.expose())
        .map_err(|_| (Denial::MalformedRequest, "Malformed message header."))?;
    if msg_type != MSG_LOGON_START {
        return Err((
            Denial::MalformedRequest,
            "A conversation must open with LogonStart.",
        ));
    }

    decode_logon_start(received.expose())
        .map_err(|_| (Denial::MalformedRequest, "Malformed LogonStart."))
}

/// Whether a principal may originate logons at all.
///
/// Permits SYSTEM only, which is what the compiled-in `login` service runs as.
/// This widens to a dedicated `LogonService` principal once there is one — the
/// point of a narrow list now is that widening it is a visible, deliberate edit
/// rather than a discovery.
fn may_originate(peer: &Sid) -> bool {
    peer::is_system(peer)
}

/// Whether a given originator may request a given logon type.
///
/// The constraint half of "client proposes, authority constrains". A WebUI
/// should be able to ask for `Network` and nothing else; `peinit` for `Service`
/// and nothing else. There is one originator today and it is SYSTEM, so the
/// table is trivial — but the check exists at the right place, which is what
/// makes adding the real table a data change rather than a structural one.
fn may_request(peer: &Sid, _logon_type: LogonType) -> bool {
    peer::is_system(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::wire::{CredentialType, IdentifierType, Prompt};

    fn start_supporting(types: Vec<CredentialType>) -> LogonStart {
        LogonStart {
            logon_type: LogonType::Interactive,
            identifier_type: IdentifierType::Username,
            identifier: b"jack".to_vec(),
            tty: None,
            remote_host: None,
            supported_credential_types: types,
        }
    }

    fn requesting(types: &[CredentialType]) -> CredentialRequest {
        CredentialRequest {
            messages: Vec::new(),
            prompts: types
                .iter()
                .enumerate()
                .map(|(i, credential_type)| Prompt {
                    credential_ref: i as u32 + 1,
                    credential_type: *credential_type,
                    credential_name: "Password".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn an_advertised_credential_type_is_relayed() {
        let start = start_supporting(vec![CredentialType::Password]);
        assert!(unrenderable_prompt(&start, &requesting(&[CredentialType::Password])).is_none());
    }

    /// The relay's one refusal to carry: a client that advertised nothing must
    /// not be sent a prompt it would have to hard-fail on.
    #[test]
    fn an_unadvertised_credential_type_is_caught() {
        let start = start_supporting(Vec::new());
        assert_eq!(
            unrenderable_prompt(&start, &requesting(&[CredentialType::Password])),
            Some(CredentialType::Password)
        );
    }

    #[test]
    fn a_request_with_no_prompts_is_always_relayable() {
        // Messages without prompts are how an authority says something without
        // asking for anything.
        let start = start_supporting(Vec::new());
        assert!(unrenderable_prompt(&start, &requesting(&[])).is_none());
    }

    fn sid(text: &str) -> Sid {
        text.parse().expect("a valid SID")
    }

    /// The case the whole restriction exists for: a directory source must not
    /// be able to declare its users administrators of this machine.
    #[test]
    fn builtin_administrators_is_a_foreign_membership() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let administrators = sid("S-1-5-32-544");
        let groups = [administrators.as_ref()];
        assert_eq!(
            foreign_membership(user.as_ref(), &groups).map(ToString::to_string),
            Some("S-1-5-32-544".to_string())
        );
    }

    #[test]
    fn a_domains_own_groups_are_not_foreign() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let own = [sid("S-1-5-21-1-2-3-513"), sid("S-1-5-21-1-2-3-512")];
        let groups: Vec<&SidRef> = own.iter().map(Sid::as_ref).collect();
        assert!(foreign_membership(user.as_ref(), &groups).is_none());
    }

    #[test]
    fn no_groups_are_never_foreign() {
        let user = sid("S-1-5-21-1-2-3-1000");
        assert!(foreign_membership(user.as_ref(), &[]).is_none());
    }

    /// The first offender is reported, not merely "some group was foreign" —
    /// the log line is the only way an administrator finds a misconfigured
    /// source.
    #[test]
    fn the_offending_group_is_the_one_reported() {
        let user = sid("S-1-5-21-1-2-3-1000");
        let all = [
            sid("S-1-5-21-1-2-3-513"),
            sid("S-1-5-32-544"),
            sid("S-1-1-0"),
        ];
        let groups: Vec<&SidRef> = all.iter().map(Sid::as_ref).collect();
        assert_eq!(
            foreign_membership(user.as_ref(), &groups).map(ToString::to_string),
            Some("S-1-5-32-544".to_string())
        );
    }
}
