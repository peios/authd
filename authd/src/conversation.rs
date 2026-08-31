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
use std::time::{Duration, Instant};

use libauthd::transport::{recv_message, send_message, send_message_with_fd};
use libauthd::wire::{
    self, AccessDenied, AccessGranted, CredentialRequest, CredentialResponse, Denial, LogonStart,
    LogonType, MSG_CREDENTIAL_RESPONSE, MSG_LOGON_START, MSG_SERVICE_ATTEST, ServiceAttest,
    decode_credential_response, decode_header, decode_logon_start, decode_service_attest,
    encode_access_denied, encode_access_granted, encode_credential_request,
};
use peios::security::{Sid, SidRef};

use crate::derive;
use crate::home;
use crate::log;
use crate::peer;
use crate::policy;
use crate::source::{Conversation, Inbound, Registry, Stalled};
use crate::unix_id;

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

/// The wall-clock ceiling on one conversation, start to finish.
///
/// Obligation 11 bounds both the number of conversations served at once and
/// **the time a conversation may remain open**. The first exists
/// (`MAX_CONCURRENT_CONVERSATIONS`); the second did not, because
/// [`CLIENT_TIMEOUT`] is `SO_RCVTIMEO` and therefore per *read*. A client
/// sending one byte every 119 seconds reset it indefinitely and held one of 64
/// slots for as long as it liked — a cheap way to stop anyone signing in, on a
/// socket whose access control is currently an inherited DACL.
///
/// Sized above a well-behaved client's emergent worst case, roughly
/// `MAX_ROUNDS × (CLIENT_TIMEOUT + SOURCE_TIMEOUT)`, so this bounds the
/// deliberate case without cutting off a slow but honest one.
const CONVERSATION_DEADLINE: Duration = Duration::from_secs(25 * 60);

/// How long authd will wait to hand bytes to the client.
///
/// The ident and PSI paths both set one; the logon socket did not, so a client
/// that connected, sent a valid `LogonStart` and then never read blocked a
/// conversation thread in `send_message` with nothing to time it out.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
    if let Err(error) = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)) {
        log::warn(format_args!("could not set write timeout: {error}"));
        return;
    }

    let deadline = Instant::now() + CONVERSATION_DEADLINE;
    match run(&registry, &stream, deadline) {
        Ok(()) => {}
        Err(error) => log::warn(format_args!("conversation ended: {error}")),
    }
}

/// Whether the conversation has outlived its wall-clock bound.
fn expired(deadline: Instant) -> bool {
    Instant::now() >= deadline
}

fn run(registry: &Registry, stream: &UnixStream, deadline: Instant) -> io::Result<()> {
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

    let start = match read_opening(stream) {
        Ok(Opening::Logon(start)) => start,
        // A service attestation is not a conversation: it carries no
        // credential, so none of the relay below applies to it. Dispatched here
        // rather than earlier because everything up to this point -- the
        // timeouts, and establishing who the peer actually is -- is identical
        // and must not be duplicated into a second path that could drift.
        Ok(Opening::Attest(attest)) => {
            return crate::attest::serve(registry, stream, &peer, &attest);
        }
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

    let source = match crate::resolve::route(registry, &start.identifier) {
        crate::resolve::Route::Owner(source) => source,
        crate::resolve::Route::Blind(source) => {
            // Logged for the administrator; the caller learns nothing. The
            // source runs a blinded conversation for a name it does not hold
            // and denies AuthenticationFailed, indistinguishable from a
            // wrong password (PGSS §2.10).
            log::info(format_args!(
                "no source claims {}; blinding via {}",
                String::from_utf8_lossy(&start.identifier),
                source.name()
            ));
            source
        }
        crate::resolve::Route::Unavailable => {
            return deny(
                stream,
                Denial::AuthorityUnavailable,
                "The authority could not be reached.",
            );
        }
        crate::resolve::Route::NoSources => {
            log::warn(format_args!(
                "no principal source can answer for {}",
                String::from_utf8_lossy(&start.identifier)
            ));
            return deny(
                stream,
                Denial::AuthorityUnavailable,
                "No authority is available for that principal.",
            );
        }
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

    relay(stream, &start, &mut conversation, deadline)
}

/// Carry messages between the client and the source until one of them finishes.
fn relay(
    stream: &UnixStream,
    start: &LogonStart,
    conversation: &mut Conversation,
    deadline: Instant,
) -> io::Result<()> {
    for _ in 0..MAX_ROUNDS {
        // The wall-clock bound, checked once per round. Per-read timeouts
        // cannot see a client that keeps resetting them.
        if expired(deadline) {
            log::warn(format_args!(
                "conversation exceeded {CONVERSATION_DEADLINE:?}"
            ));
            return deny(
                stream,
                Denial::ConversationLimit,
                "The logon took too long.",
            );
        }
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
                if let Some(repeated) = duplicate_credential_ref(&request) {
                    log::error(format_args!(
                        "source {} repeated credential_ref {repeated}; refusing to relay",
                        conversation.source_name()
                    ));
                    return deny(
                        stream,
                        Denial::Internal,
                        "The authority asked an ambiguous question.",
                    );
                }

                // §2.3, obligation 12: a response MUST follow the request
                // for it. Bytes already waiting before this prompt has been
                // sent are a pipelined CredentialResponse — sent on
                // speculation about a question the source had not asked,
                // which the round-trip discipline exists to forbid. Checked
                // per prompt rather than once, since round 2's answer can be
                // pipelined behind round 1's as easily as round 1's behind
                // LogonStart.
                if client_already_answered(stream) {
                    log::warn(format_args!(
                        "client answered before being asked; refusing the conversation"
                    ));
                    return deny(
                        stream,
                        Denial::MalformedRequest,
                        "A response arrived before the request for it.",
                    );
                }

                let answers = match ask_client(stream, &request) {
                    Ok(answers) => answers,
                    Err(ClientFailed::Protocol(denial, reason)) => {
                        return deny(stream, denial, reason);
                    }
                    Err(ClientFailed::Io(error)) if is_read_timeout(&error) => {
                        log::warn(format_args!(
                            "client did not answer within {CLIENT_TIMEOUT:?}"
                        ));
                        return deny(
                            stream,
                            Denial::ConversationLimit,
                            "The logon took too long to answer.",
                        );
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
            // A lookup answer, on a logon conversation. authd allocated this
            // identifier for a logon and asked no question a query could answer,
            // so the source has confused two of its own conversations — which
            // means anything else it says on this one is suspect too.
            Inbound::Results(_) | Inbound::Page(_) => {
                log::error(format_args!(
                    "source {} answered a logon with a lookup result",
                    conversation.source_name()
                ));
                return deny(
                    stream,
                    Denial::Internal,
                    "The authority could not complete the logon.",
                );
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

/// PSI rules 4 and 5, applied before rule 2.
///
/// Rule 4: an asserted logon SID is **dropped**, loudly, rather than refusing
/// the assertion — the token still ends up correct, and refusing would punish a
/// principal for a source's defect without making anything safer. Rule 5 drops
/// a duplicate.
///
/// Obligation 23 puts both *before* membership scope, and the ordering is
/// load-bearing rather than tidy. A logon SID is `S-1-5-5-X-Y`, by construction
/// never a sibling of an `S-1-5-21` principal, so a scope check running first
/// caught it and refused the very logon rule 4 says to survive by dropping. The
/// two rules gave opposite answers for the same input, and rule 4's outcome was
/// unreachable for any source without `MayAssertForeignMemberships`.
fn drop_unassertable(memberships: Vec<(Sid, u32)>, source_name: &str) -> Vec<(Sid, u32)> {
    let mut kept: Vec<(Sid, u32)> = Vec::with_capacity(memberships.len());
    for (sid, unix_id) in memberships {
        if crate::derive::is_logon_sid(sid.as_ref()) {
            log::error(format_args!(
                "source {source_name} asserted logon SID {sid}: logon SIDs are the kernel's \
                 to mint, dropping it"
            ));
            continue;
        }
        if kept.iter().any(|(seen, _)| *seen == sid) {
            continue;
        }
        kept.push((sid, unix_id));
    }
    kept
}

/// The memberships membership scope applies to.
///
/// Every group the source claimed, including a primary group it named — but
/// **not** a primary group authd substituted for an empty field. PSI authority
/// obligation 26: never apply membership scope to a `primary_group` the
/// authority chose itself, because it needs no permission from anybody to
/// apply its own default.
///
/// Conflating the two cancelled two correct rules against each other. The
/// default is `Authenticated Users`, `S-1-5-11` — two sub-authorities — and a
/// principal is `S-1-5-21-A-B-C-RID`, so [`crate::domain::siblings`] can never
/// hold between them. Every source that omitted `primary_group` therefore had
/// every logon denied, naming the source for a claim it never made.
fn scoped_groups<'a>(
    memberships: &'a [(Sid, u32)],
    primary_group: &SidRef,
    primary_group_asserted: bool,
) -> Vec<&'a SidRef> {
    memberships
        .iter()
        .map(|(sid, _)| sid.as_ref())
        .filter(|sid| primary_group_asserted || *sid != primary_group)
        .collect()
}

/// The relative id a source gave a group, or 0 if it named no number for it.
///
/// 0 is what the protocol already means by "this source does not number this
/// group", so a group the source never mentioned at all -- one authd stapled on
/// -- lands on the same answer without a separate case.
fn asserted_relative(memberships: &[(Sid, u32)], sid: &SidRef) -> u32 {
    memberships
        .iter()
        .find(|(candidate, _)| candidate.as_ref().as_bytes() == sid.as_bytes())
        .map_or(0, |(_, relative)| *relative)
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

/// Whether a request repeats a `credential_ref`.
///
/// Obligation 20: the refs in one request are unique. Nothing checked, so a
/// source sending duplicates was relayed verbatim and the client's answers
/// became ambiguous — two prompts asking for different things, one ref to
/// carry both answers back under.
///
/// Vacuous against lpsd, which only ever sends one prompt. It is a source
/// obligation, and a source is the thing a third party is invited to write.
fn duplicate_credential_ref(request: &CredentialRequest) -> Option<u32> {
    let mut seen = Vec::with_capacity(request.prompts.len());
    for prompt in &request.prompts {
        if seen.contains(&prompt.credential_ref) {
            return Some(prompt.credential_ref);
        }
        seen.push(prompt.credential_ref);
    }
    None
}

enum ClientFailed {
    Protocol(Denial, &'static str),
    Io(io::Error),
}

/// Whether an I/O error is the client running out of answering time.
///
/// `CLIENT_TIMEOUT` is installed as `SO_RCVTIMEO`, so a client that sits at the
/// prompt too long surfaces here as `WouldBlock` (or `TimedOut` on some
/// platforms) rather than as a broken connection. PGSS authority obligation 11
/// requires that case to end in a terminal `AccessDenied` carrying
/// `ConversationLimit` rather than a silent close, so a client can distinguish
/// a policy limit from a crash.
///
/// It matters because client obligation 4 requires an abnormal close to be
/// treated as a failed logon and **not** retried automatically. A principal who
/// simply took too long at the prompt was getting the treatment reserved for
/// "something is broken and we do not know what", and a greeter that would have
/// re-prompted on `ConversationLimit` did not.
fn is_read_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
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
    let (msg_type, _) = decode_header(received.expose()).map_err(|_| {
        ClientFailed::Protocol(Denial::MalformedRequest, "Malformed message header.")
    })?;
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

    // **Logon type restrictions.** The principal's own record says which kinds
    // of sign-on it may be used for, and the authority enforces it — a source
    // states the property and has no business acting on it.
    //
    // Checked here, after the credential held, rather than before asking. The
    // authority does not know which principal it is dealing with until the
    // source says so, and asking first would cost a lookup on every logon to
    // answer a question that almost never refuses.
    //
    // A source that predates the field says nothing, and nothing means the
    // authority's default rather than "nothing permitted": everything a person
    // could use, and never `Service`. So no existing principal changes
    // behaviour, and none becomes usable for a credential-free service logon
    // by an upgrade.
    if !assertion.permitted_logon_types.permits(start.logon_type) {
        log::warn(format_args!(
            "refused {:?} logon for {}: the principal permits {:#x}",
            start.logon_type,
            assertion.canonical_name,
            assertion.permitted_logon_types.effective().bits()
        ));
        return deny(
            stream,
            Denial::AccountRestricted,
            "That account may not be used for this kind of sign-on.",
        );
    }

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
    let mut memberships = drop_unassertable(memberships, &source_name);

    // The primary group. Empty means the source did not say, and Authenticated
    // Users is the answer: it is a membership authd derives for every principal
    // anyway, so naming it as primary asserts nothing new.
    //
    // Peios deliberately has no per-user group. That Linux convention exists so
    // a file's *group ownership* means something, and under KACS it means
    // nothing — every managed credential carries `CAP_DAC_OVERRIDE`.
    // Whether the primary group is the source's claim or authd's own default.
    // The distinction decides whether membership scope applies to it: PSI
    // authority obligation 26 says never to apply scope to a primary_group the
    // authority substituted itself for an empty field.
    //
    // Conflating the two cancelled two correct rules against each other. The
    // default is Authenticated Users, S-1-5-11 — a two-sub-authority NT SID —
    // and a principal is S-1-5-21-A-B-C-RID, so domain::siblings can never hold
    // between them. Every source that omitted primary_group therefore had every
    // logon denied, naming the source for a claim it never made. lpsd escaped
    // only because it always sets one *and* ships with
    // MayAssertForeignMemberships; a directory-backed source — exactly the case
    // that should not have that permission — hit it on its first logon.
    let primary_group_asserted = !assertion.primary_group.is_empty();
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

    let groups = scoped_groups(&memberships, primary_group.as_ref(), primary_group_asserted);

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

    // The SID set the token will carry, derived SIDs included. Built here
    // because everything below is a statement about *this* set rather than
    // about what the source sent: local policy is evaluated against it, and so
    // is the projection.
    let token_groups = derive::token_groups(user, &groups, start.logon_type);
    let token_sids: Vec<&SidRef> = token_groups.iter().map(|(sid, _)| sid.as_ref()).collect();

    // The POSIX numbers. Every id a source sends is *relative* to the range the
    // registry assigned it; this is where the base is added, and it is the only
    // place that may add it.
    //
    // Numbered from the token's groups rather than from the assertion. The
    // groups authd staples on -- Everyone, Local, the logon type -- are
    // numbered by authd's own table, which no source can speak for, so
    // numbering only what a source sent dropped them entirely: `Everyone` has
    // carried gid 100 in `well_known` from the start and `getgrgid(100)`
    // resolved it, yet no token this path minted ever carried that gid, and
    // `id`/`groups` reported a membership short. `attest::mint_and_send`
    // already numbered the token's own groups; this is that rule applied to
    // both paths rather than to one.
    let numbered: Vec<unix_id::Numbered<'_>> = token_groups
        .iter()
        .map(|(sid, _)| unix_id::Numbered {
            sid: sid.as_ref(),
            // What the source called it, where the source named it at all. A
            // stapled group has no relative id and needs none: `built_in`
            // answers for it first, and deliberately outranks a source.
            relative: asserted_relative(&memberships, sid.as_ref()),
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
        // A source checked a credential, which is evidence that does not stop
        // at this machine's edge.
        evidence: derive::Evidence::Verified,
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

    // The profile is not identity and decides no access — a home directory
    // appears in no ACL — but obligation 23 still requires the authority to
    // hold `home` and `shell` to the absolute-path rule. The client half is the
    // more serious one (a relative shell reaching execvp gets a PATH search),
    // and it is enforced in `login`; this is the other end of the same rule, so
    // a source that asserts a relative path is corrected here rather than
    // relied upon to be caught downstream.
    //
    // Cleared to empty rather than refused: an empty field already means "the
    // authority did not say", and every client already falls back for it. A
    // logon is not worth failing over a home directory.
    let mut profile = assertion.profile.clone();
    if !profile.home.is_empty() && !profile.home.starts_with('/') {
        log::warn(format_args!(
            "source {source_name} asserted a relative home {:?}; clearing it",
            profile.home
        ));
        profile.home.clear();
    }
    if !profile.shell.is_empty() && !profile.shell.starts_with('/') {
        log::warn(format_args!(
            "source {source_name} asserted a relative shell {:?}; clearing it",
            profile.shell
        ));
        profile.shell.clear();
    }

    // The home directory, if the profile names one and it is absent.
    //
    // After minting and after the absolute-path correction above, so
    // that a relative home has already been cleared and cannot reach
    // the filesystem; before the grant is sent, so the directory is
    // there by the time `login` chdirs into it. `login` cannot create it
    // itself — it has assumed the principal's token by then, and /home
    // grants Everyone traverse but not create.
    //
    // Never fatal: a logon is not worth failing over a directory.
    home::ensure(user, &profile.home);

    let message = encode_access_granted(&AccessGranted {
        session_id: granted.session.0,
        profile,
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

/// What a client opened with.
enum Opening {
    /// A logon conversation, which will exchange credentials.
    Logon(LogonStart),
    /// A service attestation, which will not. See [`crate::attest`].
    Attest(ServiceAttest),
}

/// Read and validate the opening message.
fn read_opening(stream: &UnixStream) -> Result<Opening, (Denial, &'static str)> {
    let received = recv_message(&wire::FRAMING, stream).map_err(|error| {
        // A client slow to send LogonStart was told its message was malformed,
        // which is both wrong and unactionable. A timeout is a policy limit.
        if is_read_timeout(&error) {
            (
                Denial::ConversationLimit,
                "The logon did not begin in time.",
            )
        } else {
            (
                Denial::MalformedRequest,
                "Could not read the opening message.",
            )
        }
    })?;

    // Obligation 6: a client speaking a version this build does not implement
    // is told so. `Denial::UnsupportedVersion` was defined and never sent,
    // because every WireError — that one included — was flattened into
    // MalformedRequest, so a future client was told its message was malformed
    // rather than that its version is not implemented.
    let (msg_type, _) = decode_header(received.expose()).map_err(|error| match error {
        wire::WireError::UnsupportedVersion(_) => (
            Denial::UnsupportedVersion,
            "This authority does not implement that protocol version.",
        ),
        _ => (Denial::MalformedRequest, "Malformed message header."),
    })?;
    match msg_type {
        MSG_LOGON_START => decode_logon_start(received.expose())
            .map(Opening::Logon)
            .map_err(|_| (Denial::MalformedRequest, "Malformed LogonStart.")),
        MSG_SERVICE_ATTEST => decode_service_attest(received.expose())
            .map(Opening::Attest)
            .map_err(|_| (Denial::MalformedRequest, "Malformed ServiceAttest.")),
        _ => Err((
            Denial::MalformedRequest,
            "A connection must open with LogonStart or ServiceAttest.",
        )),
    }
}

/// Are there bytes from the client already in the socket before we prompt?
///
/// A non-blocking `MSG_PEEK`: a positive count is the pipelined answer,
/// `EAGAIN` is the good answer (nothing pending), and `0` — the client
/// hung up — is left for the send/receive path to report as what it is
/// rather than as pipelining. Any error abstains: this is a
/// protocol-discipline check, not a security boundary, and failing a
/// logon over a socket errno would invert its purpose.
fn client_already_answered(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut probe = [0u8; 1];
    let received = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            probe.as_mut_ptr().cast(),
            probe.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    received > 0
}

/// Whether a principal may originate logons at all.
///
/// SYSTEM unconditionally, plus any peer whose policy record grants at
/// least one logon type. Widening the originator set is therefore a
/// registry edit — a `LogonTypes` list on the peer's record under
/// `Machine\Generic\Authn\Policy` — which is the visible, deliberate act
/// this check exists to require.
fn may_originate(peer: &Sid) -> bool {
    peer::is_system(peer)
        || policy::originator_logon_types(peer.as_ref()).is_some_and(|types| types.bits() != 0)
}

/// Whether a given originator may request a given logon type.
///
/// The constraint half of "client proposes, authority constrains" (PGSS
/// §2.4, obligation 15): `logon_type` selects a group SID the minted token
/// will carry, and derivation policy is evaluated against it, so the type
/// must be what the *peer* is permitted — not what it proposed. A greeter
/// granted `["Interactive"]` cannot mint itself a network-shaped token, and
/// a web console granted `["Network"]` cannot mint a console-shaped one.
///
/// SYSTEM is permitted every type, compiled in rather than configured:
/// SYSTEM administers the policy store, so a registry constraint on it
/// enforces nothing, and pretending otherwise would dress a non-control as
/// policy. Every other peer gets exactly what its record's `LogonTypes`
/// lists, and a peer with no record gets nothing — tested against the raw
/// bits, never [`LogonTypes::permits`], whose substitution of a default for
/// the empty set is right for a principal's own sign-on surface and wrong
/// for a grant.
fn may_request(peer: &Sid, logon_type: LogonType) -> bool {
    if peer::is_system(peer) {
        return true;
    }
    policy::originator_logon_types(peer.as_ref())
        .is_some_and(|types| types.bits() & (1 << logon_type as u32) != 0)
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

    fn sid_of(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    /// PSI obligation 26: membership scope never applies to a `primary_group`
    /// the authority substituted for an empty field.
    ///
    /// Before this, a source that omitted `primary_group` had *every* logon
    /// denied: authd substituted `S-1-5-11`, pushed it into the membership set
    /// so it could not bypass the scope check, and then failed its own check
    /// against it — because a two-sub-authority NT SID is never a sibling of an
    /// `S-1-5-21-A-B-C-RID` principal. lpsd escaped it only by always setting
    /// one *and* shipping with MayAssertForeignMemberships. A directory-backed
    /// source, which should not have that permission, hit it on first logon.
    #[test]
    fn an_authority_substituted_primary_group_is_not_scope_checked() {
        let user = sid_of("S-1-5-21-1-2-3-1000");
        let authenticated_users = sid_of("S-1-5-11");
        let memberships = vec![(authenticated_users, 0u32)];

        let substituted = scoped_groups(&memberships, authenticated_users.as_ref(), false);
        assert!(
            foreign_membership(user.as_ref(), &substituted).is_none(),
            "authd's own default must not be held against the source"
        );

        // Asserted by the source, the same SID *is* checked — otherwise the
        // exemption would be a bypass.
        let asserted = scoped_groups(&memberships, authenticated_users.as_ref(), true);
        assert!(
            foreign_membership(user.as_ref(), &asserted).is_some(),
            "a source-asserted foreign primary group must still be caught"
        );
    }

    /// The exemption covers only the substituted SID. Any other membership the
    /// source claimed is still checked.
    #[test]
    fn the_exemption_does_not_extend_to_other_memberships() {
        let user = sid_of("S-1-5-21-1-2-3-1000");
        let authenticated_users = sid_of("S-1-5-11");
        let builtin_admins = sid_of("S-1-5-32-544");
        let memberships = vec![(authenticated_users, 0u32), (builtin_admins, 0u32)];

        let groups = scoped_groups(&memberships, authenticated_users.as_ref(), false);
        assert_eq!(
            foreign_membership(user.as_ref(), &groups).map(|s| s.to_sid()),
            Some(builtin_admins),
            "a foreign group the source did claim must still be caught"
        );
    }

    /// Obligation 20: the `credential_ref`s in one request are unique. Nothing
    /// checked, so a source sending duplicates was relayed verbatim and the
    /// client's answers became ambiguous — two prompts asking for different
    /// things, one ref to carry both answers back under.
    #[test]
    fn a_repeated_credential_ref_is_caught() {
        let mut request = requesting(&[CredentialType::Password, CredentialType::Password]);
        assert_eq!(
            duplicate_credential_ref(&request),
            None,
            "distinct refs are the ordinary case"
        );
        request.prompts[1].credential_ref = request.prompts[0].credential_ref;
        assert_eq!(
            duplicate_credential_ref(&request),
            Some(request.prompts[0].credential_ref)
        );
    }

    #[test]
    fn a_single_prompt_and_an_empty_request_are_never_duplicates() {
        assert_eq!(
            duplicate_credential_ref(&requesting(&[CredentialType::Password])),
            None
        );
        assert_eq!(duplicate_credential_ref(&requesting(&[])), None);
    }

    /// Obligation 11 bounds the *time* a conversation may remain open, not only
    /// how many run at once. `CLIENT_TIMEOUT` is `SO_RCVTIMEO` and therefore
    /// per read, so a client sending one byte every 119 seconds reset it
    /// indefinitely and held one of 64 slots for as long as it liked.
    #[test]
    fn a_conversation_deadline_expires() {
        let past = Instant::now() - Duration::from_secs(1);
        assert!(expired(past), "a deadline already passed must be expired");

        let future = Instant::now() + Duration::from_secs(60);
        assert!(!expired(future), "a deadline still ahead must not be");
    }

    /// The ceiling has to sit above a well-behaved client's emergent worst
    /// case, or an honest slow logon is cut off — the point is to bound the
    /// deliberate case, not to tighten the honest one.
    #[test]
    fn the_deadline_leaves_room_for_a_well_behaved_client() {
        let emergent = (CLIENT_TIMEOUT + SOURCE_TIMEOUT) * MAX_ROUNDS;
        assert!(
            CONVERSATION_DEADLINE > emergent,
            "deadline {CONVERSATION_DEADLINE:?} must exceed the honest worst case {emergent:?}"
        );
    }

    /// Obligation 23: rules 4 and 5 run before rule 2.
    ///
    /// A logon SID is `S-1-5-5-X-Y` and a principal is `S-1-5-21-A-B-C-RID`, so
    /// membership scope can never accept one. Running scope first therefore
    /// refused the logon that rule 4 says to survive by dropping — the two
    /// rules gave opposite answers for the same input.
    #[test]
    fn an_asserted_logon_sid_is_dropped_before_the_scope_check_sees_it() {
        let user = sid_of("S-1-5-21-1-2-3-1000");
        let logon = sid_of("S-1-5-5-7-7");
        let staff = sid_of("S-1-5-21-1-2-3-1001");

        // The scope check would have caught the logon SID and refused.
        assert!(
            !crate::domain::siblings(user.as_ref(), logon.as_ref()),
            "the premise: a logon SID is never a sibling of its principal"
        );

        let kept = drop_unassertable(vec![(staff, 0), (logon, 0)], "corp");
        let groups = scoped_groups(&kept, staff.as_ref(), true);
        assert!(
            foreign_membership(user.as_ref(), &groups).is_none(),
            "the logon SID must be gone before scope runs, not refused by it"
        );
        assert_eq!(kept.len(), 1, "and the real membership must survive");
    }

    /// Rule 5. Harmless either way — a duplicate of a legitimate group passes
    /// scope anyway — but dropping it keeps what reaches the check equal to
    /// what the source is actually claiming.
    #[test]
    fn a_duplicate_membership_is_dropped() {
        let staff = sid_of("S-1-5-21-1-2-3-1001");
        let kept = drop_unassertable(vec![(staff, 0), (staff, 99)], "corp");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].1, 0, "the first occurrence wins");
    }

    /// A client that ran out of answering time is a policy limit, not a
    /// transport failure — PGSS obligation 11 requires it to end in a terminal
    /// ConversationLimit rather than a silent close.
    #[test]
    fn a_read_timeout_is_distinguished_from_a_transport_failure() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert!(is_read_timeout(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(!is_read_timeout(&io::Error::from(kind)), "{kind:?}");
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
