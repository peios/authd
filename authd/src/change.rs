//! Changing the caller's own credential — PGSS Logon §2.20, relayed to the
//! owning source as PSI's change conversation (PSPU §2.21) — and its sibling,
//! adding a credential of one's own or removing one (PGSS §2.23, PSPU §2.23).
//! Everything below holds for both.
//!
//! # The principal is the peer
//!
//! Nothing in [`CredentialChangeStart`] names anybody. The credential that
//! changes is the one belonging to the user of the connected peer's token,
//! read from the socket in [`crate::conversation`] before the opening message
//! arrived. So a caller can only ever ask about themselves, and reaching this
//! socket — which every authenticated principal can — is not a way to try
//! somebody else's password.
//!
//! Holding a token for the principal is not taken as proof enough. A token says
//! someone signed in; it does not say the person at the keyboard now is them.
//! The source asks for the current credential inside the conversation, as the
//! protocol requires, and this module only relays.
//!
//! # Nothing is minted
//!
//! The one successful end is [`CredentialChanged`], which carries no token and
//! no session. The relay is shared with logons, and [`Purpose::Change`] is what
//! stops a source ending this conversation with an assertion authd would mint
//! from.

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use libauthd::psi::Capabilities;
use libauthd::transport::send_message;
use libauthd::wire::{
    CredentialChangeStart, CredentialChanged, CredentialEnrollStart, CredentialType, Denial,
    EnrollAction, encode_credential_changed,
};
use peios::security::Sid;

use crate::conversation::{Ended, Purpose, deny, relay};
use crate::log;
use crate::source::{Registry, Source};

/// Which source answers for a principal's credential.
enum Route {
    /// The source whose domain holds the principal.
    Owner(Arc<Source>),
    /// No registered source holds it, and none is missing that might.
    Nobody,
    /// No registered source holds it, but a configured one is not here — and
    /// could be the one that does.
    Unavailable,
}

/// A SID names its own domain, so the owner needs no search and no name: the
/// one registered source authoritative for the domain, or nobody.
///
/// An absent configured source makes "nobody" unsayable. Its domain is not
/// known while it is away, so a principal it holds would look ownerless, and
/// telling that principal their account has no credential to change would turn
/// an outage into a statement about their account.
fn route(registry: &Registry, principal: &Sid) -> Route {
    match registry.owning(principal.as_ref()) {
        Some(source) => Route::Owner(source),
        None if registry.complete() => Route::Nobody,
        None => Route::Unavailable,
    }
}

/// Which of the two conversations this module relays.
#[derive(Clone, Copy)]
enum Request<'a> {
    /// PGSS §2.20: replace the credential.
    Change(&'a CredentialChangeStart),
    /// PGSS §2.23: add a credential beside it, or remove one.
    Enroll(&'a CredentialEnrollStart),
}

impl Request<'_> {
    fn supported(&self) -> &[CredentialType] {
        match self {
            Request::Change(start) => &start.supported_credential_types,
            Request::Enroll(start) => &start.supported_credential_types,
        }
    }

    fn purpose(&self) -> Purpose {
        match self {
            Request::Change(_) => Purpose::Change,
            Request::Enroll(_) => Purpose::Enroll,
        }
    }

    fn describe(&self) -> &'static str {
        match self {
            Request::Change(_) => "credential change",
            Request::Enroll(start) => match start.action {
                EnrollAction::Add => "credential enrolment",
                EnrollAction::Remove => "credential removal",
            },
        }
    }
}

/// Serve one change conversation to its terminal message.
///
/// `peer` is the verified user of the connected peer's token, and the only
/// principal this conversation can change.
pub fn serve(
    registry: &Registry,
    stream: &UnixStream,
    peer: &Sid,
    start: &CredentialChangeStart,
    deadline: Instant,
) -> io::Result<()> {
    serve_request(registry, stream, peer, Request::Change(start), deadline)
}

/// Serve one enrolment conversation (PGSS §2.23) to its terminal message:
/// adding a credential to `peer`'s own principal, or removing one.
///
/// Routed, gated and relayed as a change is, with one difference at the gate:
/// a source that does not declare `ENROLLS_CREDENTIALS` is refused as
/// `PermissionDenied`, the answer §2.23 gives for an authority that does not
/// offer enrolment — because for this principal, it does not.
pub fn serve_enroll(
    registry: &Registry,
    stream: &UnixStream,
    peer: &Sid,
    start: &CredentialEnrollStart,
    deadline: Instant,
) -> io::Result<()> {
    serve_request(registry, stream, peer, Request::Enroll(start), deadline)
}

fn serve_request(
    registry: &Registry,
    stream: &UnixStream,
    peer: &Sid,
    request: Request<'_>,
    deadline: Instant,
) -> io::Result<()> {
    let what = request.describe();
    log::info(format_args!("{what} started: peer={peer}"));

    let source = match route(registry, peer) {
        Route::Owner(source) => source,
        // SYSTEM, a platform service identity, anything no source holds.
        // There is no credential for this principal anywhere authd can reach.
        Route::Nobody => {
            log::info(format_args!(
                "refused a {what} for {peer}: no source holds it"
            ));
            return deny(
                stream,
                Denial::AccountRestricted,
                "This account has no credential that can be changed here.",
            );
        }
        Route::Unavailable => {
            return deny(
                stream,
                Denial::AuthorityUnavailable,
                "The authority could not be reached.",
            );
        }
    };

    // PSI §2.8: never send a source a message it did not declare it answers.
    //
    // A source that does not change credentials still holds this principal, so
    // that refusal is a statement about the account rather than an outage. One
    // that does not enrol them is refused as §2.23 refuses an authority that
    // does not offer enrolment: for this principal, this authority does not.
    let (needed, denial, reason) = match request {
        Request::Change(_) => (
            Capabilities::CHANGES_CREDENTIALS,
            Denial::AccountRestricted,
            "The credential for this account cannot be changed here.",
        ),
        Request::Enroll(_) => (
            Capabilities::ENROLLS_CREDENTIALS,
            Denial::PermissionDenied,
            "Keys for this account cannot be added or removed here.",
        ),
    };
    if !source.capabilities().contains(needed) {
        log::info(format_args!(
            "refused a {what} for {peer}: source {} does not declare it",
            source.name()
        ));
        return deny(stream, denial, reason);
    }

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

    let principal = peer.as_ref().as_bytes();
    let opened = match request {
        Request::Change(start) => conversation.change_credential(start, principal),
        Request::Enroll(start) => conversation.enroll_credential(start, principal),
    };
    if let Err(error) = opened {
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

    match relay(
        stream,
        request.supported(),
        &mut conversation,
        deadline,
        request.purpose(),
    )? {
        Ok(Ended::Changed) => {
            let message = encode_credential_changed(&CredentialChanged)
                .map_err(|_| io::Error::other("could not encode a credential change"))?;
            send_message(stream, &message)?;
            log::info(format_args!(
                "{what} done: user={peer} source={}",
                conversation.source_name()
            ));
            Ok(())
        }
        // `relay` ends a change in `Changed` or in a denial it has already
        // sent. Answered anyway rather than trusted: a mistake there must cost
        // a denial, never a connection closed with nothing said — and never,
        // on this path, a token.
        Ok(Ended::Asserted(_)) => deny(
            stream,
            Denial::Internal,
            "The authority could not complete the change.",
        ),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;
    use crate::source::pump_for_test;
    use libauthd::psi;
    use libauthd::transport::recv_message;
    use libauthd::wire::{
        self, CredentialType, MSG_ACCESS_DENIED, MSG_CREDENTIAL_CHANGED, decode_access_denied,
        decode_header,
    };
    use std::time::Duration;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    fn start() -> CredentialChangeStart {
        CredentialChangeStart {
            supported_credential_types: vec![CredentialType::Password],
        }
    }

    /// A registry with one live source for `S-1-5-21-1-2-3`, declaring
    /// `capabilities`, and the far end of its PSI connection.
    fn with_source(capabilities: Capabilities) -> (Registry, Arc<Source>, UnixStream) {
        let registry = Registry::for_test(&[("lpsd", policy::sources::DEFAULT_SEARCH_ORDER, None)]);
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let source = registry.admit_for_test(
            "lpsd",
            sid("S-1-5-21-1-2-3"),
            None,
            capabilities,
            policy::sources::DEFAULT_SEARCH_ORDER,
            ours,
        );
        pump_for_test(&source);
        (registry, source, theirs)
    }

    /// Run [`serve`] against a client socket, returning the client's end.
    fn serve_for(registry: &Registry, peer: &Sid) -> (UnixStream, io::Result<()>) {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let deadline = Instant::now() + Duration::from_secs(60);
        let result = serve(registry, &server, peer, &start(), deadline);
        (client, result)
    }

    fn denial(client: &UnixStream) -> Denial {
        let received = recv_message(&wire::FRAMING, client).expect("a terminal message");
        let (msg_type, _) = decode_header(received.expose()).expect("a header");
        assert_eq!(msg_type, MSG_ACCESS_DENIED, "expected a denial");
        decode_access_denied(received.expose())
            .expect("a denial")
            .denial
    }

    #[test]
    fn a_principal_no_source_holds_is_refused_as_restricted() {
        let (registry, _source, _psi) = with_source(Capabilities::CHANGES_CREDENTIALS);
        let (client, result) = serve_for(&registry, &sid("S-1-5-18"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AccountRestricted);
    }

    /// An absent source could be the one holding this principal, so the answer
    /// is an outage and never "this account has nothing to change".
    #[test]
    fn a_missing_configured_source_is_unavailable_rather_than_nobody() {
        let registry = Registry::for_test(&[("lpsd", policy::sources::DEFAULT_SEARCH_ORDER, None)]);
        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AuthorityUnavailable);
    }

    /// PSI §2.8: a source is never sent a message it did not declare it
    /// answers. It holds the principal, so the refusal is about the account.
    #[test]
    fn a_source_that_does_not_change_credentials_is_not_asked() {
        let (registry, _source, psi_end) = with_source(Capabilities::QUERIES);
        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AccountRestricted);

        psi_end
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        assert!(
            recv_message(&psi::FRAMING, &psi_end).is_err(),
            "the source must have been sent nothing"
        );
    }

    /// The whole path: the change reaches the owning source naming the peer,
    /// and the source's `CredentialChanged` reaches the client as one — with no
    /// descriptor, because nothing was minted.
    #[test]
    fn a_change_the_source_completes_reaches_the_client() {
        let (registry, _source, psi_end) = with_source(Capabilities::CHANGES_CREDENTIALS);
        let peer = sid("S-1-5-21-1-2-3-1000");

        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("a change");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            assert_eq!(envelope.msg_type, psi::MSG_CHANGE_CREDENTIAL);
            let change = psi::decode_change_credential(received.expose()).expect("decodes");
            let reply = psi::encode_credential_changed(envelope.conversation).expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
            change.principal
        });

        let (client, result) = serve_for(&registry, &peer);
        result.expect("served");
        let asked_about = fake_source.join().expect("the fake source");
        assert_eq!(
            asked_about,
            peer.as_ref().as_bytes(),
            "the source must be told the peer"
        );

        let (received, descriptor) =
            libauthd::transport::recv_message_with_fd(&wire::FRAMING, &client).expect("terminal");
        let (msg_type, _) = decode_header(received.expose()).expect("a header");
        assert_eq!(msg_type, MSG_CREDENTIAL_CHANGED);
        assert!(descriptor.is_none(), "a change must hand over no token");
    }

    /// The case the purpose check exists for: a source answering a change with
    /// an assertion must get a denial, never a grant.
    #[test]
    fn an_assertion_on_a_change_is_refused() {
        let (registry, _source, psi_end) = with_source(Capabilities::CHANGES_CREDENTIALS);

        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("a change");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            let reply = psi::encode_assertion(
                envelope.conversation,
                &psi::Assertion {
                    authenticated_credential_type: None,

                    user_sid: sid("S-1-5-21-1-2-3-1000").as_ref().as_bytes().to_vec(),
                    canonical_name: "jack".into(),
                    ..psi::Assertion::default()
                },
            )
            .expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
        });

        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        fake_source.join().expect("the fake source");
        assert_eq!(denial(&client), Denial::Internal);
    }

    /// NoSuchSession answers only a request to end a session, which no source
    /// is asked; from a source it is never relayed (PSPU §2.13).
    #[test]
    fn a_sources_no_such_session_is_not_relayed() {
        let (registry, _source, psi_end) = with_source(Capabilities::CHANGES_CREDENTIALS);

        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("a change");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            let reply = psi::encode_refusal(
                envelope.conversation,
                &psi::Refusal {
                    denial: Denial::NoSuchSession,
                    reason: "No such session.".into(),
                },
            )
            .expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
        });

        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        fake_source.join().expect("the fake source");
        assert_eq!(denial(&client), Denial::Internal);
    }

    /// A source's refusal is relayed, code and all.
    #[test]
    fn a_refusal_is_relayed() {
        let (registry, _source, psi_end) = with_source(Capabilities::CHANGES_CREDENTIALS);

        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("a change");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            let reply = psi::encode_refusal(
                envelope.conversation,
                &psi::Refusal {
                    denial: Denial::AuthenticationFailed,
                    reason: "Authentication failed.".into(),
                },
            )
            .expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
        });

        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        fake_source.join().expect("the fake source");
        assert_eq!(denial(&client), Denial::AuthenticationFailed);
    }

    // -- Enrolment (PGSS §2.23) -------------------------------------------

    const KEY_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample laptop";

    fn enroll_start() -> CredentialEnrollStart {
        CredentialEnrollStart {
            supported_credential_types: vec![CredentialType::Password],
            action: EnrollAction::Add,
            credential_type: CredentialType::SshPublicKey,
            material: KEY_LINE.into(),
        }
    }

    fn enroll_for(registry: &Registry, peer: &Sid) -> (UnixStream, io::Result<()>) {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let deadline = Instant::now() + Duration::from_secs(60);
        let result = serve_enroll(registry, &server, peer, &enroll_start(), deadline);
        (client, result)
    }

    fn nothing_sent(psi_end: &UnixStream) {
        psi_end
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        assert!(
            recv_message(&psi::FRAMING, psi_end).is_err(),
            "the source must have been sent nothing"
        );
    }

    /// PSI §2.8: a source that changes passwords but does not declare
    /// enrolment is sent nothing, and the client hears what an authority that
    /// does not offer enrolment says (§2.23).
    #[test]
    fn a_source_that_does_not_enrol_is_not_asked() {
        let (registry, _source, psi_end) = with_source(Capabilities::CHANGES_CREDENTIALS);
        let (client, result) = enroll_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::PermissionDenied);
        nothing_sent(&psi_end);
    }

    /// And the reverse: declaring enrolment does not make a source one that
    /// changes passwords.
    #[test]
    fn enrolment_does_not_imply_change() {
        let (registry, _source, psi_end) = with_source(Capabilities::ENROLLS_CREDENTIALS);
        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AccountRestricted);
        nothing_sent(&psi_end);
    }

    #[test]
    fn an_enrolment_for_a_principal_no_source_holds_is_restricted() {
        let (registry, _source, psi_end) = with_source(Capabilities::ENROLLS_CREDENTIALS);
        let (client, result) = enroll_for(&registry, &sid("S-1-5-18"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AccountRestricted);
        nothing_sent(&psi_end);
    }

    #[test]
    fn an_enrolment_with_a_configured_source_missing_is_unavailable() {
        let registry = Registry::for_test(&[("lpsd", policy::sources::DEFAULT_SEARCH_ORDER, None)]);
        let (client, result) = enroll_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        assert_eq!(denial(&client), Denial::AuthorityUnavailable);
    }

    /// The whole path: the enrolment reaches the owning source naming the
    /// peer and carrying the material, the proof round is relayed, and the
    /// source's `CredentialChanged` reaches the client with no descriptor.
    #[test]
    fn an_enrolment_the_source_completes_reaches_the_client() {
        let (registry, _source, psi_end) = with_source(Capabilities::ENROLLS_CREDENTIALS);
        let peer = sid("S-1-5-21-1-2-3-1000");

        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("an enrolment");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            assert_eq!(envelope.msg_type, psi::MSG_ENROLL_CREDENTIAL);
            let enroll = psi::decode_enroll_credential(received.expose()).expect("decodes");

            // The proof round, relayed to the client and back.
            let ask = psi::encode_credential_request(
                envelope.conversation,
                &libauthd::wire::CredentialRequest {
                    messages: Vec::new(),
                    prompts: vec![libauthd::wire::Prompt {
                        parameters: Vec::new(),
                        credential_ref: 1,
                        credential_type: CredentialType::Password,
                        credential_name: "Current password".into(),
                    }],
                },
            )
            .expect("encodes");
            libauthd::transport::send_message(&psi_end, &ask).expect("sends");
            let answer = recv_message(&psi::FRAMING, &psi_end).expect("an answer");
            let response = psi::decode_credential_response(answer.expose()).expect("decodes");
            assert_eq!(response.answers[0].data.expose(), b"old");

            let reply = psi::encode_credential_changed(envelope.conversation).expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
            enroll
        });

        let (client, server) = UnixStream::pair().expect("socketpair");
        let answering = std::thread::spawn(move || {
            let request = recv_message(&wire::FRAMING, &client).expect("the proof prompt");
            let (msg_type, _) = decode_header(request.expose()).expect("a header");
            assert_eq!(msg_type, wire::MSG_CREDENTIAL_REQUEST);
            let response = wire::encode_credential_response(&libauthd::wire::CredentialResponse {
                answers: vec![libauthd::wire::Answer {
                    credential_ref: 1,
                    data: libauthd::Secret::from_slice(b"old"),
                }],
            })
            .expect("encodes");
            libauthd::transport::send_message(&client, response.expose()).expect("sends");
            let (terminal, descriptor) =
                libauthd::transport::recv_message_with_fd(&wire::FRAMING, &client)
                    .expect("terminal");
            let (msg_type, _) = decode_header(terminal.expose()).expect("a header");
            (msg_type, descriptor.is_none())
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        serve_enroll(&registry, &server, &peer, &enroll_start(), deadline).expect("served");

        let enroll = fake_source.join().expect("the fake source");
        assert_eq!(enroll.principal, peer.as_ref().as_bytes(), "the peer, from the socket");
        assert_eq!(enroll.start, enroll_start(), "the opening, nested whole");
        let (msg_type, no_descriptor) = answering.join().expect("the client");
        assert_eq!(msg_type, MSG_CREDENTIAL_CHANGED);
        assert!(no_descriptor, "an enrolment hands over no token");
    }

    fn refusing_with(
        denial: Denial,
        capabilities: Capabilities,
    ) -> (Registry, std::thread::JoinHandle<()>) {
        let (registry, _source, psi_end) = with_source(capabilities);
        let fake_source = std::thread::spawn(move || {
            let received = recv_message(&psi::FRAMING, &psi_end).expect("an opening");
            let envelope = psi::decode_envelope(received.expose()).expect("an envelope");
            let reply = psi::encode_refusal(
                envelope.conversation,
                &psi::Refusal {
                    denial,
                    reason: "That is not an SSH public key this machine accepts.".into(),
                },
            )
            .expect("encodes");
            libauthd::transport::send_message(&psi_end, &reply).expect("sends");
        });
        (registry, fake_source)
    }

    /// `CredentialRejected` answers an enrolment, and is relayed there...
    #[test]
    fn a_rejected_credential_is_relayed_on_an_enrolment() {
        let (registry, fake_source) = refusing_with(
            Denial::CredentialRejected,
            Capabilities::ENROLLS_CREDENTIALS,
        );
        let (client, result) = enroll_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        fake_source.join().expect("the fake source");
        assert_eq!(denial(&client), Denial::CredentialRejected);
    }

    /// ...and nowhere else: a change offered no material to reject.
    #[test]
    fn a_rejected_credential_is_not_relayed_on_a_change() {
        let (registry, fake_source) = refusing_with(
            Denial::CredentialRejected,
            Capabilities::CHANGES_CREDENTIALS,
        );
        let (client, result) = serve_for(&registry, &sid("S-1-5-21-1-2-3-1000"));
        result.expect("served");
        fake_source.join().expect("the fake source");
        assert_eq!(denial(&client), Denial::Internal);
    }
}
