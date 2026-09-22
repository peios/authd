//! Changing the caller's own credential — PGSS Logon §2.20, relayed to the
//! owning source as PSI's change conversation (PSPU §2.21).
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
use libauthd::wire::{CredentialChangeStart, CredentialChanged, Denial, encode_credential_changed};
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
    log::info(format_args!("credential change started: peer={peer}"));

    let source = match route(registry, peer) {
        Route::Owner(source) => source,
        // SYSTEM, a platform service identity, anything no source holds.
        // There is no credential for this principal anywhere authd can reach.
        Route::Nobody => {
            log::info(format_args!(
                "refused a credential change for {peer}: no source holds it"
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
    // A source that does not change credentials still holds this principal, so
    // this is a statement about the account rather than an outage.
    if !source
        .capabilities()
        .contains(Capabilities::CHANGES_CREDENTIALS)
    {
        log::info(format_args!(
            "refused a credential change for {peer}: source {} does not change credentials",
            source.name()
        ));
        return deny(
            stream,
            Denial::AccountRestricted,
            "The credential for this account cannot be changed here.",
        );
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

    if let Err(error) = conversation.change_credential(start, peer.as_ref().as_bytes()) {
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
        &start.supported_credential_types,
        &mut conversation,
        deadline,
        Purpose::Change,
    )? {
        Some(Ended::Changed) => {
            let message = encode_credential_changed(&CredentialChanged)
                .map_err(|_| io::Error::other("could not encode a credential change"))?;
            send_message(stream, &message)?;
            log::info(format_args!(
                "credential changed: user={peer} source={}",
                conversation.source_name()
            ));
            Ok(())
        }
        // `relay` ends a change in `Changed` or in a denial it has already
        // sent. Answered anyway rather than trusted: a mistake there must cost
        // a denial, never a connection closed with nothing said — and never,
        // on this path, a token.
        Some(Ended::Asserted(_)) => deny(
            stream,
            Denial::Internal,
            "The authority could not complete the change.",
        ),
        None => Ok(()),
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
}
