use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use auth_core::{ident, wire};
use auth_core::transport::{recv_message, send_message};
use peios_auth::{Answer, Capabilities, Client, IdentityKind, Key, Options, Progress};

static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

#[test]
fn rust_wrapper_drives_the_shared_library_and_preserves_failure_details() {
    let path = format!(
        "/tmp/auth-rust-{}-{}",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    );
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let opening = recv_message(&wire::FRAMING, &socket).unwrap();
        wire::decode_credential_change_start(opening.expose()).unwrap();
        send_message(
            &socket,
            &wire::encode_credential_request(&wire::CredentialRequest {
                messages: Vec::new(),
                prompts: vec![wire::Prompt {
                    parameters: Vec::new(),
                    credential_ref: 9,
                    credential_type: wire::CredentialType::Password,
                    credential_name: "Current password".into(),
                }],
            })
            .unwrap(),
        )
        .unwrap();
        let answer = recv_message(&wire::FRAMING, &socket).unwrap();
        assert_eq!(
            wire::decode_credential_response(answer.expose())
                .unwrap()
                .answers[0]
                .data
                .expose(),
            b"wrong"
        );
        send_message(
            &socket,
            &wire::encode_access_denied(&wire::AccessDenied {
                denial: wire::Denial::AuthenticationFailed,
                reason: "Authentication failed".into(),
            })
            .unwrap(),
        )
        .unwrap();
    });
    let client = Client::with_options(Options {
        logon_socket: &path,
        ..Options::default()
    })
    .unwrap();
    let mut operation = client.change_password(Capabilities::PASSWORD).unwrap();
    drop(client);
    assert_eq!(operation.wait().unwrap(), Progress::Prompt);
    let round = operation.round().unwrap();
    assert!(round.prompts[0].secret);
    operation
        .respond(
            round.id,
            &[Answer {
                credential_ref: 9,
                data: b"wrong",
            }],
        )
        .unwrap();
    let error = operation.wait().unwrap_err();
    assert_eq!(error.category, 6);
    assert_eq!(error.code, wire::Denial::AuthenticationFailed as u32);
    assert!(!error.outcome_unknown);
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}

#[test]
fn identity_results_are_owned_and_survive_operation_destruction() {
    let path = format!(
        "/tmp/auth-rust-{}-{}",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    );
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let message = recv_message(&wire::FRAMING, &socket).unwrap();
        let request = ident::decode_lookup(message.expose()).unwrap();
        send_message(
            &socket,
            &ident::encode_lookup_reply(&ident::LookupReply {
                tag: request.tag,
                outcome: ident::Outcome::Found,
                record: Some(ident::Record {
                    sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                    qualified_name: "local\\jack".into(),
                    kind_found: ident::Kind::Principal,
                    values: vec![
                        ident::Value::DisplayName("Jack".into()),
                        ident::Value::Claims(vec![auth_core::Claim {
                            name: "team".into(),
                            flags: 0,
                            values: auth_core::claim::Values::String(vec!["engineering".into()]),
                        }]),
                    ],
                    withheld: vec![ident::Withheld {
                        field: ident::Fields::MEMBERS,
                        reason: ident::WithheldReason::Restricted,
                    }],
                }),
            })
            .unwrap(),
        )
        .unwrap();
    });
    let client = Client::with_options(Options {
        identity_socket: &path,
        ..Options::default()
    })
    .unwrap();
    let mut operation = client
        .lookup(
            Key::Name("jack"),
            IdentityKind::Principal,
            peios_auth::fields::ALL,
        )
        .unwrap();
    assert_eq!(operation.wait().unwrap(), Progress::Complete);
    let identity = operation.identity().unwrap();
    drop(operation);
    assert_eq!(identity.records[0].name, "local\\jack");
    assert!(matches!(
        identity.records[0].fields[&peios_auth::fields::MEMBERS],
        peios_auth::Field::Withheld(2)
    ));
    let peios_auth::Field::Claims(claims) =
        &identity.records[0].fields[&peios_auth::fields::CLAIMS]
    else {
        panic!("claims missing");
    };
    assert!(
        matches!(&claims[0].values[0], peios_auth::ClaimValue::Text(text) if text == "engineering")
    );
    server.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
