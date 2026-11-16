//! Run only in a disposable Peios guest. Accounts and policy are fixtures;
//! this program never creates a token or installs somebody else's identity.

use std::os::unix::net::UnixStream;
use std::time::Duration;
use auth_core::transport::{recv_message_with_fd, send_message};
use auth_core::wire::*;
use auth_core::Secret;

#[derive(Clone, Copy, Debug)]
enum ClaimAccess {
    All,
    Restricted,
    DepartmentDenied,
}

fn identity_checks(socket: &UnixStream, access: ClaimAccess) {
    use auth_core::ident::{self, Fields, Kind, Outcome, Value, WithheldReason};
    let allowed = matches!(access, ClaimAccess::All);
    let fields = Fields::UNIX_ID | Fields::GROUPS | Fields::CLAIMS;
    let check = |record: &ident::Record| {
        assert!(record.value(Fields::UNIX_ID).is_some());
        assert!(matches!(record.value(Fields::GROUPS), Some(Value::Groups(g)) if !g.is_empty()));
        if allowed {
            let Some(Value::Claims(claims)) = record.value(Fields::CLAIMS) else {
                panic!("authorized lookup did not return claims")
            };
            assert!(
                claims
                    .iter()
                    .any(|claim| claim.name.eq_ignore_ascii_case("Department"))
            );
            assert!(record.reason(Fields::CLAIMS).is_none());
        } else {
            assert!(record.value(Fields::CLAIMS).is_none());
            assert_eq!(
                record.reason(Fields::CLAIMS),
                Some(WithheldReason::Restricted)
            );
        }
    };
    send_message(
        socket,
        &ident::encode_lookup(&ident::Lookup {
            tag: 1,
            key: ident::Key::Name("dev-auth".into()),
            kind: Kind::Principal,
            fields,
        })
        .unwrap(),
    )
    .unwrap();
    let (reply, fd) = recv_message_with_fd(&FRAMING, socket).unwrap();
    assert!(fd.is_none());
    let reply = ident::decode_lookup_reply(reply.expose()).unwrap();
    assert_eq!(reply.tag, 1);
    assert_eq!(reply.outcome, Outcome::Found);
    check(reply.record.as_ref().unwrap());

    for of in [None, Some(ident::Key::Name("developers".into()))] {
        let mut cursor = Vec::new();
        let mut found = false;
        for _ in 0..100 {
            send_message(
                socket,
                &ident::encode_enumerate(&ident::Enumerate {
                    tag: 2,
                    kind: Kind::Principal,
                    fields,
                    of: of.clone(),
                    cursor,
                })
                .unwrap(),
            )
            .unwrap();
            let (reply, fd) = recv_message_with_fd(&FRAMING, socket).unwrap();
            assert!(fd.is_none());
            let reply = ident::decode_enumerate_reply(reply.expose()).unwrap();
            assert_eq!(reply.tag, 2);
            assert_eq!(reply.outcome, Outcome::Found);
            assert!(reply.incomplete.is_empty());
            for record in &reply.entries {
                if record.qualified_name == "dev-auth" {
                    check(record);
                    found = true;
                }
                if matches!(access, ClaimAccess::Restricted) {
                    assert!(record.value(Fields::CLAIMS).is_none());
                    assert_eq!(
                        record.reason(Fields::CLAIMS),
                        Some(WithheldReason::Restricted)
                    );
                } else if matches!(access, ClaimAccess::DepartmentDenied)
                    && let Some(Value::Claims(claims)) = record.value(Fields::CLAIMS)
                {
                    assert!(
                        !claims
                            .iter()
                            .any(|claim| claim.name.eq_ignore_ascii_case("Department"))
                    );
                }
            }
            cursor = reply.next;
            if cursor.is_empty() {
                break;
            }
        }
        assert!(cursor.is_empty(), "unbounded enumeration");
        assert!(found, "enumeration did not return the fixture principal");
    }
    println!(
        "NATIVE IDENTITY: lookup, enumeration and membership claims={access:?}; public fields preserved"
    );
}

fn request(name: &str, claims: &[&str], groups: bool) -> AuthenticateStart {
    AuthenticateStart {
        authentication: AuthenticationRequest {
            identifier_type: IdentifierType::Username,
            identifier: name.as_bytes().to_vec(),
            supported_credential_types: vec![CredentialType::Password],
            required_credential_type: Some(CredentialType::Password),
            ssh_binding: None,
        },
        disclosure: DisclosureRequest {
            groups,
            claims: if claims.is_empty() {
                auth_core::wire::ClaimSelection::None
            } else {
                auth_core::wire::ClaimSelection::Named(
                    claims.iter().map(|s| (*s).to_owned()).collect(),
                )
            },
        },
    }
}

fn converse(start: &AuthenticateStart, password: &str) -> Result<Authenticated, Denial> {
    let socket = UnixStream::connect(auth_core::LOGON_SOCKET_PATH).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    send_message(&socket, &encode_authenticate_start(start).unwrap()).unwrap();
    for _ in 0..10 {
        let (message, fd) = recv_message_with_fd(&FRAMING, &socket).unwrap();
        assert!(fd.is_none(), "Authenticate delivered a descriptor");
        match decode_header(message.expose()).unwrap().0 {
            MSG_CREDENTIAL_REQUEST => {
                let challenge = decode_credential_request(message.expose()).unwrap();
                let answers = challenge
                    .prompts
                    .iter()
                    .map(|prompt| {
                        assert_eq!(prompt.credential_type, CredentialType::Password);
                        Answer {
                            credential_ref: prompt.credential_ref,
                            data: Secret::from_slice(password.as_bytes()),
                        }
                    })
                    .collect();
                let response = encode_credential_response(&CredentialResponse { answers }).unwrap();
                send_message(&socket, response.expose()).unwrap();
            }
            MSG_AUTHENTICATED => {
                let result = decode_authenticated(message.expose()).unwrap();
                result.validate_for(start).unwrap();
                return Ok(result);
            }
            MSG_ACCESS_DENIED => {
                return Err(decode_access_denied(message.expose()).unwrap().denial);
            }
            other => panic!("unexpected reply {other}"),
        }
    }
    panic!("unbounded credential conversation")
}

fn immediate_denial(message: &[u8], expected: Denial) {
    let socket = UnixStream::connect(auth_core::LOGON_SOCKET_PATH).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    send_message(&socket, message).unwrap();
    let (reply, fd) = recv_message_with_fd(&FRAMING, &socket).unwrap();
    assert!(fd.is_none());
    assert_eq!(
        decode_access_denied(reply.expose()).unwrap().denial,
        expected,
        "the request must fail before any credential prompt"
    );
}

fn local_logon(kind: LogonType) -> Result<AccessGranted, Denial> {
    let expected = converse(
        &request("dev-auth", &[], false),
        "development-only-password",
    )
    .unwrap();
    let socket = UnixStream::connect(auth_core::LOGON_SOCKET_PATH).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let opening = encode_logon_start(&LogonStart {
        authentication: request("dev-auth", &[], false).authentication,
        logon_type: kind,
        tty: None,
        remote_host: None,
    })
    .unwrap();
    send_message(&socket, &opening).unwrap();
    for _ in 0..10 {
        let (message, fd) = recv_message_with_fd(&FRAMING, &socket).unwrap();
        match decode_header(message.expose()).unwrap().0 {
            MSG_CREDENTIAL_REQUEST => {
                assert!(fd.is_none());
                let challenge = decode_credential_request(message.expose()).unwrap();
                let answers = challenge
                    .prompts
                    .iter()
                    .map(|prompt| Answer {
                        credential_ref: prompt.credential_ref,
                        data: Secret::from_slice(b"development-only-password"),
                    })
                    .collect();
                send_message(
                    &socket,
                    encode_credential_response(&CredentialResponse { answers })
                        .unwrap()
                        .expose(),
                )
                .unwrap();
            }
            MSG_ACCESS_GRANTED => {
                let grant = decode_access_granted(message.expose()).unwrap();
                let token = peios::token::Token::from(fd.expect("Logon must deliver a token"));
                assert_eq!(token.auth_id().unwrap().0, grant.session_id);
                assert_eq!(token.user().unwrap().as_ref().as_bytes(), expected.user_sid);
                assert!(std::path::Path::new("/home/dev-auth").is_dir());
                return Ok(grant);
            }
            MSG_ACCESS_DENIED => {
                assert!(fd.is_none());
                return Err(decode_access_denied(message.expose()).unwrap().denial);
            }
            other => panic!("unexpected Logon reply {other}"),
        }
    }
    panic!("unbounded Logon conversation")
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "allowed".into());
    if matches!(
        mode.as_str(),
        "all-complete" | "all-filtered" | "all-denied-claim"
    ) {
        for name in ["dev-auth", "dev-state"] {
            let mut start = request(name, &[], false);
            start.disclosure.claims = ClaimSelection::AllPermitted;
            let result = converse(&start, "development-only-password").unwrap();
            result.validate_for(&start).unwrap();
            assert!(result.absent_claims.is_empty());
            assert_eq!(
                result.claim_coverage,
                if mode == "all-complete" {
                    ClaimCoverage::Complete
                } else {
                    ClaimCoverage::Filtered
                }
            );
            let has = |name: &str| {
                result
                    .claims
                    .iter()
                    .any(|claim| claim.name.eq_ignore_ascii_case(name))
            };
            if name == "dev-auth" {
                assert_eq!(has("Department"), mode != "all-denied-claim");
                assert_eq!(has("Salary"), mode != "all-filtered");
            } else {
                assert!(result.claims.is_empty());
            }
        }
        println!("NATIVE DISCLOSURE: {mode} passed; omitted names are not reported absent");
        return;
    }
    if mode == "scoped-only" || mode == "scoped-groups" {
        if mode == "scoped-only" {
            immediate_denial(
                &encode_authenticate_start(&request("dev-auth", &[], false)).unwrap(),
                Denial::PermissionDenied,
            );
        } else {
            immediate_denial(
                &encode_authenticate_start(&request("dev-auth", &[], true)).unwrap(),
                Denial::PermissionDenied,
            );
            converse(
                &request("dev-auth", &["Department"], false),
                "development-only-password",
            )
            .unwrap();
        }
        immediate_denial(
            &encode_logon_start(&LogonStart {
                authentication: request("dev-auth", &[], false).authentication,
                logon_type: LogonType::Interactive,
                tty: None,
                remote_host: None,
            })
            .unwrap(),
            Denial::PermissionDenied,
        );
        println!("NATIVE AUTHORIZATION: {mode} passed");
        return;
    }
    if mode == "scoped-deny" {
        converse(&request("dev-auth", &[], true), "development-only-password").unwrap();
        immediate_denial(
            &encode_authenticate_start(&request("dev-auth", &["Department"], false)).unwrap(),
            Denial::PermissionDenied,
        );
        println!("NATIVE AUTHORIZATION: scoped-deny passed");
        return;
    }
    if mode == "ident-refresh" {
        use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};
        let key = Key::open(
            None,
            auth_policy::KEY,
            KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
            OpenFlags::empty(),
        )
        .unwrap();
        let name = auth_policy::authentication::SECURITY_VALUE.as_bytes();
        let saved = key.query_value(name, None).unwrap();
        let socket = UnixStream::connect(auth_core::IDENT_SOCKET_PATH).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        identity_checks(&socket, ClaimAccess::All);
        key.set_value(name, ValueType::SZ, b"O:SYG:SYD:\0")
            .call()
            .unwrap();
        identity_checks(&socket, ClaimAccess::Restricted);
        key.set_value(name, saved.ty, &saved.data).call().unwrap();
        identity_checks(&socket, ClaimAccess::All);
        println!("NATIVE IDENTITY: policy refresh on an existing connection passed");
        return;
    }
    if mode == "ident-allowed" || mode == "ident-restricted" {
        let socket = UnixStream::connect(auth_core::IDENT_SOCKET_PATH).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        identity_checks(
            &socket,
            if mode == "ident-allowed" {
                ClaimAccess::All
            } else {
                ClaimAccess::DepartmentDenied
            },
        );
        return;
    }
    if mode == "no-local-state" {
        let before =
            peios::token::Token::open_self(true, peios::token::TokenAccess::QUERY).unwrap();
        let result = converse(
            &request("dev-state", &[], false),
            "development-only-password",
        )
        .unwrap();
        let after = peios::token::Token::open_self(true, peios::token::TokenAccess::QUERY).unwrap();
        assert_eq!(before.auth_id().unwrap(), after.auth_id().unwrap());
        assert_eq!(before.user().unwrap(), after.user().unwrap());
        assert!(
            !peios::token::Session::list()
                .unwrap()
                .iter()
                .any(|session| session.user.as_ref().as_bytes() == result.user_sid)
        );
        let sid = peios::security::SidRef::from_bytes(&result.user_sid).unwrap();
        let error = peios::registry::Key::open(
            None,
            &format!("Users\\{sid}"),
            peios::registry::KeyAccess::QUERY_VALUE,
            peios::registry::OpenFlags::empty(),
        )
        .expect_err("Authenticate created a user registry");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!std::path::Path::new("/home/dev-state").exists());
        println!(
            "NATIVE AUTHENTICATION: no principal session, user registry, home or caller token change"
        );
        return;
    }
    if mode == "type-restricted" {
        immediate_denial(
            &encode_logon_start(&LogonStart {
                authentication: request("dev-auth", &[], false).authentication,
                logon_type: LogonType::Interactive,
                tty: None,
                remote_host: None,
            })
            .unwrap(),
            Denial::LogonTypeNotPermitted,
        );
        println!("NATIVE LOGON: caller logon-type restriction passed");
        return;
    }
    if mode == "attest-denied" {
        immediate_denial(
            &encode_service_attest(&ServiceAttest {
                identity: "Service".into(),
                service: "untrusted".into(),
            })
            .unwrap(),
            Denial::PermissionDenied,
        );
        println!("NATIVE ATTESTATION: non-PID-1 SYSTEM caller denied");
        return;
    }
    if mode == "logon" {
        local_logon(LogonType::Interactive).unwrap();
        assert_eq!(
            local_logon(LogonType::Service).unwrap_err(),
            Denial::AccountRestricted
        );
        println!("NATIVE LOGON: token, session, home and account logon-type restriction passed");
        return;
    }
    if mode == "system-denied" {
        immediate_denial(
            &encode_logon_start(&LogonStart {
                authentication: request("dev-auth", &[], false).authentication,
                logon_type: LogonType::Interactive,
                tty: None,
                remote_host: None,
            })
            .unwrap(),
            Denial::PermissionDenied,
        );
        println!("NATIVE LOGON: SYSTEM has no hard-coded operation bypass");
        return;
    }
    if mode == "denied" {
        let socket = UnixStream::connect(auth_core::IDENT_SOCKET_PATH).unwrap();
        identity_checks(&socket, ClaimAccess::Restricted);
        immediate_denial(
            &encode_authenticate_start(&request("dev-auth", &[], false)).unwrap(),
            Denial::PermissionDenied,
        );
        println!("NATIVE AUTHENTICATION: capability denial passed");
        return;
    }
    let token = peios::token::Token::open_self(true, peios::token::TokenAccess::QUERY).unwrap();
    let groups = token.groups().unwrap();
    let authenticate = auth_policy::authentication::capability_sid(
        auth_policy::authentication::AUTHENTICATE_CAPABILITY,
    )
    .unwrap();
    let logon =
        auth_policy::authentication::capability_sid(auth_policy::authentication::LOGON_CAPABILITY)
            .unwrap();
    assert!(groups.iter().any(|(sid, _)| *sid == authenticate));
    assert!(!groups.iter().any(|(sid, _)| *sid == logon));
    // This fixture service has Authenticate and selected disclosure grants,
    // but no Logon grant or token-creation privileges.
    let socket = UnixStream::connect(auth_core::IDENT_SOCKET_PATH).unwrap();
    identity_checks(&socket, ClaimAccess::Restricted);
    immediate_denial(
        &encode_logon_start(&LogonStart {
            authentication: request("dev-auth", &[], false).authentication,
            logon_type: LogonType::Interactive,
            tty: None,
            remote_host: None,
        })
        .unwrap(),
        Denial::PermissionDenied,
    );
    immediate_denial(
        &encode_authenticate_start(&request("dev-auth", &["private"], false)).unwrap(),
        Denial::PermissionDenied,
    );
    let start = request("dev-auth", &["Department", "missing"], true);
    let result = converse(&start, "development-only-password").unwrap();
    assert_eq!(result.canonical_name, "dev-auth");
    assert!(!result.groups.as_ref().unwrap().is_empty());
    assert_eq!(result.claims.len(), 1);
    assert!(result.claims[0].name.eq_ignore_ascii_case("department"));
    assert_eq!(result.absent_claims, ["missing"]);
    assert_eq!(result.verified_credentials, [CredentialType::Password]);
    let minimal = converse(
        &request("dev-auth", &[], false),
        "development-only-password",
    )
    .unwrap();
    assert!(minimal.groups.is_none());
    assert!(minimal.claims.is_empty());
    assert_eq!(
        converse(&start, "incorrect").unwrap_err(),
        Denial::AuthenticationFailed
    );
    assert_eq!(
        converse(
            &request("dev-disabled", &[], false),
            "development-only-password"
        )
        .unwrap_err(),
        Denial::AuthenticationFailed
    );
    assert_eq!(
        converse(
            &request("dev-none", &[], false),
            "development-only-password"
        )
        .unwrap_err(),
        Denial::AuthenticationFailed
    );
    assert!(
        !std::path::Path::new("/home/dev-auth").exists(),
        "Authenticate created a home"
    );
    println!(
        "NATIVE AUTHENTICATION: password, groups, claim ACEs, absence, no token/home, and denials passed"
    );
}
