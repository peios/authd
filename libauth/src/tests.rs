//! End-to-end C entry point tests against disposable Unix socket authorities.
//! All unsafe calls below use handles owned by the test, valid initialized
//! structures, and input buffers that remain live for the entire call.
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use auth_abi::*;
use auth_core::{ident, lps, wire};
use auth_core::transport::{recv_message, send_message, send_message_with_fd};
use crate::api::*;
use crate::results::*;

static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);
struct Server {
    path: PathBuf,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    fn new(serve: impl FnOnce(UnixStream) + Send + 'static) -> Self {
        let path = PathBuf::from(format!(
            "/tmp/auth-api-{}-{}",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let thread = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            serve(socket);
        });
        Self {
            path,
            thread: Some(thread),
        }
    }
    fn client(&self, timeout: u64) -> *mut Client {
        let options = ClientOptions {
            size: size_of::<ClientOptions>(),
            logon_socket: bytes(self.path.as_os_str().as_encoded_bytes()),
            identity_socket: bytes(self.path.as_os_str().as_encoded_bytes()),
            self_socket: bytes(self.path.as_os_str().as_encoded_bytes()),
            reply_timeout_ms: timeout,
        };
        unsafe { peios_auth_client_create(&options) }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.thread.take().unwrap().join().unwrap();
        std::fs::remove_file(&self.path).unwrap();
    }
}
fn start() -> LogonRequest {
    LogonRequest {
        size: size_of::<LogonRequest>(),
        logon_type: 2,
        identifier_type: 1,
        identifier: bytes(b"jack"),
        tty: bytes(b"/dev/tty1"),
        remote_host: bytes(&[]),
        required_credential_type: 1,
        supported_credentials: 1,
        ssh_connection: bytes(&[]),
        ssh_session: bytes(&[]),
        ssh_username: bytes(&[]),
    }
}
fn prompts() -> Vec<u8> {
    wire::encode_credential_request(&wire::CredentialRequest {
        messages: vec![wire::Message {
            severity: wire::MessageSeverity::Info,
            text: "Sign in".into(),
        }],
        prompts: vec![wire::Prompt {
            parameters: Vec::new(),
            credential_ref: 77,
            credential_type: wire::CredentialType::Password,
            credential_name: "Password".into(),
        }],
    })
    .unwrap()
}
fn denied() -> Vec<u8> {
    wire::encode_access_denied(&wire::AccessDenied {
        denial: wire::Denial::AuthenticationFailed,
        reason: "Authentication failed".into(),
    })
    .unwrap()
}

#[test]
fn logon_handles_fragmented_prompts_and_transfers_token_once() {
    let server = Server::new(|mut socket| {
        let request = recv_message(&wire::FRAMING, &socket).unwrap();
        assert_eq!(
            wire::decode_logon_start(request.expose())
                .unwrap()
                .identifier,
            b"jack"
        );
        for byte in prompts() {
            socket.write_all(&[byte]).unwrap();
        }
        let response = recv_message(&wire::FRAMING, &socket).unwrap();
        let response = wire::decode_credential_response(response.expose()).unwrap();
        assert_eq!(response.answers[0].credential_ref, 77);
        assert_eq!(response.answers[0].data.expose(), b"secret");
        let token = std::fs::File::open("/dev/null").unwrap();
        send_message_with_fd(
            &socket,
            &wire::encode_access_granted(&wire::AccessGranted {
                session_id: 42,
                profile: wire::Profile {
                    home: "/home/jack".into(),
                    shell: "/bin/sh".into(),
                    display_name: "Jack".into(),
                },
            })
            .unwrap(),
            token.as_fd(),
        )
        .unwrap();
    });
    unsafe {
        let client = server.client(1000);
        let operation = peios_auth_logon_begin(client, &start());
        peios_auth_client_destroy(client);
        assert_eq!(peios_auth_operation_wait(operation), 1);
        let (mut round, mut messages, mut count) = (0, 0, 0);
        assert_eq!(
            peios_auth_operation_round(operation, &mut round, &mut messages, &mut count),
            0
        );
        assert_eq!((round, messages, count), (1, 1, 1));
        let answer = Answer {
            credential_ref: 77,
            data: bytes(b"secret"),
        };
        assert_eq!(
            peios_auth_operation_respond(operation, round + 1, &answer, 1),
            -1
        );
        assert_eq!(
            peios_auth_operation_respond(operation, round, &answer, 1),
            0
        );
        assert_eq!(peios_auth_operation_wait(operation), 2);
        let mut grant = std::mem::MaybeUninit::uninit();
        assert_eq!(peios_auth_operation_grant(operation, grant.as_mut_ptr()), 0);
        assert_eq!(grant.assume_init().session_id, 42);
        let fd = peios_auth_operation_take_token(operation);
        assert!(fd >= 0);
        assert_ne!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
        assert_eq!(peios_auth_operation_take_token(operation), -1);
        assert_eq!(libc::close(fd), 0);
        peios_auth_operation_destroy(operation);
    }
}

#[test]
fn grant_without_descriptor_fails_and_unknown_denials_are_preserved() {
    for missing_token in [false, true] {
        let server = Server::new(move |socket| {
            recv_message(&wire::FRAMING, &socket).unwrap();
            let message = if missing_token {
                wire::encode_access_granted(&wire::AccessGranted::default()).unwrap()
            } else {
                let mut message = denied();
                message[16..20].copy_from_slice(&99999u32.to_le_bytes());
                message
            };
            send_message(&socket, &message).unwrap();
        });
        unsafe {
            let client = server.client(1000);
            let operation = peios_auth_logon_begin(client, &start());
            assert_eq!(
                peios_auth_operation_wait(operation),
                if missing_token { 4 } else { 3 }
            );
            let mut error = std::mem::MaybeUninit::uninit();
            assert_eq!(peios_auth_operation_error(operation, error.as_mut_ptr()), 0);
            let error = error.assume_init();
            if !missing_token {
                assert_eq!(error.code, 99999);
                assert_eq!(error.outcome_unknown, 0);
            } else {
                assert_eq!(error.category, 3);
            }
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn change_connection_loss_and_cancellation_preserve_unknown_outcomes() {
    for cancel in [false, true] {
        let server = Server::new(move |socket| {
            let opening = recv_message(&wire::FRAMING, &socket).unwrap();
            wire::decode_credential_change_start(opening.expose()).unwrap();
            if cancel {
                send_message(&socket, &prompts()).unwrap();
            }
        });
        unsafe {
            let client = server.client(1000);
            let operation = peios_auth_password_change_begin(client, 1);
            assert_eq!(
                peios_auth_operation_wait(operation),
                if cancel { 1 } else { 4 }
            );
            if cancel {
                peios_auth_operation_cancel(operation);
                assert_eq!(peios_auth_operation_step(operation), 5);
            }
            let mut error = std::mem::MaybeUninit::uninit();
            peios_auth_operation_error(operation, error.as_mut_ptr());
            assert_eq!(error.assume_init().outcome_unknown, 1);
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn lookup_preserves_absence_withholding_and_wrong_tags_fail() {
    for tag in [1, 2] {
        let server = Server::new(move |socket| {
            let request = recv_message(&wire::FRAMING, &socket).unwrap();
            let lookup = ident::decode_lookup(request.expose()).unwrap();
            assert_eq!(lookup.key, ident::Key::Name("jack".into()));
            send_message(
                &socket,
                &ident::encode_lookup_reply(&ident::LookupReply {
                    tag,
                    outcome: ident::Outcome::Found,
                    record: Some(ident::Record {
                        sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                        qualified_name: "local\\jack".into(),
                        kind_found: ident::Kind::Principal,
                        values: vec![ident::Value::Home(String::new())],
                        withheld: vec![ident::Withheld {
                            field: ident::Fields::CLAIMS,
                            reason: ident::WithheldReason::Restricted,
                        }],
                    }),
                })
                .unwrap(),
            )
            .unwrap();
        });
        unsafe {
            let client = server.client(1000);
            let request = LookupRequest {
                size: size_of::<LookupRequest>(),
                key: Key {
                    size: size_of::<Key>(),
                    kind: 1,
                    value: bytes(b"jack"),
                    unix_id: 0,
                },
                kind: 1,
                fields: 4 | 128,
            };
            let operation = peios_auth_identity_lookup_begin(client, &request);
            assert_eq!(
                peios_auth_operation_wait(operation),
                if tag == 1 { 2 } else { 4 }
            );
            if tag == 1 {
                assert_eq!(peios_auth_record_field_state(operation, 0, 4), 5);
                assert_eq!(peios_auth_record_field_state(operation, 0, 128), 2);
                assert_eq!(peios_auth_record_field_state(operation, 0, 8), 0);
            }
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn query_and_end_are_distinct_and_end_counts_survive() {
    for query in [false, true] {
        let server = Server::new(move |socket| {
            let request = recv_message(&wire::FRAMING, &socket).unwrap();
            let response = if query {
                assert_eq!(
                    wire::decode_session_end_query(request.expose())
                        .unwrap()
                        .logon_session_id,
                    123
                );
                wire::encode_session_end_allowed(&wire::SessionEndAllowed).unwrap()
            } else {
                assert_eq!(
                    wire::decode_session_end(request.expose())
                        .unwrap()
                        .logon_session_id,
                    123
                );
                wire::encode_session_ended(&wire::SessionEnded {
                    ended: 5,
                    remaining: 2,
                })
                .unwrap()
            };
            send_message(&socket, &response).unwrap();
        });
        unsafe {
            let client = server.client(1000);
            let operation = if query {
                peios_auth_session_end_query_begin(client, 123)
            } else {
                peios_auth_session_end_begin(client, 123)
            };
            assert_eq!(peios_auth_operation_wait(operation), 2);
            if !query {
                let mut ended = std::mem::MaybeUninit::uninit();
                assert_eq!(peios_auth_operation_ended(operation, ended.as_mut_ptr()), 0);
                let ended = ended.assume_init();
                assert_eq!((ended.ended, ended.remaining), (5, 2));
            }
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn password_change_and_key_enrollment_complete_without_tokens() {
    for action in 0..3 {
        let server = Server::new(move |socket| {
            let request = recv_message(&wire::FRAMING, &socket).unwrap();
            if action == 0 {
                wire::decode_credential_change_start(request.expose()).unwrap();
            } else {
                let enroll = wire::decode_credential_enroll_start(request.expose()).unwrap();
                assert_eq!(
                    enroll.action,
                    if action == 1 {
                        wire::EnrollAction::Add
                    } else {
                        wire::EnrollAction::Remove
                    }
                );
            }
            send_message(
                &socket,
                &wire::encode_credential_changed(&wire::CredentialChanged).unwrap(),
            )
            .unwrap();
        });
        unsafe {
            let client = server.client(1000);
            let operation = match action {
                0 => peios_auth_password_change_begin(client, 1),
                1 => peios_auth_key_add_begin(client, bytes(b"ssh-ed25519 test"), 1),
                _ => peios_auth_key_remove_begin(client, bytes(b"SHA256:test"), 1),
            };
            assert!(!operation.is_null());
            assert_eq!(peios_auth_operation_wait(operation), 2);
            assert_eq!(peios_auth_operation_take_token(operation), -1);
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn own_account_and_display_name_use_the_self_protocol() {
    for show in [false, true] {
        let server = Server::new(move |socket| {
            let request = recv_message(&lps::FRAMING, &socket).unwrap();
            let response = if show {
                lps::decode_show_self(request.expose()).unwrap();
                lps::encode_self(&lps::OwnAccount {
                    name: "jack".into(),
                    sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
                    display_name: "Jack".into(),
                    enabled: true,
                    policy: auth_core::credential::Policy::Password,
                    has_password: true,
                    keys: Vec::new(),
                })
                .unwrap()
            } else {
                assert_eq!(
                    lps::decode_set_display_name(request.expose())
                        .unwrap()
                        .display_name,
                    "Jack"
                );
                lps::encode_done().unwrap()
            };
            send_message(&socket, &response).unwrap();
        });
        unsafe {
            let client = server.client(1000);
            let operation = if show {
                peios_auth_account_self_begin(client)
            } else {
                peios_auth_display_name_set_begin(client, bytes(b"Jack"))
            };
            assert_eq!(peios_auth_operation_wait(operation), 2);
            if show {
                let mut account = std::mem::MaybeUninit::uninit();
                assert_eq!(
                    peios_auth_operation_account(operation, account.as_mut_ptr()),
                    0
                );
                assert_eq!(account.assume_init().has_password, 1);
            }
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn enumeration_retains_empty_page_cursor_and_incomplete_sources() {
    let server = Server::new(|socket| {
        let request = recv_message(&wire::FRAMING, &socket).unwrap();
        ident::decode_enumerate(request.expose()).unwrap();
        send_message(
            &socket,
            &ident::encode_enumerate_reply(&ident::EnumerateReply {
                tag: 1,
                outcome: ident::Outcome::Found,
                entries: Vec::new(),
                next: vec![42],
                incomplete: vec!["remote".into()],
            })
            .unwrap(),
        )
        .unwrap();
    });
    unsafe {
        let client = server.client(1000);
        let request = EnumerateRequest {
            size: size_of::<EnumerateRequest>(),
            kind: 1,
            fields: 0,
            group: std::ptr::null(),
            cursor: bytes(&[]),
        };
        let operation = peios_auth_identity_enumerate_begin(client, &request);
        assert_eq!(peios_auth_operation_wait(operation), 2);
        let mut identity = std::mem::MaybeUninit::uninit();
        assert_eq!(
            peios_auth_operation_identity(operation, identity.as_mut_ptr()),
            0
        );
        let identity = identity.assume_init();
        assert_eq!(
            (
                identity.record_count,
                identity.next.len,
                identity.incomplete_count
            ),
            (0, 1, 1)
        );
        peios_auth_operation_destroy(operation);
        peios_auth_client_destroy(client);
    }
}

#[test]
fn timeouts_and_invalid_requests_are_explicit() {
    let server = Server::new(|socket| {
        recv_message(&wire::FRAMING, &socket).unwrap();
        std::thread::sleep(Duration::from_millis(50));
    });
    unsafe {
        let client = server.client(10);
        let mut request = start();
        request.size = 0;
        assert!(peios_auth_logon_begin(client, &request).is_null());
        request = start();
        request.supported_credentials = 0x8000;
        assert!(peios_auth_logon_begin(client, &request).is_null());
        let operation = peios_auth_logon_begin(client, &start());
        assert_eq!(peios_auth_operation_wait(operation), 4);
        let mut error = std::mem::MaybeUninit::uninit();
        peios_auth_operation_error(operation, error.as_mut_ptr());
        assert_eq!(error.assume_init().category, 2);
        peios_auth_operation_destroy(operation);
        peios_auth_client_destroy(client);
    }
}

#[test]
fn service_attestation_keeps_its_distinct_message_and_returns_a_token() {
    let server = Server::new(|socket| {
        let request = recv_message(&wire::FRAMING, &socket).unwrap();
        let attest = wire::decode_service_attest(request.expose()).unwrap();
        assert_eq!(
            (attest.identity.as_str(), attest.service.as_str()),
            ("service", "worker")
        );
        assert!(wire::decode_logon_start(request.expose()).is_err());
        let token = std::fs::File::open("/dev/null").unwrap();
        send_message_with_fd(
            &socket,
            &wire::encode_access_granted(&wire::AccessGranted::default()).unwrap(),
            token.as_fd(),
        )
        .unwrap();
    });
    unsafe {
        let client = server.client(1000);
        let request = ServiceRequest {
            size: size_of::<ServiceRequest>(),
            identity: bytes(b"service"),
            service: bytes(b"worker"),
        };
        let operation = peios_auth_service_attest_begin(client, &request);
        assert_eq!(peios_auth_operation_wait(operation), 2);
        // Deliberately leave the token in the result: destruction owns its close.
        peios_auth_operation_destroy(operation);
        peios_auth_client_destroy(client);
    }
}

#[test]
fn unadvertised_credentials_and_descriptors_on_denials_are_rejected() {
    for descriptor in [false, true] {
        let server = Server::new(move |socket| {
            recv_message(&wire::FRAMING, &socket).unwrap();
            if descriptor {
                let token = std::fs::File::open("/dev/null").unwrap();
                send_message_with_fd(&socket, &denied(), token.as_fd()).unwrap();
            } else {
                let request = wire::CredentialRequest {
                    messages: Vec::new(),
                    prompts: vec![wire::Prompt {
                        credential_ref: 1,
                        credential_type: wire::CredentialType::SshPublicKey,
                        parameters: auth_core::ssh::disposition(0).unwrap(),
                        credential_name: "Key".into(),
                    }],
                };
                send_message(&socket, &wire::encode_credential_request(&request).unwrap()).unwrap();
            }
        });
        unsafe {
            let client = server.client(1000);
            let operation = peios_auth_logon_begin(client, &start());
            assert_eq!(peios_auth_operation_wait(operation), 4);
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
    }
}

#[test]
fn extra_and_truncated_descriptor_arrays_are_closed() {
    use std::os::fd::AsRawFd;
    for count in [2, 100] {
        let file_path = format!("/tmp/auth-fd-test-{}-{count}", std::process::id());
        let file = std::fs::File::create(&file_path).unwrap();
        let server = Server::new(move |socket| {
            recv_message(&wire::FRAMING, &socket).unwrap();
            let message = wire::encode_access_granted(&wire::AccessGranted::default()).unwrap();
            let mut iov = libc::iovec {
                iov_base: message.as_ptr().cast_mut().cast(),
                iov_len: message.len(),
            };
            // Aligned storage for the intentionally overpopulated descriptor array.
            let mut control = [0usize; 128];
            unsafe {
                let mut header: libc::msghdr = std::mem::zeroed();
                header.msg_iov = &mut iov;
                header.msg_iovlen = 1;
                header.msg_control = control.as_mut_ptr().cast();
                header.msg_controllen = libc::CMSG_SPACE(count * size_of::<i32>() as u32) as usize;
                let ancillary = libc::CMSG_FIRSTHDR(&header);
                (*ancillary).cmsg_level = libc::SOL_SOCKET;
                (*ancillary).cmsg_type = libc::SCM_RIGHTS;
                (*ancillary).cmsg_len = libc::CMSG_LEN(count * size_of::<i32>() as u32) as usize;
                for index in 0..count as usize {
                    libc::CMSG_DATA(ancillary)
                        .cast::<i32>()
                        .add(index)
                        .write_unaligned(file.as_raw_fd());
                }
                assert_eq!(
                    libc::sendmsg(socket.as_raw_fd(), &header, libc::MSG_NOSIGNAL),
                    message.len() as isize
                );
            }
        });
        unsafe {
            let client = server.client(1000);
            let operation = peios_auth_logon_begin(client, &start());
            assert_eq!(peios_auth_operation_wait(operation), 4);
            peios_auth_operation_destroy(operation);
            peios_auth_client_destroy(client);
        }
        drop(server);
        let leaked = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .filter(|path| path == &PathBuf::from(&file_path))
            .count();
        assert_eq!(leaked, 0, "received descriptors must be closed on error");
        std::fs::remove_file(file_path).unwrap();
    }
}

#[test]
fn truncated_headers_cannot_leak_attached_descriptors() {
    let server = Server::new(|socket| {
        recv_message(&wire::FRAMING, &socket).unwrap();
        let token = std::fs::File::open("/dev/null").unwrap();
        send_message_with_fd(&socket, b"PG", token.as_fd()).unwrap();
    });
    unsafe {
        let client = server.client(1000);
        let operation = peios_auth_logon_begin(client, &start());
        assert_eq!(peios_auth_operation_wait(operation), 4);
        peios_auth_operation_destroy(operation);
        peios_auth_client_destroy(client);
    }
}

#[test]
fn unknown_self_account_refusal_codes_remain_denials() {
    let server = Server::new(|socket| {
        recv_message(&lps::FRAMING, &socket).unwrap();
        let mut refusal = lps::encode_failed(&lps::Failed {
            failure: lps::Failure::Denied,
            reason: "Not permitted".into(),
        })
        .unwrap();
        refusal[16..20].copy_from_slice(&99999u32.to_le_bytes());
        send_message(&socket, &refusal).unwrap();
    });
    unsafe {
        let client = server.client(1000);
        let operation = peios_auth_account_self_begin(client);
        assert_eq!(peios_auth_operation_wait(operation), 3);
        let mut error = std::mem::MaybeUninit::uninit();
        assert_eq!(peios_auth_operation_error(operation, error.as_mut_ptr()), 0);
        let error = error.assume_init();
        assert_eq!(
            (error.category, error.code, error.outcome_unknown),
            (7, 99999, 0)
        );
        peios_auth_operation_destroy(operation);
        peios_auth_client_destroy(client);
    }
}
