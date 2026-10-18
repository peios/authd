//! C entry points. Pointer validity and exclusive access are caller contracts
//! documented in auth.h. Input buffers are copied before an entry point returns;
//! output views borrow their operation and expire when it is mutated or freed.
#![allow(non_camel_case_types)]
use std::os::fd::IntoRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use auth_abi::*;
use auth_core::{Secret, ident, lps, wire};
use crate::engine::{Kind, Operation, Output, State};

pub struct Client {
    logon: PathBuf,
    identity: PathBuf,
    own: PathBuf,
    timeout: Duration,
}

pub(crate) fn bytes(value: &[u8]) -> Bytes {
    Bytes {
        data: value.as_ptr(),
        len: value.len(),
    }
}

// SAFETY: callers uphold auth.h's readable-buffer and alignment contracts.
unsafe fn input<'a>(value: Bytes) -> Option<&'a [u8]> {
    if value.len > wire::FRAMING.max_message_bytes {
        return None;
    }
    if value.len == 0 {
        return Some(&[]);
    }
    if value.data.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(value.data, value.len) })
}
unsafe fn text(value: Bytes) -> Option<String> {
    let text = std::str::from_utf8(unsafe { input(value)? }).ok()?;
    if text.contains('\0') {
        return None;
    }
    Some(text.to_owned())
}
unsafe fn sized<'a, T>(value: *const T) -> Option<&'a T> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the contract requires the readable size member even for an older
    // structure; inspect it before accessing the rest of the current layout.
    if unsafe { value.cast::<usize>().read() } < size_of::<T>() {
        return None;
    }
    unsafe { value.as_ref() }
}
pub(crate) unsafe fn write<T>(out: *mut T, value: T) -> i32 {
    if out.is_null() {
        return -1;
    }
    // SAFETY: out is caller-provided writable storage for T.
    unsafe {
        out.write(value);
    }
    0
}
fn capabilities(mask: u32) -> Option<Vec<wire::CredentialType>> {
    if mask & !3 != 0 || mask == 0 {
        return None;
    }
    let mut types = Vec::new();
    if mask & 1 != 0 {
        types.push(wire::CredentialType::Password);
    }
    if mask & 2 != 0 {
        types.push(wire::CredentialType::SshPublicKey);
    }
    Some(types)
}
unsafe fn key(value: &Key) -> Option<ident::Key> {
    if value.size < size_of::<Key>() {
        return None;
    }
    Some(match value.kind {
        1 => ident::Key::Name(unsafe { text(value.value)? }),
        2 => ident::Key::Sid(unsafe { input(value.value)? }.to_vec()),
        3 => ident::Key::UnixId(value.unix_id),
        _ => return None,
    })
}
fn kind(value: u32) -> Option<ident::Kind> {
    ident::Kind::from_u8(u8::try_from(value).ok()?)
}
fn begin(
    client: &Client,
    kind: Kind,
    message: Result<Vec<u8>, wire::WireError>,
    supported: Vec<wire::CredentialType>,
) -> Option<*mut Operation> {
    let path = match kind {
        Kind::Lookup | Kind::Enumerate => &client.identity,
        Kind::Account | Kind::DisplayName => &client.own,
        _ => &client.logon,
    };
    Some(Box::into_raw(Box::new(Operation::begin(
        path,
        client.timeout,
        kind,
        Secret::from_slice(&message.ok()?),
        supported,
    ))))
}
macro_rules! pointer_result {
    ($body:block) => {
        (|| -> Option<_> { $body })().unwrap_or(std::ptr::null_mut())
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn peios_auth_abi_version() -> u32 {
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_client_create(options: *const ClientOptions) -> *mut Client {
    pointer_result!({
        let mut client = Client {
            logon: auth_core::LOGON_SOCKET_PATH.into(),
            identity: auth_core::IDENT_SOCKET_PATH.into(),
            own: auth_core::LPSD_SELF_SOCKET_PATH.into(),
            timeout: Duration::from_secs(90),
        };
        if !options.is_null() {
            let options = unsafe { sized(options)? };
            for (path, value) in [
                (&mut client.logon, options.logon_socket),
                (&mut client.identity, options.identity_socket),
                (&mut client.own, options.self_socket),
            ] {
                if value.len != 0 {
                    *path = Path::new(&unsafe { text(value)? }).to_owned();
                }
            }
            if options.reply_timeout_ms != 0 {
                if options.reply_timeout_ms > 86_400_000 {
                    return None;
                }
                client.timeout = Duration::from_millis(options.reply_timeout_ms);
            }
        }
        Some(Box::into_raw(Box::new(client)))
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_client_destroy(client: *mut Client) {
    if !client.is_null() {
        // SAFETY: client is an exclusively owned handle returned by create.
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_logon_begin(
    client: *const Client,
    request: *const LogonRequest,
) -> *mut Operation {
    pointer_result!({
        let client = unsafe { client.as_ref()? };
        let request = unsafe { sized(request)? };
        let supported = capabilities(request.supported_credentials)?;
        let credential = if request.required_credential_type == 0 {
            None
        } else {
            Some(wire::CredentialType::from_u8(
                u8::try_from(request.required_credential_type).ok()?,
            )?)
        };
        if credential.is_some_and(|credential| !supported.contains(&credential)) {
            return None;
        }
        let ssh_binding = if request.ssh_connection.len == 0
            && request.ssh_session.len == 0
            && request.ssh_username.len == 0
        {
            None
        } else {
            let binding = auth_core::ssh::Binding {
                connection: unsafe { input(request.ssh_connection)? }.try_into().ok()?,
                session: unsafe { input(request.ssh_session)? }.to_vec(),
                username: unsafe { text(request.ssh_username)? },
            };
            binding.validate().ok()?;
            Some(binding)
        };
        let start = wire::LogonStart {
            logon_type: wire::LogonType::from_u8(u8::try_from(request.logon_type).ok()?)?,
            identifier_type: wire::IdentifierType::from_u8(
                u8::try_from(request.identifier_type).ok()?,
            )?,
            identifier: unsafe { input(request.identifier)? }.to_vec(),
            tty: if request.tty.len == 0 {
                None
            } else {
                Some(unsafe { text(request.tty)? })
            },
            remote_host: if request.remote_host.len == 0 {
                None
            } else {
                Some(unsafe { text(request.remote_host)? })
            },
            required_credential_type: credential,
            supported_credential_types: supported.clone(),
            ssh_binding,
        };
        begin(
            client,
            Kind::Logon,
            wire::encode_logon_start(&start),
            supported,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_service_attest_begin(
    client: *const Client,
    request: *const ServiceRequest,
) -> *mut Operation {
    pointer_result!({
        let request = unsafe { sized(request)? };
        begin(
            unsafe { client.as_ref()? },
            Kind::Attest,
            wire::encode_service_attest(&wire::ServiceAttest {
                identity: unsafe { text(request.identity)? },
                service: unsafe { text(request.service)? },
            }),
            Vec::new(),
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_password_change_begin(
    client: *const Client,
    supported_credentials: u32,
) -> *mut Operation {
    pointer_result!({
        let supported = capabilities(supported_credentials)?;
        begin(
            unsafe { client.as_ref()? },
            Kind::Change,
            wire::encode_credential_change_start(&wire::CredentialChangeStart {
                supported_credential_types: supported.clone(),
            }),
            supported,
        )
    })
}
unsafe fn enroll(
    client: *const Client,
    material: Bytes,
    supported_credentials: u32,
    action: wire::EnrollAction,
) -> Option<*mut Operation> {
    let supported = capabilities(supported_credentials)?;
    begin(
        unsafe { client.as_ref()? },
        Kind::Change,
        wire::encode_credential_enroll_start(&wire::CredentialEnrollStart {
            supported_credential_types: supported.clone(),
            action,
            credential_type: wire::CredentialType::SshPublicKey,
            material: unsafe { text(material)? },
        }),
        supported,
    )
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_key_add_begin(
    client: *const Client,
    public_key: Bytes,
    supported_credentials: u32,
) -> *mut Operation {
    unsafe {
        enroll(
            client,
            public_key,
            supported_credentials,
            wire::EnrollAction::Add,
        )
    }
    .unwrap_or(std::ptr::null_mut())
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_key_remove_begin(
    client: *const Client,
    fingerprint: Bytes,
    supported_credentials: u32,
) -> *mut Operation {
    unsafe {
        enroll(
            client,
            fingerprint,
            supported_credentials,
            wire::EnrollAction::Remove,
        )
    }
    .unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_identity_lookup_begin(
    client: *const Client,
    request: *const LookupRequest,
) -> *mut Operation {
    pointer_result!({
        let request = unsafe { sized(request)? };
        begin(
            unsafe { client.as_ref()? },
            Kind::Lookup,
            ident::encode_lookup(&ident::Lookup {
                tag: 1,
                key: unsafe { key(&request.key)? },
                kind: kind(request.kind)?,
                fields: ident::Fields(request.fields),
            }),
            Vec::new(),
        )
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_identity_enumerate_begin(
    client: *const Client,
    request: *const EnumerateRequest,
) -> *mut Operation {
    pointer_result!({
        let request = unsafe { sized(request)? };
        begin(
            unsafe { client.as_ref()? },
            Kind::Enumerate,
            ident::encode_enumerate(&ident::Enumerate {
                tag: 1,
                kind: kind(request.kind)?,
                fields: ident::Fields(request.fields),
                of: if request.group.is_null() {
                    None
                } else {
                    Some(unsafe { key(sized(request.group)?)? })
                },
                cursor: unsafe { input(request.cursor)? }.to_vec(),
            }),
            Vec::new(),
        )
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_account_self_begin(client: *const Client) -> *mut Operation {
    pointer_result!({
        begin(
            unsafe { client.as_ref()? },
            Kind::Account,
            lps::encode_show_self(),
            Vec::new(),
        )
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_display_name_set_begin(
    client: *const Client,
    name: Bytes,
) -> *mut Operation {
    pointer_result!({
        begin(
            unsafe { client.as_ref()? },
            Kind::DisplayName,
            lps::encode_set_display_name(&lps::SetDisplayName {
                display_name: unsafe { text(name)? },
            }),
            Vec::new(),
        )
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_session_end_query_begin(
    client: *const Client,
    session_id: u64,
) -> *mut Operation {
    pointer_result!({
        begin(
            unsafe { client.as_ref()? },
            Kind::Query,
            wire::encode_session_end_query(&wire::SessionEndQuery {
                logon_session_id: session_id,
            }),
            Vec::new(),
        )
    })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_session_end_begin(
    client: *const Client,
    session_id: u64,
) -> *mut Operation {
    pointer_result!({
        begin(
            unsafe { client.as_ref()? },
            Kind::End,
            wire::encode_session_end(&wire::SessionEnd {
                logon_session_id: session_id,
            }),
            Vec::new(),
        )
    })
}

fn state(operation: &Operation) -> i32 {
    match operation.state {
        State::Pending => 0,
        State::Prompt(_) => 1,
        State::Complete(_) => 2,
        State::Denied(_) => 3,
        State::Failed(_) => 4,
        State::Cancelled(_) => 5,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_step(operation: *mut Operation) -> i32 {
    // SAFETY: a live operation is exclusively borrowed for this call.
    let Some(operation) = (unsafe { operation.as_mut() }) else {
        return -1;
    };
    operation.step();
    state(operation)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_poll_info(
    operation: *const Operation,
    out: *mut PollInfo,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let (fd, events, timeout_ms) = operation.poll_info().unwrap_or((-1, 0, 0));
    unsafe {
        write(
            out,
            PollInfo {
                fd,
                events,
                timeout_ms,
            },
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_wait(operation: *mut Operation) -> i32 {
    let Some(operation) = (unsafe { operation.as_mut() }) else {
        return -1;
    };
    loop {
        operation.step();
        if state(operation) != 0 {
            return state(operation);
        }
        let Some((fd, events, timeout_ms)) = operation.poll_info() else {
            return -1;
        };
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, bounded timeout. EINTR is retried by
        // the loop, which recomputes the deadline rather than extending it.
        let result = unsafe { libc::poll(&mut poll, 1, timeout_ms.min(i32::MAX as u64) as i32) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return -1;
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_respond(
    operation: *mut Operation,
    round: u64,
    answers: *const Answer,
    count: usize,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_mut() }) else {
        return -1;
    };
    if count > wire::MAX_PROMPTS || (count > 0 && answers.is_null()) {
        return -1;
    }
    let answers = if count == 0 {
        &[]
    } else {
        // SAFETY: caller provides count readable Answer elements.
        unsafe { std::slice::from_raw_parts(answers, count) }
    };
    let mut owned = Vec::new();
    for answer in answers {
        let Some(data) = (unsafe { input(answer.data) }) else {
            return -1;
        };
        owned.push(wire::Answer {
            credential_ref: answer.credential_ref,
            data: Secret::from_slice(data),
        });
    }
    match operation.respond(round, owned) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_cancel(operation: *mut Operation) {
    if let Some(operation) = unsafe { operation.as_mut() } {
        operation.cancel();
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_destroy(operation: *mut Operation) {
    if !operation.is_null() {
        // SAFETY: operation is exclusively owned and was allocated by begin.
        unsafe {
            drop(Box::from_raw(operation));
        }
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_error(
    operation: *const Operation,
    out: *mut ErrorView,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let failure = match &operation.state {
        State::Denied(f) | State::Failed(f) | State::Cancelled(f) => f,
        _ => return -1,
    };
    unsafe {
        write(
            out,
            ErrorView {
                category: failure.category,
                code: failure.code,
                outcome_unknown: u32::from(failure.unknown),
                message: bytes(failure.message.as_bytes()),
            },
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_round(
    operation: *const Operation,
    round: *mut u64,
    messages: *mut usize,
    prompts: *mut usize,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let State::Prompt(request) = &operation.state else {
        return -1;
    };
    if round.is_null() || messages.is_null() || prompts.is_null() {
        return -1;
    }
    // SAFETY: the caller supplies three distinct writable output objects.
    unsafe {
        round.write(operation.round);
        messages.write(request.messages.len());
        prompts.write(request.prompts.len());
    }
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_prompt(
    operation: *const Operation,
    index: usize,
    out: *mut PromptView,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let State::Prompt(request) = &operation.state else {
        return -1;
    };
    let Some(prompt) = request.prompts.get(index) else {
        return -1;
    };
    unsafe {
        write(
            out,
            PromptView {
                credential_ref: prompt.credential_ref,
                credential_type: prompt.credential_type as u32,
                secret: u32::from(prompt.credential_type == wire::CredentialType::Password),
                label: bytes(prompt.credential_name.as_bytes()),
                parameters: bytes(&prompt.parameters),
            },
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_message(
    operation: *const Operation,
    index: usize,
    out: *mut MessageView,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let State::Prompt(request) = &operation.state else {
        return -1;
    };
    let Some(message) = request.messages.get(index) else {
        return -1;
    };
    unsafe {
        write(
            out,
            MessageView {
                severity: message.severity as u32,
                text: bytes(message.text.as_bytes()),
            },
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_grant(
    operation: *const Operation,
    out: *mut GrantView,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let State::Complete(Output::Grant { grant, .. }) = &operation.state else {
        return -1;
    };
    unsafe {
        write(
            out,
            GrantView {
                session_id: grant.session_id,
                home: bytes(grant.profile.home.as_bytes()),
                shell: bytes(grant.profile.shell.as_bytes()),
                display_name: bytes(grant.profile.display_name.as_bytes()),
            },
        )
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_take_token(operation: *mut Operation) -> i32 {
    let Some(operation) = (unsafe { operation.as_mut() }) else {
        return -1;
    };
    let State::Complete(Output::Grant { token, .. }) = &mut operation.state else {
        return -1;
    };
    token.take().map(IntoRawFd::into_raw_fd).unwrap_or(-1)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_ended(
    operation: *const Operation,
    out: *mut EndedView,
) -> i32 {
    let Some(operation) = (unsafe { operation.as_ref() }) else {
        return -1;
    };
    let State::Complete(Output::Ended(ended)) = &operation.state else {
        return -1;
    };
    unsafe {
        write(
            out,
            EndedView {
                ended: ended.ended,
                remaining: ended.remaining,
            },
        )
    }
}
