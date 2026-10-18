//! Safe client bindings to libauth.so.1. This crate links the shared library;
//! it does not contain a second implementation of the authentication protocol.
//!
//! Each operation owns its resources. Drive it with step/poll_info for an event
//! loop, or wait for blocking use. Respond to prompt rounds explicitly. A
//! granted token is returned as an OwnedFd; installing it is the caller's job.
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::fd::{FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::rc::Rc;

use auth_abi as abi;
mod identity;
mod sys;
pub use identity::{
    Account, AccountKey, Claim, ClaimValue, EnumerateRequest, Field, Identity, IdentityKind, Key,
    Record, Reference, fields,
};

/// Application-visible operation progress. Denials and failures are Errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Wait,
    Prompt,
    Complete,
}

/// Failure including whether a submitted mutation might have taken effect.
#[derive(Debug, Clone)]
pub struct Error {
    pub category: u32,
    pub code: u32,
    pub outcome_unknown: bool,
    pub message: String,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}
impl std::error::Error for Error {}
fn invalid() -> Error {
    Error {
        category: 0,
        code: 0,
        outcome_unknown: false,
        message: "invalid authentication argument or operation state".into(),
    }
}

fn span(value: &[u8]) -> abi::Bytes {
    abi::Bytes {
        data: value.as_ptr(),
        len: value.len(),
    }
}
fn string(value: &str) -> abi::Bytes {
    span(value.as_bytes())
}
fn copy_bytes(value: abi::Bytes) -> Vec<u8> {
    if value.len == 0 {
        return Vec::new();
    }
    // SAFETY: callers pass only library-returned views while their operation
    // remains immutably borrowed. libauth guarantees readable spans.
    unsafe { std::slice::from_raw_parts(value.data, value.len) }.to_vec()
}
fn copy_text(value: abi::Bytes) -> String {
    // libauth validates UTF-8 before exposing text. Lossy conversion also keeps
    // this safe wrapper total if an incompatible library is loaded accidentally.
    String::from_utf8_lossy(&copy_bytes(value)).into_owned()
}
fn read<T>(call: impl FnOnce(*mut T) -> i32) -> Result<T, Error> {
    let mut value = MaybeUninit::uninit();
    if call(value.as_mut_ptr()) != 0 {
        return Err(invalid());
    }
    // SAFETY: successful C getters initialize the entire output structure.
    Ok(unsafe { value.assume_init() })
}

/// Socket overrides are explicit. Supply only trusted endpoints.
#[derive(Default)]
pub struct Options<'a> {
    pub logon_socket: &'a str,
    pub identity_socket: &'a str,
    pub self_socket: &'a str,
    /// Zero selects the library's 90-second reply timeout.
    pub reply_timeout_ms: u64,
}

/// Credential types this client knows how to collect.
#[derive(Clone, Copy)]
pub struct Capabilities(pub u32);
impl Capabilities {
    // Bit values are the public libauth capability mask from peios/auth.h.
    pub const PASSWORD: Self = Self(1);
    pub const SSH_PUBLIC_KEY: Self = Self(2);
    pub const BOTH: Self = Self(3);
}

/// Logon category using the numeric values defined by peios/auth.h.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum LogonType {
    Interactive = 2,
    Network = 3,
    Batch = 4,
    Service = 5,
    NetworkCleartext = 8,
    NewCredentials = 9,
    RemoteInteractive = 10,
}

/// Binding obtained from the authorised originator's live SSH transport.
pub struct SshBinding<'a> {
    pub connection: &'a [u8; 16],
    pub session: &'a [u8],
    pub username: &'a str,
}

/// A proposed logon; authd decides whether the connected caller may originate it.
pub struct LogonRequest<'a> {
    pub logon_type: LogonType,
    pub username: &'a str,
    pub tty: Option<&'a str>,
    pub remote_host: Option<&'a str>,
    pub supported_credentials: Capabilities,
    /// None allows the authority's credential policy, including credential-free policy.
    pub required_credential_type: Option<u32>,
    pub ssh_binding: Option<SshBinding<'a>>,
}

/// Configuration handle. Operations remain valid after this is dropped.
pub struct Client {
    handle: NonNull<sys::Client>,
    marker: PhantomData<Rc<()>>,
}
impl Client {
    /// Create a client using the standard local sockets and reply timeout.
    pub fn new() -> Result<Self, Error> {
        Self::with_options(Options::default())
    }
    /// Create a client with copied configuration; reject an incompatible library ABI.
    pub fn with_options(options: Options<'_>) -> Result<Self, Error> {
        // SAFETY: this scalar query takes no pointers or mutable state.
        if unsafe { sys::peios_auth_abi_version() } != 1 {
            return Err(invalid());
        }
        let raw = abi::ClientOptions {
            size: size_of::<abi::ClientOptions>(),
            logon_socket: string(options.logon_socket),
            identity_socket: string(options.identity_socket),
            self_socket: string(options.self_socket),
            reply_timeout_ms: options.reply_timeout_ms,
        };
        // SAFETY: raw and its borrowed spans live through create; it copies them.
        let handle =
            NonNull::new(unsafe { sys::peios_auth_client_create(&raw) }).ok_or_else(invalid)?;
        Ok(Self {
            handle,
            marker: PhantomData,
        })
    }
    /// Begin a logon conversation. Drive the returned operation and answer its prompts.
    pub fn logon(&self, request: LogonRequest<'_>) -> Result<Operation, Error> {
        let raw = abi::LogonRequest {
            size: size_of::<abi::LogonRequest>(),
            logon_type: request.logon_type as u32,
            identifier_type: 1,
            identifier: string(request.username),
            tty: string(request.tty.unwrap_or("")),
            remote_host: string(request.remote_host.unwrap_or("")),
            required_credential_type: request.required_credential_type.unwrap_or(0),
            supported_credentials: request.supported_credentials.0,
            ssh_connection: request
                .ssh_binding
                .as_ref()
                .map(|b| span(b.connection))
                .unwrap_or(span(&[])),
            ssh_session: request
                .ssh_binding
                .as_ref()
                .map(|b| span(b.session))
                .unwrap_or(span(&[])),
            ssh_username: request
                .ssh_binding
                .as_ref()
                .map(|b| string(b.username))
                .unwrap_or(span(&[])),
        };
        // SAFETY: this owns a live client; request buffers outlive the call.
        Operation::new(unsafe { sys::peios_auth_logon_begin(self.handle.as_ptr(), &raw) })
    }
    /// Request a token for the named service identity; the authority checks permission.
    pub fn service_attest(&self, identity: &str, service: &str) -> Result<Operation, Error> {
        let raw = abi::ServiceRequest {
            size: size_of::<abi::ServiceRequest>(),
            identity: string(identity),
            service: string(service),
        };
        // SAFETY: the client and the borrowed request remain live through begin.
        Operation::new(unsafe { sys::peios_auth_service_attest_begin(self.handle.as_ptr(), &raw) })
    }
    /// Begin changing the calling account’s password through a credential conversation.
    pub fn change_password(&self, supported: Capabilities) -> Result<Operation, Error> {
        // SAFETY: this owns the live client handle; remaining input is scalar.
        Operation::new(unsafe {
            sys::peios_auth_password_change_begin(self.handle.as_ptr(), supported.0)
        })
    }
    /// Begin enrolling an SSH public key for the calling account.
    pub fn add_key(&self, public_key: &str, supported: Capabilities) -> Result<Operation, Error> {
        // SAFETY: the library copies public_key before returning.
        Operation::new(unsafe {
            sys::peios_auth_key_add_begin(self.handle.as_ptr(), string(public_key), supported.0)
        })
    }
    /// Begin removing the calling account’s SSH key identified by its fingerprint.
    pub fn remove_key(
        &self,
        fingerprint: &str,
        supported: Capabilities,
    ) -> Result<Operation, Error> {
        // SAFETY: the library copies fingerprint before returning.
        Operation::new(unsafe {
            sys::peios_auth_key_remove_begin(self.handle.as_ptr(), string(fingerprint), supported.0)
        })
    }
    /// Request the calling account’s profile and enrolled public-key metadata.
    pub fn own_account(&self) -> Result<Operation, Error> {
        // SAFETY: this owns the live client handle.
        Operation::new(unsafe { sys::peios_auth_account_self_begin(self.handle.as_ptr()) })
    }
    /// Begin changing the calling account’s display name.
    pub fn set_display_name(&self, name: &str) -> Result<Operation, Error> {
        // SAFETY: the library copies name before returning.
        Operation::new(unsafe {
            sys::peios_auth_display_name_set_begin(self.handle.as_ptr(), string(name))
        })
    }
    /// Query permission to end a session without ending it.
    pub fn may_end_session(&self, session_id: u64) -> Result<Operation, Error> {
        // SAFETY: the handle is live; the session ID grants no authority.
        Operation::new(unsafe {
            sys::peios_auth_session_end_query_begin(self.handle.as_ptr(), session_id)
        })
    }
    /// Request termination of a session; the authority checks permission again.
    pub fn end_session(&self, session_id: u64) -> Result<Operation, Error> {
        // SAFETY: the handle is live; authd authorises the requested action.
        Operation::new(unsafe {
            sys::peios_auth_session_end_begin(self.handle.as_ptr(), session_id)
        })
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner; operations retain no client pointer.
        unsafe {
            sys::peios_auth_client_destroy(self.handle.as_ptr());
        }
    }
}

/// One independently owned request. Mutable methods cannot overlap borrowed views.
pub struct Operation {
    handle: NonNull<sys::Operation>,
    marker: PhantomData<Rc<()>>,
}
/// Readiness request for the operation’s borrowed socket.
#[derive(Debug)]
pub struct PollInfo {
    pub fd: i32,
    pub events: i16,
    pub timeout_ms: u64,
}
/// An owned message displayed during a prompt round.
#[derive(Debug)]
pub struct Message {
    pub severity: u32,
    pub text: String,
}
/// One credential request in a prompt round.
#[derive(Debug)]
pub struct Prompt {
    pub credential_ref: u32,
    pub credential_type: u32,
    pub secret: bool,
    pub label: String,
    pub parameters: Vec<u8>,
}
/// An owned snapshot of the active messages and credential prompts.
#[derive(Debug)]
pub struct Round {
    pub id: u64,
    pub messages: Vec<Message>,
    pub prompts: Vec<Prompt>,
}
/// Borrowed credential material. The caller owns and erases the backing buffer.
pub struct Answer<'a> {
    pub credential_ref: u32,
    pub data: &'a [u8],
}
/// Profile data returned by a successful logon.
#[derive(Debug)]
pub struct Grant {
    pub session_id: u64,
    pub home: String,
    pub shell: String,
    pub display_name: String,
}
/// Counts reported by a completed session termination.
#[derive(Debug)]
pub struct Ended {
    pub ended: u32,
    pub remaining: u32,
}

impl Operation {
    fn new(handle: *mut sys::Operation) -> Result<Self, Error> {
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(invalid)?,
            marker: PhantomData,
        })
    }
    fn progress(&self, state: i32) -> Result<Progress, Error> {
        match state {
            0 => Ok(Progress::Wait),
            1 => Ok(Progress::Prompt),
            2 => Ok(Progress::Complete),
            3..=5 => Err(self.error()?),
            _ => Err(invalid()),
        }
    }
    /// Advance without blocking; report waiting, prompts, completion, or failure.
    pub fn step(&mut self) -> Result<Progress, Error> {
        // SAFETY: exclusive access to the uniquely owned operation.
        let state = unsafe { sys::peios_auth_operation_step(self.handle.as_ptr()) };
        self.progress(state)
    }
    /// Block until prompts, completion, or failure requires the caller’s attention.
    pub fn wait(&mut self) -> Result<Progress, Error> {
        // SAFETY: exclusive access for the duration of the blocking driver.
        let state = unsafe { sys::peios_auth_operation_wait(self.handle.as_ptr()) };
        self.progress(state)
    }
    /// The descriptor is borrowed. Never read, write or close it yourself.
    pub fn poll_info(&self) -> Result<PollInfo, Error> {
        // SAFETY: read supplies writable storage and this handle remains live.
        let raw =
            read(|out| unsafe { sys::peios_auth_operation_poll_info(self.handle.as_ptr(), out) })?;
        Ok(PollInfo {
            fd: raw.fd,
            events: raw.events,
            timeout_ms: raw.timeout_ms,
        })
    }
    /// Cancel locally. A submitted mutation can still have taken effect.
    pub fn cancel(&mut self) {
        // SAFETY: exclusive access to the uniquely owned operation.
        unsafe {
            sys::peios_auth_operation_cancel(self.handle.as_ptr());
        }
    }
    /// Copy the failure details; return an error if no failure is available.
    pub fn error(&self) -> Result<Error, Error> {
        // SAFETY: the getter initializes storage on success; views are copied now.
        let raw =
            read(|out| unsafe { sys::peios_auth_operation_error(self.handle.as_ptr(), out) })?;
        Ok(Error {
            category: raw.category,
            code: raw.code,
            outcome_unknown: raw.outcome_unknown != 0,
            message: copy_text(raw.message),
        })
    }
    /// Copy the active prompt round; reject an operation without pending prompts.
    pub fn round(&self) -> Result<Round, Error> {
        let (mut id, mut messages, mut prompts) = (0, 0, 0);
        // SAFETY: all three outputs are distinct live stack variables.
        if unsafe {
            sys::peios_auth_operation_round(
                self.handle.as_ptr(),
                &mut id,
                &mut messages,
                &mut prompts,
            )
        } != 0
        {
            return Err(invalid());
        }
        let mut result = Round {
            id,
            messages: Vec::new(),
            prompts: Vec::new(),
        };
        for index in 0..messages {
            // SAFETY: index is bounded by this immutable operation's count.
            let raw = read(|out| unsafe {
                sys::peios_auth_operation_message(self.handle.as_ptr(), index, out)
            })?;
            result.messages.push(Message {
                severity: raw.severity,
                text: copy_text(raw.text),
            });
        }
        for index in 0..prompts {
            // SAFETY: index is bounded by this immutable operation's count.
            let raw = read(|out| unsafe {
                sys::peios_auth_operation_prompt(self.handle.as_ptr(), index, out)
            })?;
            result.prompts.push(Prompt {
                credential_ref: raw.credential_ref,
                credential_type: raw.credential_type,
                secret: raw.secret != 0,
                label: copy_text(raw.label),
                parameters: copy_bytes(raw.parameters),
            });
        }
        Ok(result)
    }
    /// Submit answers for the active round. The caller remains responsible for wiping them.
    pub fn respond(&mut self, round: u64, answers: &[Answer<'_>]) -> Result<(), Error> {
        let raw: Vec<_> = answers
            .iter()
            .map(|answer| abi::Answer {
                credential_ref: answer.credential_ref,
                data: span(answer.data),
            })
            .collect();
        // SAFETY: descriptors and borrowed answer buffers live through respond.
        if unsafe {
            sys::peios_auth_operation_respond(self.handle.as_ptr(), round, raw.as_ptr(), raw.len())
        } != 0
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Copy a successful logon’s profile; reject other operation states.
    pub fn grant(&self) -> Result<Grant, Error> {
        // SAFETY: live immutable operation and valid writable result storage.
        let raw =
            read(|out| unsafe { sys::peios_auth_operation_grant(self.handle.as_ptr(), out) })?;
        Ok(Grant {
            session_id: raw.session_id,
            home: copy_text(raw.home),
            shell: copy_text(raw.shell),
            display_name: copy_text(raw.display_name),
        })
    }
    /// Transfer the granted token once. The caller owns and closes the returned descriptor.
    pub fn take_token(&mut self) -> Result<OwnedFd, Error> {
        // SAFETY: the operation transfers ownership of a fresh CLOEXEC fd.
        let fd = unsafe { sys::peios_auth_operation_take_token(self.handle.as_ptr()) };
        if fd < 0 {
            return Err(invalid());
        }
        // SAFETY: this descriptor is now exclusively owned by the caller.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    /// Copy the termination counts from a completed session-end operation.
    pub fn ended(&self) -> Result<Ended, Error> {
        // SAFETY: the getter validates result kind and initializes out on success.
        let raw =
            read(|out| unsafe { sys::peios_auth_operation_ended(self.handle.as_ptr(), out) })?;
        Ok(Ended {
            ended: raw.ended,
            remaining: raw.remaining,
        })
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        // SAFETY: this is the unique owner and no library views escape its methods.
        unsafe {
            sys::peios_auth_operation_destroy(self.handle.as_ptr());
        }
    }
}
