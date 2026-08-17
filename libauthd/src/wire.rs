//! The PGSS Logon wire format.
//!
//! This is a *standard*, not authd's private business. `/run/logon.sock` speaks
//! PGSS Logon; authd is Mainline's implementation of the authority side, and
//! nothing here may assume it. A third party shipping a different authority, or
//! a different logon originator, must be able to interoperate from this
//! description alone.
//!
//! # The conversation
//!
//! A logon is a conversation, not a single exchange. The client opens with
//! [`LogonStart`], and the authority then drives:
//!
//! ```text
//!   client                                authority
//!     |-------------- LogonStart ------------->|
//!     |<---------- CredentialRequest ----------|   (prompts + messages)
//!     |--------- CredentialResponse ---------->|
//!     |<---------- CredentialRequest ----------|   (repeatable)
//!     |--------- CredentialResponse ---------->|
//!     |<--- AccessGranted | AccessDenied ------|
//! ```
//!
//! Most logons are one round: the authority asks for everything the principal's
//! policy requires, in one array, and decides. The conversational shape exists
//! for what one round cannot express — choosing between authentication paths,
//! or a shared account where one credential unlocks a requirement for another.
//!
//! One conversation per connection. The connection's lifetime bounds the
//! credential's lifetime, which makes it the kernel's job to enforce rather
//! than ours to remember. (PSI, which multiplexes, must therefore carry a
//! conversation id that this protocol does not need — see [`crate::psi`].)
//!
//! # Framing and extensibility
//!
//! See [`crate::frame`], which owns the header layout, the codec and the
//! append-only rules. PGSS Logon adds nothing to the twelve-byte header.

use crate::frame::{self, Framing, Reader, Writer};
use crate::secret::Secret;

pub use crate::frame::WireError;

/// Four literal bytes opening every message: **P**eios **G**eneric **S**ystem
/// Standards, **L**ogon.
pub const MAGIC: [u8; 4] = *b"PGSL";

/// Protocol version. Bump for any change to the meaning of an existing field,
/// or for a new enum value; appending an optional field does not require it.
pub const VERSION: u16 = 1;

pub const HEADER_BYTES: usize = frame::COMMON_HEADER_BYTES;

pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The framing constants, for the transport.
pub const FRAMING: Framing = Framing {
    magic: MAGIC,
    version: VERSION,
    header_bytes: HEADER_BYTES,
    max_message_bytes: MAX_MESSAGE_BYTES,
};

// Client -> authority.
pub const MSG_LOGON_START: u16 = 0x0001;
pub const MSG_CREDENTIAL_RESPONSE: u16 = 0x0002;
// Authority -> client. Responses carry the high bit, as RSI does.
pub const MSG_CREDENTIAL_REQUEST: u16 = 0x8001;
pub const MSG_ACCESS_GRANTED: u16 = 0x8002;
pub const MSG_ACCESS_DENIED: u16 = 0x8003;

pub const MAX_IDENTIFIER_BYTES: usize = 1024;
pub const MAX_CREDENTIAL_BYTES: usize = 32 * 1024;
pub const MAX_PROMPTS: usize = 16;
pub const MAX_MESSAGES: usize = 8;
pub const MAX_ANSWERS: usize = 16;
pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_TEXT_BYTES: usize = 512;
pub const MAX_TTY_BYTES: usize = 128;
pub const MAX_REMOTE_HOST_BYTES: usize = 256;
pub const MAX_REASON_BYTES: usize = 512;
pub const MAX_SUPPORTED_CREDENTIAL_TYPES: usize = 32;

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// The nature of the sign-on. The authority derives token group membership from
/// this, so unknown values are rejected rather than guessed at.
///
/// Values match the KACS logon types. All six KACS defines are present, so the
/// protocol can express every session the kernel can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogonType {
    Interactive = 2,
    Network = 3,
    Batch = 4,
    Service = 5,
    NetworkCleartext = 8,
    NewCredentials = 9,
}

impl LogonType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            2 => Self::Interactive,
            3 => Self::Network,
            4 => Self::Batch,
            5 => Self::Service,
            8 => Self::NetworkCleartext,
            9 => Self::NewCredentials,
            _ => return None,
        })
    }
}

/// How the client is naming the principal.
///
/// Distinct from [`CredentialType`]: this is the *claim of identity*, that is
/// the *proof*. A passkey names you and proves you in one artefact; a username
/// names you and proves nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentifierType {
    /// UTF-8 principal name.
    Username = 1,
}

impl IdentifierType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Username,
            _ => return None,
        })
    }
}

/// What a prompt is asking for, and therefore how a client must render it.
///
/// **Closed by design.** Every PGSS Logon client is required to understand
/// every credential type it may be sent — that is what lets an authority prompt
/// a client it has never met and get a correctly rendered input. A client
/// meeting an unknown type must fail the logon, not guess: guessing risks
/// echoing a secret to the screen.
///
/// The cost is that adding a credential type is a [`VERSION`] bump rather than
/// a free extension. That is the price of the rendering guarantee.
///
/// Each type fixes its own presentation:
///
/// | Type | Presentation |
/// |---|---|
/// | [`Password`](Self::Password) | Free text, echo suppressed. |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialType {
    /// Free text, never echoed.
    Password = 1,
}

impl CredentialType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Password,
            _ => return None,
        })
    }
}

/// How a client should present an authority's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageSeverity {
    /// Ordinary notice — "your password expires in 3 days".
    Info = 0,
    /// Something went wrong the user should see, without the logon necessarily
    /// having ended.
    Error = 1,
}

impl MessageSeverity {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Info,
            1 => Self::Error,
            _ => return None,
        })
    }
}

/// Why a logon was refused.
///
/// Note what is absent: nothing distinguishes "no such principal" from "wrong
/// credential". Both are [`Denial::AuthenticationFailed`]. The difference is a
/// username-enumeration oracle, so it is not representable here — it belongs in
/// the authority's audit trail, where an administrator can see it and a caller
/// cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Denial {
    /// A message did not decode, or violated a bound.
    MalformedRequest = 1,
    UnsupportedVersion = 2,
    /// The peer may not originate logons at all.
    PermissionDenied = 3,
    /// The principal does not exist, or a credential did not verify. One value
    /// for both, deliberately.
    AuthenticationFailed = 4,
    /// The peer may originate logons, but not of the type it asked for.
    LogonTypeNotPermitted = 5,
    /// Authentication succeeded, but this principal may not sign on now —
    /// disabled, expired, locked, or outside its permitted hours.
    AccountRestricted = 6,
    /// The authority could not reach what it needed to answer.
    AuthorityUnavailable = 7,
    /// The conversation exceeded a limit the authority imposes — too many
    /// rounds, or it ran too long.
    ConversationLimit = 8,
    /// The authority failed internally. Detail belongs in its log, not here.
    Internal = 9,
}

impl Denial {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::MalformedRequest,
            2 => Self::UnsupportedVersion,
            3 => Self::PermissionDenied,
            4 => Self::AuthenticationFailed,
            5 => Self::LogonTypeNotPermitted,
            6 => Self::AccountRestricted,
            7 => Self::AuthorityUnavailable,
            8 => Self::ConversationLimit,
            9 => Self::Internal,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Opens a conversation. Client to authority.
///
/// Everything here is *asserted by the client*. An authority must establish the
/// peer's identity from the connected socket, never from this struct, and must
/// treat [`Self::logon_type`] as a proposal to be checked against what that
/// verified peer is permitted to request.
#[derive(Debug)]
pub struct LogonStart {
    pub logon_type: LogonType,
    pub identifier_type: IdentifierType,
    /// The identifier itself, interpreted per [`Self::identifier_type`].
    pub identifier: Vec<u8>,
    /// The terminal this logon is happening on, if any.
    pub tty: Option<String>,
    /// The remote peer, for a logon originated on a network client's behalf.
    pub remote_host: Option<String>,
    /// Every [`CredentialType`] this client can render.
    ///
    /// An authority **must not** send a prompt for a type absent from this
    /// list. This is what makes adding a credential type a non-breaking change:
    /// length-framing lets us append *fields* freely, but says nothing about
    /// new *enum values*, which every peer is otherwise required to understand.
    /// Advertising capability closes that gap — an old client simply never
    /// claims the new type, and the authority falls back or denies with a
    /// reason rather than sending something the client would have to hard-fail
    /// on.
    ///
    /// Decoding this field is the one place where an unrecognised enum value is
    /// *not* fatal: it is a statement of capability, not an instruction, so a
    /// value this build does not know is dropped and the intersection of "what
    /// the client claims" and "what this build understands" is what remains.
    pub supported_credential_types: Vec<CredentialType>,
}

/// One thing the authority wants from the user.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// Correlates the answer. Unique within the conversation; opaque to the
    /// client, which must echo it back unchanged.
    pub credential_ref: u32,
    pub credential_type: CredentialType,
    /// The label to show, e.g. "Password" or "Verification code".
    pub credential_name: String,
}

/// Something the authority wants shown to the user, asked for or not.
#[derive(Debug, Clone)]
pub struct Message {
    pub severity: MessageSeverity,
    pub text: String,
}

/// The authority asking for credentials. Authority to client.
///
/// Both arrays may be empty — a request carrying only messages is how an
/// authority says something without asking for anything.
#[derive(Debug)]
pub struct CredentialRequest {
    pub messages: Vec<Message>,
    pub prompts: Vec<Prompt>,
}

/// One answer to one [`Prompt`].
#[derive(Debug)]
pub struct Answer {
    /// Echoed unchanged from the prompt this answers.
    pub credential_ref: u32,
    pub data: Secret,
}

/// The client's answers. Client to authority.
#[derive(Debug)]
pub struct CredentialResponse {
    pub answers: Vec<Answer>,
}

/// Where a principal's session starts, and what to call them.
///
/// **Not identity.** Nothing here is an access-control input: no ACL mentions a
/// home directory, and a token carries none of these fields. They are the
/// answers a logon originator needs in order to *start a session* — `login`
/// cannot `chdir` or `exec` without them — and they are on this message rather
/// than looked up separately because the authority has just read them, so
/// anything else would be a second round trip to learn what it already knows.
///
/// That is also the limit of the claim being made. `getpwuid` must answer for
/// principals who are not the caller and who never logged on, which this cannot
/// do; a directory query interface is the answer to that and this does not
/// replace it. See PSD-004 §12.2.
///
/// Every field may be empty, meaning "the authority did not say". A client must
/// have a fallback for each rather than treating an empty value as an error: an
/// authority that knows nothing about home directories is conforming.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// An absolute path, or empty.
    pub home: String,
    /// An absolute path, or empty.
    pub shell: String,
    /// A human's name for a human to read. **Not** GECOS: that field is a
    /// comma-separated `/etc/passwd` artefact, and a protocol that carried one
    /// would make every client parse it back apart.
    pub display_name: String,
}

pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// The logon succeeded. Authority to client.
///
/// The minted token accompanies this message out-of-band as an `SCM_RIGHTS`
/// file descriptor; it is not part of the body.
#[derive(Debug, Default)]
pub struct AccessGranted {
    /// The logon session the token belongs to.
    pub session_id: u64,
    /// Where to start the session. Appended after `session_id`, so an authority
    /// that predates it says nothing and every field arrives empty — which is
    /// exactly what such an authority meant.
    pub profile: Profile,
}

/// The logon failed. Authority to client.
#[derive(Debug)]
pub struct AccessDenied {
    pub denial: Denial,
    /// Human-readable detail, safe to show a user. Must never narrow an
    /// [`Denial::AuthenticationFailed`] into a specific cause.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Bodies
//
// Split out from the message codecs because PSI reuses them verbatim: the two
// protocols share their interrogation phase, and sharing the *code* is what
// keeps that from being a claim in a comment somewhere that quietly stops
// being true. See `crate::psi`.
// ---------------------------------------------------------------------------

pub(crate) fn read_profile_body(b: &mut Reader<'_>) -> Result<Profile, WireError> {
    Ok(Profile {
        home: b.string(MAX_PATH_BYTES)?.to_owned(),
        shell: b.string(MAX_PATH_BYTES)?.to_owned(),
        display_name: b.string(MAX_DISPLAY_NAME_BYTES)?.to_owned(),
    })
}

pub(crate) fn write_profile_body(w: &mut Writer, profile: &Profile) -> Result<(), WireError> {
    w.string(&profile.home, MAX_PATH_BYTES)?;
    w.string(&profile.shell, MAX_PATH_BYTES)?;
    w.string(&profile.display_name, MAX_DISPLAY_NAME_BYTES)
}

pub(crate) fn read_logon_start_body(b: &mut Reader<'_>) -> Result<LogonStart, WireError> {
    let logon_type = LogonType::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let identifier_type = IdentifierType::from_u8(b.u8()?).ok_or(WireError::UnknownValue)?;
    let identifier = b.bytes(MAX_IDENTIFIER_BYTES)?.to_vec();
    let tty = frame::non_empty(b.string(MAX_TTY_BYTES)?);
    let remote_host = frame::non_empty(b.string(MAX_REMOTE_HOST_BYTES)?);

    // Optional trailing field. A client predating it supports exactly the
    // credential types that existed when it was added — which is Password, the
    // only one there has ever been.
    let supported_credential_types = if b.at_end() {
        vec![CredentialType::Password]
    } else {
        b.bytes(MAX_SUPPORTED_CREDENTIAL_TYPES)?
            .iter()
            // Unrecognised values are dropped, not rejected: see the field docs.
            .filter_map(|value| CredentialType::from_u8(*value))
            .collect()
    };

    Ok(LogonStart {
        logon_type,
        identifier_type,
        identifier,
        tty,
        remote_host,
        supported_credential_types,
    })
}

pub(crate) fn write_logon_start_body(w: &mut Writer, start: &LogonStart) -> Result<(), WireError> {
    w.u8(start.logon_type as u8);
    w.u8(start.identifier_type as u8);
    w.bytes(&start.identifier, MAX_IDENTIFIER_BYTES)?;
    w.string(start.tty.as_deref().unwrap_or(""), MAX_TTY_BYTES)?;
    w.string(
        start.remote_host.as_deref().unwrap_or(""),
        MAX_REMOTE_HOST_BYTES,
    )?;
    let supported: Vec<u8> = start
        .supported_credential_types
        .iter()
        .map(|t| *t as u8)
        .collect();
    w.bytes(&supported, MAX_SUPPORTED_CREDENTIAL_TYPES)
}

pub(crate) fn read_credential_request_body(
    b: &mut Reader<'_>,
) -> Result<CredentialRequest, WireError> {
    let messages = b.array(MAX_MESSAGES, |m| {
        Ok(Message {
            severity: MessageSeverity::from_u8(m.u8()?).ok_or(WireError::UnknownValue)?,
            text: m.string(MAX_TEXT_BYTES)?.to_owned(),
        })
    })?;
    let prompts = b.array(MAX_PROMPTS, |p| {
        Ok(Prompt {
            credential_ref: p.u32()?,
            credential_type: CredentialType::from_u8(p.u8()?).ok_or(WireError::UnknownValue)?,
            credential_name: p.string(MAX_NAME_BYTES)?.to_owned(),
        })
    })?;
    Ok(CredentialRequest { messages, prompts })
}

pub(crate) fn write_credential_request_body(
    w: &mut Writer,
    req: &CredentialRequest,
) -> Result<(), WireError> {
    w.count(req.messages.len(), MAX_MESSAGES)?;
    for message in &req.messages {
        let at = w.open();
        w.u8(message.severity as u8);
        w.string(&message.text, MAX_TEXT_BYTES)?;
        w.close(at);
    }

    w.count(req.prompts.len(), MAX_PROMPTS)?;
    for prompt in &req.prompts {
        let at = w.open();
        w.u32(prompt.credential_ref);
        w.u8(prompt.credential_type as u8);
        w.string(&prompt.credential_name, MAX_NAME_BYTES)?;
        w.close(at);
    }
    Ok(())
}

pub(crate) fn read_credential_response_body(
    b: &mut Reader<'_>,
) -> Result<CredentialResponse, WireError> {
    let answers = b.array(MAX_ANSWERS, |a| {
        Ok(Answer {
            credential_ref: a.u32()?,
            data: Secret::from_slice(a.bytes(MAX_CREDENTIAL_BYTES)?),
        })
    })?;
    Ok(CredentialResponse { answers })
}

pub(crate) fn write_credential_response_body(
    w: &mut Writer,
    resp: &CredentialResponse,
) -> Result<(), WireError> {
    w.count(resp.answers.len(), MAX_ANSWERS)?;
    for answer in &resp.answers {
        let at = w.open();
        w.u32(answer.credential_ref);
        w.bytes(answer.data.expose(), MAX_CREDENTIAL_BYTES)?;
        w.close(at);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Read a PGSS Logon header, returning `(msg_type, total_len)`.
pub fn decode_header(buf: &[u8]) -> Result<(u16, usize), WireError> {
    frame::decode_header(&FRAMING, buf)
}

pub fn decode_logon_start(buf: &[u8]) -> Result<LogonStart, WireError> {
    read_logon_start_body(&mut frame::open_body(&FRAMING, buf, MSG_LOGON_START)?)
}

pub fn encode_logon_start(start: &LogonStart) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_LOGON_START);
    let body = w.open();
    write_logon_start_body(&mut w, start)?;
    w.close(body);
    w.finish()
}

pub fn decode_credential_request(buf: &[u8]) -> Result<CredentialRequest, WireError> {
    read_credential_request_body(&mut frame::open_body(&FRAMING, buf, MSG_CREDENTIAL_REQUEST)?)
}

pub fn encode_credential_request(req: &CredentialRequest) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_CREDENTIAL_REQUEST);
    let body = w.open();
    write_credential_request_body(&mut w, req)?;
    w.close(body);
    w.finish()
}

/// Decode credential answers.
///
/// **The caller must wipe `buf` afterwards.** It holds credential material in
/// the clear; the [`Secret`]s in the result are copies, not moves.
pub fn decode_credential_response(buf: &[u8]) -> Result<CredentialResponse, WireError> {
    read_credential_response_body(&mut frame::open_body(
        &FRAMING,
        buf,
        MSG_CREDENTIAL_RESPONSE,
    )?)
}

/// Encode credential answers.
///
/// Returns a [`Secret`] rather than a `Vec<u8>` because the encoded message
/// *contains the credentials in the clear*. There is no way to hold the encoded
/// form without also inheriting the obligation to erase it.
pub fn encode_credential_response(resp: &CredentialResponse) -> Result<Secret, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_CREDENTIAL_RESPONSE);
    let body = w.open();
    write_credential_response_body(&mut w, resp)?;
    w.close(body);

    let encoded = w.finish()?;
    let secret = Secret::from_slice(&encoded);
    frame::wipe(encoded);
    Ok(secret)
}

pub fn decode_access_granted(buf: &[u8]) -> Result<AccessGranted, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_ACCESS_GRANTED)?;
    let session_id = b.u64()?;
    // Nested rather than inlined, so the profile can grow a field without
    // displacing anything appended to `AccessGranted` after it.
    let profile = if b.at_end() {
        Profile::default()
    } else {
        read_profile_body(&mut b.open()?)?
    };
    Ok(AccessGranted {
        session_id,
        profile,
    })
}

pub fn encode_access_granted(granted: &AccessGranted) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_ACCESS_GRANTED);
    let body = w.open();
    w.u64(granted.session_id);
    let nested = w.open();
    write_profile_body(&mut w, &granted.profile)?;
    w.close(nested);
    w.close(body);
    w.finish()
}

pub fn decode_access_denied(buf: &[u8]) -> Result<AccessDenied, WireError> {
    let mut b = frame::open_body(&FRAMING, buf, MSG_ACCESS_DENIED)?;
    Ok(AccessDenied {
        denial: Denial::from_u32(b.u32()?).ok_or(WireError::UnknownValue)?,
        reason: b.string(MAX_REASON_BYTES)?.to_owned(),
    })
}

pub fn encode_access_denied(denied: &AccessDenied) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(&FRAMING, MSG_ACCESS_DENIED);
    let body = w.open();
    w.u32(denied.denial as u32);
    w.string(&denied.reason, MAX_REASON_BYTES)?;
    w.close(body);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> LogonStart {
        LogonStart {
            logon_type: LogonType::Interactive,
            identifier_type: IdentifierType::Username,
            identifier: b"jack".to_vec(),
            tty: Some("/dev/console".into()),
            remote_host: None,
            supported_credential_types: vec![CredentialType::Password],
        }
    }

    fn request() -> CredentialRequest {
        CredentialRequest {
            messages: vec![Message {
                severity: MessageSeverity::Info,
                text: "Password expires in 3 days.".into(),
            }],
            prompts: vec![Prompt {
                credential_ref: 1,
                credential_type: CredentialType::Password,
                credential_name: "Password".into(),
            }],
        }
    }

    #[test]
    fn logon_start_round_trips() {
        let decoded = decode_logon_start(&encode_logon_start(&start()).unwrap()).unwrap();
        assert_eq!(decoded.logon_type, LogonType::Interactive);
        assert_eq!(decoded.identifier_type, IdentifierType::Username);
        assert_eq!(decoded.identifier, b"jack");
        assert_eq!(decoded.tty.as_deref(), Some("/dev/console"));
        assert_eq!(decoded.remote_host, None);
        assert_eq!(
            decoded.supported_credential_types,
            vec![CredentialType::Password]
        );
    }

    /// A client predating the capability field must still be understood, and
    /// must be read as supporting the types that existed before it.
    #[test]
    fn absent_capability_field_defaults_to_password() {
        let full = encode_logon_start(&start()).unwrap();

        // Truncate the trailing capability field (u32 length + one byte),
        // fixing up the body and message lengths as an older encoder would
        // have written them.
        let mut bytes = full[..full.len() - 5].to_vec();
        let body_len = (bytes.len() - HEADER_BYTES - 4) as u32;
        bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&body_len.to_le_bytes());
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());

        let decoded = decode_logon_start(&bytes).expect("older client must decode");
        assert_eq!(decoded.identifier, b"jack");
        assert_eq!(
            decoded.supported_credential_types,
            vec![CredentialType::Password]
        );
    }

    /// The one place an unknown enum value is not fatal. A capability list is a
    /// statement about the client, not an instruction to it, so a type this
    /// build has never heard of is dropped and the intersection survives.
    #[test]
    fn unknown_capability_is_dropped_not_rejected() {
        let mut bytes = encode_logon_start(&start()).unwrap();

        // Append an unknown credential type to the capability list.
        bytes.push(99);
        let list_len_at = bytes.len() - 2 - 4;
        let list_len = u32::from_le_bytes(bytes[list_len_at..list_len_at + 4].try_into().unwrap());
        bytes[list_len_at..list_len_at + 4].copy_from_slice(&(list_len + 1).to_le_bytes());
        let body_len = (bytes.len() - HEADER_BYTES - 4) as u32;
        bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&body_len.to_le_bytes());
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());

        let decoded = decode_logon_start(&bytes).expect("unknown capability must not be fatal");
        assert_eq!(
            decoded.supported_credential_types,
            vec![CredentialType::Password]
        );
    }

    #[test]
    fn credential_request_round_trips() {
        let decoded =
            decode_credential_request(&encode_credential_request(&request()).unwrap()).unwrap();
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].severity, MessageSeverity::Info);
        assert_eq!(decoded.prompts.len(), 1);
        assert_eq!(decoded.prompts[0].credential_ref, 1);
        assert_eq!(decoded.prompts[0].credential_type, CredentialType::Password);
        assert_eq!(decoded.prompts[0].credential_name, "Password");
    }

    #[test]
    fn credential_response_round_trips() {
        let resp = CredentialResponse {
            answers: vec![
                Answer {
                    credential_ref: 1,
                    data: Secret::from_slice(b"hunter2"),
                },
                Answer {
                    credential_ref: 2,
                    data: Secret::from_slice(b"123456"),
                },
            ],
        };
        let encoded = encode_credential_response(&resp).unwrap();
        let decoded = decode_credential_response(encoded.expose()).unwrap();
        assert_eq!(decoded.answers.len(), 2);
        assert_eq!(decoded.answers[0].credential_ref, 1);
        assert_eq!(decoded.answers[0].data.expose(), b"hunter2");
        assert_eq!(decoded.answers[1].data.expose(), b"123456");
    }

    #[test]
    fn a_profile_round_trips_on_access_granted() {
        let profile = Profile {
            home: "/home/jack".into(),
            shell: "/bin/sh".into(),
            display_name: "Jack Palfrey".into(),
        };
        let granted = decode_access_granted(
            &encode_access_granted(&AccessGranted {
                session_id: 9,
                profile: profile.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(granted.session_id, 9);
        assert_eq!(granted.profile, profile);
    }

    /// An authority that knows nothing about home directories is conforming, so
    /// an empty profile must survive rather than be confused with an absent one.
    #[test]
    fn an_empty_profile_round_trips() {
        let granted = decode_access_granted(
            &encode_access_granted(&AccessGranted::default()).unwrap(),
        )
        .unwrap();
        assert_eq!(granted.profile, Profile::default());
    }

    /// The profile was appended to a message that already existed. An authority
    /// built against the older shape sends only the session id, and that must
    /// decode as "said nothing" rather than as a framing error.
    #[test]
    fn an_access_granted_without_a_profile_decodes_as_empty() {
        let mut w = Writer::new(&FRAMING, MSG_ACCESS_GRANTED);
        let body = w.open();
        w.u64(1234);
        w.close(body);
        let bytes = w.finish().unwrap();

        let granted = decode_access_granted(&bytes).expect("an older authority must decode");
        assert_eq!(granted.session_id, 1234);
        assert_eq!(granted.profile, Profile::default());
    }

    /// The profile is nested for the same reason `LogonStart` is inside PSI's
    /// `Authenticate`: a field appended to it must not displace anything
    /// appended to `AccessGranted` afterwards.
    #[test]
    fn a_field_appended_to_a_profile_is_skipped() {
        let mut bytes = encode_access_granted(&AccessGranted {
            session_id: 5,
            profile: Profile {
                home: "/home/jack".into(),
                shell: "/bin/sh".into(),
                display_name: String::new(),
            },
        })
        .unwrap();

        // The profile is the last thing in the body: grow it, fixing up its own
        // length and the enclosing body's.
        let profile_len_at = HEADER_BYTES + 4 + 8;
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let bump = |buf: &mut Vec<u8>, at: usize| {
            let old = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
            buf[at..at + 4].copy_from_slice(&(old + 4).to_le_bytes());
        };
        bump(&mut bytes, profile_len_at);
        bump(&mut bytes, HEADER_BYTES);
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());

        let granted = decode_access_granted(&bytes).expect("older decoder must cope");
        assert_eq!(granted.profile.home, "/home/jack");
        assert_eq!(granted.session_id, 5);
    }

    #[test]
    fn an_oversized_profile_field_is_rejected() {
        assert_eq!(
            encode_access_granted(&AccessGranted {
                session_id: 1,
                profile: Profile {
                    home: "h".repeat(MAX_PATH_BYTES + 1),
                    ..Profile::default()
                },
            })
            .unwrap_err(),
            WireError::TooLong
        );
        assert_eq!(
            encode_access_granted(&AccessGranted {
                session_id: 1,
                profile: Profile {
                    display_name: "d".repeat(MAX_DISPLAY_NAME_BYTES + 1),
                    ..Profile::default()
                },
            })
            .unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn terminal_messages_round_trip() {
        let granted = decode_access_granted(
            &encode_access_granted(&AccessGranted { session_id: 42, ..Default::default() }).unwrap(),
        )
        .unwrap();
        assert_eq!(granted.session_id, 42);

        let denied = decode_access_denied(
            &encode_access_denied(&AccessDenied {
                denial: Denial::AuthenticationFailed,
                reason: "Authentication failed.".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(denied.denial, Denial::AuthenticationFailed);
    }

    #[test]
    fn empty_arrays_are_legal() {
        // A request carrying only messages, asking for nothing.
        let req = CredentialRequest {
            messages: vec![Message {
                severity: MessageSeverity::Error,
                text: "Try again shortly.".into(),
            }],
            prompts: Vec::new(),
        };
        let decoded = decode_credential_request(&encode_credential_request(&req).unwrap()).unwrap();
        assert!(decoded.prompts.is_empty());
        assert_eq!(decoded.messages.len(), 1);
    }

    /// The extensibility contract: a newer peer appending a field to a nested
    /// array element must not break an older decoder.
    #[test]
    fn appended_field_inside_array_element_is_skipped() {
        let mut bytes = encode_credential_request(&request()).unwrap();

        // Walk to the single prompt element and grow it by a trailing field,
        // fixing up each enclosing length as we go.
        //   [header 12][body len][messages count..][prompts count][prompt len][prompt..]
        let prompt_len_at = bytes.len()
            - (4 + 1 + 4 + "Password".len()) // prompt body
            - 4; // its length prefix
        let extra = b"\xde\xad\xbe\xef";
        bytes.extend_from_slice(extra);

        let bump = |buf: &mut Vec<u8>, at: usize| {
            let old = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
            let new = old + extra.len() as u32;
            buf[at..at + 4].copy_from_slice(&new.to_le_bytes());
        };
        bump(&mut bytes, prompt_len_at); // the prompt struct
        bump(&mut bytes, HEADER_BYTES); // the message body
        let total = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&total.to_le_bytes());

        let decoded = decode_credential_request(&bytes).expect("older decoder must cope");
        assert_eq!(decoded.prompts.len(), 1);
        assert_eq!(decoded.prompts[0].credential_name, "Password");
    }

    #[test]
    fn unknown_credential_type_is_rejected() {
        // Closed-enum rule: a client that cannot render a type must fail rather
        // than guess, since guessing risks echoing a secret.
        let mut bytes = encode_credential_request(&request()).unwrap();
        let at = bytes
            .windows(8)
            .position(|w| w == b"Password".as_slice())
            .unwrap();
        bytes[at - 5] = 99; // the credential_type byte, before the name's u32 length
        assert_eq!(
            decode_credential_request(&bytes).unwrap_err(),
            WireError::UnknownValue
        );
    }

    #[test]
    fn unknown_logon_type_is_rejected() {
        let mut bytes = encode_logon_start(&start()).unwrap();
        bytes[HEADER_BYTES + 4] = 99;
        assert_eq!(
            decode_logon_start(&bytes).unwrap_err(),
            WireError::UnknownValue
        );
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = encode_logon_start(&start()).unwrap();
        bytes[0] = b'X';
        assert_eq!(decode_logon_start(&bytes).unwrap_err(), WireError::BadMagic);
    }

    #[test]
    fn version_mismatch_is_named() {
        let mut bytes = encode_logon_start(&start()).unwrap();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode_logon_start(&bytes).unwrap_err(),
            WireError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn wrong_message_type_is_rejected() {
        let bytes = encode_logon_start(&start()).unwrap();
        assert_eq!(
            decode_credential_request(&bytes).unwrap_err(),
            WireError::UnexpectedMessage(MSG_LOGON_START)
        );
    }

    #[test]
    fn oversized_array_count_is_rejected() {
        let mut bytes = encode_credential_request(&request()).unwrap();
        // The messages count is the first field of the body.
        let at = HEADER_BYTES + 4;
        bytes[at..at + 4].copy_from_slice(&(MAX_MESSAGES as u32 + 1).to_le_bytes());
        assert_eq!(
            decode_credential_request(&bytes).unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn every_truncation_errors_rather_than_panics() {
        let messages: Vec<Vec<u8>> = vec![
            encode_logon_start(&start()).unwrap(),
            encode_credential_request(&request()).unwrap(),
            encode_access_granted(&AccessGranted { session_id: 1, ..Default::default() }).unwrap(),
            encode_access_denied(&AccessDenied {
                denial: Denial::Internal,
                reason: "x".into(),
            })
            .unwrap(),
        ];
        for message in &messages {
            for cut in 0..message.len() {
                let prefix = &message[..cut];
                let _ = decode_logon_start(prefix);
                let _ = decode_credential_request(prefix);
                let _ = decode_credential_response(prefix);
                let _ = decode_access_granted(prefix);
                let _ = decode_access_denied(prefix);
            }
        }
    }
}
