//! **libauthd** — the wire protocols of Peios' authentication stack.
//!
//! Three protocols live here, and the distinctions between them are
//! load-bearing:
//!
//! - **PGSS Logon** is a *standard*: the language `/run/logon.sock` speaks. It
//!   is defined in [`wire`] and belongs to nobody. A third party may ship a
//!   different authority, or a different logon originator, and interoperate.
//!   PGSS is the "if you do not do this you are not Peios" bar.
//! - **PSI**, the Principal Source Interface in [`psi`], is *authd's own*. It is
//!   documented well enough that a third party can implement a principal
//!   source, but it is not a conformance requirement: a system running entirely
//!   different authentication infrastructure is still Peios.
//! - **LPS**, in [`lps`], is *lpsd's own*: the language `lps` speaks to
//!   administer the local principal store. Narrower still than PSI — it is one
//!   source's administrative interface, and a machine whose principals live
//!   somewhere else has no use for it.
//!
//! Nothing in [`wire`] may assume authd exists. [`psi`] may assume whatever it
//! likes — and if you find yourself wanting to put a principal source, a
//! backend daemon, or anything else from authd's internal architecture into
//! [`wire`], that is the signal you are on the wrong side of the line.
//!
//! The two share a codec ([`frame`]) and, deliberately, their whole
//! interrogation phase — PSI is a superset of PGSS Logon. See [`psi`] for what
//! that buys and where the two diverge.
//!
//! Two naming wrinkles worth being honest about. [`wire`] is not authd's — PGSS
//! Logon belongs to nobody — and [`lps`] is not authd's either, being spoken
//! between lpsd and a tool authd never sees. The crate is named for its first
//! consumer rather than for what it holds, which is the authentication stack's
//! protocols generally. Tolerable while they ship together; it wants splitting
//! if PGSS Logon ever grows a second implementation.
//!
//! # The shape of a logon
//!
//! A logon is a conversation. The client opens with a
//! [`LogonStart`](wire::LogonStart); the authority then asks for whatever the
//! principal's policy requires, possibly over several rounds, and finishes with
//! [`AccessGranted`](wire::AccessGranted) — carrying the minted token as an
//! `SCM_RIGHTS` file descriptor — or [`AccessDenied`](wire::AccessDenied).
//!
//! The value of that shape is that **the client stays generic**. It does not
//! know what a password is. It renders the prompts it is given and returns the
//! answers, so adding multi-factor, or password-expiry-forces-change, or
//! smartcards, changes the authority and leaves every client untouched.
//!
//! # Why credentials cross in the clear
//!
//! Credential material travels as plaintext over a local Unix socket. That is
//! deliberate, and the alternative is worse.
//!
//! Challenge-response requires the verifier to store something it can recompute
//! the response from: either the plaintext, or a *password-equivalent* value.
//! NTLM works exactly this way — the stored NT hash is as good as the password
//! forever, which is why pass-the-hash has been the most valuable credential on
//! a Windows network for twenty years. A modern verifier (argon2id and friends)
//! is deliberately *not* password-equivalent, and cannot answer a challenge.
//!
//! So challenge-response would trade a permanent weakness at rest for
//! protection of a channel that is not the weak point: anyone able to read this
//! socket can already `ptrace` the process holding the password. The real
//! answer to "plaintext must never cross the wire" is a PAKE (OPAQUE, SRP),
//! worth revisiting if an authority ever authenticates across a network without
//! TLS, and not worth its complexity here.
//!
//! What follows from that choice is this crate's other job: bounding how long
//! plaintext lives. Credential material is always a [`Secret`], which allocates
//! exactly and wipes itself on drop, and
//! [`encode_credential_response`](wire::encode_credential_response) hands back
//! the encoded message as a `Secret` too — the encoded form holds the
//! credential just as much as the credential field does.
//!
//! # What an authority must not trust
//!
//! Nothing a client sends is trusted. A [`LogonStart`](wire::LogonStart) is
//! what a caller *said*. An authority **must** establish the peer's identity
//! from the connected socket's peer token, never from the message body, and
//! **must** treat the requested logon type as a proposal to check against what
//! that verified peer is permitted to ask for. Otherwise anything that can
//! reach the socket can mint itself an interactive session.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod claim;
pub mod frame;
pub mod ident;
pub mod lps;
pub mod psi;
pub mod secret;
pub mod transport;
pub mod wire;

pub use claim::Claim;
pub use secret::Secret;
pub use wire::{
    AccessDenied, AccessGranted, Answer, CredentialRequest, CredentialResponse, CredentialType,
    Denial, IdentifierType, LogonStart, LogonType, Message, MessageSeverity, Prompt, WireError,
};

/// The socket a PGSS Logon authority listens on.
pub const LOGON_SOCKET_PATH: &str = "/run/logon.sock";

/// The socket an authority answers identity lookups on.
///
/// Separate from [`LOGON_SOCKET_PATH`] for admission rather than isolation: one
/// authority answers both, so a second socket buys no fault containment. What it
/// buys is a second accept queue, so that a filesystem walk issuing millions of
/// lookups cannot fill the queue an administrator needs in order to sign in.
pub const IDENT_SOCKET_PATH: &str = "/run/ident.sock";

/// The socket principal sources connect *to*.
///
/// The direction matters: sources dial in, so authd — the process holding
/// `SeCreateTokenPrivilege` — never initiates an outbound connection to a path
/// named in configuration. It only ever accepts.
pub const PSI_SOCKET_PATH: &str = "/run/psi.sock";

/// The directory lpsd owns under `/run`.
///
/// A per-daemon directory rather than a bare socket path, following the modern
/// convention (`/run/udev/`, `/run/systemd/`): the *directory* carries the
/// security descriptor, which is the better place for it, and there is room if
/// lpsd ever serves a second socket. `/run` is tmpfs, so lpsd recreates this
/// every boot.
pub const LPSD_RUN_DIR: &str = "/run/lpsd";

/// The socket `lps` administers the local principal store over.
///
/// Named for the daemon rather than the protocol, unlike the two above, and
/// deliberately: authd serves both of those, so naming either after the daemon
/// would have been ambiguous, while lpsd serves exactly one socket. The
/// protocol-named alternative, `/run/lps.sock`, would also have sat one letter
/// from `psi.sock` in a directory listing — the very confusion the distinct
/// magic numbers exist to catch.
pub const LPSD_ADMIN_SOCKET_PATH: &str = "/run/lpsd/admin.sock";
