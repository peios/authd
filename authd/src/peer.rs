//! Who is on the other end of a connection.
//!
//! Both of authd's sockets need this and neither may take the answer from a
//! message body. On `logon.sock` the peer's identity is an *input to
//! derivation* — only the caller knows whether an sshd connection is an
//! interactive shell or a batch command, so the client proposes a logon type
//! and the authority constrains it against who is actually asking. On
//! `psi.sock` it is the gate on who may assert identity at all, which is the
//! most dangerous thing any peer can do to this process.

use std::fmt;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use peios::security::{Sid, WellKnown};
use peios::token::Token;

use crate::policy::SourceEntry;

/// The connected peer's user SID, taken from the socket by the kernel.
///
/// `SO_PEERCRED` would answer a similar-looking question and must not be used:
/// it returns the *projected* UID, which cannot distinguish an authenticated
/// user from an unauthenticated process running as the same UID, and carries
/// none of the token's SIDs, groups, integrity or privileges.
pub fn identity(stream: &UnixStream) -> peios::Result<Sid> {
    Token::open_peer(stream.as_fd())?.user()
}

/// Whether a principal is the local SYSTEM account.
pub fn is_system(peer: &Sid) -> bool {
    *peer == Sid::well_known(WellKnown::System)
}

/// Why a connection could not be matched to a configured principal source.
#[derive(Debug)]
pub enum NotASource {
    /// The peer's token could not be read.
    Unidentifiable(peios::Error),
    /// No entry in the allowlist matched the peer's service SID. Covers both
    /// "not a service" and "a service nobody configured", deliberately: the
    /// distinction is only useful to someone probing.
    NotConfigured,
}

impl fmt::Display for NotASource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unidentifiable(error) => write!(f, "peer identity unavailable: {error}"),
            Self::NotConfigured => {
                write!(f, "peer is not a configured principal source")
            }
        }
    }
}

/// Match a connecting peer against the configured principal sources.
///
/// The peer's token carries a per-service SID that peinit derived from the
/// service's name and that only peinit can mint. So rather than believe a name
/// the peer sends, authd derives the SID for each *configured* name and asks
/// whether the peer holds it. The identity that comes back is therefore built
/// from the registry and the kernel, with nothing contributed by the process on
/// the other end.
///
/// Ambiguity is not possible in practice — distinct names give distinct SIDs —
/// but the first match wins if it ever were.
pub fn identify_source(
    stream: &UnixStream,
    configured: &[SourceEntry],
) -> Result<SourceEntry, NotASource> {
    let groups = Token::open_peer(stream.as_fd())
        .and_then(|token| token.groups())
        .map_err(NotASource::Unidentifiable)?;

    configured
        .iter()
        .find(|entry| groups.iter().any(|(sid, _)| *sid == entry.service_sid))
        .cloned()
        .ok_or(NotASource::NotConfigured)
}
