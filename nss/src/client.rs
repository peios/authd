//! Talking to the authority.
//!
//! # A connection per call
//!
//! Deliberately, and it is the one performance decision in this module worth
//! defending. A shared object cannot see its process fork, so a connection held
//! across calls would be inherited by a child that then interleaves requests on
//! it with its parent — the bug class that made `nss_ldap` notorious. There is
//! no portable hook that fires early enough to prevent it.
//!
//! Connecting to a Unix socket is cheap. Answering from a cache would be
//! cheaper, and that cache belongs in the authority where every caller shares
//! it, not here where every process would keep its own and none could be told
//! when it went stale.
//!
//! An enumeration is the exception: `setpwent`/`getpwent`/`endpwent` is an
//! explicit session with a cursor, so it holds one connection for its length.
//!
//! # Failing the right way
//!
//! A module that cannot reach the authority answers `Unavail`, and there is
//! nothing behind it: no `files`, no `/etc/passwd`. Before the authority is
//! running, names do not resolve and callers see numbers — which is the honest
//! answer, since identity comes from the authority and until it exists there is
//! none to have.
//!
//! An authority that answers `Unavailable` is different in kind and maps to
//! `TryAgain`, never `NotFound`. A source that could have answered did not, and
//! recording that as "no such user" would let an outage be remembered as a fact.
//!
//! # The client is libauthd-client's
//!
//! Speaking the socket — connecting, the question, the answer, matching one
//! to the other — is libauthd-client's [`Session`], which every program
//! asking authd shares. What is here is the mapping above: its [`Failure`]
//! said in the terms an NSS entry point answers in.

use std::io;
use std::time::Duration;

use libauthd::ident::{self, Fields, Kind, Record};
use libauthd_client::ident::{Failure, Ident, Session};

/// How long the authority has to answer before the caller is told to try again.
///
/// A name resolver is called synchronously from every process on the system, so
/// this bounds how long an unrelated program can be made to sit still. Shorter
/// than authd's own budget for asking a source, on purpose: better to tell a
/// caller to retry than to hold it while authd waits on a directory.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to `/run/ident.sock`.
pub struct Client(Session);

/// What one page of an enumeration produced.
///
/// The distinction that matters is that none of these variants means "the walk
/// is over". Only an empty cursor does.
pub enum Paged {
    Page(ident::EnumerateReply),
    /// Something that could have answered did not.
    TryAgain,
    /// The authority cannot be reached, or would not say.
    Unavailable,
}

/// What a lookup produced, in the terms an NSS entry point answers in.
pub enum Found {
    Record(Box<Record>),
    /// No such object, authoritatively.
    NotFound,
    /// Something that could have answered did not. Never an absence.
    TryAgain,
    /// The authority cannot be reached, or would not say. glibc moves on to the
    /// next source in the stack.
    Unavailable,
}

/// Whether a failure is worth the caller asking again: a timeout, or a
/// source that could have answered and did not. Everything else — no
/// authority, an answer that could not be read or answered another question,
/// a refusal — is unavailable.
fn transient(failure: &Failure) -> bool {
    failure.transient()
}

impl Client {
    pub fn open() -> io::Result<Self> {
        Ident::new().with_timeout(TIMEOUT).session().map(Client).map_err(io::Error::from)
    }

    pub fn lookup(&mut self, key: ident::Key, kind: Kind, fields: Fields) -> Found {
        match self.0.lookup(key, kind, fields) {
            Ok(Some(record)) => Found::Record(Box::new(record)),
            Ok(None) => Found::NotFound,
            Err(failure) if transient(&failure) => Found::TryAgain,
            Err(_) => Found::Unavailable,
        }
    }

    /// One page of an enumeration, or why there is not one.
    ///
    /// Flattening every non-`Found` outcome *and* every transport failure into
    /// `None` made an authority answering `Unavailable` mid-walk, or a socket
    /// that closed, indistinguishable from having reached the last principal —
    /// `getpwent_r` then returned `NotFound` and glibc read it as the end of
    /// the enumeration.
    ///
    /// The single-lookup path was already careful about exactly this (see
    /// [`Found`]); the enumeration path threw it away at a scale where it
    /// matters more. One lookup failing softly affects one principal; a walk
    /// failing softly makes `getent passwd` print a short list that looks
    /// complete, for every principal at once, with nothing recording it.
    pub fn enumerate(
        &mut self,
        kind: Kind,
        fields: Fields,
        cursor: &[u8],
    ) -> Paged {
        // A NotFound has no meaning for a walk, and the session reports it as
        // a refusal like the rest: the one thing that must never happen is a
        // failure reading as the end.
        match self.0.page(kind, fields, None, cursor) {
            Ok(reply) => Paged::Page(reply),
            Err(failure) if transient(&failure) => Paged::TryAgain,
            Err(_) => Paged::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::Outcome;

    /// The mapping this module exists for: a timeout or a source that did
    /// not answer is worth trying again; nothing else is, and none of it is
    /// ever "no such principal".
    #[test]
    fn only_a_silence_or_an_unanswering_source_is_worth_trying_again() {
        let error = || io::Error::from(io::ErrorKind::TimedOut);
        assert!(transient(&Failure::Unanswered(error())));
        assert!(transient(&Failure::Declined(Outcome::Unavailable)));
        for failure in [
            Failure::Unreachable(error()),
            Failure::Unsent(error()),
            Failure::Unreadable("another question".into()),
            Failure::Declined(Outcome::Refused),
            Failure::Declined(Outcome::Malformed),
            Failure::Declined(Outcome::NotFound),
        ] {
            assert!(!transient(&failure), "{failure:?}");
        }
    }
}
