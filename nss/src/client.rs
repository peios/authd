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

use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use libauthd::ident::{self, Fields, Kind, Outcome, Record};
use libauthd::transport::{recv_message, send_message};

/// How long the authority has to answer before the caller is told to try again.
///
/// A name resolver is called synchronously from every process on the system, so
/// this bounds how long an unrelated program can be made to sit still. Shorter
/// than authd's own budget for asking a source, on purpose: better to tell a
/// caller to retry than to hold it while authd waits on a directory.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to `/run/ident.sock`.
pub struct Client {
    stream: UnixStream,
    tag: u32,
}

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

impl Client {
    pub fn open() -> io::Result<Self> {
        let stream = UnixStream::connect(libauthd::IDENT_SOCKET_PATH)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        Ok(Self { stream, tag: 1 })
    }

    fn next_tag(&mut self) -> u32 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);
        tag
    }

    pub fn lookup(&mut self, key: ident::Key, kind: Kind, fields: Fields) -> Found {
        let tag = self.next_tag();
        let Ok(request) = ident::encode_lookup(&ident::Lookup {
            tag,
            key,
            kind,
            fields,
        }) else {
            return Found::Unavailable;
        };
        if send_message(&self.stream, &request).is_err() {
            return Found::Unavailable;
        }

        let Ok(received) = recv_message(&libauthd::wire::FRAMING, &self.stream) else {
            // A timeout lands here too, and `TryAgain` is the right reading:
            // the authority exists, it just did not answer in time.
            return Found::TryAgain;
        };
        let Ok(reply) = ident::decode_lookup_reply(received.expose()) else {
            return Found::Unavailable;
        };
        // Replies may legitimately arrive out of order, but this module never
        // has more than one request outstanding — so a mismatched tag means the
        // stream is not what it should be.
        if reply.tag != tag {
            return Found::Unavailable;
        }

        match reply.outcome {
            Outcome::Found => match reply.record {
                Some(record) => Found::Record(Box::new(record)),
                None => Found::Unavailable,
            },
            Outcome::NotFound => Found::NotFound,
            Outcome::Unavailable => Found::TryAgain,
            Outcome::Refused | Outcome::Malformed => Found::Unavailable,
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
        let tag = self.next_tag();
        let Ok(request) = ident::encode_enumerate(&ident::Enumerate {
            tag,
            kind,
            fields,
            of: None,
            cursor: cursor.to_vec(),
        }) else {
            return Paged::Unavailable;
        };
        if send_message(&self.stream, &request).is_err() {
            return Paged::Unavailable;
        }

        let Ok(received) = recv_message(&libauthd::wire::FRAMING, &self.stream) else {
            // A timeout lands here, and as on the lookup path it means the
            // authority exists and did not answer in time.
            return Paged::TryAgain;
        };
        let Ok(reply) = ident::decode_enumerate_reply(received.expose()) else {
            return Paged::Unavailable;
        };
        if reply.tag != tag {
            return Paged::Unavailable;
        }
        match reply.outcome {
            Outcome::Found => Paged::Page(reply),
            Outcome::Unavailable => Paged::TryAgain,
            // NotFound has no meaning for a walk, so it joins the rest: the
            // one thing that must never happen is a failure reading as the end.
            Outcome::NotFound | Outcome::Refused | Outcome::Malformed => Paged::Unavailable,
        }
    }
}
