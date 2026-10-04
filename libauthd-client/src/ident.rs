//! authd's identity socket: who a name or a SID is, and the principals and
//! groups there are, as PGSS Logon's identity lookup answers them.
//!
//! Anyone may ask. [`Ident::lookup`] and [`Ident::enumerate`] open a
//! connection for each question, or for each walk through a listing, since
//! authd closes one left idle. A caller that walks a listing a page at a
//! time, as nss's `getpwent` does, holds a [`Session`] for the walk instead.
//!
//! # Why a question went unanswered
//!
//! A [`Failure`] says which of the ways it could fail it was, because callers
//! answer them differently: nss tells glibc to try again when authd is there
//! but a source didn't answer in time ([`Failure::transient`]), and says it
//! is unavailable otherwise, and neither may ever read as "nobody by that
//! name".

use std::fmt;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::IDENT_SOCKET_PATH;
use libauthd::ident::{self, Enumerate, EnumerateReply, Fields, Key, Kind, Lookup, Outcome, Record};
use libauthd::transport::{recv_message, send_message};
use libauthd::wire::FRAMING;

/// How long authd is given to answer each request, unless the caller says.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Why a question to authd got no answer.
#[derive(Debug)]
pub enum Failure {
    /// authd couldn't be reached: no socket, or nothing listening on it.
    Unreachable(io::Error),
    /// The question couldn't be sent.
    Unsent(io::Error),
    /// No answer came: the time ran out, or the connection closed. authd is
    /// there, so asking again may do.
    Unanswered(io::Error),
    /// The answer couldn't be read, or answered another question: the
    /// versions on each side may differ.
    Unreadable(String),
    /// authd answered that it couldn't: a source that could have answered
    /// didn't ([`Outcome::Unavailable`]), it refused, or it couldn't read the
    /// question.
    Declined(Outcome),
}

impl Failure {
    /// Whether asking again may get an answer: authd is there, and either
    /// didn't answer in time or a source that could have didn't.
    pub fn transient(&self) -> bool {
        matches!(self, Failure::Unanswered(_) | Failure::Declined(Outcome::Unavailable))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Unreachable(error) | Failure::Unsent(error) | Failure::Unanswered(error) => write!(f, "{error}"),
            Failure::Unreadable(why) => write!(f, "authd's answer could not be read ({why}); versions may differ"),
            Failure::Declined(outcome) => f.write_str(match outcome {
                Outcome::Unavailable => "a source that could have answered did not",
                Outcome::Refused => "authd refused the question",
                Outcome::Malformed => "authd could not read the question",
                Outcome::Found | Outcome::NotFound => "authd's answer was not the one expected",
            }),
        }
    }
}

impl std::error::Error for Failure {}

impl From<Failure> for io::Error {
    fn from(failure: Failure) -> io::Error {
        match failure {
            Failure::Unreachable(error) | Failure::Unsent(error) | Failure::Unanswered(error) => error,
            Failure::Unreadable(_) => io::Error::new(io::ErrorKind::InvalidData, failure.to_string()),
            Failure::Declined(_) => io::Error::other(failure.to_string()),
        }
    }
}

/// One connection to authd's identity socket, for as many questions as the
/// caller has, one at a time.
#[derive(Debug)]
pub struct Session {
    stream: UnixStream,
    tag: u32,
}

impl Session {
    fn next_tag(&mut self) -> u32 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);
        tag
    }

    fn ask(&mut self, request: Result<Vec<u8>, libauthd::WireError>) -> Result<Vec<u8>, Failure> {
        let request = request.map_err(|error| Failure::Unreadable(format!("the question could not be encoded: {error:?}")))?;
        send_message(&self.stream, &request).map_err(Failure::Unsent)?;
        let received = recv_message(&FRAMING, &self.stream).map_err(Failure::Unanswered)?;
        Ok(received.expose().to_vec())
    }

    /// Who `key` is, with `fields` of them. `Ok(None)` is authd's word that
    /// there is nobody by it, every source having been asked.
    pub fn lookup(&mut self, key: Key, kind: Kind, fields: Fields) -> Result<Option<Record>, Failure> {
        let tag = self.next_tag();
        let received = self.ask(ident::encode_lookup(&Lookup { tag, key, kind, fields }))?;
        let reply = ident::decode_lookup_reply(&received).map_err(|error| Failure::Unreadable(format!("{error:?}")))?;
        // One question is outstanding at a time, so an answer to another
        // means the connection is not what it should be.
        if reply.tag != tag {
            return Err(Failure::Unreadable("it answered another question".into()));
        }
        match (reply.outcome, reply.record) {
            (Outcome::Found, Some(record)) => Ok(Some(record)),
            (Outcome::Found, None) => Err(Failure::Unreadable("it said it found someone, and gave nobody".into())),
            (Outcome::NotFound, _) => Ok(None),
            (outcome, _) => Err(Failure::Declined(outcome)),
        }
    }

    /// One page of every principal or every group, or with `of` a group's
    /// members, from `cursor` (empty for the first). The walk is over only
    /// when a page's `next` is empty: no failure ever reads as the end.
    pub fn page(&mut self, kind: Kind, fields: Fields, of: Option<Key>, cursor: &[u8]) -> Result<EnumerateReply, Failure> {
        let tag = self.next_tag();
        let received = self.ask(ident::encode_enumerate(&Enumerate { tag, kind, fields, of, cursor: cursor.to_vec() }))?;
        let reply = ident::decode_enumerate_reply(&received).map_err(|error| Failure::Unreadable(format!("{error:?}")))?;
        if reply.tag != tag {
            return Err(Failure::Unreadable("it answered another question".into()));
        }
        match reply.outcome {
            Outcome::Found => Ok(reply),
            // NotFound has no meaning for a walk, so it is a refusal like
            // the rest.
            outcome => Err(Failure::Declined(outcome)),
        }
    }
}

/// A listing, as far as it could be had.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    pub records: Vec<Record>,
    /// The sources that didn't contribute, declining or unreachable. A short
    /// listing that looks complete is what this is here to prevent.
    pub incomplete: Vec<String>,
}

/// authd's identity socket.
#[derive(Debug, Clone)]
pub struct Ident {
    path: PathBuf,
    timeout: Duration,
}

impl Default for Ident {
    fn default() -> Ident {
        Ident::new()
    }
}

impl Ident {
    /// The identity socket where it is: [`IDENT_SOCKET_PATH`].
    pub fn new() -> Ident {
        Ident::at(IDENT_SOCKET_PATH)
    }

    /// An identity socket at `path`: for tests, and nothing else.
    pub fn at(path: impl AsRef<Path>) -> Ident {
        Ident { path: path.as_ref().to_path_buf(), timeout: TIMEOUT }
    }

    /// The same socket, giving authd `timeout` to answer each request: short
    /// for a program a person is waiting on, longer for one that would
    /// rather wait than be told to try again.
    pub fn with_timeout(self, timeout: Duration) -> Ident {
        Ident { timeout, ..self }
    }

    /// A connection, for a caller with several questions or a walk to take a
    /// page at a time.
    pub fn session(&self) -> Result<Session, Failure> {
        let stream = UnixStream::connect(&self.path)
            .map_err(|error| Failure::Unreachable(io::Error::new(error.kind(), format!("cannot reach authd on {}: {error}", self.path.display()))))?;
        stream.set_read_timeout(Some(self.timeout)).map_err(Failure::Unreachable)?;
        stream.set_write_timeout(Some(self.timeout)).map_err(Failure::Unreachable)?;
        Ok(Session { stream, tag: 1 })
    }

    /// Who `key` is, with `fields` of them, on a connection of its own.
    /// `Ok(None)` is authd's word that there is nobody by it, every source
    /// having been asked.
    pub fn lookup(&self, key: Key, kind: Kind, fields: Fields) -> Result<Option<Record>, Failure> {
        self.session()?.lookup(key, kind, fields)
    }

    /// Every principal or every group, with `fields` of each, page after
    /// page on one connection. With `of`, a group's members instead.
    pub fn enumerate(&self, kind: Kind, fields: Fields, of: Option<Key>) -> Result<Listing, Failure> {
        let mut session = self.session()?;
        let mut listing = Listing::default();
        let mut cursor = Vec::new();
        loop {
            let reply = session.page(kind, fields, of.clone(), &cursor)?;
            listing.records.extend(reply.entries);
            for source in reply.incomplete {
                if !listing.incomplete.contains(&source) {
                    listing.incomplete.push(source);
                }
            }
            if reply.next.is_empty() {
                return Ok(listing);
            }
            cursor = reply.next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::{EnumerateReply, LookupReply, Value};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A stand-in authd at a fresh path, answering every message on a
    /// connection with `answer` of it.
    fn stand_in(answer: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) -> (Ident, PathBuf) {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("libauthd-client-ident-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ident.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                while let Ok(received) = recv_message(&FRAMING, &stream) {
                    if send_message(&stream, &answer(received.expose())).is_err() {
                        break;
                    }
                }
            }
        });
        (Ident::at(&path), dir)
    }

    fn record(name: &str) -> Record {
        Record { sid: vec![1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], qualified_name: name.into(), kind_found: Kind::Principal, values: vec![Value::Enabled(true)], withheld: Vec::new() }
    }

    #[test]
    fn a_listing_is_followed_to_its_last_page() {
        let (ident, dir) = stand_in(|request| {
            let request = ident::decode_enumerate(request).unwrap();
            let (entries, next) = if request.cursor.is_empty() { (vec![record("dana")], b"more".to_vec()) } else { (vec![record("alice")], Vec::new()) };
            ident::encode_enumerate_reply(&EnumerateReply { tag: request.tag, outcome: Outcome::Found, entries, next, incomplete: vec!["lpsd".into()] }).unwrap()
        });
        let listing = ident.enumerate(Kind::Principal, Fields::ENABLED, None).unwrap();
        let names: Vec<&str> = listing.records.iter().map(|record| record.qualified_name.as_str()).collect();
        assert_eq!(names, ["dana", "alice"]);
        assert_eq!(listing.incomplete, ["lpsd"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nobody_by_a_name_is_none_and_a_refusal_is_an_error() {
        let (ident, dir) = stand_in(|request| {
            let request = ident::decode_lookup(request).unwrap();
            let outcome = if request.key == Key::Name("nobody".into()) { Outcome::NotFound } else { Outcome::Unavailable };
            ident::encode_lookup_reply(&LookupReply { tag: request.tag, outcome, record: None }).unwrap()
        });
        assert_eq!(ident.lookup(Key::Name("nobody".into()), Kind::Any, Fields::empty()).unwrap(), None);
        let error = ident.lookup(Key::Name("dana".into()), Kind::Any, Fields::empty()).unwrap_err();
        assert_eq!(error.to_string(), "a source that could have answered did not");
        assert!(error.transient(), "a source that didn't answer may next time");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The ways a question fails are told apart, so a caller can tell glibc
    /// to try again, or that authd isn't there, and never "nobody".
    #[test]
    fn why_a_question_failed_is_told() {
        let missing = Ident::at("/nonexistent/ident.sock");
        let unreachable = missing.lookup(Key::Name("dana".into()), Kind::Any, Fields::empty()).unwrap_err();
        assert!(matches!(unreachable, Failure::Unreachable(_)) && !unreachable.transient(), "{unreachable:?}");
        assert!(unreachable.to_string().starts_with("cannot reach authd on /nonexistent/ident.sock"));

        // An answer to another question, and a refusal.
        let (ident, dir) = stand_in(|request| {
            let request = ident::decode_lookup(request).unwrap();
            let (tag, outcome) = if request.key == Key::Name("stale".into()) { (request.tag + 1, Outcome::NotFound) } else { (request.tag, Outcome::Refused) };
            ident::encode_lookup_reply(&LookupReply { tag, outcome, record: None }).unwrap()
        });
        let mut session = ident.session().unwrap();
        assert!(matches!(session.lookup(Key::Name("stale".into()), Kind::Any, Fields::empty()), Err(Failure::Unreadable(_))));
        // The stand-in answers one connection at a time.
        drop(session);
        let refused = ident.lookup(Key::Name("dana".into()), Kind::Any, Fields::empty()).unwrap_err();
        assert!(matches!(refused, Failure::Declined(Outcome::Refused)) && !refused.transient());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A walk taken a page at a time on one connection, and a page refused
    /// mid-walk, which must never read as the end.
    #[test]
    fn a_session_walks_page_by_page_and_a_refused_page_is_no_end() {
        let (ident, dir) = stand_in(|request| {
            let request = ident::decode_enumerate(request).unwrap();
            let (outcome, entries, next) = match request.cursor.as_slice() {
                b"" => (Outcome::Found, vec![record("dana")], b"more".to_vec()),
                _ => (Outcome::Unavailable, Vec::new(), Vec::new()),
            };
            ident::encode_enumerate_reply(&EnumerateReply { tag: request.tag, outcome, entries, next, incomplete: Vec::new() }).unwrap()
        });
        let mut session = ident.with_timeout(Duration::from_secs(1)).session().unwrap();
        let first = session.page(Kind::Principal, Fields::empty(), None, b"").unwrap();
        assert_eq!(first.next, b"more");
        let second = session.page(Kind::Principal, Fields::empty(), None, &first.next).unwrap_err();
        assert!(second.transient(), "{second:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
