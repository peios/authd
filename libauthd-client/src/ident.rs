//! authd's identity socket: who a name or a SID is, and the principals and
//! groups there are, as PGSS Logon's identity lookup answers them.
//!
//! Anyone may ask. A connection is opened for each question, or for each
//! walk through a listing, since authd closes one left idle.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use libauthd::IDENT_SOCKET_PATH;
use libauthd::ident::{self, Enumerate, Fields, Key, Kind, Lookup, Outcome, Record};
use libauthd::transport::{recv_message, send_message};
use libauthd::wire::FRAMING;

/// How long authd is given to answer each request.
const TIMEOUT: Duration = Duration::from_secs(5);

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
        Ident { path: path.as_ref().to_path_buf() }
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let stream = UnixStream::connect(&self.path).map_err(|error| {
            io::Error::new(error.kind(), format!("cannot reach authd on {}: {error}", self.path.display()))
        })?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        Ok(stream)
    }

    /// Who `key` is, with `fields` of them. `Ok(None)` is authd's word that
    /// there is nobody by it, every source having been asked.
    pub fn lookup(&self, key: Key, kind: Kind, fields: Fields) -> io::Result<Option<Record>> {
        let stream = self.connect()?;
        let request = ident::encode_lookup(&Lookup { tag: 1, key, kind, fields }).map_err(unencodable)?;
        send_message(&stream, &request)?;
        let received = recv_message(&FRAMING, &stream)?;
        let reply = ident::decode_lookup_reply(received.expose()).map_err(unreadable)?;
        match (reply.outcome, reply.record) {
            (Outcome::Found, Some(record)) => Ok(Some(record)),
            (Outcome::NotFound, _) => Ok(None),
            (outcome, _) => Err(refused(outcome)),
        }
    }

    /// Every principal or every group, with `fields` of each, page after
    /// page. With `of`, a group's members instead.
    pub fn enumerate(&self, kind: Kind, fields: Fields, of: Option<Key>) -> io::Result<Listing> {
        let stream = self.connect()?;
        let mut listing = Listing::default();
        let mut cursor = Vec::new();
        for tag in 1.. {
            let request = Enumerate { tag, kind, fields, of: of.clone(), cursor };
            send_message(&stream, &ident::encode_enumerate(&request).map_err(unencodable)?)?;
            let received = recv_message(&FRAMING, &stream)?;
            let reply = ident::decode_enumerate_reply(received.expose()).map_err(unreadable)?;
            if reply.outcome != Outcome::Found {
                return Err(refused(reply.outcome));
            }
            listing.records.extend(reply.entries);
            for source in reply.incomplete {
                if !listing.incomplete.contains(&source) {
                    listing.incomplete.push(source);
                }
            }
            if reply.next.is_empty() {
                break;
            }
            cursor = reply.next;
        }
        Ok(listing)
    }
}

fn unencodable(error: libauthd::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("could not encode the request: {error:?}"))
}

fn unreadable(error: libauthd::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("authd's answer could not be read ({error:?}); versions may differ"))
}

fn refused(outcome: Outcome) -> io::Error {
    io::Error::other(match outcome {
        Outcome::Unavailable => "a source that could have answered did not",
        Outcome::Refused => "authd refused the question",
        Outcome::Malformed => "authd could not read the question",
        Outcome::Found | Outcome::NotFound => "authd's answer was not the one expected",
    })
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
        std::fs::remove_dir_all(dir).unwrap();
    }
}
