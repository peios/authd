//! Serving `/run/ident.sock` — PGSS Logon chapter 6.
//!
//! One connection carries as many independent requests as a caller cares to
//! send. There is no conversation here and no state between requests: a lookup
//! is a question and an answer, and the connection is a pipe for them.
//!
//! # Why this is a second socket
//!
//! Not for isolation. authd answers both sockets, so a defect or a hang in
//! either reaches the other regardless and a second socket buys nothing there.
//!
//! It is for **admission**. A listening socket has one accept queue. Listing a
//! large directory is thousands of lookups and a filesystem walk is millions,
//! where logons are a handful per boot — so on a shared socket an ordinary
//! `find` could fill the queue an administrator needs in order to sign in.
//!
//! # Why it is reachable by everyone
//!
//! The descriptor is deliberately open, and restricting it would protect
//! nothing: a principal excluded from connecting would see numbers where names
//! should be, while one that *can* connect learns the same names either way.
//! Restriction, if authd ever wants it, belongs on individual fields.
//!
//! # Serially, per connection
//!
//! A request is read, answered, and the next is read. The protocol permits
//! replies out of order and a client may pipeline; answering in order is
//! conformant, and it keeps this loop free of the bookkeeping that a shared
//! nothing-in-common connection would otherwise need.
//!
//! What that costs is one blocked source query holding up the rest of *that
//! connection's* requests. It does not hold up another connection's, which is
//! the property that matters — a name resolver opens its own.

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use libauthd::ident::{self, Kind, Outcome};
use libauthd::transport::{recv_message, send_message};

use crate::log;
use crate::resolve;
use crate::source::Registry;

/// How long a connection may sit between requests before authd reclaims it.
///
/// A name resolver linked into every process on the system will open a
/// connection, ask, and often never speak again — the process it lives in has
/// moved on. Without this they accumulate.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a reply may block.
///
/// Bounds the damage from a caller that asks and stops reading: without it that
/// caller would hold a thread in the daemon the whole system's identity depends
/// on, for as long as it liked.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many requests one connection may make before authd closes it.
///
/// Not a rate limit — it is a bound on how long one caller may hold a thread.
/// Reconnecting is cheap and a resolver does it without noticing.
const MAX_REQUESTS_PER_CONNECTION: usize = 100_000;

/// Serve one connection until it goes quiet.
pub fn serve(registry: Arc<Registry>, stream: UnixStream) {
    if let Err(error) = stream.set_read_timeout(Some(IDLE_TIMEOUT)) {
        log::warn(format_args!("ident: could not set a read timeout: {error}"));
        return;
    }
    if let Err(error) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        log::warn(format_args!("ident: could not set a write timeout: {error}"));
        return;
    }

    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let received = match recv_message(&libauthd::wire::FRAMING, &stream) {
            Ok(received) => received,
            // The ordinary end of a connection, and an idle one timing out.
            // Neither is worth a line in a log that a name resolver will
            // produce thousands of.
            Err(_) => return,
        };

        let (msg_type, _) = match ident::decode_header(received.expose()) {
            Ok(header) => header,
            Err(_) => {
                // Nowhere to put a tag, since the tag is in the body that failed
                // to parse. Closing is the only honest answer: the byte stream
                // is desynchronised and the next message's boundary is unknown.
                log::warn(format_args!("ident: malformed header, closing"));
                return;
            }
        };

        let reply = match msg_type {
            ident::MSG_LOOKUP => lookup(&registry, received.expose()),
            ident::MSG_ENUMERATE => enumerate(&registry, received.expose()),
            // A logon message on the identity socket. Refused rather than
            // served, which is the whole point of the two message ranges being
            // disjoint: a peer connected to the wrong socket learns so from the
            // message type instead of misreading a structure several fields in.
            other => {
                log::warn(format_args!(
                    "ident: {other:#06x} is not served here, closing"
                ));
                return;
            }
        };

        let Ok(reply) = reply else {
            log::error(format_args!("ident: could not encode a reply, closing"));
            return;
        };
        if send_message(&stream, &reply).is_err() {
            return;
        }
    }

    log::info(format_args!(
        "ident: closing a connection after {MAX_REQUESTS_PER_CONNECTION} requests"
    ));
}

fn lookup(registry: &Registry, buf: &[u8]) -> io::Result<Vec<u8>> {
    let request = match ident::decode_lookup(buf) {
        Ok(request) => request,
        // The tag was in the body, so there is none to echo. A caller cannot
        // pair this with anything, which is correct: it sent something that was
        // not a request.
        Err(_) => return encode_refusal(0, Outcome::Malformed),
    };

    let answer = resolve::lookup(registry, &request.key, request.kind, request.fields);
    ident::encode_lookup_reply(&ident::LookupReply {
        tag: request.tag,
        outcome: answer.outcome,
        record: answer.record,
    })
    .map_err(|_| io::Error::other("could not encode a lookup reply"))
}

fn enumerate(registry: &Registry, buf: &[u8]) -> io::Result<Vec<u8>> {
    let request = match ident::decode_enumerate(buf) {
        Ok(request) => request,
        Err(_) => return encode_enumerate_refusal(0, Outcome::Malformed),
    };

    // A caller filling a `passwd` or a `group` table wants one or the other.
    if request.kind == Kind::Any {
        return encode_enumerate_refusal(request.tag, Outcome::Malformed);
    }
    // Members of one group are a lookup that overflowed, and belong to the
    // source that holds the group rather than to a walk across all of them.
    if request.of.is_some() {
        return encode_enumerate_refusal(request.tag, Outcome::Refused);
    }

    let fields = request.fields;
    let page = resolve::enumerate(registry, request.kind, fields, &request.cursor);

    // The well-known principals belong to no source, so they appear in no
    // source's enumeration and are added here — on the first page only, since a
    // caller walking a cursor would otherwise see them again with every page.
    let mut entries = page.entries;
    if request.cursor.is_empty() {
        let mut first = resolve::well_known_page(request.kind, fields);
        first.extend(entries);
        entries = first;
    }

    ident::encode_enumerate_reply(&ident::EnumerateReply {
        tag: request.tag,
        outcome: Outcome::Found,
        entries,
        next: page.next,
        incomplete: page.incomplete,
    })
    .map_err(|_| io::Error::other("could not encode an enumeration reply"))
}

fn encode_refusal(tag: u32, outcome: Outcome) -> io::Result<Vec<u8>> {
    ident::encode_lookup_reply(&ident::LookupReply {
        tag,
        outcome,
        record: None,
    })
    .map_err(|_| io::Error::other("could not encode a refusal"))
}

fn encode_enumerate_refusal(tag: u32, outcome: Outcome) -> io::Result<Vec<u8>> {
    ident::encode_enumerate_reply(&ident::EnumerateReply {
        tag,
        outcome,
        entries: Vec::new(),
        next: Vec::new(),
        incomplete: Vec::new(),
    })
    .map_err(|_| io::Error::other("could not encode a refusal"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::Fields;
    use std::thread;

    fn client() -> (UnixStream, thread::JoinHandle<()>) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let registry = Arc::new(Registry::new());
        let handle = thread::spawn(move || serve(registry, theirs));
        (ours, handle)
    }

    fn round_trip(request: &[u8]) -> Vec<u8> {
        let (stream, handle) = client();
        send_message(&stream, request).expect("must send");
        let reply = recv_message(&libauthd::wire::FRAMING, &stream).expect("must reply");
        let bytes = reply.expose().to_vec();
        drop(stream);
        let _ = handle.join();
        bytes
    }

    /// No sources registered, so nothing holds the name — and the answer is a
    /// definite absence rather than a hang or a fault.
    #[test]
    fn a_lookup_with_no_sources_is_not_found() {
        let request = ident::encode_lookup(&ident::Lookup {
            tag: 42,
            key: ident::Key::Name("jack".into()),
            kind: Kind::Principal,
            fields: Fields::PASSWD,
        })
        .unwrap();
        let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
        assert_eq!(reply.tag, 42, "the tag must come back unchanged");
        assert_eq!(reply.outcome, Outcome::NotFound);
        assert!(reply.record.is_none());
    }

    /// Answered by authd's own table, with no source consulted — these numbers
    /// are below every source's base and belong to nobody else.
    #[test]
    fn a_well_known_group_resolves_without_a_source() {
        for key in [
            ident::Key::Name("Everyone".into()),
            ident::Key::UnixId(100),
        ] {
            let request = ident::encode_lookup(&ident::Lookup {
                tag: 1,
                key: key.clone(),
                kind: Kind::Group,
                fields: Fields::UNIX_ID,
            })
            .unwrap();
            let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
            assert_eq!(reply.outcome, Outcome::Found, "{key:?}");
            let record = reply.record.expect("a record");
            assert_eq!(record.qualified_name, "Everyone");
            assert_eq!(record.kind_found, Kind::Group);
            assert_eq!(
                record.value(Fields::UNIX_ID),
                Some(&libauthd::ident::Value::UnixId(100))
            );
        }
    }

    /// `Interactive` and its siblings are properties of a session rather than of
    /// an account, so they are nameable and unnumbered.
    #[test]
    fn a_logon_sid_is_nameable_but_carries_no_number() {
        let request = ident::encode_lookup(&ident::Lookup {
            tag: 1,
            key: ident::Key::Name("Interactive".into()),
            kind: Kind::Group,
            fields: Fields::UNIX_ID,
        })
        .unwrap();
        let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
        let record = reply.record.expect("a record");
        assert!(record.value(Fields::UNIX_ID).is_none());
        assert_eq!(
            record.reason(Fields::UNIX_ID),
            Some(libauthd::ident::WithheldReason::Absent)
        );
    }

    #[test]
    fn a_well_known_group_is_not_answered_to_a_principal_request() {
        let request = ident::encode_lookup(&ident::Lookup {
            tag: 1,
            key: ident::Key::Name("Everyone".into()),
            kind: Kind::Principal,
            fields: Fields::empty(),
        })
        .unwrap();
        let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
        assert_eq!(reply.outcome, Outcome::NotFound);
    }

    /// A name no source is permitted to hold is refused here rather than asked
    /// about, so `jack@local` is a clean answer instead of a mysterious absence.
    #[test]
    fn a_name_with_a_reserved_character_is_malformed() {
        for name in ["jack@local", "PEIOS\\jack", "jack/x", "jack:x", "jack,x"] {
            let request = ident::encode_lookup(&ident::Lookup {
                tag: 1,
                key: ident::Key::Name(name.into()),
                kind: Kind::Any,
                fields: Fields::empty(),
            })
            .unwrap();
            let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
            assert_eq!(reply.outcome, Outcome::Malformed, "{name}");
        }
    }

    #[test]
    fn a_key_that_is_not_a_sid_is_malformed() {
        let request = ident::encode_lookup(&ident::Lookup {
            tag: 1,
            key: ident::Key::Sid(vec![0xff, 0xff]),
            kind: Kind::Any,
            fields: Fields::empty(),
        })
        .unwrap();
        let reply = ident::decode_lookup_reply(&round_trip(&request)).unwrap();
        assert_eq!(reply.outcome, Outcome::Malformed);
    }

    /// Several requests on one connection, answered in order.
    #[test]
    fn a_connection_carries_many_requests() {
        let (stream, handle) = client();
        for tag in 1..=5u32 {
            let request = ident::encode_lookup(&ident::Lookup {
                tag,
                key: ident::Key::Name("Everyone".into()),
                kind: Kind::Group,
                fields: Fields::empty(),
            })
            .unwrap();
            send_message(&stream, &request).expect("must send");
            let reply = recv_message(&libauthd::wire::FRAMING, &stream).expect("must reply");
            let reply = ident::decode_lookup_reply(reply.expose()).unwrap();
            assert_eq!(reply.tag, tag);
        }
        drop(stream);
        let _ = handle.join();
    }

    /// The point of the two message ranges being disjoint.
    #[test]
    fn a_logon_message_is_not_served_here() {
        let (stream, handle) = client();
        let start = libauthd::wire::encode_logon_start(&libauthd::wire::LogonStart {
            logon_type: libauthd::wire::LogonType::Interactive,
            identifier_type: libauthd::wire::IdentifierType::Username,
            identifier: b"jack".to_vec(),
            tty: None,
            remote_host: None,
            supported_credential_types: vec![libauthd::wire::CredentialType::Password],
        })
        .unwrap();
        send_message(&stream, &start).expect("must send");
        assert!(
            recv_message(&libauthd::wire::FRAMING, &stream).is_err(),
            "a LogonStart on the identity socket must close the connection"
        );
        drop(stream);
        let _ = handle.join();
    }

    /// Every well-known group that carries a number, with no source registered.
    #[test]
    fn enumerating_groups_lists_the_well_known_ones() {
        let request = ident::encode_enumerate(&ident::Enumerate {
            tag: 9,
            kind: Kind::Group,
            fields: Fields::UNIX_ID,
            of: None,
            cursor: Vec::new(),
        })
        .unwrap();
        let reply = ident::decode_enumerate_reply(&round_trip(&request)).unwrap();
        assert_eq!(reply.tag, 9);
        assert_eq!(reply.outcome, Outcome::Found);
        assert!(
            reply
                .entries
                .iter()
                .any(|e| e.qualified_name == "Administrators")
        );
        assert!(
            !reply
                .entries
                .iter()
                .any(|e| e.qualified_name == "Interactive"),
            "a session property is not a row in a group table"
        );
        assert!(reply.next.is_empty());
    }

    /// They belong to authd rather than to a source, so a caller resuming a walk
    /// must not be shown them again with every page.
    #[test]
    fn the_well_known_groups_appear_on_the_first_page_only() {
        let request = ident::encode_enumerate(&ident::Enumerate {
            tag: 1,
            kind: Kind::Group,
            fields: Fields::empty(),
            of: None,
            cursor: vec![0, 0, 0, 0],
        })
        .unwrap();
        let reply = ident::decode_enumerate_reply(&round_trip(&request)).unwrap();
        assert!(reply.entries.is_empty());
    }

    #[test]
    fn enumerating_anything_at_all_is_malformed() {
        let request = ident::encode_enumerate(&ident::Enumerate {
            tag: 1,
            kind: Kind::Any,
            fields: Fields::empty(),
            of: None,
            cursor: Vec::new(),
        })
        .unwrap();
        let reply = ident::decode_enumerate_reply(&round_trip(&request)).unwrap();
        assert_eq!(reply.outcome, Outcome::Malformed);
    }
}
