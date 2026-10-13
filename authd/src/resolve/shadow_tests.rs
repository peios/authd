use super::*;
use crate::source::pump_for_test;
use libauthd::transport::{recv_message, send_message};
use peios::security::Sid;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Instant;

struct Stub {
    source: Arc<Source>,
    queries: Arc<Mutex<Vec<psi::Query>>>,
    socket: UnixStream,
    worker: Option<JoinHandle<()>>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        // Wake both the test worker and authd's pump; no parked fixture threads
        // or sockets survive into later tests.
        let _ = self.socket.shutdown(Shutdown::Both);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn stub(
    registry: &Registry,
    name: &str,
    order: u32,
    answer: Option<Outcome>,
    queries: bool,
) -> Stub {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let domain = format!("S-1-5-21-{}-2-3", registry.ordered().len() + 1);
    let user: Sid = format!("{domain}-1000").parse().unwrap();
    let source = registry.admit_for_test(
        name,
        domain.parse().unwrap(),
        None,
        if queries {
            psi::Capabilities::QUERIES
        } else {
            psi::Capabilities::empty()
        },
        order,
        ours,
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&captured);
    let socket = theirs.try_clone().unwrap();
    let worker = thread::spawn(move || {
        while let Ok(message) = recv_message(&psi::FRAMING, &theirs) {
            let envelope = psi::decode_envelope(message.expose()).unwrap();
            if envelope.msg_type == psi::MSG_ABANDON {
                continue;
            }
            // Any Authenticate or credential-bearing message is a failure.
            assert_eq!(envelope.msg_type, psi::MSG_QUERY);
            let query = psi::decode_query(message.expose()).unwrap();
            assert!(query.fields.is_empty());
            assert_eq!(query.keys.len(), 1);
            assert_eq!(query.keys[0].kind, Kind::Principal);
            assert_eq!(query.keys[0].key, psi::Key::Name("jack".into()));
            observed.lock().unwrap().push(query);
            let Some(outcome) = answer else { continue };
            let result = psi::QueryResult {
                results: vec![psi::QueryEntry {
                    outcome,
                    sid: if outcome == Outcome::Found {
                        user.as_ref().as_bytes().to_vec()
                    } else {
                        vec![]
                    },
                    canonical_name: if outcome == Outcome::Found {
                        "jack".into()
                    } else {
                        String::new()
                    },
                    ..psi::QueryEntry::default()
                }],
            };
            let reply = psi::encode_query_result(envelope.conversation, &result).unwrap();
            if send_message(&theirs, &reply).is_err() {
                break;
            }
        }
    });
    pump_for_test(&source);
    Stub {
        source,
        queries: captured,
        socket,
        worker: Some(worker),
    }
}

fn checked(registry: &Registry, owner: &Arc<Source>, deadline: Instant) -> Vec<String> {
    let mut shadows = Vec::new();
    check_shadowing(registry, owner, "jack", deadline, |other| {
        shadows.push(other.to_owned())
    });
    shadows
}

#[test]
fn shadow_check_queries_only_later_sources_and_reports_each_claim() {
    let registry = Registry::for_test(&[]);
    let before = stub(&registry, "before", 1, Some(Outcome::Found), true);
    let owner = stub(&registry, "owner", 2, Some(Outcome::Found), true);
    // Same-order slots use the same name tie-breaker as routing.
    let later = stub(&registry, "z-later", 2, Some(Outcome::Found), true);
    let absent_name = stub(&registry, "absent-name", 3, Some(Outcome::NotFound), true);
    let last = stub(&registry, "last", 4, Some(Outcome::Found), true);
    assert_eq!(
        checked(&registry, &owner.source, Instant::now() + QUERY_TIMEOUT),
        ["z-later", "last"]
    );
    assert!(before.queries.lock().unwrap().is_empty());
    assert!(owner.queries.lock().unwrap().is_empty());
    for source in [&later, &absent_name, &last] {
        assert_eq!(source.queries.lock().unwrap().len(), 1);
    }
}

#[test]
fn shadow_check_single_source_is_free_even_without_query_capability() {
    let registry = Registry::for_test(&[]);
    let owner = stub(&registry, "only", 1, Some(Outcome::Found), false);
    warn_shadowed(&registry, &owner.source, b"jack");
    assert!(owner.queries.lock().unwrap().is_empty());
}

#[test]
fn shadow_check_missing_refusing_and_logon_only_slots_are_inconclusive() {
    let registry = Registry::for_test(&[("missing", 2, None)]);
    let owner = stub(&registry, "owner", 1, Some(Outcome::Found), true);
    let refused = stub(&registry, "refused", 3, Some(Outcome::Refused), true);
    let logon_only = stub(&registry, "logon-only", 4, Some(Outcome::Found), false);
    let later = stub(&registry, "later", 5, Some(Outcome::Found), true);
    assert_eq!(
        checked(&registry, &owner.source, Instant::now() + QUERY_TIMEOUT),
        ["later"]
    );
    assert_eq!(refused.queries.lock().unwrap().len(), 1);
    assert!(logon_only.queries.lock().unwrap().is_empty());
    assert_eq!(later.queries.lock().unwrap().len(), 1);
}

#[test]
fn shadow_check_does_not_confuse_a_replacement_with_the_original_owner() {
    let old_registry = Registry::for_test(&[]);
    let old = stub(&old_registry, "owner", 1, Some(Outcome::Found), true);
    let registry = Registry::for_test(&[]);
    let replacement = stub(&registry, "owner", 1, Some(Outcome::Found), true);
    let later = stub(&registry, "later", 2, Some(Outcome::Found), true);
    assert!(checked(&registry, &old.source, Instant::now() + QUERY_TIMEOUT).is_empty());
    assert!(replacement.queries.lock().unwrap().is_empty());
    assert!(later.queries.lock().unwrap().is_empty());
}

#[test]
fn shadow_check_spends_one_deadline_not_one_timeout_per_source() {
    let registry = Registry::for_test(&[]);
    let owner = stub(&registry, "owner", 1, Some(Outcome::Found), true);
    let stalled = stub(&registry, "stalled", 2, None, true);
    let later = stub(&registry, "later", 3, Some(Outcome::Found), true);
    assert!(
        checked(
            &registry,
            &owner.source,
            Instant::now() + Duration::from_millis(100)
        )
        .is_empty()
    );
    assert_eq!(stalled.queries.lock().unwrap().len(), 1);
    assert!(later.queries.lock().unwrap().is_empty());
}

#[test]
fn shadow_check_expired_budget_and_unusable_identifiers_send_nothing() {
    let registry = Registry::for_test(&[]);
    let owner = stub(&registry, "owner", 1, Some(Outcome::Found), true);
    let later = stub(&registry, "later", 2, Some(Outcome::Found), true);
    assert!(checked(&registry, &owner.source, Instant::now()).is_empty());
    warn_shadowed(&registry, &owner.source, b"\xff");
    warn_shadowed(&registry, &owner.source, b" jack ");
    assert!(later.queries.lock().unwrap().is_empty());
}

#[test]
fn shadow_warning_records_a_confirmed_duplicate() {
    let registry = Registry::for_test(&[]);
    let owner = stub(&registry, "local", 1, Some(Outcome::Found), true);
    let later = stub(&registry, "directory", 2, Some(Outcome::Found), true);
    warn_shadowed(&registry, &owner.source, b"jack");
    assert_eq!(later.queries.lock().unwrap().len(), 1);
}
