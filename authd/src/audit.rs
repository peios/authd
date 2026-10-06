//! The events authd writes: what it did, for the audit trail.
//!
//! Three types, defined in `authd.evman` at the repository root, which is the
//! catalogue's word on what each field means:
//!
//! - `authd.logon.attempted` (essential), from [`crate::conversation`];
//! - `authd.service.attested` (standard), from [`crate::attest`];
//! - `authd.session.ended` (essential), from [`crate::end`].
//!
//! **No denial events.** Whether a caller may do something is an access
//! decision, and access decisions are KACS's to record: a check authd makes
//! with an `AccessCheck` names what it guarded with an audit context, and the
//! kernel writes `kacs.audit.access.checked` when the descriptor's SACL asks
//! for it (PGSS §6.7). What is recorded here is what authd *did* — a logon
//! that failed is still a logon attempted.
//!
//! **Never a name.** A principal is a SID in every record. On a failed logon
//! authd does not know who was signing in, and the name the caller typed is
//! caller input rather than an identity, so it is not recorded at all.
//!
//! **Emission never fails the work.** A record KMES will not take — authd
//! without `SeAuditPrivilege`, a full rate budget — is logged and the logon
//! goes on. Refusing a sign-on because the audit trail is unavailable would
//! hand anyone who can fill the event budget a way to lock the machine.

use std::sync::OnceLock;

use libauthd::wire::Denial;
use peios::event::{EventPolicy, Tier};
use peios::msgpack::Writer;
use peios::security::SidRef;

use crate::log;

/// One payload value, in its PGSS §6.5 wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Uint(u64),
    Bool(bool),
    /// Binary: a SID, as its bytes.
    Bin(Vec<u8>),
}

/// An event payload, built field by field and encoded as the nested maps
/// PGSS §6.4 requires: `subject.token.sid` is `{subject: {token: {sid}}}`.
///
/// Fields are kept in the order they were set, and setting one twice keeps
/// the last value, so an emitter can fill a record as it learns things.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    fields: Vec<(&'static str, Value)>,
}

impl Record {
    pub fn new() -> Self {
        Self::default()
    }

    fn set(&mut self, path: &'static str, value: Value) -> &mut Self {
        match self.fields.iter_mut().find(|(have, _)| *have == path) {
            Some((_, slot)) => *slot = value,
            None => self.fields.push((path, value)),
        }
        self
    }

    pub fn str(&mut self, path: &'static str, value: &str) -> &mut Self {
        self.set(path, Value::Str(value.to_string()))
    }

    pub fn uint(&mut self, path: &'static str, value: u64) -> &mut Self {
        self.set(path, Value::Uint(value))
    }

    pub fn bool(&mut self, path: &'static str, value: bool) -> &mut Self {
        self.set(path, Value::Bool(value))
    }

    pub fn sid(&mut self, path: &'static str, sid: &SidRef) -> &mut Self {
        self.set(path, Value::Bin(sid.as_bytes().to_vec()))
    }

    /// `outcome.success`, and `outcome.reason` when it failed.
    pub fn outcome(&mut self, reason: Option<&str>) -> &mut Self {
        self.bool("outcome.success", reason.is_none());
        if let Some(reason) = reason {
            self.str("outcome.reason", reason);
        }
        self
    }

    /// A field's value, for tests and for an emitter checking what it set.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get(&self, path: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find(|(have, _)| *have == path)
            .map(|(_, value)| value)
    }

    /// The MessagePack payload.
    pub fn encode(&self) -> peios::Result<Vec<u8>> {
        let entries: Vec<(Vec<&str>, &Value)> = self
            .fields
            .iter()
            .map(|(path, value)| (path.split('.').collect(), value))
            .collect();
        let mut writer = Writer::new();
        write_level(&mut writer, &entries, 0);
        writer.to_bytes()
    }
}

/// Write the map at `depth`: one key per distinct segment at that depth, in
/// first-seen order, holding a value or the map beneath it.
///
/// A path that is both a value and a prefix of another is the catalogue's
/// rule 3 broken by the emitter; it is a bug here, and the value wins so that
/// the payload is still well formed.
fn write_level(writer: &mut Writer, entries: &[(Vec<&str>, &Value)], depth: usize) {
    let mut keys: Vec<&str> = Vec::new();
    for (segments, _) in entries {
        if !keys.contains(&segments[depth]) {
            keys.push(segments[depth]);
        }
    }
    writer.write_map(keys.len() as u32);
    for key in keys {
        writer.write_str(key);
        let beneath: Vec<(Vec<&str>, &Value)> = entries
            .iter()
            .filter(|(segments, _)| segments[depth] == key)
            .map(|(segments, value)| (segments.clone(), *value))
            .collect();
        match beneath
            .iter()
            .find(|(segments, _)| segments.len() == depth + 1)
        {
            Some((_, value)) => {
                debug_assert!(beneath.len() == 1, "a path is both a value and a map");
                write_value(writer, value);
            }
            None => write_level(writer, &beneath, depth + 1),
        }
    }
}

fn write_value(writer: &mut Writer, value: &Value) {
    match value {
        Value::Str(text) => writer.write_str(text),
        Value::Uint(number) => writer.write_uint(*number),
        Value::Bool(flag) => writer.write_bool(*flag),
        Value::Bin(bytes) => writer.write_bin(bytes),
    };
}

/// A logon type's name in `object.session.logon-type`, from its value — the
/// kernel's `KACS_LOGON_TYPE_*`, which PGSS Logon's `LogonType` and the
/// kernel's session listing both use. `None` for a value no session can have.
pub fn logon_type_name(value: u32) -> Option<&'static str> {
    Some(match value {
        2 => "interactive",
        3 => "network",
        4 => "batch",
        5 => "service",
        8 => "network-cleartext",
        9 => "new-credentials",
        10 => "remote-interactive",
        _ => return None,
    })
}

/// A denial's `outcome.reason`: its PGSS Logon name, in kebab-case.
pub fn denial_reason(denial: Denial) -> &'static str {
    match denial {
        Denial::MalformedRequest => "malformed-request",
        Denial::UnsupportedVersion => "unsupported-version",
        Denial::PermissionDenied => "permission-denied",
        Denial::AuthenticationFailed => "authentication-failed",
        Denial::LogonTypeNotPermitted => "logon-type-not-permitted",
        Denial::AccountRestricted => "account-restricted",
        Denial::AuthorityUnavailable => "authority-unavailable",
        Denial::ConversationLimit => "conversation-limit",
        Denial::Internal => "internal",
        Denial::NoSuchSession => "no-such-session",
        Denial::CredentialRejected => "credential-rejected",
    }
}

/// The emission policy (PGSS §6.9), opened on first use and kept: it watches
/// `Machine\Generic\Events` itself, so one view serves the daemon's life.
///
/// `None` only where it could not be opened at all, which is want of memory;
/// a standard event is then decided by its tier, which is what the policy
/// does without a registry.
fn policy() -> Option<&'static EventPolicy> {
    static POLICY: OnceLock<Option<EventPolicy>> = OnceLock::new();
    POLICY
        .get_or_init(|| match EventPolicy::open() {
            Ok(policy) => Some(policy),
            Err(error) => {
                log::warn(format_args!(
                    "could not open the event policy: {error}; deciding by tier"
                ));
                None
            }
        })
        .as_ref()
}

/// Write an essential event. The policy is never asked: an essential event
/// cannot be switched off.
pub fn essential(event_type: &str, record: &Record) {
    write(event_type, record);
}

/// Write a standard event, building it only if the policy has it on.
pub fn standard(event_type: &str, build: impl FnOnce() -> Record) {
    if cfg!(not(test)) {
        let on = match policy() {
            Some(policy) => policy.enabled(event_type, Tier::Standard),
            None => Ok(true),
        };
        match on {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                log::warn(format_args!(
                    "could not ask the event policy about {event_type}: {error}"
                ));
                return;
            }
        }
    }
    write(event_type, &build());
}

#[cfg(not(test))]
fn write(event_type: &str, record: &Record) {
    let result = record
        .encode()
        .and_then(|payload| peios::event::emit(event_type, &payload));
    if let Err(error) = result {
        log::warn(format_args!("could not record {event_type}: {error}"));
    }
}

/// Under test nothing reaches KMES: each record is kept for the test that
/// caused it to read back with [`take`].
#[cfg(test)]
fn write(event_type: &str, record: &Record) {
    record.encode().expect("a record encodes");
    WRITTEN.with(|written| {
        written
            .borrow_mut()
            .push((event_type.to_string(), record.clone()))
    });
}

#[cfg(test)]
thread_local! {
    static WRITTEN: std::cell::RefCell<Vec<(String, Record)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Every record this thread has written since the last call.
#[cfg(test)]
pub fn take() -> Vec<(String, Record)> {
    WRITTEN.with(|written| written.borrow_mut().drain(..).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::msgpack::{Reader, Type};
    use peios::security::Sid;

    #[test]
    fn paths_become_nested_maps() {
        let sid: Sid = "S-1-5-18".parse().unwrap();
        let mut record = Record::new();
        record
            .sid("subject.token.sid", sid.as_ref())
            .uint("object.session.id", 7)
            .str("object.session.logon-type", "interactive")
            .outcome(None);
        let bytes = record.encode().unwrap();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_map().unwrap(), 3);
        assert_eq!(reader.read_str().unwrap(), "subject");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "token");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "sid");
        assert_eq!(reader.read_bin().unwrap(), sid.as_ref().as_bytes());
        assert_eq!(reader.read_str().unwrap(), "object");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "session");
        assert_eq!(reader.read_map().unwrap(), 2);
        assert_eq!(reader.read_str().unwrap(), "id");
        assert_eq!(reader.read_uint().unwrap(), 7);
        assert_eq!(reader.read_str().unwrap(), "logon-type");
        assert_eq!(reader.read_str().unwrap(), "interactive");
        assert_eq!(reader.read_str().unwrap(), "outcome");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "success");
        assert_eq!(reader.peek(), Some(Type::Bool));
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn a_failure_carries_its_reason_and_a_field_set_twice_keeps_the_last() {
        let mut record = Record::new();
        record.str("object.session.auth-package", "first");
        record.str("object.session.auth-package", "lpsd");
        record.outcome(Some("authentication-failed"));
        assert_eq!(
            record.get("object.session.auth-package"),
            Some(&Value::Str("lpsd".into()))
        );
        assert_eq!(record.get("outcome.success"), Some(&Value::Bool(false)));
        assert_eq!(
            record.get("outcome.reason"),
            Some(&Value::Str("authentication-failed".into()))
        );
        let bytes = record.encode().unwrap();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_map().unwrap(), 2);
        reader.skip().unwrap();
        reader.skip().unwrap();
        assert_eq!(reader.read_str().unwrap(), "outcome");
        assert_eq!(reader.read_map().unwrap(), 2);
    }
}
