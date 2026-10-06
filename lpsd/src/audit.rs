//! The events lpsd writes: what it checked and what it changed, for the audit
//! trail.
//!
//! The types are defined in `lpsd.evman` at the repository root, which is the
//! catalogue's word on what each field means:
//!
//! - `lpsd.credential.verified` (standard): a credential checked for a logon;
//! - `lpsd.credential.changed` (essential): a principal changing their own
//!   password or SSH keys through authd;
//! - `lpsd.account.created`, `.deleted` and `.modified`, `lpsd.group.created`
//!   and `.deleted`, and `lpsd.group.member.added` and `.removed` (all
//!   essential): an administrator's changes through `lps`, and a principal's
//!   own display name.
//!
//! **The wire hides what the audit trail may know.** A caller is told only
//! "authentication failed" whether the account exists or not (PGSS Logon
//! §2.10); `lpsd.credential.verified` says which, for whoever may read the
//! trail.
//!
//! **Never a name.** Accounts and groups are SIDs in every record. A name can be
//! reused by somebody else, and the name a logon was attempted under is the
//! caller's input rather than anyone's identity, so it is not recorded at all.
//!
//! **No denial events.** Whether a caller may administer the store is an access
//! decision, and access decisions are KACS's to record (PGSS §6.7).
//!
//! **Emission never fails the work.** A record KMES will not take is logged and
//! the change stands: lpsd is single-threaded and serves every logon, and an
//! audit trail that could stall or refuse them would be a way to stop anybody
//! signing in.

use std::sync::OnceLock;

use peios::event::{EventPolicy, Tier};
use peios::msgpack::Writer;
use peios::security::{Sid, SidRef};
use peios::token::{Token, TokenAccess};

use crate::log;

/// One payload value, in its PGSS §6.5 wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Bool(bool),
    /// Binary: a SID, as its bytes.
    Bin(Vec<u8>),
}

/// An event payload, built field by field and encoded as the nested maps
/// PGSS §6.4 requires: `subject.token.sid` is `{subject: {token: {sid}}}`.
///
/// Fields are kept in the order they were set, and setting one twice keeps
/// the last value.
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

    pub fn sid(&mut self, path: &'static str, sid: &SidRef) -> &mut Self {
        self.set(path, Value::Bin(sid.as_bytes().to_vec()))
    }

    /// `outcome.success`, and `outcome.reason` when it failed.
    pub fn outcome(&mut self, reason: Option<&str>) -> &mut Self {
        self.set("outcome.success", Value::Bool(reason.is_none()));
        if let Some(reason) = reason {
            self.str("outcome.reason", reason);
        }
        self
    }

    /// A field's value, for tests.
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
        Value::Bool(flag) => writer.write_bool(*flag),
        Value::Bin(bytes) => writer.write_bin(bytes),
    };
}

/// lpsd's own user SID — its service account — for the records where lpsd is
/// the principal that acted: a credential it checked (PGSS §6.4, the subject of
/// an action is whoever acted, the emitter included).
///
/// Read once; `None` where lpsd's own token cannot be read, and the record is
/// then written without it rather than not at all.
pub fn own_sid() -> Option<&'static SidRef> {
    static OWN: OnceLock<Option<Sid>> = OnceLock::new();
    OWN.get_or_init(|| {
        match Token::open_self(true, TokenAccess::QUERY).and_then(|token| token.user()) {
            Ok(sid) => Some(sid),
            Err(error) => {
                log::warn(format_args!("could not read lpsd's own SID: {error}"));
                None
            }
        }
    })
    .as_ref()
    .map(Sid::as_ref)
}

/// The emission policy (PGSS §6.9), opened on first use and kept: it watches
/// `Machine\Generic\Events` itself, so one view serves the daemon's life.
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
    use peios::msgpack::Reader;

    #[test]
    fn paths_become_nested_maps() {
        let account: Sid = "S-1-5-21-1-2-3-1000".parse().unwrap();
        let group: Sid = "S-1-5-32-544".parse().unwrap();
        let mut record = Record::new();
        record
            .sid("object.account.sid", account.as_ref())
            .sid("object.group.sid", group.as_ref())
            .outcome(Some("not-saved"));
        let bytes = record.encode().unwrap();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_map().unwrap(), 2);
        assert_eq!(reader.read_str().unwrap(), "object");
        assert_eq!(reader.read_map().unwrap(), 2);
        assert_eq!(reader.read_str().unwrap(), "account");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "sid");
        assert_eq!(reader.read_bin().unwrap(), account.as_ref().as_bytes());
        assert_eq!(reader.read_str().unwrap(), "group");
        assert_eq!(reader.read_map().unwrap(), 1);
        assert_eq!(reader.read_str().unwrap(), "sid");
        assert_eq!(reader.read_bin().unwrap(), group.as_ref().as_bytes());
        assert_eq!(reader.read_str().unwrap(), "outcome");
        assert_eq!(reader.read_map().unwrap(), 2);
        assert_eq!(reader.read_str().unwrap(), "success");
        assert!(!reader.read_bool().unwrap());
        assert_eq!(reader.read_str().unwrap(), "reason");
        assert_eq!(reader.read_str().unwrap(), "not-saved");
        assert_eq!(reader.remaining(), 0);
    }
}
