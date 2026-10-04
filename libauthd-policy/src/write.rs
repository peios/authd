//! Writing the policy key, for the programs that edit it.
//!
//! Only with the `write` feature, which authd does not turn on. Each change is
//! one registry transaction, so a record is saved whole or not at all, and is
//! written in the shapes the shipped seed uses: privileges as a
//! `REG_MULTI_SZ` of their names, integrity as a tier's name (a number only
//! for a level between them), an owner as a well-known name or a SID, and a
//! default DACL as SDDL. Everything is written to the base layer.
//!
//! # The key, once made, is the whole policy
//!
//! A machine with no key gets [`FLOOR`](crate::FLOOR); one with the key gets
//! exactly what it says. So the first record saved on an unconfigured machine
//! would take away the floor, and with it `SeChangeNotifyPrivilege` from
//! everyone, which no shell can start without. [`save`] makes the key with the
//! floor's records in the same transaction, so making the key changes nothing
//! but the record saved.

use std::io::ErrorKind;

use peios::registry::{CreateFlags, Disposition, Key, KeyAccess, OpenFlags, Transaction, ValueType};
use peios::security::{IntegrityLevel, Privileges, SidRef, sddl};

use crate::{
    DEFAULT_DACL_VALUE, DENIED_PRIVILEGES_VALUE, FLOOR, INTEGRITY_VALUE, KEY, OWNER_VALUE, PRIVILEGES_VALUE, Record, encode_multi_sz, encode_sz, resolve,
    tier_name, well_known,
};

/// What a record says, as a form gives it: each `None` is a value the record
/// doesn't have, which says nothing, rather than an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Draft {
    pub privileges: Option<Privileges>,
    pub integrity: Option<IntegrityLevel>,
    /// A well-known name or a SID, as written.
    pub owner: Option<String>,
    /// SDDL.
    pub default_dacl: Option<String>,
}

impl Draft {
    /// What `record` says now.
    pub fn of(record: &Record) -> Draft {
        Draft {
            privileges: record.privileges,
            integrity: record.integrity,
            owner: record.owner.as_ref().map(|owner| record_name(owner.as_ref())),
            default_dacl: record.default_dacl.as_ref().map(|dacl| dacl.sddl.clone()),
        }
    }

    /// Whether authd would read it as written: an owner naming a principal,
    /// and a default DACL that parses. A value it can't read it ignores, so
    /// one is refused here rather than saved to be ignored.
    pub fn check(&self) -> Result<(), String> {
        if let Some(owner) = &self.owner
            && resolve(owner).is_none()
        {
            return Err(format!("{owner} is not a well-known principal or a SID."));
        }
        if let Some(dacl) = &self.default_dacl
            && sddl::parse_acl(dacl).is_err()
        {
            return Err("The default DACL is not SDDL that can be used. It is a DACL alone, such as D:(A;;GA;;;OW)(A;;GA;;;SY).".into());
        }
        Ok(())
    }
}

/// The name a record for `sid` is keyed by, and an owner is written as: its
/// well-known name, or the SID. Never a local principal's name, which authd
/// could not resolve without asking a source.
pub fn record_name(sid: &SidRef) -> String {
    well_known::name_of(sid).map_or_else(|| sid.to_string(), str::to_string)
}

/// Saves the record `name`, making it, and the key, where they aren't there.
/// The values a draft doesn't cover, such as `LogonTypes`, are left as they
/// are.
pub fn save(name: &str, draft: &Draft) -> Result<(), String> {
    if resolve(name).is_none() {
        return Err(format!("{name} is not a well-known principal or a SID, so authd would ignore a record for it."));
    }
    draft.check()?;
    let txn = Transaction::begin().map_err(|error| said(&error, "change this machine's policy"))?;
    let policy = policy_key(&txn)?;
    let (record, _) = Key::create(Some(&policy), name, KeyAccess::SET_VALUE | KeyAccess::QUERY_VALUE, CreateFlags::empty(), None, Some(&txn))
        .map_err(|error| said(&error, "make this record"))?;
    let integrity = draft.integrity.map(|level| match tier_name(level) {
        Some(tier) => (ValueType::SZ, encode_sz(tier)),
        None => (ValueType::DWORD, level.0.to_le_bytes().to_vec()),
    });
    set(&record, PRIVILEGES_VALUE, draft.privileges.map(|privileges| (ValueType::MULTI_SZ, encode_multi_sz(privileges.canonical_names()))), &txn)?;
    set(&record, INTEGRITY_VALUE, integrity, &txn)?;
    set(&record, OWNER_VALUE, draft.owner.as_deref().map(|owner| (ValueType::SZ, encode_sz(owner.trim()))), &txn)?;
    set(&record, DEFAULT_DACL_VALUE, draft.default_dacl.as_deref().map(|dacl| (ValueType::SZ, encode_sz(dacl.trim()))), &txn)?;
    txn.commit().map_err(|error| said(&error, "change this machine's policy"))
}

/// Deletes the record `name`. What it granted is no longer granted, from the
/// next sign-in.
pub fn delete(name: &str) -> Result<(), String> {
    let record = Key::open(None, &format!("{KEY}\\{name}"), KeyAccess::DELETE, OpenFlags::empty()).map_err(|error| said(&error, "delete this record"))?;
    record.delete_key(None, None).map_err(|error| said(&error, "delete this record"))
}

/// Sets the privileges no record may grant; `None` removes the list.
pub fn set_denied(denied: Option<Privileges>) -> Result<(), String> {
    let txn = Transaction::begin().map_err(|error| said(&error, "change this machine's policy"))?;
    let policy = policy_key(&txn)?;
    set(&policy, DENIED_PRIVILEGES_VALUE, denied.map(|denied| (ValueType::MULTI_SZ, encode_multi_sz(denied.canonical_names()))), &txn)?;
    txn.commit().map_err(|error| said(&error, "change this machine's policy"))
}

/// Whether this person may change the policy, or why not: the key's own
/// descriptor says, not anyone else's. On a machine with no key, whether they
/// may make it under its parent.
pub fn may_write() -> Result<(), String> {
    let opened = match Key::open(None, KEY, KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY, OpenFlags::empty()) {
        Err(error) if error.kind() == ErrorKind::NotFound => Key::open(None, "Machine", KeyAccess::CREATE_SUB_KEY, OpenFlags::empty()),
        opened => opened,
    };
    opened.map(|_| ()).map_err(|error| said(&error, "change this machine's policy"))
}

/// The policy key, opened to make records under and to set its own values;
/// made, with the floor's records, where it isn't there.
fn policy_key(txn: &Transaction) -> Result<Key, String> {
    let mut key = Key::open(None, "Machine", KeyAccess::CREATE_SUB_KEY, OpenFlags::empty()).map_err(|error| said(&error, "change this machine's policy"))?;
    let mut made = false;
    let parts: Vec<&str> = KEY.split('\\').skip(1).collect();
    for (at, part) in parts.iter().enumerate() {
        let last = at + 1 == parts.len();
        let access = if last { KeyAccess::CREATE_SUB_KEY | KeyAccess::SET_VALUE } else { KeyAccess::CREATE_SUB_KEY };
        let (next, disposition) = Key::create(Some(&key), part, access, CreateFlags::empty(), None, Some(txn)).map_err(|error| said(&error, "make the policy key"))?;
        made = last && disposition == Disposition::CreatedNew;
        key = next;
    }
    if made {
        for (name, privileges) in FLOOR {
            let (record, _) = Key::create(Some(&key), name, KeyAccess::SET_VALUE, CreateFlags::empty(), None, Some(txn)).map_err(|error| said(&error, "make the policy key"))?;
            set(&record, PRIVILEGES_VALUE, Some((ValueType::MULTI_SZ, encode_multi_sz(privileges.canonical_names()))), txn)?;
        }
    }
    Ok(key)
}

/// Sets a value, or deletes it for `None`.
fn set(key: &Key, name: &str, value: Option<(ValueType, Vec<u8>)>, txn: &Transaction) -> Result<(), String> {
    match value {
        Some((ty, data)) => key.set_value(name.as_bytes(), ty, &data).in_txn(txn).call(),
        None => match key.delete_value(name.as_bytes(), None, Some(txn)) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            done => done,
        },
    }
    .map_err(|error| said(&error, &format!("set {name}")))
}

fn said(error: &peios::Error, what: &str) -> String {
    match error.kind() {
        ErrorKind::PermissionDenied => format!("You may not {what}: it needs Administrators, enabled in your token."),
        _ => format!("Couldn't {what}: {error}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultDacl;

    #[test]
    fn a_record_is_named_as_authd_resolves_it() {
        let administrators: peios::security::Sid = "S-1-5-32-544".parse().unwrap();
        assert_eq!(record_name(administrators.as_ref()), "Administrators");
        let dana: peios::security::Sid = "S-1-5-21-1-2-3-1002".parse().unwrap();
        assert_eq!(record_name(dana.as_ref()), "S-1-5-21-1-2-3-1002");
    }

    #[test]
    fn a_draft_is_what_the_record_says_and_is_checked_as_authd_reads_it() {
        let record = Record {
            privileges: Some(Privileges::BACKUP),
            owner: resolve("Administrators"),
            default_dacl: Some(DefaultDacl { sddl: "D:(A;;GA;;;SY)".into(), acl: sddl::parse_acl("D:(A;;GA;;;SY)").unwrap() }),
            ..Record::empty("Users", resolve("Users").unwrap())
        };
        let draft = Draft::of(&record);
        assert_eq!(draft.owner.as_deref(), Some("Administrators"));
        assert_eq!(draft.default_dacl.as_deref(), Some("D:(A;;GA;;;SY)"));
        assert!(draft.check().is_ok());
        assert!(Draft { owner: Some("developers".into()), ..draft.clone() }.check().is_err(), "a local name is nobody to authd");
        assert!(Draft { default_dacl: Some("D:(nonsense)".into()), ..draft }.check().is_err());
    }
}
