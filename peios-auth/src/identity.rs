//! Identity and self-account views, copied out of the C ABI into owned Rust data.
use std::collections::BTreeMap;
use super::{abi, sys, Client, Operation, Error, copy_bytes, copy_text, invalid, read, span, string};

/// Identity attributes to request. Combine constants with bitwise OR.
pub mod fields {
    pub const UNIX_ID: u32 = 1 << 0;
    pub const PRIMARY_GROUP: u32 = 1 << 1;
    pub const HOME: u32 = 1 << 2;
    pub const SHELL: u32 = 1 << 3;
    pub const DISPLAY_NAME: u32 = 1 << 4;
    pub const GROUPS: u32 = 1 << 5;
    pub const MEMBERS: u32 = 1 << 6;
    pub const CLAIMS: u32 = 1 << 7;
    pub const ENABLED: u32 = 1 << 8;
    pub const LOGON_TYPES: u32 = 1 << 9;
    pub const DESCRIPTION: u32 = 1 << 10;
    pub const ALL: u32 = (1 << 11) - 1;
}
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum IdentityKind {
    Any = 0,
    Principal = 1,
    Group = 2,
}
pub enum Key<'a> {
    Name(&'a str),
    Sid(&'a [u8]),
    UnixId(u32),
}
impl Key<'_> {
    fn raw(&self) -> abi::Key {
        let (kind, value, unix_id) = match self {
            Self::Name(name) => (1, string(name), 0),
            Self::Sid(sid) => (2, span(sid), 0),
            Self::UnixId(id) => (3, span(&[]), *id),
        };
        abi::Key {
            size: size_of::<abi::Key>(),
            kind,
            value,
            unix_id,
        }
    }
}
/// Pass the previous reply's next cursor unchanged to continue enumeration.
pub struct EnumerateRequest<'a> {
    pub kind: IdentityKind,
    pub fields: u32,
    pub group: Option<Key<'a>>,
    pub cursor: &'a [u8],
}
impl Client {
    /// Begin an identity lookup; requested fields can be withheld by policy.
    pub fn lookup(
        &self,
        key: Key<'_>,
        kind: IdentityKind,
        fields: u32,
    ) -> Result<Operation, Error> {
        let raw = abi::LookupRequest {
            size: size_of::<abi::LookupRequest>(),
            key: key.raw(),
            kind: kind as u32,
            fields,
        };
        // SAFETY: client and every borrowed input remain live through begin.
        Operation::new(unsafe { sys::peios_auth_identity_lookup_begin(self.handle.as_ptr(), &raw) })
    }
    /// Begin one enumeration page. Preserve its cursor and incomplete-source status.
    pub fn enumerate(&self, request: EnumerateRequest<'_>) -> Result<Operation, Error> {
        let group = request.group.as_ref().map(Key::raw);
        let raw = abi::EnumerateRequest {
            size: size_of::<abi::EnumerateRequest>(),
            kind: request.kind as u32,
            fields: request.fields,
            group: group.as_ref().map_or(std::ptr::null(), |key| key),
            cursor: span(request.cursor),
        };
        // SAFETY: raw, group and borrowed cursor remain live through begin.
        Operation::new(unsafe {
            sys::peios_auth_identity_enumerate_begin(self.handle.as_ptr(), &raw)
        })
    }
}
#[derive(Debug)]
pub struct Identity {
    pub outcome: u32,
    pub records: Vec<Record>,
    pub next: Vec<u8>,
    pub incomplete_sources: Vec<String>,
}
#[derive(Debug)]
pub struct Record {
    pub sid: Vec<u8>,
    pub name: String,
    pub kind: u32,
    pub fields: BTreeMap<u32, Field>,
}
#[derive(Debug)]
pub enum Field {
    Withheld(u32),
    Text(String),
    Number(u32),
    References(Vec<Reference>),
    Claims(Vec<Claim>),
}
#[derive(Debug)]
pub struct Reference {
    pub sid: Vec<u8>,
    pub name: String,
    pub unix_id: u32,
}
#[derive(Debug)]
pub struct Claim {
    pub name: String,
    pub flags: u32,
    pub value_type: u32,
    pub values: Vec<ClaimValue>,
}
#[derive(Debug)]
pub enum ClaimValue {
    Signed(i64),
    Unsigned(u64),
    Boolean(bool),
    Text(String),
    Bytes(Vec<u8>),
}
#[derive(Debug)]
pub struct Account {
    pub name: String,
    pub sid: Vec<u8>,
    pub display_name: String,
    pub enabled: bool,
    pub credential_policy: u32,
    pub has_password: bool,
    pub keys: Vec<AccountKey>,
}
#[derive(Debug)]
pub struct AccountKey {
    pub id: Vec<u8>,
    pub fingerprint: String,
    pub algorithm: String,
    pub label: String,
    pub created_unix_seconds: u64,
}

impl Operation {
    /// Copy the completed identity result, including partial results and the next cursor.
    pub fn identity(&self) -> Result<Identity, Error> {
        // SAFETY: every getter in this method uses the same immutable live
        // operation; read initializes the output and bytes are copied immediately.
        unsafe {
            let view = read(|out| sys::peios_auth_operation_identity(self.handle.as_ptr(), out))?;
            let mut records = Vec::new();
            for index in 0..view.record_count {
                records.push(self.record(index)?);
            }
            let mut incomplete_sources = Vec::new();
            for index in 0..view.incomplete_count {
                incomplete_sources.push(copy_text(read(|out| {
                    sys::peios_auth_operation_incomplete_source(self.handle.as_ptr(), index, out)
                })?));
            }
            Ok(Identity {
                outcome: view.outcome,
                records,
                next: copy_bytes(view.next),
                incomplete_sources,
            })
        }
    }
    fn record(&self, index: usize) -> Result<Record, Error> {
        // SAFETY: views stay within an immutable borrow of the operation and all
        // output buffers are initialized by successful getters through read.
        unsafe {
            let raw = read(|out| sys::peios_auth_record(self.handle.as_ptr(), index, out))?;
            let mut values = BTreeMap::new();
            for bit in 0..11 {
                let field = 1 << bit;
                let state = sys::peios_auth_record_field_state(self.handle.as_ptr(), index, field);
                if state < 0 {
                    return Err(invalid());
                }
                if state == 0 {
                    continue;
                }
                let value = if state == 5 {
                    self.record_field(index, field)?
                } else {
                    Field::Withheld(state as u32)
                };
                values.insert(field, value);
            }
            Ok(Record {
                sid: copy_bytes(raw.sid),
                name: copy_text(raw.name),
                kind: raw.kind,
                fields: values,
            })
        }
    }
    fn record_field(&self, index: usize, field: u32) -> Result<Field, Error> {
        // SAFETY: the operation remains immutably borrowed; getters validate the
        // record index and field, initialize outputs, and return readable views.
        unsafe {
            match field {
                fields::HOME | fields::SHELL | fields::DISPLAY_NAME | fields::DESCRIPTION => {
                    Ok(Field::Text(copy_text(read(|out| {
                        sys::peios_auth_record_text(self.handle.as_ptr(), index, field, out)
                    })?)))
                }
                fields::UNIX_ID | fields::ENABLED | fields::LOGON_TYPES => {
                    Ok(Field::Number(read(|out| {
                        sys::peios_auth_record_number(self.handle.as_ptr(), index, field, out)
                    })?))
                }
                fields::PRIMARY_GROUP | fields::GROUPS | fields::MEMBERS => {
                    Ok(Field::References(self.references(index, field)?))
                }
                fields::CLAIMS => Ok(Field::Claims(self.claims(index)?)),
                _ => Err(invalid()),
            }
        }
    }

    fn references(&self, index: usize, field: u32) -> Result<Vec<Reference>, Error> {
        // SAFETY: all views are read from one immutable operation and copied.
        unsafe {
            let count = read(|out| {
                sys::peios_auth_record_reference_count(self.handle.as_ptr(), index, field, out)
            })?;
            let mut values = Vec::new();
            for item in 0..count {
                let raw = read(|out| {
                    sys::peios_auth_record_reference(self.handle.as_ptr(), index, field, item, out)
                })?;
                values.push(Reference {
                    sid: copy_bytes(raw.sid),
                    name: copy_text(raw.name),
                    unix_id: raw.unix_id,
                });
            }
            Ok(values)
        }
    }
    fn claims(&self, index: usize) -> Result<Vec<Claim>, Error> {
        // SAFETY: all views are read from one immutable operation and copied.
        unsafe {
            let count =
                read(|out| sys::peios_auth_record_claim_count(self.handle.as_ptr(), index, out))?;
            let mut claims = Vec::new();
            for item in 0..count {
                let raw = read(|out| {
                    sys::peios_auth_record_claim(self.handle.as_ptr(), index, item, out)
                })?;
                let mut values = Vec::new();
                for value in 0..raw.value_count {
                    let raw_value = read(|out| {
                        sys::peios_auth_record_claim_value(
                            self.handle.as_ptr(),
                            index,
                            item,
                            value,
                            out,
                        )
                    })?;
                    values.push(match raw.value_type {
                        1 => ClaimValue::Signed(raw_value.signed_value),
                        2 => ClaimValue::Unsigned(raw_value.unsigned_value),
                        6 => ClaimValue::Boolean(raw_value.unsigned_value != 0),
                        3 => ClaimValue::Text(copy_text(raw_value.bytes)),
                        5 | 16 => ClaimValue::Bytes(copy_bytes(raw_value.bytes)),
                        _ => return Err(invalid()),
                    });
                }
                claims.push(Claim {
                    name: copy_text(raw.name),
                    flags: raw.flags,
                    value_type: raw.value_type,
                    values,
                });
            }
            Ok(claims)
        }
    }
    /// Copy the completed self-account profile and enrolled public keys.
    pub fn account(&self) -> Result<Account, Error> {
        // SAFETY: all getters borrow a live immutable operation and all returned
        // spans are copied before any mutation or destruction can take place.
        unsafe {
            let raw = read(|out| sys::peios_auth_operation_account(self.handle.as_ptr(), out))?;
            let mut keys = Vec::new();
            for index in 0..raw.key_count {
                let key = read(|out| {
                    sys::peios_auth_operation_account_key(self.handle.as_ptr(), index, out)
                })?;
                keys.push(AccountKey {
                    id: copy_bytes(key.id),
                    fingerprint: copy_text(key.fingerprint),
                    algorithm: copy_text(key.algorithm),
                    label: copy_text(key.label),
                    created_unix_seconds: key.created_unix_seconds,
                });
            }
            Ok(Account {
                name: copy_text(raw.name),
                sid: copy_bytes(raw.sid),
                display_name: copy_text(raw.display_name),
                enabled: raw.enabled != 0,
                credential_policy: raw.credential_policy,
                has_password: raw.has_password != 0,
                keys,
            })
        }
    }
}
