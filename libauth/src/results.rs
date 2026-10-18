//! Borrowed result views; no wire layouts or Rust collections cross the ABI.
use auth_abi::{
    AccountKeyView, AccountView, Bytes, ClaimValue, ClaimView, IdentityView, RecordView,
    ReferenceView,
};
use auth_core::{claim::Values, ident};
use crate::api::{bytes, write};
use crate::engine::{Operation, Output, State};

// Public PEIOS_AUTH_FIELD_PRESENT from peios/auth.h; other field states use
// the identity protocol's preserved withheld-reason discriminants.
const FIELD_PRESENT: i32 = 5;

fn record(operation: &Operation, index: usize) -> Option<&ident::Record> {
    match &operation.state {
        State::Complete(Output::Lookup(reply)) if index == 0 => reply.record.as_ref(),
        State::Complete(Output::Listing(reply)) => reply.entries.get(index),
        _ => None,
    }
}
macro_rules! view {
    ($out:expr, $body:block) => {{
        let value = (|| -> Option<_> { $body })();
        match value {
            Some(value) => {
                // SAFETY: each accessor requires writable, aligned output storage
                // disjoint from the live operation whose views it returns.
                unsafe { write($out, value) }
            }
            None => -1,
        }
    }};
}
/// Copy identity outcome, record count, cursor, and incomplete-source count.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_identity(
    operation: *const Operation,
    out: *mut IdentityView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        Some(match &unsafe { operation.as_ref()? }.state {
            State::Complete(Output::Lookup(reply)) => IdentityView {
                outcome: reply.outcome as u32,
                record_count: usize::from(reply.record.is_some()),
                next: bytes(&[]),
                incomplete_count: 0,
            },
            State::Complete(Output::Listing(reply)) => IdentityView {
                outcome: reply.outcome as u32,
                record_count: reply.entries.len(),
                next: bytes(&reply.next),
                incomplete_count: reply.incomplete.len(),
            },
            _ => return None,
        })
    })
}
/// Copy the name of one incomplete source as a borrowed byte span.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_incomplete_source(
    operation: *const Operation,
    index: usize,
    out: *mut Bytes,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let State::Complete(Output::Listing(reply)) = &unsafe { operation.as_ref()? }.state else {
            return None;
        };
        Some(bytes(reply.incomplete.get(index)?.as_bytes()))
    })
}
/// Copy one identity record's SID, name, kind, and present-field mask.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record(
    operation: *const Operation,
    index: usize,
    out: *mut RecordView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let record = record(unsafe { operation.as_ref()? }, index)?;
        Some(RecordView {
            sid: bytes(&record.sid),
            name: bytes(record.qualified_name.as_bytes()),
            kind: record.kind_found as u32,
            present_fields: record.present().0,
        })
    })
}
/// Return a field's presence/withholding state, or -1 for invalid input.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_field_state(
    operation: *const Operation,
    index: usize,
    field: u32,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live.
    (|| -> Option<i32> {
        let record = record(unsafe { operation.as_ref()? }, index)?;
        if field.count_ones() != 1 || field & !ident::Fields::KNOWN.0 != 0 {
            return None;
        }
        if record.value(ident::Fields(field)).is_some() {
            return Some(FIELD_PRESENT);
        }
        Some(
            record
                .reason(ident::Fields(field))
                .map(|reason| reason as i32)
                .unwrap_or(0),
        )
    })()
    .unwrap_or(-1)
}
/// Copy a text field as a borrowed UTF-8 byte span.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_text(
    operation: *const Operation,
    index: usize,
    field: u32,
    out: *mut Bytes,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let record = record(unsafe { operation.as_ref()? }, index)?;
        let value = match record.value(ident::Fields(field))? {
            ident::Value::Home(value)
            | ident::Value::Shell(value)
            | ident::Value::DisplayName(value)
            | ident::Value::Description(value) => value,
            _ => return None,
        };
        Some(bytes(value.as_bytes()))
    })
}
/// Copy a numeric identity field.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_number(
    operation: *const Operation,
    index: usize,
    field: u32,
    out: *mut u32,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let record = record(unsafe { operation.as_ref()? }, index)?;
        Some(match record.value(ident::Fields(field))? {
            ident::Value::UnixId(value) => *value,
            ident::Value::Enabled(value) => u32::from(*value),
            ident::Value::LogonTypes(value) => value.0,
            _ => return None,
        })
    })
}
fn references(record: &ident::Record, field: u32) -> Option<&[ident::Reference]> {
    match record.value(ident::Fields(field))? {
        ident::Value::PrimaryGroup(value) => Some(std::slice::from_ref(value)),
        ident::Value::Groups(values) | ident::Value::Members(values) => Some(values),
        _ => None,
    }
}
/// Copy the number of referenced identities in a field.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_reference_count(
    operation: *const Operation,
    index: usize,
    field: u32,
    out: *mut usize,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        Some(references(record(unsafe { operation.as_ref()? }, index)?, field)?.len())
    })
}
/// Copy one referenced identity as a borrowed view.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_reference(
    operation: *const Operation,
    index: usize,
    field: u32,
    item: usize,
    out: *mut ReferenceView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let value = references(record(unsafe { operation.as_ref()? }, index)?, field)?.get(item)?;
        Some(ReferenceView {
            sid: bytes(&value.sid),
            name: bytes(value.name.as_bytes()),
            unix_id: value.unix_id,
        })
    })
}
/// Copy the number of claims on an identity record.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_claim_count(
    operation: *const Operation,
    index: usize,
    out: *mut usize,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let ident::Value::Claims(values) =
            record(unsafe { operation.as_ref()? }, index)?.value(ident::Fields::CLAIMS)?
        else {
            return None;
        };
        Some(values.len())
    })
}
/// Copy one claim's metadata as a borrowed view.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_claim(
    operation: *const Operation,
    index: usize,
    item: usize,
    out: *mut ClaimView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let ident::Value::Claims(values) =
            record(unsafe { operation.as_ref()? }, index)?.value(ident::Fields::CLAIMS)?
        else {
            return None;
        };
        let claim = values.get(item)?;
        Some(ClaimView {
            name: bytes(claim.name.as_bytes()),
            flags: claim.flags,
            value_type: claim.values.type_code(),
            value_count: claim.values.len(),
        })
    })
}
/// Copy one claim value, selecting the member indicated by its claim type.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_record_claim_value(
    operation: *const Operation,
    index: usize,
    item: usize,
    value: usize,
    out: *mut ClaimValue,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let ident::Value::Claims(values) =
            record(unsafe { operation.as_ref()? }, index)?.value(ident::Fields::CLAIMS)?
        else {
            return None;
        };
        let claim = values.get(item)?;
        let mut result = ClaimValue {
            signed_value: 0,
            unsigned_value: 0,
            bytes: bytes(&[]),
        };
        match &claim.values {
            Values::Int64(values) => result.signed_value = *values.get(value)?,
            Values::Uint64(values) => result.unsigned_value = *values.get(value)?,
            Values::Boolean(values) => result.unsigned_value = u64::from(*values.get(value)?),
            Values::String(values) => result.bytes = bytes(values.get(value)?.as_bytes()),
            Values::Sid(values) | Values::Octet(values) => result.bytes = bytes(values.get(value)?),
        }
        Some(result)
    })
}
/// Copy the calling account's profile as a borrowed view.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_account(
    operation: *const Operation,
    out: *mut AccountView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let State::Complete(Output::Account(account)) = &unsafe { operation.as_ref()? }.state
        else {
            return None;
        };
        Some(AccountView {
            name: bytes(account.name.as_bytes()),
            sid: bytes(&account.sid),
            display_name: bytes(account.display_name.as_bytes()),
            enabled: u32::from(account.enabled),
            credential_policy: account.policy as u32,
            has_password: u32::from(account.has_password),
            key_count: account.keys.len(),
        })
    })
}
/// Copy one enrolled public key's metadata as a borrowed view.
///
/// # Safety
///
/// Operation must be null or a live library handle with no concurrent access.
/// The handle must not have been reused across fork.
/// Out must be null or aligned, writable storage for its declared type,
/// disjoint from the operation. Returned spans remain operation-owned and
/// expire at its next mutation or destruction; the caller must not free them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_auth_operation_account_key(
    operation: *const Operation,
    index: usize,
    out: *mut AccountKeyView,
) -> i32 {
    // SAFETY: the accessor contract keeps the operation immutable and live;
    // indices and field kinds are checked before constructing borrowed views.
    view!(out, {
        let State::Complete(Output::Account(account)) = &unsafe { operation.as_ref()? }.state
        else {
            return None;
        };
        let key = account.keys.get(index)?;
        Some(AccountKeyView {
            id: bytes(&key.id),
            fingerprint: bytes(key.fingerprint.as_bytes()),
            algorithm: bytes(key.algorithm.as_bytes()),
            label: bytes(key.label.as_bytes()),
            created_unix_seconds: key.created,
        })
    })
}
