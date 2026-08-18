//! Flattening a record into POSIX's shapes.
//!
//! Everything lossy about the shim happens here, and each loss is a property of
//! `struct passwd` and `struct group` rather than of the protocol.

use libauthd::ident::{Fields, Record, Value};

use crate::buffer::Packer;

/// What a POSIX identifier is when there is not one.
///
/// `nobody`. The authority already projects an unnumbered principal to this, and
/// repeating the constant here keeps the shim from having to be told.
const UNMAPPED: u32 = 65534;

fn unix_id(record: &Record, field: Fields) -> u32 {
    match record.value(field) {
        Some(Value::UnixId(id)) => *id,
        _ => UNMAPPED,
    }
}

fn text<'a>(record: &'a Record, field: Fields) -> &'a str {
    match record.value(field) {
        Some(Value::Home(value) | Value::Shell(value) | Value::DisplayName(value)) => value,
        _ => "",
    }
}

/// A `struct passwd`, with every string packed into `packer`.
///
/// `None` means the buffer was too small, which the caller turns into `ERANGE`.
pub fn passwd(record: &Record, packer: &mut Packer) -> Option<libc::passwd> {
    let gid = match record.value(Fields::PRIMARY_GROUP) {
        Some(Value::PrimaryGroup(reference)) => reference.unix_id,
        _ => UNMAPPED,
    };

    Some(libc::passwd {
        pw_name: packer.str(&record.qualified_name)?,
        // Not a hash, and never has been one here: verifiers live in a source's
        // store and cannot be read out at all. `x` is what every modern system
        // puts here and what every reader expects.
        pw_passwd: packer.str("x")?,
        pw_uid: unix_id(record, Fields::UNIX_ID),
        pw_gid: gid,
        pw_gecos: packer.str(text(record, Fields::DISPLAY_NAME))?,
        pw_dir: packer.str(text(record, Fields::HOME))?,
        pw_shell: packer.str(text(record, Fields::SHELL))?,
    })
}

/// A `struct group`.
///
/// `gr_mem` is empty for a group whose membership is a rule rather than a
/// record — `Everyone`, `Authenticated Users`, and every group reflecting *how*
/// someone signed in. The authority says so by withholding the field rather than
/// returning nothing, but POSIX has only one way to render either, so both
/// arrive here as an empty list.
///
/// That is the honest rendering. The alternative would be to invent members, and
/// a `gr_mem` listing this machine's principals for `Everyone` would be a wrong
/// answer rather than a partial one.
pub fn group(record: &Record, packer: &mut Packer) -> Option<libc::group> {
    let members: &[libauthd::ident::Reference] = match record.value(Fields::MEMBERS) {
        Some(Value::Members(refs)) => refs,
        _ => &[],
    };

    // The name strings first, then the array — so a buffer that runs out does so
    // before anything points at memory it did not get.
    let mut packed = Vec::with_capacity(members.len());
    for member in members {
        packed.push(packer.str(&member.name)?);
    }

    let array = packer.pointers(packed.len() + 1)?;
    for (index, pointer) in packed.iter().enumerate() {
        // SAFETY: the array was reserved with `packed.len() + 1` slots.
        unsafe { array.add(index).write(*pointer) };
    }
    // SAFETY: the terminating slot is the one reserved past `packed.len()`.
    unsafe { array.add(packed.len()).write(core::ptr::null_mut()) };

    Some(libc::group {
        gr_name: packer.str(&record.qualified_name)?,
        gr_passwd: packer.str("x")?,
        gr_gid: unix_id(record, Fields::UNIX_ID),
        gr_mem: array,
    })
}

/// Every group identifier a principal's record carries.
///
/// Both the memberships and the primary group, because a token's primary group
/// is a membership whether or not the source listed it among the others — and a
/// supplementary list that omitted it would disagree with the token the same
/// principal signs in with.
///
/// Unnumbered groups are skipped rather than rendered as `nobody`: a logon SID
/// has no POSIX identifier because it is not a group in the POSIX sense, and
/// putting 65534 in a supplementary list would grant whatever `nobody` can reach.
pub fn gids(record: &Record) -> Vec<libc::gid_t> {
    let mut out = Vec::new();
    if let Some(Value::PrimaryGroup(reference)) = record.value(Fields::PRIMARY_GROUP)
        && reference.unix_id != 0
        && reference.unix_id != UNMAPPED
    {
        out.push(reference.unix_id);
    }
    if let Some(Value::Groups(refs)) = record.value(Fields::GROUPS) {
        for reference in refs {
            if reference.unix_id != 0 && reference.unix_id != UNMAPPED {
                out.push(reference.unix_id);
            }
        }
    }
    out
}

/// A pointer to a NUL-terminated string, read back.
///
/// Only the tests need this; it is the inverse of what [`Packer`] does and is
/// what lets them check a rendering rather than a return value.
#[cfg(test)]
pub fn read(pointer: *mut core::ffi::c_char) -> String {
    // SAFETY: every pointer this is called on came from `Packer::str`.
    unsafe {
        let mut out = Vec::new();
        let mut at = pointer as *const u8;
        while *at != 0 {
            out.push(*at);
            at = at.add(1);
        }
        String::from_utf8(out).expect("what went in was UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::{Kind, Reference, Withheld, WithheldReason};

    fn reference(name: &str, unix_id: u32) -> Reference {
        Reference {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0],
            name: name.into(),
            unix_id,
        }
    }

    fn principal() -> Record {
        Record {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0],
            qualified_name: "jack".into(),
            kind_found: Kind::Principal,
            values: vec![
                Value::UnixId(1_001_000),
                Value::PrimaryGroup(reference("Authenticated Users", 101)),
                Value::Home("/home/jack".into()),
                Value::Shell("/bin/sh".into()),
                Value::DisplayName("Jack".into()),
            ],
            withheld: vec![],
        }
    }

    #[test]
    fn a_principal_renders_a_whole_passwd_entry() {
        let mut buf = [0i8; 512];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let entry = passwd(&principal(), &mut packer).expect("must fit");

        assert_eq!(read(entry.pw_name), "jack");
        assert_eq!(read(entry.pw_passwd), "x", "never a verifier");
        assert_eq!(entry.pw_uid, 1_001_000);
        assert_eq!(entry.pw_gid, 101);
        assert_eq!(read(entry.pw_gecos), "Jack");
        assert_eq!(read(entry.pw_dir), "/home/jack");
        assert_eq!(read(entry.pw_shell), "/bin/sh");
    }

    /// An unnumbered principal is `nobody`, not zero. Zero is where the SYSTEM
    /// token projects, and no source's principal may land on it.
    #[test]
    fn a_record_with_no_number_renders_nobody() {
        let mut record = principal();
        record.values.retain(|v| v.field() != Fields::UNIX_ID);
        let mut buf = [0i8; 512];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let entry = passwd(&record, &mut packer).expect("must fit");
        assert_eq!(entry.pw_uid, UNMAPPED);
        assert_ne!(entry.pw_uid, 0);
    }

    /// The signal that makes glibc retry with a bigger buffer.
    #[test]
    fn a_small_buffer_refuses_rather_than_truncating() {
        let mut buf = [0i8; 8];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        assert!(passwd(&principal(), &mut packer).is_none());
    }

    fn group_record(members: Vec<Reference>) -> Record {
        Record {
            sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0],
            qualified_name: "developers".into(),
            kind_found: Kind::Group,
            values: vec![Value::UnixId(1_001_001), Value::Members(members)],
            withheld: vec![],
        }
    }

    #[test]
    fn a_group_renders_its_members_in_one_pass() {
        let mut buf = [0i8; 512];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let entry = group(
            &group_record(vec![reference("jack", 1_001_000), reference("ada", 1_001_002)]),
            &mut packer,
        )
        .expect("must fit");

        assert_eq!(read(entry.gr_name), "developers");
        assert_eq!(entry.gr_gid, 1_001_001);
        // SAFETY: `group` wrote a NUL-terminated array here.
        unsafe {
            assert_eq!(read(*entry.gr_mem), "jack");
            assert_eq!(read(*entry.gr_mem.add(1)), "ada");
            assert!(
                (*entry.gr_mem.add(2)).is_null(),
                "the array must be NUL-terminated or a reader walks off it"
            );
        }
    }

    /// A group whose membership is a rule rather than a record. POSIX has one
    /// way to render it, and inventing members would be a wrong answer rather
    /// than a partial one.
    #[test]
    fn a_group_with_a_withheld_membership_renders_empty() {
        let mut record = group_record(vec![]);
        record.values.retain(|v| v.field() != Fields::MEMBERS);
        record.withheld.push(Withheld {
            field: Fields::MEMBERS,
            reason: WithheldReason::Absent,
        });

        let mut buf = [0i8; 256];
        let mut packer = unsafe { Packer::new(buf.as_mut_ptr(), buf.len()) };
        let entry = group(&record, &mut packer).expect("must fit");
        // SAFETY: an empty membership still writes the terminator.
        unsafe { assert!((*entry.gr_mem).is_null()) };
    }

    #[test]
    fn a_supplementary_list_carries_the_primary_group_and_the_memberships() {
        let mut record = principal();
        record.values.push(Value::Groups(vec![
            reference("Administrators", 102),
            reference("developers", 1_001_001),
        ]));
        assert_eq!(gids(&record), vec![101, 102, 1_001_001]);
    }

    /// A logon SID has no number because it is not a group in the POSIX sense.
    /// Rendering it as `nobody` would grant whatever `nobody` can reach.
    #[test]
    fn an_unnumbered_group_is_skipped_rather_than_rendered_as_nobody() {
        let mut record = principal();
        record.values.push(Value::Groups(vec![
            reference("Interactive", 0),
            reference("Administrators", 102),
            reference("unmapped", UNMAPPED),
        ]));
        assert_eq!(gids(&record), vec![101, 102]);
    }
}
