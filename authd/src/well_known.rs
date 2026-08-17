//! The principals every Peios machine has, and what this machine calls them.
//!
//! A table in code, not configuration. These SIDs are constants and mean the
//! same thing on every Peios machine, so a per-machine value could only ever
//! disagree with another machine's for no benefit.
//!
//! Two things need this table and they need different subsets of it, which is
//! why it is one table with an optional number rather than two lists:
//!
//! - [`crate::unix_id`] projects a SID to a POSIX id. Only some of these have
//!   one.
//! - [`crate::policy`] resolves the name an administrator wrote as a policy
//!   record — `Administrators` rather than `S-1-5-32-544` — because a policy
//!   key nobody can read is a policy nobody audits.
//!
//! The logon-type SIDs are the reason the number is optional. They are real
//! group memberships and ACLs are written against them, but nothing wants a
//! *gid* for "arrived over the network", and PSD-004 §12.1 is explicit that
//! supplementary GIDs come only from groups that have a number. Carrying them
//! with `None` says that in the data; leaving them out of the table entirely —
//! as this previously did — said it only by absence, and made them unnameable
//! in policy as a side effect.

use peios::security::{Sid, SidRef};

/// One well-known principal: what to call it, which SID it is, and the POSIX
/// id this machine projects it to.
struct Entry {
    name: &'static str,
    authority: u64,
    sub_authorities: &'static [u32],
    unix_id: Option<u32>,
}

/// Every well-known principal authd knows.
///
/// Names are the bare form. `BUILTIN\Administrators` is deliberately not here
/// and cannot be: a backslash is the registry's path separator, so the
/// qualified spelling is unrepresentable as a policy record's key name.
const WELL_KNOWN: &[Entry] = &[
    // SYSTEM is root. Fixed by peinit, not chosen here.
    Entry { name: "SYSTEM", authority: 5, sub_authorities: &[18], unix_id: Some(0) },
    // Well-known groups, from a block clear of both SYSTEM and the low numbers
    // Linux distributions traditionally hand to system daemons.
    Entry { name: "Everyone", authority: 1, sub_authorities: &[0], unix_id: Some(100) },
    Entry { name: "Authenticated Users", authority: 5, sub_authorities: &[11], unix_id: Some(101) },
    Entry { name: "Administrators", authority: 5, sub_authorities: &[32, 544], unix_id: Some(102) },
    Entry { name: "Users", authority: 5, sub_authorities: &[32, 545], unix_id: Some(103) },
    Entry { name: "Guests", authority: 5, sub_authorities: &[32, 546], unix_id: Some(104) },
    Entry { name: "Local Service", authority: 5, sub_authorities: &[19], unix_id: Some(105) },
    Entry { name: "Network Service", authority: 5, sub_authorities: &[20], unix_id: Some(106) },
    // Nameable in policy, deliberately unnumbered — see the module docs. These
    // are what make "network logons cap at Low" expressible without any
    // mechanism beyond a policy record.
    Entry { name: "Interactive", authority: 5, sub_authorities: &[4], unix_id: None },
    Entry { name: "Network", authority: 5, sub_authorities: &[2], unix_id: None },
    Entry { name: "Batch", authority: 5, sub_authorities: &[3], unix_id: None },
    Entry { name: "Service", authority: 5, sub_authorities: &[6], unix_id: None },
    Entry { name: "Anonymous", authority: 5, sub_authorities: &[7], unix_id: None },
];

impl Entry {
    fn sid(&self) -> Option<Sid> {
        Sid::build(self.authority, self.sub_authorities).ok()
    }

    fn is(&self, sid: &SidRef) -> bool {
        self.sid()
            .is_some_and(|built| built.as_ref().as_bytes() == sid.as_bytes())
    }
}

/// The POSIX id this machine projects a well-known SID to, if it has one.
///
/// `None` covers both "not a well-known SID" and "well-known but deliberately
/// unnumbered". The caller wants the same thing in either case — no number —
/// so the distinction is not worth a second return type.
pub fn unix_id(sid: &SidRef) -> Option<u32> {
    WELL_KNOWN
        .iter()
        .find(|entry| entry.is(sid))
        .and_then(|entry| entry.unix_id)
}

/// Resolve the name an administrator wrote to the SID it means.
///
/// Matched **case-insensitively**, unlike a privilege name. A privilege name is
/// an ABI identifier copied from documentation; this is a word an administrator
/// types, and `administrators` is not a different principal from
/// `Administrators`. `lps` already resolves group names the same way, so the two
/// places an operator writes a principal's name agree.
pub fn by_name(name: &str) -> Option<Sid> {
    let name = name.trim();
    WELL_KNOWN
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .and_then(Entry::sid)
}

/// What this machine calls a well-known SID.
///
/// Only the tests use this today — nothing renders a principal back to a human
/// yet. It earns its place by being the inverse [`by_name`] is checked against:
/// a round trip is the one test that catches a table entry whose name and SID
/// disagree, which no amount of one-directional testing would.
#[cfg(test)]
fn name_of(sid: &SidRef) -> Option<&'static str> {
    WELL_KNOWN
        .iter()
        .find(|entry| entry.is(sid))
        .map(|entry| entry.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().expect("a well-formed SID")
    }

    #[test]
    fn the_documented_sids_carry_the_documented_numbers() {
        assert_eq!(unix_id(sid("S-1-5-18").as_ref()), Some(0));
        assert_eq!(unix_id(sid("S-1-1-0").as_ref()), Some(100));
        assert_eq!(unix_id(sid("S-1-5-11").as_ref()), Some(101));
        assert_eq!(unix_id(sid("S-1-5-32-544").as_ref()), Some(102));
        assert_eq!(unix_id(sid("S-1-5-32-545").as_ref()), Some(103));
        assert_eq!(unix_id(sid("S-1-5-32-546").as_ref()), Some(104));
        assert_eq!(unix_id(sid("S-1-5-19").as_ref()), Some(105));
        assert_eq!(unix_id(sid("S-1-5-20").as_ref()), Some(106));
    }

    /// §12.1: supplementary GIDs come only from groups that have a number, so a
    /// logon-type SID must stay unnumbered even though it is nameable.
    #[test]
    fn logon_type_sids_are_nameable_but_unnumbered() {
        for (name, text) in [
            ("Interactive", "S-1-5-4"),
            ("Network", "S-1-5-2"),
            ("Batch", "S-1-5-3"),
            ("Service", "S-1-5-6"),
        ] {
            assert_eq!(by_name(name).as_deref().map(SidRef::to_sid), Some(sid(text)));
            assert_eq!(unix_id(sid(text).as_ref()), None, "{name} must have no gid");
        }
    }

    #[test]
    fn an_unknown_sid_has_no_number_and_no_name() {
        let local = sid("S-1-5-21-1-2-3-1000");
        assert_eq!(unix_id(local.as_ref()), None);
        assert_eq!(name_of(local.as_ref()), None);
    }

    #[test]
    fn names_resolve_case_insensitively_and_ignore_surrounding_space() {
        let administrators = sid("S-1-5-32-544");
        for spelling in [
            "Administrators",
            "administrators",
            "ADMINISTRATORS",
            "  Administrators  ",
        ] {
            assert_eq!(
                by_name(spelling).as_ref().map(|s| s.to_string()),
                Some(administrators.to_string()),
                "{spelling:?} must resolve"
            );
        }
    }

    #[test]
    fn a_multi_word_name_resolves() {
        assert_eq!(
            by_name("authenticated users").as_ref().map(|s| s.to_string()),
            Some(sid("S-1-5-11").to_string())
        );
    }

    /// The qualified spelling cannot be a registry key name — the backslash is
    /// the path separator — so it must not silently resolve either.
    #[test]
    fn the_qualified_spelling_does_not_resolve() {
        assert_eq!(by_name("BUILTIN\\Administrators"), None);
        assert_eq!(by_name(""), None);
        assert_eq!(by_name("Domain Admins"), None);
    }

    #[test]
    fn every_name_round_trips_through_its_sid() {
        for entry in WELL_KNOWN {
            let built = entry.sid().expect("a buildable SID");
            assert_eq!(
                name_of(built.as_ref()),
                Some(entry.name),
                "{} must name itself back",
                entry.name
            );
            assert_eq!(
                by_name(entry.name).as_ref().map(|s| s.to_string()),
                Some(built.to_string())
            );
        }
    }

    /// Two entries sharing a SID would make `name_of` arbitrary; two sharing a
    /// name would make `by_name` arbitrary. Neither may happen.
    #[test]
    fn the_table_has_no_duplicates() {
        let mut sids: Vec<String> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for entry in WELL_KNOWN {
            let text = entry.sid().expect("a buildable SID").to_string();
            assert!(!sids.contains(&text), "{text} appears twice");
            sids.push(text);

            let lowered = entry.name.to_ascii_lowercase();
            assert!(!names.contains(&lowered), "{} appears twice", entry.name);
            names.push(lowered);
        }
    }

    /// Every number is distinct, and none collides with the band a principal
    /// source's range can reach.
    #[test]
    fn the_numbers_are_distinct_and_below_the_source_band() {
        let mut seen: Vec<u32> = Vec::new();
        for entry in WELL_KNOWN {
            let Some(id) = entry.unix_id else { continue };
            assert!(!seen.contains(&id), "{} reuses id {id}", entry.name);
            assert!(
                id < crate::unix_id::RESERVED,
                "{} at {id} is inside the band sources can reach",
                entry.name
            );
            seen.push(id);
        }
    }
}
