//! Rendering replies for a person to read.
//!
//! Kept apart from the commands so the output is testable without a daemon, and
//! so that the question "what does this look like?" has one place to be
//! answered.
//!
//! Plain text, aligned columns, no colour and no borrowed table drawing. The
//! output is as likely to be read over a serial console during a bad morning as
//! in a terminal that renders anything clever.

use libauthd::claim::{Claim, Values};
use libauthd::lps::{Detail, GroupRef, GroupSummary, Summary};
use peios::security::SidRef;

/// Render a SID, or say plainly that it could not be read.
///
/// A SID that will not parse is a real possibility — these arrive as bytes from
/// another process — and printing a placeholder beats both panicking and
/// silently omitting a membership the principal actually has.
pub fn sid(bytes: &[u8]) -> String {
    match SidRef::from_bytes(bytes) {
        Some(sid) => sid.to_string(),
        None => format!("<unreadable SID, {} bytes>", bytes.len()),
    }
}

/// A Unix ID, or a dash where there is none.
///
/// Zero is not an id — the store counts from 1 — so it always means "nothing
/// numbers this". A dash says that at a glance; printing `0` would read as
/// **root**, which is the one number this must never appear to claim.
fn unix_id(id: u32) -> String {
    if id == 0 {
        "-".to_string()
    } else {
        id.to_string()
    }
}

/// A group, named if this machine knows a name for it.
///
/// The SID is kept alongside the name rather than replaced by it. A name is what
/// an operator recognises; the SID is what a security descriptor actually holds,
/// and the moment those two disagree is exactly when somebody needs to see both.
fn group(group: &GroupRef) -> String {
    let sid = sid(&group.sid);
    match (group.name.is_empty(), group.unix_id) {
        (true, 0) => sid,
        (true, id) => format!("{sid} (gid {id})"),
        (false, 0) => format!("{} [{sid}]", group.name),
        (false, id) => format!("{} [{sid}] (gid {id})", group.name),
    }
}

/// `lps list`.
pub fn listing(principals: &[Summary]) -> String {
    if principals.is_empty() {
        return "no principals\n".to_string();
    }

    let width = principals
        .iter()
        .map(|principal| principal.name.chars().count())
        .max()
        .unwrap_or(0)
        .max("NAME".len());

    let mut out = format!(
        "{:<width$}  {:>6}  {:>8}  {:<8}  {}\n",
        "NAME", "RID", "UID", "STATE", "GROUPS"
    );
    for principal in principals {
        out.push_str(&format!(
            "{:<width$}  {:>6}  {:>8}  {:<8}  {}\n",
            principal.name,
            principal.rid,
            unix_id(principal.unix_id),
            if principal.enabled { "enabled" } else { "disabled" },
            principal.groups,
        ));
    }
    out
}

/// `lps group list`.
pub fn groups(groups: &[GroupSummary]) -> String {
    if groups.is_empty() {
        return "no local groups\n".to_string();
    }

    let width = groups
        .iter()
        .map(|group| group.name.chars().count())
        .max()
        .unwrap_or(0)
        .max("NAME".len());

    let mut out = format!(
        "{:<width$}  {:>6}  {:>8}  {:>7}  {}\n",
        "NAME", "RID", "GID", "MEMBERS", "SID"
    );
    for group in groups {
        out.push_str(&format!(
            "{:<width$}  {:>6}  {:>8}  {:>7}  {}\n",
            group.name,
            group.rid,
            unix_id(group.unix_id),
            group.members,
            sid(&group.sid),
        ));
    }
    out
}

/// One claim, as `lps show` prints it.
fn claim(claim: &Claim) -> String {
    let values = match &claim.values {
        Values::Int64(v) => v.iter().map(i64::to_string).collect::<Vec<_>>(),
        Values::Uint64(v) => v.iter().map(u64::to_string).collect(),
        Values::Boolean(v) => v.iter().map(bool::to_string).collect(),
        Values::String(v) => v.iter().map(|s| format!("{s:?}")).collect(),
        Values::Sid(v) => v.iter().map(|s| sid(s)).collect(),
        // Bytes have no sensible plain-text rendering, and printing them raw
        // would put arbitrary control characters on a terminal.
        Values::Octet(v) => v.iter().map(|b| format!("<{} bytes>", b.len())).collect(),
    };

    let rendered = if values.is_empty() {
        // Distinct from a claim that is absent: §3.9 makes an empty claim
        // legal, and an administrator who emptied one should see that they did.
        "(no values)".to_string()
    } else {
        values.join(", ")
    };
    format!(
        "{} ({}) = {rendered}",
        claim.name,
        claim.values.type_name()
    )
}

/// `lps show`.
pub fn detail(principal: &Detail) -> String {
    let mut out = String::new();
    let field = |out: &mut String, label: &str, value: &str| {
        out.push_str(&format!("{label:<14} {value}\n"));
    };

    field(&mut out, "name", &principal.name);
    if !principal.display_name.is_empty() {
        field(&mut out, "display name", &principal.display_name);
    }
    field(&mut out, "rid", &principal.rid.to_string());
    field(&mut out, "sid", &sid(&principal.sid));
    field(&mut out, "uid", &unix_id(principal.unix_id));
    field(
        &mut out,
        "state",
        if principal.enabled { "enabled" } else { "disabled" },
    );
    field(&mut out, "primary group", &group(&principal.primary_group));
    field(&mut out, "home", &principal.home);
    field(&mut out, "shell", &principal.shell);

    if principal.groups.is_empty() {
        field(&mut out, "groups", "none");
    } else {
        for (index, member) in principal.groups.iter().enumerate() {
            let label = if index == 0 { "groups" } else { "" };
            out.push_str(&format!("{label:<14} {}\n", group(member)));
        }
    }

    if principal.claims.is_empty() {
        field(&mut out, "claims", "none");
    } else {
        for (index, held) in principal.claims.iter().enumerate() {
            let label = if index == 0 { "claims" } else { "" };
            out.push_str(&format!("{label:<14} {}\n", claim(held)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn administrators() -> Vec<u8> {
        let mut bytes = vec![1, 2, 0, 0, 0, 0, 0, 5];
        for sub in [32u32, 544] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes
    }

    fn jack() -> Vec<u8> {
        let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, 1000] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        bytes
    }

    fn named_group() -> GroupRef {
        GroupRef {
            sid: administrators(),
            name: "Administrators".into(),
            unix_id: 102,
        }
    }

    fn detail_of(principal: Detail) -> String {
        detail(&principal)
    }

    fn summary(name: &str, rid: u32, enabled: bool) -> Summary {
        Summary {
            name: name.into(),
            rid,
            enabled,
            groups: 1,
            unix_id: 1_000_001,
        }
    }

    #[test]
    fn an_empty_store_says_so_rather_than_printing_a_bare_header() {
        assert_eq!(listing(&[]), "no principals\n");
        assert_eq!(groups(&[]), "no local groups\n");
    }

    #[test]
    fn a_listing_aligns_to_the_longest_name() {
        let listing = listing(&[
            summary("jack", 1000, true),
            summary("a-much-longer-name", 1001, false),
        ]);

        let lines: Vec<&str> = listing.lines().collect();
        assert!(lines[0].starts_with("NAME"));
        // Every RID column starts at the same offset.
        let rid_at = |line: &str| line.find("100").expect("a RID");
        assert_eq!(rid_at(lines[1]), rid_at(lines[2]));
    }

    #[test]
    fn a_listing_distinguishes_enabled_from_disabled() {
        let listing = listing(&[summary("guest", 1001, false)]);
        assert!(listing.contains("disabled"), "{listing}");
    }

    /// Zero is not an id, and printing it would read as root — the one number
    /// this output must never appear to claim.
    #[test]
    fn an_absent_unix_id_prints_as_a_dash_rather_than_zero() {
        let listing = listing(&[Summary {
            unix_id: 0,
            ..summary("jack", 1000, true)
        }]);
        assert!(listing.contains(" - "), "{listing}");
        assert!(
            !listing.contains(" 0 "),
            "0 would read as root: {listing}"
        );
    }

    #[test]
    fn detail_renders_every_membership() {
        let rendered = detail_of(Detail {
            name: "jack".into(),
            rid: 1000,
            enabled: true,
            sid: jack(),
            groups: vec![named_group(), named_group()],
            primary_group: named_group(),
            ..Detail::default()
        });
        assert!(rendered.contains("S-1-5-21-1-2-3-1000"), "{rendered}");
        assert_eq!(
            rendered.matches("S-1-5-32-544").count(),
            3,
            "two memberships and the primary group: {rendered}"
        );
        assert!(rendered.contains("enabled"), "{rendered}");
    }

    /// The name is what an operator recognises; the SID is what a descriptor
    /// holds. Showing both is what makes a disagreement between them visible.
    #[test]
    fn a_named_group_shows_its_name_and_its_sid() {
        let rendered = group(&named_group());
        assert!(rendered.contains("Administrators"), "{rendered}");
        assert!(rendered.contains("S-1-5-32-544"), "{rendered}");
        assert!(rendered.contains("gid 102"), "{rendered}");
    }

    #[test]
    fn an_unnamed_group_still_shows_its_sid() {
        let rendered = group(&GroupRef {
            sid: administrators(),
            name: String::new(),
            unix_id: 0,
        });
        assert_eq!(rendered, "S-1-5-32-544");
    }

    #[test]
    fn detail_says_none_rather_than_nothing_for_no_groups() {
        let rendered = detail_of(Detail {
            name: "guest".into(),
            rid: 1001,
            sid: jack(),
            ..Detail::default()
        });
        assert!(rendered.contains("groups         none"), "{rendered}");
        assert!(rendered.contains("claims         none"), "{rendered}");
    }

    #[test]
    fn detail_shows_the_profile() {
        let rendered = detail_of(Detail {
            name: "jack".into(),
            sid: jack(),
            home: "/home/jack".into(),
            shell: "/bin/sh".into(),
            display_name: "Jack Palfrey".into(),
            ..Detail::default()
        });
        assert!(rendered.contains("/home/jack"), "{rendered}");
        assert!(rendered.contains("/bin/sh"), "{rendered}");
        assert!(rendered.contains("Jack Palfrey"), "{rendered}");
    }

    #[test]
    fn every_claim_type_renders() {
        let rendered = |values| {
            claim(&Claim {
                name: "Attr".into(),
                flags: 0,
                values,
            })
        };
        assert!(rendered(Values::Int64(vec![-3, 7])).contains("-3, 7"));
        assert!(rendered(Values::Uint64(vec![9])).contains('9'));
        assert!(rendered(Values::Boolean(vec![true])).contains("true"));
        assert!(rendered(Values::String(vec!["Eng".into()])).contains("\"Eng\""));
        assert!(rendered(Values::Sid(vec![administrators()])).contains("S-1-5-32-544"));
        // Raw bytes would put control characters on a terminal.
        let octet = rendered(Values::Octet(vec![vec![0x1b, 0x5b, 0x41]]));
        assert!(octet.contains("<3 bytes>"), "{octet}");
    }

    /// An empty claim is legal and distinct from an absent one, so it has to
    /// render as something an administrator can recognise as their own doing.
    #[test]
    fn an_empty_claim_renders_distinctly() {
        let rendered = claim(&Claim {
            name: "Department".into(),
            flags: 0,
            values: Values::String(Vec::new()),
        });
        assert!(rendered.contains("no values"), "{rendered}");
        assert!(rendered.contains("string"), "the type is still worth showing");
    }

    #[test]
    fn an_unreadable_sid_is_shown_rather_than_dropped() {
        // A membership that cannot be rendered must still be visible: silently
        // omitting it would understate what the principal actually holds.
        let rendered = sid(b"not a sid");
        assert!(rendered.contains("unreadable"), "{rendered}");
        assert!(rendered.contains('9'), "the length is worth reporting: {rendered}");
    }
}
