//! Unix IDs: turning what a source counted into what a token projects.
//!
//! KACS tokens are the only identity that decides anything. Linux programs do
//! not know tokens exist — they call `getuid`, `getgid`, `getgroups` — so every
//! token carries precomputed POSIX numbers (PSD-004 §12.1). The kernel does not
//! resolve them; authd computes them once, here, and they ride on the token.
//!
//! # Sources count, authd numbers
//!
//! A principal source counts from 1 and knows nothing about where its numbers
//! land. authd adds a base from the registry, so `lpsd`'s first principal is
//! 1 and projects to 1,000,001.
//!
//! That split is not administrative tidiness. It is the numeric half of the same
//! confinement as the domain SID:
//!
//! - A source cannot reach **uid 0**, or any other number in the reserved band,
//!   because the only numbers it can influence are the ones its base is added
//!   to and every base sits above [`RESERVED`].
//! - A source cannot reach **another source's** numbers, because a relative id
//!   at or past its count is refused rather than wrapped or clamped.
//!
//! A source that never learns its own base also cannot bake one in, so rebasing
//! is a registry edit rather than a rewrite of every record it holds.
//!
//! # What authd numbers itself
//!
//! Everything below [`RESERVED`]: the well-known SIDs in [`crate::well_known`], and, in
//! time, the service and confinement SIDs that have no directory to come from.
//! The band is large because that last group is open-ended.
//!
//! `SYSTEM` is **0** and that is not a choice this module gets to make —
//! `peinit` already projects the SYSTEM token to uid 0 when it launches
//! services, and a disagreement between the two would mean the same principal
//! projecting differently depending on who minted the token.

use peios::security::SidRef;

/// The projection given to a SID nothing can number.
///
/// 65534 is the conventional Linux `nobody`, and it is what PSD-004 §12.1
/// specifies for a SID with no `uidNumber`. Setting it explicitly is not
/// optional: the projection defaults to **0**, and KACS refuses to create a
/// token projecting uid 0 for any user SID that is not SYSTEM.
pub const UNMAPPED: u32 = 65534;

/// The first Unix ID a principal source may be given.
///
/// Everything below belongs to authd. The band is deliberately enormous
/// relative to the number of well-known SIDs, because service SIDs and
/// confinement SIDs will be numbered out of it and there is no bound on how many
/// of those a machine has.
pub const RESERVED: u32 = 1_000_000;

/// How many ids a source gets when the registry names a base but no count.
pub const DEFAULT_COUNT: u32 = 1_000_000;

/// The number this machine projects a well-known SID to, if it is one.
///
/// The table itself lives in [`crate::well_known`], because policy needs the
/// same principals under the names an administrator writes and a second copy
/// keyed the same way could only drift.
///
/// The logon-type SIDs (`S-1-5-4` Interactive and friends) are in that table but
/// carry no number, so they answer `None` here. They are real group memberships
/// and ACLs are written against them, but nothing wants a *gid* for "arrived
/// over the network" — and §12.1 is explicit that supplementary GIDs come only
/// from groups that have a number.
pub fn built_in(sid: &SidRef) -> Option<u32> {
    crate::well_known::unix_id(sid)
}

/// The span of Unix IDs a principal source's numbers land in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// `UnixIDBase`: what authd adds to every relative id from this source.
    pub base: u32,
    /// `UnixIDCount`: how many ids the range spans, so `[base, base + count)`.
    pub count: u32,
}

/// Why a configured range is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// At or below [`RESERVED`], so it would overlap authd's own numbers — at
    /// the bottom of which is uid 0.
    Reserved,
    /// Zero-sized, so it could never number anybody.
    Empty,
    /// `base + count` does not fit in a `u32`.
    Overflows,
}

impl core::fmt::Display for RangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reserved => write!(
                f,
                "a Unix ID base below {RESERVED} would overlap the numbers authd reserves \
                 for itself, which begin at uid 0"
            ),
            Self::Empty => write!(f, "a Unix ID count of zero can number nobody"),
            Self::Overflows => write!(f, "the Unix ID range runs past the end of a 32-bit id"),
        }
    }
}

impl Range {
    /// Check a range an administrator configured.
    ///
    /// The reserved-band check is the one that matters. Without it, a base of
    /// zero would make a source's first principal project to **uid 1**, and a
    /// source that could choose its own relative numbers could reach uid 0
    /// outright — which is the whole reason ids are relative in the first place.
    pub fn new(base: u32, count: u32) -> Result<Self, RangeError> {
        if base < RESERVED {
            return Err(RangeError::Reserved);
        }
        if count == 0 {
            return Err(RangeError::Empty);
        }
        base.checked_add(count).ok_or(RangeError::Overflows)?;
        Ok(Self { base, count })
    }

    /// Turn a source-relative id into the number a token carries.
    ///
    /// `None` for anything this range cannot express:
    ///
    /// - **0**, which is how a source says "I have no number for this". It is
    ///   not an id, so it must not become `base`.
    /// - **At or past `count`**, which is a source reaching outside the range it
    ///   was given. Refused rather than clamped: clamping would silently put two
    ///   principals on one number, and wrapping would land in somebody else's
    ///   range entirely.
    pub fn rebase(&self, relative: u32) -> Option<u32> {
        if relative == 0 || relative >= self.count {
            return None;
        }
        self.base.checked_add(relative)
    }
}

/// The POSIX numbers a token carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub uid: u32,
    pub gid: u32,
    /// Every group that has a number, in the order the groups were asserted.
    /// Groups without one are simply absent, per §12.1.
    pub supplementary: Vec<u32>,
}

/// A group as the projection sees it: its SID, and what its source numbered it.
pub struct Numbered<'a> {
    pub sid: &'a SidRef,
    /// The source's relative id, or 0 if the source does not number this group.
    pub relative: u32,
}

/// The number a single SID projects to.
///
/// authd's own table wins over anything a source said. That ordering is
/// load-bearing rather than a preference: a source asserting
/// `BUILTIN\Administrators` is naming a membership, not claiming authority over
/// what that group projects to, and honouring a relative id for it would put a
/// well-known group inside the source's range — where a second source could
/// number something else the same way.
fn number(range: Option<&Range>, sid: &SidRef, relative: u32) -> Option<u32> {
    built_in(sid).or_else(|| range?.rebase(relative))
}

/// Compute everything a token needs to project.
///
/// `range` is `None` for a source that has none configured, in which case
/// nothing it asserts can be numbered and every principal it vouches for
/// projects to `nobody`. That is safe — 65534 grants nothing — and it is the
/// honest outcome for a source an administrator has not finished configuring.
pub fn project(
    range: Option<&Range>,
    principal_relative: u32,
    primary_group: &SidRef,
    groups: &[Numbered<'_>],
) -> Projection {
    let uid = range
        .and_then(|range| range.rebase(principal_relative))
        .unwrap_or(UNMAPPED);

    // The primary group's number, looked up the same way as any other group.
    // Its relative id comes from the group list when it appears there, because
    // a source states a group's number once rather than once per use.
    let primary_relative = groups
        .iter()
        .find(|group| group.sid.as_bytes() == primary_group.as_bytes())
        .map_or(0, |group| group.relative);
    let gid = number(range, primary_group, primary_relative).unwrap_or(UNMAPPED);

    let supplementary = groups
        .iter()
        .filter_map(|group| number(range, group.sid, group.relative))
        .collect();

    Projection {
        uid,
        gid,
        supplementary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::security::Sid;

    fn sid(text: &str) -> Sid {
        text.parse().expect("must parse")
    }

    fn range() -> Range {
        Range::new(1_000_000, 1_000_000).expect("must be valid")
    }

    #[test]
    fn system_projects_to_root() {
        // Fixed by peinit, which mints SYSTEM tokens with (0, 0). A
        // disagreement would mean one principal projecting two ways.
        assert_eq!(built_in(sid("S-1-5-18").as_ref()), Some(0));
    }

    #[test]
    fn well_known_groups_are_numbered_below_the_reserved_boundary() {
        for text in [
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-544",
            "S-1-5-32-545",
            "S-1-5-32-546",
            "S-1-5-19",
            "S-1-5-20",
        ] {
            let id = built_in(sid(text).as_ref())
                .unwrap_or_else(|| panic!("{text} must have a number"));
            assert!(id < RESERVED, "{text} must be inside authd's own band");
        }
    }

    /// Distinctness and the band check live with the table in
    /// [`crate::well_known`]. What belongs here is the one property that is
    /// about *this* module's vocabulary rather than the table's shape: no
    /// well-known SID may resolve to the number that means "unmapped", because
    /// a principal that legitimately projected to 65534 would be
    /// indistinguishable from one nothing could number.
    #[test]
    fn nobody_is_not_handed_out_as_a_built_in() {
        for text in [
            "S-1-5-18",
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-32-544",
            "S-1-5-32-545",
            "S-1-5-32-546",
            "S-1-5-19",
            "S-1-5-20",
        ] {
            assert_ne!(
                built_in(sid(text).as_ref()),
                Some(UNMAPPED),
                "{text} must not project to the unmapped number"
            );
        }
    }

    #[test]
    fn an_ordinary_sid_has_no_built_in_number() {
        assert_eq!(built_in(sid("S-1-5-21-1-2-3-1000").as_ref()), None);
        // A logon-type SID is a real membership with no meaningful gid.
        assert_eq!(built_in(sid("S-1-5-4").as_ref()), None);
    }

    // -----------------------------------------------------------------------
    // Ranges
    // -----------------------------------------------------------------------

    #[test]
    fn a_range_inside_the_reserved_band_is_refused() {
        // The check that stops a source reaching uid 0.
        assert_eq!(Range::new(0, 1000), Err(RangeError::Reserved));
        assert_eq!(Range::new(1, 1000), Err(RangeError::Reserved));
        assert_eq!(Range::new(RESERVED - 1, 1000), Err(RangeError::Reserved));
        assert!(Range::new(RESERVED, 1000).is_ok());
    }

    #[test]
    fn a_degenerate_range_is_refused() {
        assert_eq!(Range::new(RESERVED, 0), Err(RangeError::Empty));
        assert_eq!(Range::new(u32::MAX, 2), Err(RangeError::Overflows));
    }

    #[test]
    fn rebasing_adds_the_base() {
        assert_eq!(range().rebase(1), Some(1_000_001));
        assert_eq!(range().rebase(999), Some(1_000_999));
    }

    #[test]
    fn zero_is_not_an_id() {
        assert_eq!(
            range().rebase(0),
            None,
            "0 is how a source says it has no number, and must not become the base"
        );
    }

    #[test]
    fn a_relative_id_past_the_range_is_refused_rather_than_clamped() {
        let small = Range::new(RESERVED, 10).unwrap();
        assert_eq!(small.rebase(9), Some(RESERVED + 9));
        assert_eq!(small.rebase(10), None);
        assert_eq!(small.rebase(u32::MAX), None);
    }

    #[test]
    fn a_source_cannot_reach_another_sources_range() {
        // Two adjacent ranges. Whatever lpsd asserts, it cannot produce a
        // number inside adpsd's, because anything past its count is refused.
        let lpsd = Range::new(1_000_000, 1_000_000).unwrap();
        let adpsd = Range::new(2_000_000, 1_000_000).unwrap();
        for relative in [1u32, 999_999, 1_000_000, 2_000_000, u32::MAX] {
            if let Some(id) = lpsd.rebase(relative) {
                assert!(
                    id < adpsd.base,
                    "lpsd produced {id}, which is inside adpsd's range"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Projection
    // -----------------------------------------------------------------------

    #[test]
    fn a_principal_projects_through_its_sources_range() {
        let administrators = sid("S-1-5-32-544");
        let developers = sid("S-1-5-21-1-2-3-1001");
        let groups = vec![
            Numbered {
                sid: administrators.as_ref(),
                relative: 0,
            },
            Numbered {
                sid: developers.as_ref(),
                relative: 5,
            },
        ];

        let projection = project(Some(&range()), 1, developers.as_ref(), &groups);
        assert_eq!(projection.uid, 1_000_001);
        assert_eq!(projection.gid, 1_000_005, "the primary group is the local one");
        assert_eq!(
            projection.supplementary,
            vec![102, 1_000_005],
            "the well-known group takes authd's number, the local one takes the range"
        );
    }

    #[test]
    fn a_source_cannot_renumber_a_well_known_group() {
        // The ordering that matters: authd's table wins. Otherwise a source
        // could put BUILTIN\Administrators inside its own range, where a second
        // source could number something else identically.
        let administrators = sid("S-1-5-32-544");
        let groups = vec![Numbered {
            sid: administrators.as_ref(),
            relative: 7,
        }];
        let projection = project(Some(&range()), 1, administrators.as_ref(), &groups);
        assert_eq!(projection.gid, 102);
        assert_eq!(projection.supplementary, vec![102]);
    }

    #[test]
    fn a_source_with_no_range_projects_everyone_to_nobody() {
        let developers = sid("S-1-5-21-1-2-3-1001");
        let groups = vec![Numbered {
            sid: developers.as_ref(),
            relative: 5,
        }];
        let projection = project(None, 1, developers.as_ref(), &groups);
        assert_eq!(projection.uid, UNMAPPED);
        assert_eq!(projection.gid, UNMAPPED);
        assert!(
            projection.supplementary.is_empty(),
            "a group nothing can number contributes no gid"
        );
    }

    /// Even with no range, authd's own table still applies — those numbers were
    /// never the source's to give.
    #[test]
    fn well_known_groups_are_numbered_without_a_range() {
        let administrators = sid("S-1-5-32-544");
        let groups = vec![Numbered {
            sid: administrators.as_ref(),
            relative: 0,
        }];
        let projection = project(None, 1, administrators.as_ref(), &groups);
        assert_eq!(projection.uid, UNMAPPED);
        assert_eq!(projection.gid, 102);
        assert_eq!(projection.supplementary, vec![102]);
    }

    #[test]
    fn a_principal_with_no_number_projects_to_nobody() {
        let everyone = sid("S-1-1-0");
        let groups = vec![Numbered {
            sid: everyone.as_ref(),
            relative: 0,
        }];
        let projection = project(Some(&range()), 0, everyone.as_ref(), &groups);
        assert_eq!(projection.uid, UNMAPPED);
    }

    #[test]
    fn a_primary_group_outside_the_asserted_groups_still_projects() {
        // authd adds the primary group to the token if it is missing, so it has
        // to be numbered even when it is not in the asserted list.
        let administrators = sid("S-1-5-32-544");
        let projection = project(Some(&range()), 1, administrators.as_ref(), &[]);
        assert_eq!(projection.gid, 102);
        assert!(projection.supplementary.is_empty());
    }

    #[test]
    fn a_foreign_primary_group_projects_to_nobody() {
        let foreign = sid("S-1-5-21-9-9-9-1000");
        let projection = project(Some(&range()), 1, foreign.as_ref(), &[]);
        assert_eq!(projection.uid, 1_000_001);
        assert_eq!(
            projection.gid, UNMAPPED,
            "a primary group with no number must not silently borrow the uid"
        );
    }
}
