//! The principals every Peios machine has, and what this machine calls them.
//!
//! The table is libauthd-policy's, so that a program showing this machine's
//! policy resolves a record's name exactly as authd does. See
//! [`libauthd_policy::well_known`].

pub use libauthd_policy::well_known::*;
