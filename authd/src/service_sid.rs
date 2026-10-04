//! Deriving a service's SID from its name.
//!
//! The derivation is libauthd-policy's, so that a program naming the service
//! a policy record is for derives it as authd does. See
//! [`libauthd_policy::service_sid`].

pub use libauthd_policy::service_sid::*;
