//! Deriving a service's SID from its name.
//!
//! The derivation is auth-policy's, so that a program naming the service
//! a policy record is for derives it as authd does. See
//! [`auth_policy::service_sid`].

pub use auth_policy::service_sid::*;
