//! Locale preferences for newly started Peios user sessions.
//!
//! This crate resolves registry settings and discovers installed locales. It does
//! not authenticate users or change process-global state. Session launchers apply
//! the returned environment only after establishing the session's identity.

pub mod locale;
