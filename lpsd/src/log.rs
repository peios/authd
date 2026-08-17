//! Diagnostics on stderr, which peinit captures into the service's log.
//!
//! No logging framework. lpsd holds every local credential verifier on the
//! system, so a log crate is a dependency, a formatter, and a set of allocation
//! behaviours inside it — for something that needs to write prefixed lines to a
//! file descriptor peinit already owns.
//!
//! One rule this module cannot enforce but every caller must observe: **never
//! log credential material, and never log which of "no such principal" or
//! "wrong credential" caused a failure to a place a caller can read.** The
//! audit trail is allowed to know; the wire is not.

use std::fmt::Arguments;
use std::io::Write;

fn emit(level: &str, args: Arguments<'_>) {
    // Deliberately ignoring write errors: there is nowhere useful to report a
    // failure to report, and lpsd must not die because its log went away.
    let _ = writeln!(std::io::stderr(), "lpsd: {level}: {args}");
}

pub fn info(args: Arguments<'_>) {
    emit("info", args);
}

pub fn warn(args: Arguments<'_>) {
    emit("warn", args);
}

pub fn error(args: Arguments<'_>) {
    emit("error", args);
}
