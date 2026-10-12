//! Bake the SONAME glibc looks for.
//!
//! An NSS module is `dlopen`ed by literal name — `libnss_peios.so.2`, where the
//! 2 is the NSS interface version rather than anything about this module — so
//! nothing ever links against it and cargo sees no reason to give the cdylib a
//! SONAME at all.
//!
//! It still needs one. `ldconfig` builds `/etc/ld.so.cache` from SONAMEs and
//! skips a library that has none, which would leave every `dlopen` falling back
//! to scanning the default directories. That fallback does find it — the module
//! installs into glibc's own `--libdir` — but it is a directory scan on the
//! hottest path on the system, taken by every process that renders a name.
//!
//! Every NSS module on every Linux system carries this; matching them is also
//! how a reader confirms at a glance that this is one.
fn main() {
    println!("cargo::rustc-link-arg=-Wl,-soname,libnss_peios.so.2");
    // std retains backtrace/unwind references even with panic=abort. Resolve
    // those inside this module rather than adding libgcc_s to every NSS caller.
    // Whole-archive also works with GNU ld when std's objects follow this
    // archive; rustc's cdylib export map keeps the runtime symbols private.
    println!("cargo::rustc-link-lib=static:+whole-archive=gcc_eh");
    println!("cargo::rerun-if-changed=build.rs");
}
