# Building Authentication

Use pekit to build the authentication daemons, command-line clients, name
service switch (NSS) module, and shared authentication client. Pekit builds
each crate on its own, so a change rebuilds only the crates it reaches. The
supported development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: the Bootlin C toolchain, Rust 1.98.1, Python 3.14,
libclang, and the crates `Cargo.lock` selects. The first build needs
network access; later builds
find what they need in pekit's store, and every step runs without network
access in a sandbox that holds only its declared inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files, and the libraries of peios-rs and the Peios SDK. `pekit lock`
pins their commits in `pekit.lock`.

## Build

```sh
pekit build authd lpsd lps login nss libauth
```

| Target | Output |
|---|---|
| `authd` | Authentication authority |
| `lpsd` | Local principal source |
| `lps` | Account administration client |
| `login` | Terminal logon client |
| `nss` | NSS module, `libnss_peios.so.2` by its shared object name (SONAME) |
| `libauth` | Public C client library, `libauth.so.1` by its SONAME |
| `libpeios` | The Peios SDK's library, built from the SDK's own files |

Pekit prints where each output is, under `pekit-out/<target>/`. The
programs load `libpeios.so.0` by its SONAME and carry no runtime search
path, so running them needs libpeios installed. Do not run the daemons on
the development host as part of a build check.

## Test

```sh
pekit test
```

Each member's unit and integration tests are a test of their own, named
after the member: `auth_core`, `lpsd`, and so on. `auth_core_client` and
`auth_policy_write` test those crates with the `client` and `write`
features, which the daemons are built without. Two further tests check
what the C client and the NSS module promise:

| Test | Check |
|---|---|
| `abi` | The C client's exports, SONAME, C and Rust layouts, and a linked C caller |
| `nss_linkage` | The NSS module needs neither libpeios nor `libgcc_s` and searches no path |

A test whose inputs did not change is found in the store and not run
again. Socket tests use temporary Unix sockets and do not contact system
services.

## How the build is planned

`build.gcsl` plans the Cargo workspace with the gcslib rust library's
`workspace`: Cargo works out each member's build, unit by unit, and pekit
compiles each unit as a step. Each member's crates get the features Cargo
resolves for that member alone, so the daemons use the protocol-only
`auth-core`, while `lps` and NSS use its client variant, without either
reaching the other. Planning reads the manifests, `Cargo.lock`, and which
files exist, never the sources, so editing a source plans nothing again.

Keep Rust dependency versions in the Cargo manifests and `Cargo.lock`, and
update the lockfile deliberately with Cargo. A package that needs more than
its manifest says is given it in `build.gcsl`'s `crates`:

- `auth-policy` reads the registry seeds in `registry.d/`;
- `peios-sys` generates its bindings from the SDK's headers with bindgen and
  links libpeios, so it, and every crate that depends on it, is given what
  peios-rs's library says it needs, `crate_settings()`: libpeios and its
  headers;
- the tests of `peios-auth` link the C client library, which they are given
  in `tests.gcsl`.

libpeios and its headers are built from the Peios SDK's own files, through
the SDK's GCSL library, which peios-rs's library imports. The commits
`pekit.lock` pins say which SDK and which peios-rs; the rust library fails a
build whose `Cargo.lock` takes peios-rs's crates at another commit than
`pekit.lock` pins its library at, so the crates and the settings they are
built with always agree.

## Not built with pekit yet

Packages, the client SDK archive, and builds with the native Peios
toolchain, which hardens programs with control-flow enforcement technology
(CET), are not yet built with pekit. The package definitions and native
build settings from the Bazel build are kept outside this repository until
they are.

## Regenerate the client interface

Install clang-format 18.1.8 and the Rust 1.96.0 formatter. The generators
use the repository's C and Rust formatting settings. After changing the
public C interface, regenerate its shared layouts and export declarations:

```sh
rustup run 1.96.0 python3 tools/generate-auth-abi.py
rustup run 1.96.0 python3 tools/generate-auth-exports.py
```

Format the client sources with the repository settings:

```sh
rustup run 1.96.0 rustfmt --config-path tools/rustfmt.toml libauth/src/lib.rs \
    peios-auth/src/lib.rs auth-abi/src/lib.rs
```

Run `pekit test abi` after regenerating the files. Review the public
header, generated files, and export changes together.

## Source compatibility

Consumers adopting the renamed workspace crates need these dependencies:

| Previous crate | Replacement |
|---|---|
| `libauthd` | `auth-core` |
| `libauthd-client` | `auth-core` with the `client` feature |
| `libauthd-policy` | `auth-policy` |
| `libtty` | `terminal-input` |
| `libsession` | `session-preferences` |

Update the consumer's Cargo manifests and Rust imports together. The
crate renames do not change the socket protocols.

The Peios Generic System Standards (PGSS) Logon and principal source
interface (PSI) headers use version 1. Their credential-method and Secure
Shell (SSH) fields are required even though the header
version is unchanged. Rebuild wire-protocol consumers together when adopting
those fields; matching header versions alone do not establish compatibility.
Applications using the public client library follow its ABI contract.

For on-disk account compatibility and recovery, read `lpsd(8)` before
replacing the daemon. An unreadable store is not permission to create a new
one.
