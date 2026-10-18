---
title: Building Authentication
type: how-to
description: Build and test the authentication programs and client SDK with
  Bazel on Linux.
---

Use Bazel to build the authentication daemons, command-line clients, NSS
module, and shared authentication client. The supported development host is
x86-64 Linux with glibc.

## Before you start

Install Git, curl, a C compiler, libc development headers, libclang,
Python 3, pkg-config, and binutils. The checked-in `./bazel` wrapper verifies
and caches Bazel 8.4.2 outside the checkout. Bazel downloads Rust 1.96.0 and
the dependencies selected by `Cargo.lock` on the first build. Repository
fetches need network access; compilation uses declared inputs.

The C compiler, system headers, and libclang come from the host. These are
Linux development builds, not fully hermetic or cross-compilation builds.
Socket tests use temporary Unix sockets and do not contact system services.

## Build the client SDK

The client library does not require the Peios kernel SDK:

```sh
./bazel build //:sdk
./bazel test //libauth:tests //peios-auth:client-test //:abi-test
```

The archive `bazel-bin/auth-sdk.tar.gz` contains `usr/include/peios/`,
`usr/lib/libauth.so.1`, its linker symlink, and `usr/lib/pkgconfig/auth.pc`.
Extract it into a staging directory, not over the host operating system.
When using that staging directory, point `pkg-config` at its metadata and
set `PKG_CONFIG_SYSROOT_DIR` to the staging root. Runtime callers also need
its `usr/lib` directory on their library search path.

The ABI test compares C and Rust layouts, checks the public exports and
SONAME, and compiles and runs a C client. The Rust client tests load the
shared library through Bazel's runtime dependency graph.

## Prepare a Peios SDK

The full build needs a compatible `libpeios.so.0` and matching library and
kernel headers. Supply one SDK directory with this layout:

```text
peios-sdk/
    include/peios.h
    include/peios/*.h
    include/pkm/*.h
    lib/libpeios.so.0
```

To create a development SDK from existing source checkouts, install Rust
1.96.0 through rustup, then run:

```sh
rustup toolchain install 1.96.0 --profile minimal
tools/prepare-dev-sdk /path/to/libpeios /path/to/kernel/include/uapi \
    /tmp/authd-dev-sdk
export PEIOS_SDK=/tmp/authd-dev-sdk
```

Use a new output directory each time. The helper builds the separate
`libpeios` component through its current Cargo interface and copies its
headers together with the supplied kernel UAPI. It does not change the
source checkouts. Bazel then consumes the SDK library and headers as
explicit inputs. Changing those inputs invalidates dependent actions.

CI selects exact source revisions in `.github/workflows/check.yml`. The
SDK is a host development build; running Peios-specific operations still
requires a compatible Peios kernel.

## Build and test everything

```sh
./bazel build //:artifacts
./bazel test //...
```

`//:artifacts` builds all four programs, both shared libraries, and the
Rust client wrapper. Tests cover the default and optional client/policy
features separately. Choose an individual target for a shorter edit loop:

| Target | Output or check |
|---|---|
| `//authd` | Authentication authority |
| `//lpsd` | Local principal source |
| `//lps` | Account administration client |
| `//login` | Terminal logon client |
| `//nss` | NSS shared library |
| `//libauth:shared` | Public C client shared library |
| `//peios-auth` | Rust wrapper for the shared library |
| `//lpsd:tests` | Local principal source unit tests |
| `//:sdk` | Client SDK archive |
| `//:abi-test` | C/Rust ABI and linkage checks |
| `//:nss-linkage-test` | NSS runtime dependencies |
| `//:vendor-test` | Offline repository snapshot handling |

Use `-c dbg` for an unoptimized build with debug information. Do not run
the daemons on the development host as part of a build check. Bazel places
outputs under `bazel-bin`; the program paths are `authd/authd`, `lpsd/lpsd`,
`lps/lps`, and `login/login` beneath that directory. Programs that use the
Peios SDK have Bazel runtime paths and are not standalone release packages.

## Change dependencies

Keep Rust dependency versions in the Cargo manifests and `Cargo.lock`.
Bazel's crate rules read those files and preserve the checked-in lockfile.
Update the lockfile deliberately with Cargo, then run the Bazel checks and
review `MODULE.bazel.lock` before committing both lockfiles. Build-rule and
compiler versions are pinned in `MODULE.bazel`; Bazel's own version and
checksum are in `.bazelversion` and `build/bazel.sha256`.

When changing the component version, update `build/version.bzl` alongside
the Cargo manifests and the module version in `MODULE.bazel`. The native
package build checks that its version matches the Cargo workspace.

Workspace dependencies are explicit in each `BUILD.bazel`. In particular,
the daemons use the protocol-only `auth-core`, while `lps` and NSS use its
client variant. The terminal helper has matching variants so one program
never links incompatible Rust identities for the same public type. Preserve
that separation when adding a dependency.

A small Bazel-only patch makes `peios-sys` use the declared SDK instead of
probing host package metadata. It also removes its development absolute
runtime path. Cargo consumers continue to use the upstream build script.

## Package and qualify a release

Pekit invokes the same Bazel target graph with `--config=peios`. This
configuration selects the installed Peios Rust compiler and standard
library, requires Rust 1.98.1 or newer, applies CET and distribution linker
hardening, and retains debug information for package splitting. It never
substitutes the downloaded development compiler for the release compiler.
`PEIOS_RUSTC` can select an explicit compiler path; its default is
`/usr/bin/rustc`.

Run releases through the catalog's native Pekit environment. Its vendor
phase acquires the checksum-verified Bazel executable, Bazel repositories,
and Cargo sources used for license accounting. Build and test workers use
that snapshot with downloading disabled and no network. A writable
metadata view lets Bazel use the read-only acquisition output without
changing dependency contents.

The build graph marks native shared libraries as system-provided, so
release binaries do not contain Bazel runtime search paths. A small patch
to the pinned Rust rules corrects their handling of these libraries.
Native wrapper tests use the staged client library through
`LD_LIBRARY_PATH`.

After Bazel builds the artifacts, Pekit stages manuals and registry seeds,
collects licenses, splits debug information, and copies source files from
the Bazel execution tree. The test gate checks CET, RELRO, RELR, PIE,
non-executable stacks, SONAMEs, runtime paths, debug files, source-path
leaks, NSS exports, and the staged client interface. Signing and package
publication remain Pekit's responsibility.

A native userspace build root verifies the build toolchain and package
payload. Qualification of authentication and token operations on a running
Peios kernel remains a separate release requirement.
