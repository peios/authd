# Building Authentication

Use Bazel to build the authentication daemons, command-line clients, name
service switch
(NSS) module, and shared authentication client. The supported development host
is
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

The client software development kit (SDK) does not require the Peios
kernel SDK:

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

The application binary interface (ABI) test compares C and Rust layouts,
checks the public exports and shared object name (SONAME), and compiles and
runs a C client. The Rust client tests load the
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
`libpeios` component through its Cargo interface and copies its
headers together with the supplied kernel userspace API (UAPI). It does not
change the
source checkouts. Bazel then consumes the SDK library and headers as
explicit inputs. Changing those inputs invalidates dependent actions.

Continuous integration (CI) selects exact source revisions in
`.github/workflows/check.yml`. The
SDK is a host development build; running Peios-specific operations still
requires a compatible Peios kernel.

## Build and test everything

With the SDK configured, build the artifacts and run the tests:

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
the Cargo manifests, the module version in `MODULE.bazel`, and the versions
and exact dependencies in `packages/definitions/`. Package staging checks
that the source-family and package versions agree.

Workspace dependencies are explicit in each `BUILD.bazel`. In particular,
the daemons use the protocol-only `auth-core`, while `lps` and NSS use its
client variant. The terminal helper has matching variants so one program
never links incompatible Rust identities for the same public type. Preserve
that separation when adding a dependency.

A small Bazel-only patch makes `peios-sys` use the declared SDK instead of
probing host package metadata. It also removes its development absolute
runtime path. Cargo consumers continue to use the upstream build script.

## Build packages

Run `./bazel build //:packages` to build the complete package set. The output
is `bazel-bin/packages.store`, containing deduplicated, compressed blobs under
`blobs/sha256/` and canonical manifests under
`manifests/<name>/<version>/<arch>/manifest.toml`. The writer is the same
pinned package-store writer used by the kernel. Its manifest format is
unchanged.

Build one package with a target such as `//packages:authd`,
`//packages:libauth-devel`, or `//packages:authd-source`. Each target produces
its own `.ppk` directory. The source package includes only declared repository
inputs. Runtime packages share one staging action, which builds the six
executable and linkable format (ELF) artifacts, collects the declared crate
closures' license notices, splits debug
information, and stages manuals and registry seeds. Manual sources live in
`docs/man/`; event and registry manifests live in `docs/*.evman` and
`docs/*.regman`. Packaging installs them in their respective directories under
`/usr/share/`.

The package family contains the authority, principal source, administration
and `login` clients, NSS library, C client library and development headers,
six debuginfo packages, shared debug sources, source code, and the optional
live-account bootstrap. Building all packages does not select them for
installation. Keep the passwordless live-account package out of production
images unless their policy deliberately requests it.

The default configuration produces packages for the Linux development ABI.
Package binaries link to installed library SONAMEs without Bazel runtime
search paths; development tests outside packaging retain their runfiles
library paths. Package staging checks ABI layouts and exports, command-line
behavior,
registry privileges, manual pages, SONAMEs, split debug files, and path
leakage.

`index.json` records package identities, manifest hashes, input provenance,
and whether the artifacts use the development or native Peios ABI. It also
preserves package descriptions, licenses, dependencies, service-state security
descriptors, side effects, and required signing tiers. These fields are policy
metadata alongside the canonical manifests; the manifest format does
not yet encode them. A release installer must apply that policy explicitly.
The store is unsigned and is not marked release-ready.

## Build with the native toolchain

Inside a prepared Peios userspace build environment, declare the installed
SDK:

```sh
tools/prepare-native-sdk /tmp/authd-sdk
export PEIOS_SDK=/tmp/authd-sdk
export PEIOS_RUSTC=/usr/bin/rustc
./bazel build --config=peios //:packages
./bazel test --config=peios //...
```

This configuration requires the packaged Peios Rust compiler and standard
library, version 1.98.1 or newer, and applies control-flow enforcement
technology
(CET) and distribution linker hardening. It never substitutes the downloaded
development compiler. Native
package staging requires indirect branch tracking, shadow stacks, and
packed relative relocations (RELR) on every ELF artifact.
The build environment needs a C compiler, binutils, Python 3.11 or newer,
Bash, gzip, tar, pkg-config, libclang, the Peios SDK and kernel headers.

For offline workers, acquire dependencies on a networked development host
with the development SDK configured:

```sh
tools/offline-build acquire /absolute/path/authd-inputs
```

Mount that snapshot read-only in the prepared native environment, declare
its installed SDK with `PEIOS_SDK`, and provide a separate writable work
directory:

```sh
tools/offline-build build /absolute/path/authd-inputs /absolute/path/authd-work
tools/offline-build test /absolute/path/authd-inputs /absolute/path/authd-work
```

The helper checks the module lock, verifies the Bazel executable, and uses a
writable metadata view of the snapshot with repository downloads disabled.
The caller provides the native root and network isolation. It does not
install packages or alter the host SDK. Native builds suppress Bazel's
convenience symlinks; outputs are under the work directory's
`output/execroot/_main/bazel-out/k8-opt/bin/`.

Signing, publication, image policy application, and authentication/token
qualification on a running Peios kernel are separate release steps. In
particular, the authority requires the `tcb.priv` signing tier recorded in
its package metadata.

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

Run `./bazel test //:abi-test` after regenerating the files. Review the
public header, generated files, and export changes together.

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
