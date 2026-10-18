# authd

Peios' authentication authority — the process that turns "someone proved who they are" into a KACS token and a logon session. It is the only general-purpose minter of identity on a running system.

Closest prior art is Windows' LSA.

## What is here

| Crate | Installs | What it is |
|---|---|---|
| `authd` | `/usr/sbin/authd` | The authority. Holds `SeCreateTokenPrivilege`, runs at `PeiosTcb`, listens on `/run/logon.sock` (PGSS Logon) and `/run/psi.sock` (PSI). |
| `lpsd` | `/usr/sbin/lpsd` | The local principal source. Owns this machine's accounts and every local credential verifier. Runs below authd and holds none of its privileges. |
| `lps` | `/usr/bin/lps` | Administers `lpsd`'s store over `/run/lpsd/admin.sock`. A client with no state and no privilege of its own. |
| `login` | `/usr/bin/login` | A PGSS Logon client. Collects a credential, receives a token, installs it, execs a shell. |
| `nss` | `/usr/lib/x86_64-linux-peios/libnss_peios.so.2` | The NSS client through which POSIX programs resolve Peios principals. |
| `auth-core` | — | Wire formats and transport; existing client helpers under the `client` feature. |
| `auth-policy` | — | Machine policy evaluation and optional administrative writes. |
| `session-preferences` | — | Locale settings shared by session originators. |
| `libauth` | `libauth.so.1` | Public C authentication client API with `peios_auth_*` symbols. |
| `peios-auth` | — | Safe Rust bindings that link to `libauth.so.1`. |
| `auth-abi` | — | Shared C layout definitions used by the library and Rust bindings. |
| `terminal-input` | — | Terminal handling for credential collection. |

## The shape

Three ideas carry most of the design.

**The authority mints; sources assert.** A principal source verifies credentials and says *who someone is* — SID, memberships, POSIX identifiers, where their session starts. It cannot mint a token, grant a privilege, or create a session, because the protocol it speaks gives it no way to say any of those things. A completely compromised source can lie about the accounts it holds, and that is the whole of what it can do.

**Sources are processes, never in-process plugins.** This is the LSA authentication-package and Linux PAM failure mode, and it is the single thing this design most deliberately avoids. A defect in credential parsing — the code most exposed to hostile input — must not become a compromise of the code that mints tokens.

**How much this machine trusts you is local.** Privileges and integrity are not asserted by anyone; they come from a per-principal policy record in the registry that authd reads at every logon. A directory can say you are in `Domain Admins`; whether that carries `SeLoadDriverPrivilege` *here* is this machine's answer.

## Protocols

- **PGSS Logon** (PSD-012) — the standard a Peios authority must speak. `/run/logon.sock`.
- **PSI** (PSD-013) — how principal sources federate identity to the authority. Not a conformance requirement; specified so third parties can write sources. `/run/psi.sock`.
- **LPS** — `lpsd`'s administrative protocol, spoken by `lps` and Principals Manager. `/run/lpsd/admin.sock`. Its framing also carries the self socket, `/run/lpsd/self.sock`, on which any principal reads their own account and sets their display name (PSPU §10.11).

## Building

Use the checked-in Bazel wrapper on x86-64 Linux. It downloads and verifies
Bazel 8.4.2; the build pins Rust 1.96.0 and uses `Cargo.lock` for external
Rust dependencies.

The authentication client SDK needs no Peios kernel SDK:

```sh
./bazel build //:sdk
./bazel test //libauth:tests //peios-auth:client-test //:abi-test
```

The SDK archive is `bazel-bin/auth-sdk.tar.gz`. For all daemons, programs,
and tests, provide a compatible development SDK:

```sh
export PEIOS_SDK=/absolute/path/to/peios-sdk
./bazel build //:artifacts
./bazel test //...
```

The SDK contains `include/peios.h`, `include/peios/`, `include/pkm/`, and
`lib/libpeios.so.0`. Install a host C compiler, libclang, Python 3, and
binutils. Socket tests require local Unix sockets. See
[Building Authentication](docs/learn/authd.product/1--development.shelf/2--building.topic/100--building.md)
for SDK preparation, individual targets, and dependency updates.

Cargo manifests remain available for Rust tooling and consumers. Bazel builds
and tests both development and native release artifacts. `./bazel build //:packages`
creates the complete PPK blob and manifest store in `bazel-bin/packages.store`.
Native builds use `--config=peios` with the installed Peios Rust toolchain.
The default Linux configuration produces development packages. Both paths
stage licences and debug files and validate package payloads before assembly.
Signing and publication are separate release operations.

Regenerate the C/Rust layouts and export declarations with
`python3 tools/generate-auth-abi.py` and
`python3 tools/generate-auth-exports.py`. Format new API sources with
`rustfmt --config-path tools/rustfmt.toml libauth/src/lib.rs
peios-auth/src/lib.rs auth-abi/src/lib.rs`.

Crate names changed at the newtree cutover: `libauthd` and
`libauthd-client` are now `auth-core` (client modules require its `client`
feature); `libauthd-policy` is `auth-policy`, `libtty` is `terminal-input`,
and `libsession` is `session-preferences`. Independently pinned consumers
must update their manifests and imports when adopting this revision.
These source-level changes do not change the socket protocols.

Bazel package definitions live in `packages/definitions/`. Registry seeds in
`registry.d/` are offered as inert files: image policy explicitly selects which
seeds to apply. Installing the package must not silently grant authority to
assert identity. The optional passwordless live account remains a separate package.

The five runtime trust domains are independently installable as
`dev.peios.authd`, `dev.peios.authd-lpsd`, `dev.peios.authd-lps`,
`dev.peios.authd-login`, and `dev.peios.authd-nss`. The passwordless
administrator bootstrap used by disposable live images is a sixth, noarch
package, `dev.peios.authd-live-account`; it is deliberately absent from the
production lpsd package. Each ELF component has matching debuginfo, while the
family shares one debugsource and corresponding-source package. The client
SDK adds `dev.peios.libauth`, `dev.peios.libauth-devel`, and
`dev.peios.libauth-debuginfo`.

## Documentation

Authentication client guidance lives in [docs/learn](docs/learn). Build it
with `trail build docs/learn --strict`. The public C interface contract is in
[auth.h](libauth/include/peios/auth.h). Broader account and privilege guidance
lives in the Peios Learn tree.

## SSH credentials

SSH public keys are credentials owned by lpsd, attached to principals rather
than read from `~/.ssh/authorized_keys`. `lps key add NAME FILE [LABEL]`,
`lps key list NAME`, and `lps key remove NAME ID` administer them. Select policy
explicitly with `lps policy NAME password|key|either|none|denied`; enrolling or
removing material never changes that policy. Password-only logon clients cannot
satisfy key-only policy.

PGSS and PSI retain header version 1, but LogonStart, Prompt and Assertion now
require their SSH/method fields. All consumers must be rebuilt together. The
unpublished principal-store layout is likewise replaced without migration or a
version bump. Reprovision disposable development stores explicitly. A malformed
or old store is an error, never permission to create a new one.
