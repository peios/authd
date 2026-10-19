# authd

The authd repository provides Peios authentication, local account storage,
terminal sign-in, identity lookup, and the public authentication client
library. The authority issues access tokens; principal sources verify
credentials and supply identity information.

## Components

The repository builds these programs and libraries:

| Component | Role | Installed interface |
|---|---|---|
| `authd` | Authentication authority and token issuer | `/usr/sbin/authd` |
| `lpsd` | Local accounts, groups, and credential verification | `/usr/sbin/lpsd` |
| `lps` | Local account administration | `/usr/bin/lps` |
| `login` | Terminal sign-in and shell startup | `/usr/bin/login` |
| `nss` | Account lookup for libc callers | `libnss_peios.so.2` |
| `libauth` | Public C authentication client | `libauth.so.1`, `<peios/auth.h>` |
| `peios-auth` | Rust bindings to the shared client library | Rust crate |

Internal crates provide the wire formats (`auth-core`), policy evaluation
(`auth-policy`), shared C layouts (`auth-abi`), locale preferences
(`session-preferences`), and terminal input (`terminal-input`).

## Build and test

Use the checked-in Bazel wrapper on x86-64 Linux. The client software
development kit (SDK) does not require the Peios kernel SDK:

```sh
./bazel build //:sdk
./bazel test //libauth:tests //peios-auth:client-test //:abi-test
```

The output archive is `bazel-bin/auth-sdk.tar.gz`. For daemon builds, all
tests, native toolchains, and package assembly, follow
[Building Authentication](docs/building.md).

The default configuration produces Linux development artifacts. Native
Peios builds use `--config=peios` with a declared SDK and installed Peios
Rust toolchain. Signing, publication, image policy application, and runtime
qualification are separate release steps.

## Documentation

Read the component guides in
[Accounts and Sign In](docs/learn/peios.product/100--accounts-and-sign-in.shelf).
They cover local accounts, credentials, terminal sign-in, policy, service
operation, and client development.

The documentation sources have distinct roles:

- [Learn guides](docs/learn): concepts and practical tasks, merged into the
  shared Peios collection.
- [Man pages](docs/man): command and daemon references.
- [Registry manual](docs/authd.regman): authentication and source policy.
- [Authority events](docs/authd.evman) and [source events](docs/lpsd.evman):
  canonical event definitions.
- [Public C header](libauth/include/peios/auth.h): client signatures,
  ownership rules, and application binary interface (ABI) contract.

Build the guides with a Trail version that supports root anthologies and
recursive merges:

```sh
trail lint docs/learn
trail build docs/learn --strict
```

Panorama includes this tree through its documentation merge configuration.
Shared protocol specifications and other components' guides remain in the
central documentation tree.

## Package policy

`./bazel build //:packages` produces all 16 packages as a content-addressed
blob and manifest store in `bazel-bin/packages.store`. Package definitions
live under `packages/definitions/`.

Registry seeds under `registry.d/` are inert until image or administrator
policy applies them. Installing a package must not silently authorize a
principal source. The credential-free live-image administrator bootstrap is
an optional package, separate from the production local source.

Use the matching store-format and client-compatibility guidance before
replacing an installed daemon. Do not delete an unreadable credential store
to make it start; a fresh store creates different local identities.
