# authd

Peios' authentication authority — the process that turns "someone proved who they are" into a KACS token and a logon session. It is the only general-purpose minter of identity on a running system.

Closest prior art is Windows' LSA.

## What is here

| Crate | Installs | What it is |
|---|---|---|
| `authd` | `/usr/sbin/authd` | The authority. Holds `SeCreateTokenPrivilege`, runs at `PeiosTcb`, listens on `/run/logon.sock` (PGSS Logon) and `/run/psi.sock` (PSI). |
| `lpsd` | `/usr/sbin/lpsd` | The local principal source. Owns this machine's accounts and every local credential verifier. Runs below authd and holds none of its privileges. |
| `lps` | `/usr/bin/lps` | Administers `lpsd`'s store over `/run/lpsd/admin.sock`. A client with no state and no privilege of its own. |
| `login` | `/usr/sbin/login` | A PGSS Logon client. Collects a credential, receives a token, installs it, execs a shell. |
| `libauthd` | — | The wire formats: PGSS Logon, PSI, and LPS. |
| `libtty` | — | Terminal handling for credential collection. |

## The shape

Three ideas carry most of the design.

**The authority mints; sources assert.** A principal source verifies credentials and says *who someone is* — SID, memberships, POSIX identifiers, where their session starts. It cannot mint a token, grant a privilege, or create a session, because the protocol it speaks gives it no way to say any of those things. A completely compromised source can lie about the accounts it holds, and that is the whole of what it can do.

**Sources are processes, never in-process plugins.** This is the LSA authentication-package and Linux PAM failure mode, and it is the single thing this design most deliberately avoids. A defect in credential parsing — the code most exposed to hostile input — must not become a compromise of the code that mints tokens.

**How much this machine trusts you is local.** Privileges and integrity are not asserted by anyone; they come from a per-principal policy record in the registry that authd reads at every logon. A directory can say you are in `Domain Admins`; whether that carries `SeLoadDriverPrivilege` *here* is this machine's answer.

## Protocols

- **PGSS Logon** (PSD-012) — the standard a Peios authority must speak. `/run/logon.sock`.
- **PSI** (PSD-013) — how principal sources federate identity to the authority. Not a conformance requirement; specified so third parties can write sources. `/run/psi.sock`.
- **LPS** — `lpsd`'s administrative protocol, spoken only by `lps`. `/run/lpsd/admin.sock`.

## Building

Needs `libpeios` and the PKM uapi headers via `pkg-config`:

```sh
cargo test
```

Packaged with pekit; `pekit.toml` carries the build and the registry seeds it offers (`registry.d/`). Seeds are *offered*, not applied — an image opts in via `[registry] autoapply`, so installing a package never silently grants it the right to assert identity.

## Documentation

User-facing documentation lives in the Peios `learn/` tree, not here — see *Managing local principals*, *Privileges*, and *Logon sessions*.
