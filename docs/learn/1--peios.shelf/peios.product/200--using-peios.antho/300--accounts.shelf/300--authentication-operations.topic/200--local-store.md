---
title: The Local Principal Store
type: concept
description: How lpsd preserves account identities and handles missing or unreadable state.
related:
  - peios/local-accounts/retiring-an-account
  - peios/authentication-operations/diagnosing
---

`lpsd` keeps local identities in `/var/state/lpsd/principals`. The store
contains the machine's domain identifier, account and group records,
credential material, and allocation state. Losing it means losing the
identities that existing access rules name.

## Identity survives names

The machine domain is generated when a missing store is provisioned. Accounts
and local groups receive relative identifiers from one counter, starting at
1000. Deleted identifiers are not reused.

A local security identifier (SID) combines the domain and relative identifier.
Recreating the same account name in a fresh store therefore does not restore
the old SID or the access granted to it.

Well-known group identities are defined separately. The store records
memberships in them rather than inventing a local copy of their identity.

Do not bake a provisioned store into an image intended to create independent
machines. Copying the store copies its domain and account identities; giving
the machines different hostnames does not change those SIDs.

The stored Unix identifiers are relative. authd applies the source's
configured numeric range when issuing tokens and answering lookups. `lps`
displays the effective numbers. A dash in its UID column indicates that no
usable source range was assigned; it is not evidence that the account lacks
a SID.

## Credential material stays protected

The store holds password verifiers rather than plaintext passwords, along with
enrolled public keys and credential policies. Password verifiers are still
sensitive: a stolen copy can be used to guess passwords offline.

The lpsd virtual service account owns the credential file. Its protected
discretionary access control list (DACL) grants full access to that service
identity and SYSTEM. Administrator membership alone has no direct grant.

Do not widen the descriptor to make an account-management script work. Use the
daemon's administrative interface, which checks the caller and keeps a single
writer responsible for the store.

The password verifiers use Argon2id and retain their cost parameters. A
change to the parameters for newly set passwords does not rewrite existing
verifiers. Privileges and integrity levels are absent from the store: those
come from [machine policy](~peios/authentication-policy/granting-access).

## Administrative requests

`lps` reaches `/run/lpsd/admin.sock`; it never edits the file. The socket's
descriptor and the daemon's peer-token check admit SYSTEM and enabled
Administrators membership. A deny-only administrator group does not grant
access. Making the Unix mode more permissive does not repair a KACS denial.

Each connection carries one administrative request and its reply. The daemon
checks the peer before reading a request and bounds reads and writes. For a
refused connection, inspect the socket descriptor and the caller's token
before changing either service configuration or account data.

Use the identity interface for general account lookup and the [self-service
interface](~peios/authentication-client/self-service) for the caller's own
account. These do not require widening the administrative socket. The public
`libauth` client does not expose local administrative operations; `lps` and
the repository's administrative client implement that separate protocol.

The [Local Principal Administration
specification](~specifications/local-principal-administration/scope-and-roles)
defines message formats. Event names and fields belong to `lpsd.evman`; a
successful no-op is not evidence that a change event will be emitted.

## Replacement and failures

Changes replace the whole store. lpsd creates a protected temporary file,
writes and synchronizes it, renames it over the old file, and synchronizes the
containing directory. Protection is established before credential bytes are
written.

A successful administrative reply follows the save. A lost reply leaves the
caller uncertain whether a submitted change took effect. Read back inspectable
state before repeating it.

A storage error also needs investigation. In particular, failure to
synchronize the directory after replacement can leave changed on-disk state
even though the request reports failure. Do not assume every reported failure
proves that both memory and disk retain the previous state. Stop further
administrative changes and investigate the storage failure before relying on
either view.

## Format compatibility

The authd 0.0.24 source reads store formats 4 and 5 and writes format 5.
Format 4 loads with empty group descriptions; the next successful change
writes format 5. This is a specific compatibility range, not a promise that
every release can read its predecessor's store.

Check format compatibility before replacing lpsd with an older build. Preserve
the original store and its security metadata during any planned upgrade or
recovery.

## Missing and unreadable are different

A missing store means an unprovisioned machine. lpsd creates a domain and an
empty store, without creating an account.

An existing store that is corrupt, unreadable, or in an unsupported format
causes startup to fail. lpsd does not silently replace it with an empty store.
Do not delete the file to clear that error: preserve it for diagnosis and
recovery.

The daemon and state paths are documented in `lpsd(8)`.
