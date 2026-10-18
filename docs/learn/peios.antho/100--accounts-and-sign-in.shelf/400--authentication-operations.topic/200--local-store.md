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
