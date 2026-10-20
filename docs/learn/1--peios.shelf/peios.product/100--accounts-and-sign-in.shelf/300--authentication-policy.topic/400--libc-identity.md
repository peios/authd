---
title: POSIX Account Lookup
type: concept
description: How the authd NSS module presents Peios identities to POSIX account APIs.
related:
  - peios/authentication-policy/resolving-names
  - peios/authentication-client/reading-identities
---

`libnss_peios.so.2` translates libc account queries into requests to authd's
`/run/ident.sock`. An application using `getpwuid` or `getgrnam` receives a
POSIX record derived from the same authority used by native identity clients.
The module does not open lpsd's credential store.

## A limited representation

A `struct passwd` has no field for token claims. A numeric identifier does
not carry a domain name. A group's empty member list cannot distinguish every
reason that membership is not enumerable. Native applications needing these
distinctions use the [identity client
API](~peios/authentication-client/reading-identities).

Groups derived from a logon, such as `Interactive`, have no ordinary static
member list. Unnumbered groups are omitted from supplementary numeric groups
rather than all being mapped to the fallback identity. Stored account
memberships do not describe every group on a running token.

## Preserve lookup failures

The module distinguishes a record, a missing identity, a temporary source
failure, and an unavailable authority. A temporary failure is not a cached
answer that the account does not exist. If names stop resolving, inspect the
authority and source state before changing accounts.

Before the authority is available, an application can have a valid numeric
identity without a resolved display name. Display the number rather than
requiring a name to perform early-boot work.

Enumeration can be incomplete when a source does not enumerate. A short
`getent passwd` result does not establish that every other account is absent.
Native callers can retain the response's incomplete-source information.

## Requests and process lifetime

A normal lookup asks for the fields needed by the libc call in one request.
The authority resolves source ranges and group names; the module does not
reconstruct them through a separate lookup for every member.

The client opens connections for individual lookups instead of sharing one
across processes that can fork. Enumeration has its own cursor lifecycle.
There is no independent identity cache or fallback account database in the
module.

Peios' libc package fixes account lookup to this provider. Adding another
identity source is an [authority registration
operation](~peios/authentication-policy/registering-a-source), not an
`nsswitch.conf` entry that bypasses the authority's search order.
The package's libc integration and the authd module are both required.
Installing the module on another Linux system does not change that system's
libc policy.
