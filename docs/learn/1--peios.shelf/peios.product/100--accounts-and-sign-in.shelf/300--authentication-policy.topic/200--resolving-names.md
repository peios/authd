---
title: Resolving Names
type: concept
description: How authd resolves account names and preserves unavailable results.
related:
  - peios/authentication-client/reading-identities
  - peios/authentication-policy/registering-a-source
---

`authd` resolves names, security identifiers (SIDs), and Unix identifiers
through its registered principal sources. This gives clients one place to ask
for the identity behind a name or number.

## Names are not durable identifiers

An account name can change or exist in more than one source. A SID names the
identity itself. Store that SID when an application must remember which
principal it authorized, and resolve a name for display.

For an unqualified name, authd uses configured source search order. The first
matching source wins. A source that is unavailable can stop the lookup; authd
does not silently choose a different person from a later source to hide the
outage.

The name fields returned by this implementation use canonical bare names. Do
not construct a realm-qualified name and assume it is accepted merely because
a protocol field is named `qualified_name`.

## Shadowed names

Source order is explicit machine policy, not connection order. Lower
`SearchOrder` values are consulted first; source names break ties. Changing
that order can make the same bare name refer to a different SID.

After a successful logon, authd can warn that a later source also owns the
entered name. The check uses identity queries without credentials and does
not alter the granted token. Its deadline is shared across the later sources;
a source that cannot answer makes the check inconclusive. Absence of a
warning is not proof that a name is unique.

Investigate a warning by comparing the sources and SIDs. Do not remove an
account merely because its name matches an account in another source.

## Preserve failure meaning

A lookup can report that an identity does not exist, that a source could not
answer, or that the request was refused. These results require different
responses. An unavailable source is not evidence that an account has been
deleted.

For example, an application should keep an unresolved SID visible while
reporting a lookup failure. Replacing it with a different local account or
recording permanent absence would change its meaning.

## Numeric identities and groups

Sources report relative Unix identifiers. authd applies each source's
configured range, checks its bounds, and returns the effective identifiers to
clients. Clients should not repeat that arithmetic themselves.

Some well-known groups describe a session rather than a stored membership
list. An empty member listing does not mean no token can carry that group.
Likewise, a group without a Unix group identifier cannot be represented as an
ordinary numeric supplementary group.

Recorded memberships can be enumerated when their source supports it.
Groups such as `Everyone` and `Authenticated Users` are added by token
derivation rather than stored as member lists. Groups such as `Interactive`
and `Network` describe a logon, so the same account can carry different groups
in two sessions. A static account-membership list cannot reconstruct every
group on a running process's token.

## Native and libc clients

Native applications use the identity operations in `libauth` or its
`peios-auth` Rust wrapper. They can inspect unavailable outcomes, withheld
fields, and incomplete enumeration results.

The repository's name service switch (NSS) module translates libc account
queries into requests on `/run/ident.sock`. It does not open the local
principal store or provide an independent fallback database. Its libc result
distinguishes an unavailable authority from an unknown account.

authd performs live source queries rather than keeping an identity cache. Do
not assume an outage can be served from a previous successful lookup. For
client handling, read [Reading
Identities](~peios/authentication-client/reading-identities).
