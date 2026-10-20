---
title: Reading Identities
type: how-to
description: Use libauth identity queries without losing field states or incomplete results.
related:
  - peios/authentication/resolving-names
  - peios/authentication-client/using-the-library
---

Use the identity operations in `libauth` when an application needs account or
group information. Native results retain details that a simple name string or
libc account record cannot express.

## Before you start

Prepare the client:

- Link the runtime and matching headers or Rust wrapper as described in
  [Using the Authentication Client](~peios/authentication-client/using-the-library).
- Use the system authority or an explicitly trusted endpoint.

## Look up an identity

Follow these steps:

1. Choose a name, binary security identifier (SID), or Unix identifier as
   the query key. Use the SID when your application already knows the
   identity and needs its display name.
2. Request the identity kind and fields the application needs. Avoid
   requesting every field for a name-only display.
3. Begin the lookup and drive its operation to completion using `step`
   and polling, or the blocking `wait` helper.
4. Inspect the identity outcome as well as the operation state. A
   completed exchange can still report no matching identity or an
   unavailable source.
5. Interpret each returned field's state. An empty value, a withheld
   value, and an absent field are not interchangeable.

In C, the begin function is `peios_auth_identity_lookup_begin()`. In Rust, use
`Client::lookup()` and read `Operation::identity()` after completion. The
public header documents the corresponding request and result types.

## Enumerate a list

Follow these steps:

1. Start an enumeration for principals or groups with an empty cursor.
   Select a group only when requesting that group's members.
2. Present or collect the returned records while preserving their SIDs.
3. Retain the response's incomplete-source information. A partial list
   must not be presented as proof that omitted identities do not exist.
4. If the next cursor is nonempty, pass its bytes back unchanged with the
   same query parameters. Continue even when a page contains no records.
5. Stop only when the next cursor is empty or an error prevents progress.

Do not parse the cursor, derive one from the last name, or assume that every
source supports complete enumeration.

## Check the result

Exercise the application's handling of an unknown identity, an unavailable
authority, a withheld field, and an incomplete enumeration. The interface must
preserve those differences instead of collapsing them into an empty list or an
anonymous account.

C result views borrow the operation. Copy data needed after its next mutable
call or destruction. The Rust wrapper returns owned result data.
