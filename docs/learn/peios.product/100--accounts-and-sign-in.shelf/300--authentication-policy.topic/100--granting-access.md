---
title: Granting Access
type: concept
description: How authd combines machine policy with authenticated identity when issuing tokens.
related:
  - peios/authentication-policy/registering-a-source
  - peios/authentication-operations/diagnosing
---

`authd` reads local machine policy to decide which privileges, integrity
level, owner, and default access rules a token receives. An account's
principal source supplies identity and group membership, not these grants.

The policy lives under `Machine\Generic\Authn\Policy`. The registry manual for
that path owns the value types, defaults, and combination rules. Use
`authd.regman` when editing it.

## Match policy to an identity

Each principal-policy subkey names a well-known identity or a literal security
identifier (SID). Use the SID for a local account or group. `authd` does not
resolve a local group name while evaluating policy.

A record named `Administrators` refers to the built-in group. The spelling
`BUILTIN\Administrators` cannot be one subkey name because the backslash
separates registry keys.

Avoid two subkeys that resolve to the same SID. Their grants can combine,
while conflicting scalar choices can depend on evaluation order. Keep one
record per identity and investigate authd's duplicate-record warnings.

## Start from the complete policy

An existing policy key is the complete source of privilege grants. Its records
are not merged with an invisible set of compiled grants.

If the whole key is absent, authd uses a small compiled floor granting
`SeChangeNotifyPrivilege` to `Everyone`. If the key exists but cannot be read,
authd grants nothing from that fallback. Deleting a policy key is therefore
not a safe way to remove all access.

The shipped `authd-policy.reg` supplies explicit machine defaults. It is inert
until image policy applies it. Installing the file does not prove that the
machine has those values.

## Separate the three gates

A sign-in client must pass more than the account's credential check:

1. The socket's security descriptor must allow it to connect.
2. Its own identity must be allowed to originate the requested logon type.
3. The target account and principal source must allow that logon and its
   credentials.

The `LogonTypes` value in a principal-policy record controls what the
requesting process can originate. `lps logon-types` controls the account being
signed in. Changing one does not change the other.

Originator policy matches the peer token's **user SID**, not its group
memberships. A service SID used as the user of a virtual service account can
match; merely carrying the SID as a group is insufficient. SYSTEM has an
explicit originator allowance.

## Apply changes at the right boundary

Different settings have different refresh points:

| Setting | When authd uses it | Effect on existing state |
|---|---|---|
| Token grants | When issuing a token | Existing tokens retain their grants |
| `SessionEndSecurity` | Each session-end permission check | A later request is checked again |
| `LogonSocketDescriptor` | Authority startup | An existing socket is not restamped by a registry edit |
| Source registration policy | Source registration | A connected source retains its accepted configuration |

Keep a verified administrator route while changing policy. Validate a fresh
request before assuming a registry edit has taken effect. For source
configuration, read [Registering a Principal
Source](~peios/authentication-policy/registering-a-source).
