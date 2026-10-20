---
title: Local Accounts
type: concept
description: How local accounts, groups, credentials, and machine policy fit together.
related:
  - peios/local-accounts/creating-an-account
  - peios/local-accounts/managing-credentials
  - peios/authentication-operations/diagnosing
---

Local accounts identify people and services known to this machine. The local
principal source is `lpsd`. It stores those accounts and checks their
credentials. Use `lps(1)` to administer the store through the daemon.

An account is one kind of principal: an identity that can receive access.
Groups collect principals so that access rules can name a group instead of
every member. Each local account and group has a security identifier (SID),
which remains the same when its name changes.

## Identity, credentials, and access

Three separate decisions determine a sign-in:

- **The account:** its name, SID, group memberships, and profile.
- **Its credentials:** the password or public keys it holds and the policy
  selecting which credentials it accepts.
- **Machine policy:** the privileges and integrity level that `authd`
  places on the resulting access token.

An access token records the identity and authority of a running process.
`lpsd` supplies identity information; `authd` grants the token. A source
cannot grant a privilege by adding it to an account's profile.

Changing a password and requiring that password are separate actions. For
example, setting a password on an account with the `none` credential policy
does not stop credential-free sign-in. Read [Managing
Credentials](~peios/local-accounts/managing-credentials) before changing the
permitted methods.

## Choose the right tool

Use the tool for the task you need:

- **Inspect or administer local accounts:** use `lps` as an administrator.
- **Sign in at a terminal:** use the managed console's `login(1)` client.
- **Integrate an application:** use the
  [authentication client library](~peios/authentication-client/conversations).
- **Diagnose the daemons:** start with
  [Diagnosing Authentication](~peios/authentication-operations/diagnosing).

`lps` does not edit the store file directly. `lpsd` checks the caller's token,
applies the request, and saves the result. An ordinary signed-in account does
not acquire administrative rights by running the command.

## Changes and existing sessions

An account change affects later requests and tokens. Removing a group,
changing a password, or stopping an account from signing in does not rewrite
access tokens already issued to it.

For retiring an account, distinguish stopping further sign-ins from ending
existing work. Follow [Retiring an
Account](~peios/local-accounts/retiring-an-account), and keep a working
administrator session while changing access.

For desktop administration, use [Principals
Manager](~peios/security-tools/principals-manager). Personal display names,
passwords, and keys are covered by [My
Settings](~peios/security-tools/my-settings). Those interfaces preserve the
same distinction between identity, credentials, and machine grants.
