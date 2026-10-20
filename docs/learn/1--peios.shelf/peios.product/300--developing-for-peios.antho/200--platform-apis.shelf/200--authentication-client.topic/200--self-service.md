---
title: Self-Service Operations
type: concept
description: Choose account, credential, and session operations without acquiring administrative authority.
related:
  - peios/local-accounts/managing-credentials
  - peios/authentication-client/using-the-library
---

The authentication client library supports operations on the caller's own
account without granting local account-administration rights. The daemon
identifies the caller from the connected process's token.

## Account details and display names

Use `Client::own_account()` or the corresponding C operation to read the
caller's local account. The result includes its display name, credential
policy, whether a password exists, and enrolled public-key information. It
never contains a plaintext password or its verifier.

Use `Client::set_display_name()` to change the caller's presentation name. The
request does not accept a target account name, and a display name does not
change the account's security identifier (SID) or sign-in name.

These operations use lpsd's self-service socket. A caller whose account is not
held by the local source cannot use that socket to administer a different
source's account.

## Credential changes need proof

Password and key changes use credential conversations through authd. The local
source asks the caller to prove an accepted current password. Opening the
socket or possessing a session token alone is insufficient.

Follow the same prompt handling as a logon: display messages, collect only
supported credential types, and answer the current round. An account without a
usable password for this proof needs an administrator's help.

Self-service key removal selects a key by its SHA-256 fingerprint. The
administrative `lps key remove` command selects by key ID instead. Use the
identifier required by the interface you are calling.

## Session actions are checked separately

`Client::may_end_session()` queries whether the caller can request an action.
`Client::end_session()` requests the action and checks permission again. A
successful query does not guarantee a later request will succeed.

Warn the person before ending a session because running programs can lose
unsaved work. The requesting program can be among the processes stopped. Read
[Sessions and Account
Changes](~peios/local-accounts/sessions-and-account-changes) for the
result's limitations.

## Submitted changes can have uncertain outcomes

A transport error after submission can leave a change's outcome unknown. The
public error exposes `outcome_unknown`; preserve that distinction in the user
interface and inspect state before offering a retry.

Canceling or destroying the operation releases client resources. It does not
undo a request the daemon has already received. The library does not
automatically retry mutations.

For full signatures and ownership rules, use `<peios/auth.h>`. Local
administrator operations are a separate interface; they are not part of the
public self-service library.
