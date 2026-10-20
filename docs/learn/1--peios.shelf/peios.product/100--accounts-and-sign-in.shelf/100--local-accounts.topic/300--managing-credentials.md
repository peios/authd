---
title: Managing Credentials
type: how-to
description: Set passwords and public keys without confusing stored credentials with policy.
related:
  - peios/local-accounts/retiring-an-account
  - peios/terminal-sign-in/sessions-and-account-changes
---

Manage an account's credential material and its permitted methods as two
separate steps. Adding a password or public key does not change which methods
`lpsd` accepts for that account.

## Before you start

Prepare an alternate access route:

- Use an administrator session for these `lps` commands.
- Keep a working administrator route open while changing another route.
  Verify a fresh sign-in before closing it.

Inspect the account first:

```sh
lps show alice
lps key list alice
```

Replace `alice` with the account name. Credential policy selects the accepted
proof:

| Policy | Accepted proof | Required material |
|---|---|---|
| `password` | Password | Stored password verifier |
| `key` | SSH public-key proof | Enrolled public key |
| `either` | Password or SSH public-key proof | Material for the chosen method |
| `none` | No credential | None |
| `denied` | No accepted method | None |

Missing material does not cause a fallback to another method. The client and
authority also constrain which method and kind of logon are allowed. The
terminal `login` client cannot perform an SSH public-key exchange.

## Require a password

Follow these steps:

1. Set the password through the prompt, keeping it out of command history:

   ```sh
   lps password alice
   ```

2. Select password authentication:

   ```sh
   lps policy alice password
   ```

3. Inspect `lps show alice`, then verify a fresh sign-in with that password.

Both steps are needed when replacing `none` policy. Setting the password alone
leaves credential-free sign-in permitted.

## Add a public key

Follow these steps:

1. Enroll the public key file:

   ```sh
   lps key add alice /path/to/alice.pub workstation
   ```

   Replace the path with a public key file. `workstation` is a descriptive
   label. Do not supply a private key. Supported keys and input restrictions
   are documented in `lps(1)`.

2. Inspect `lps key list alice` and compare the fingerprint with the key
   you intended to enroll.

3. If password access must remain available while checking the key, select
   both methods:

   ```sh
   lps policy alice either
   ```

4. Verify a fresh connection through an SSH service configured to use this
   authority. Only after that check, use `lps policy alice key` if the
   account must accept keys exclusively.

Enrolling a key does not configure an SSH server or make one reachable.

## Remove a key

Follow these steps:

1. Run `lps key list alice` and identify the key to remove.
2. Pass its listed key ID to `lps key remove alice <key-id>`.
3. Inspect the list again and verify the remaining sign-in route.

The administrative command takes the key ID, not its fingerprint. The public
library's self-service removal operation takes a fingerprint; do not
interchange the two interfaces.

Removing a key or changing policy invalidates pending SSH key proofs but does
not end existing sessions. Stopping active access is a separate [session
operation](~peios/terminal-sign-in/sessions-and-account-changes).

## Self-service changes

A person changing their own password or keys uses an authentication
conversation through `authd`, rather than the administrative socket. `lpsd`
requires an accepted current password for these operations. An account with
only a key, no credential, or no stored password needs an administrator's
help.

Application authors can use the [self-service client
operations](~peios/authentication-client/self-service).
