---
title: Retiring an Account
type: how-to
description: Stop further sign-ins, handle active sessions, and decide whether to delete an account.
related:
  - peios/local-accounts/sessions-and-account-changes
  - peios/authentication/local-store
---

Retire an account by stopping further sign-ins before deciding whether to
delete its identity. Keeping the account preserves the security identifier
(SID) used by its files and other access rules.

## Before you start

Prepare access and active work:

- Use an administrator session other than the account being retired.
- Keep another verified administrator route available.
- Save work in sessions that must end. Ending a session can stop
  applications before they save their work.

## Stop further sign-ins

Follow these steps:

1. Inspect the account with `lps show alice` and record its SID and groups.
2. Stop it from signing in:

   ```sh
   lps disable alice
   ```

3. Inspect `lps show alice` again to confirm the saved state.
4. If active access must stop, use a session-management client to end its
   existing sessions. Account state changes do not revoke issued tokens.

To restore the account later, use `lps enable alice`, inspect its policy, and
verify a fresh sign-in.

## The last-administrator guard

`lpsd` refuses several changes to the last account it counts as an active
administrator. These include deletion, stopping sign-in, removing its
administrator membership, and leaving it no permitted credential material.

The guard counts accounts that are turned on and hold administrator
membership. It does not prove that another administrator has usable
credentials, permitted logon types, or a reachable sign-in route. It also does
not validate the whole machine's registry policy. Verify an alternate route
yourself.

## Delete only after reviewing ownership

If the identity must be removed permanently, review files and access rules
that name its SID before running `lps remove alice`.

The account's identifier is never reused. Creating another `alice` does not
restore the deleted identity, its group membership, or its access. Deleting
the account also does not remove its home directory.

Read [Sessions and Account
Changes](~peios/local-accounts/sessions-and-account-changes) for the limits
of ending active access.
