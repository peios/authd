---
title: Managing Groups
type: how-to
description: Create a local group and change membership while preserving stable identities.
related:
  - peios/local-accounts/profiles-and-claims
  - peios/authentication/granting-access
---

Use a local group when several accounts need the same access. The group has
its own security identifier (SID), so its name can change without changing the
identity named by access rules.

## Before you start

Check these prerequisites:

- Use an administrator session with access to `lpsd`.
- Create the account `alice` before following this example.

## Create a group and add a member

Follow these steps:

1. Create the group with a description:

   ```sh
   lps group create developers "Local development team"
   ```

2. Add the account:

   ```sh
   lps group add alice developers
   ```

3. Check `lps group list` and `lps show alice`. Verify the group and the
   account's membership before using the group in an access rule.

4. Start a fresh session for `alice` to receive a token with the changed
   membership. Existing tokens retain their previous groups.

Creating the group does not grant access to any file or service. Assign that
access separately using the resource's security policy.

## Name a group unambiguously

`lpsd` resolves a group name, a qualified built-in name, or a literal SID.
Well-known names such as `Administrators` take precedence over local names,
and local groups cannot take those reserved names.

For automation or policy that must survive renaming, use the SID reported for
the group. In authd's registry policy, use a local group's literal SID; local
group names are not resolved there.

## Change or remove a group

Rename a group with `lps group rename developers engineers`. Its SID and
members remain. A description can be changed separately with `lps group
describe`.

To retire a group, first remove its memberships and replace any account's
primary-group assignment. `lps group delete` refuses a group that still has
members or is used as a primary group.

Before deletion, also review resources whose access rules name the SID.
Deleting the group does not rewrite those rules. Recreating its name allocates
a different SID and does not restore its access.

Read `lps(1)` for the full command syntax.
