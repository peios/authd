---
title: Creating an Account
type: how-to
description: Create a local account, verify its profile, and check a fresh sign-in.
related:
  - peios/local-accounts/managing-groups
  - peios/local-accounts/managing-credentials
  - peios/signing-in/using-a-console
---

Create an account with `lps` when someone needs an identity held by this
machine. Account creation saves the identity and profile; the home directory
is prepared separately at sign-in.

## Before you start

Check these prerequisites:

- Use a session with active `Administrators` membership or authorized
  `LocalSystem` access.
- Confirm that `lpsd` is ready.
- Keep an existing administrator account available. These instructions
  do not provision a machine's first account.

## Create and inspect the account

Follow these steps:

1. Run the interactive account creator:

   ```sh
   lps add alice
   ```

   Replace `alice` with the account name. Supply the requested profile and
   password, review the proposed account, and confirm it. Leave additional
   groups empty unless the account needs them.

2. Inspect the saved account:

   ```sh
   lps show alice
   ```

   Check its state, credential policy, groups, home, and shell. An ordinary
   account defaults to `/home/alice` and `/bin/sh`. No matching per-user
   group is created automatically.

3. Keep your administrator session open and sign in as `alice` through a
   separate permitted console or client. Check that the intended shell
   starts and the home directory is accessible.

The final check tests the complete sign-in route. A saved account alone does
not prove that a client can reach the authority or collect its required
credentials.

## Administrator accounts

If the account must administer the machine, request the membership during
creation:

```sh
lps add alice --group Administrators
```

This grants access to local account administration. The separate [machine
policy](~peios/authentication/granting-access) determines the
privileges on tokens issued to that group.

## Home directories

`lps` records the home path without creating the directory. When `authd`
grants a logon with a home path, it creates a missing home with access for the
account, `LocalSystem`, and administrators. The descriptor blocks inherited
grants from widening that access. The parent directory must already exist;
authd creates the missing leaf, not a parent tree.

The shipped authd service retains `SeRestorePrivilege` to assign the new
home's owner and group. Removing it from the service's `RequiredPrivileges`
can leave a new directory inaccessible to its intended owner. Inspect the
authority's diagnostics and repair the descriptor deliberately; retrying a
sign-in does not take over an existing directory.

An existing directory is left alone. Changing the recorded home does not move
files or repair its ownership. If home preparation fails, the logon can still
succeed; `login` reports an inaccessible home and starts in `/`.

## The first account

On a machine with no store, `lpsd` creates an empty store and a machine
domain. It does not invent an administrator or a password. An image must
provide an authorized first-account setup route.

An installed image can use [first-boot
setup](~peios/first-boot/completing-setup). A custom image must enable that
service or provide another authorized provisioning route. A service that
uses `lps` to provision an account starts after lpsd is ready; an early boot
script running before the services cannot use its socket.

The optional `dev.peios.authd-live-account` package supplies a development
bootstrap. Its credential-free administrator is a deliberate image policy
choice, not a default for installed systems. Do not use that package to solve
ordinary account creation on a production machine.

For exact creation options, read `lps(1)`.
