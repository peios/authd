---
title: Using a Console
type: how-to
description: Sign in through the terminal client and understand its fallback behavior.
related:
  - peios/terminal-sign-in/sessions-and-account-changes
  - peios/authentication-operations/diagnosing
---

The `login(1)` client collects credentials at a terminal, receives a token
from `authd`, installs it, and replaces itself with your shell. Use the
managed console provided by the system; running `login` does not grant an
ordinary process permission to originate a logon.

## Sign in

Follow these steps:

1. At the console's account prompt, enter your account name.
2. Answer the credential prompts. Password input is not echoed.
3. Check that the intended account's shell starts in its home directory.

The terminal client supports password prompts. Accounts restricted to SSH
public-key authentication need a client that supports that exchange.

If the account's home is unavailable, `login` reports the failure and starts
in `/`. A successful sign-in does not prove that the recorded home or shell is
usable. A shell that cannot be executed causes the client to fail.

## Named attempts and automatic sign-in

A managed console can select an account before presenting a prompt:

- **A named account:** a refusal ends that attempt.
- **`--try`:** a nonfatal refusal falls back to an account prompt.
- **`--try-no-password`:** an attempt that offers no credential collection;
  an account needing credentials falls back to the ordinary prompt.

The preliminary account lookup uses read and write timeouts. If the client
cannot set those timeouts, it treats the lookup as unavailable and continues
without claiming that the account exists or is absent.

These options do not bypass authentication. `authd` and the principal source
still decide whether to grant a token. The `-f` authentication bypass is not
supported.

Credential-free automatic sign-in requires an account whose credential policy
permits it. Its use is not restricted to one console by the account policy
alone. Keep such accounts limited to deliberate development or live image use.

## Session preferences

Without `-p`, the client constructs the shell environment from the granted
profile. It sets the account and home variables, sets `PATH` to `/bin`, and
preserves or chooses the terminal type.

Locale preferences come from the machine and the granted account's user
registry settings. The client removes inherited `LC_ALL` and `LANGUAGE` and
refreshes locale preferences even with `-p`. Locale changes apply to later
sessions, not programs that already inherited an environment.

The managed `--console` mode also prepares terminal input and waits for
first-boot setup to finish before accepting credentials. Browser-address
information is optional; its absence does not prevent terminal sign-in.

For all flags and environment details, read `login(1)`. For failures, use
[Diagnosing Authentication](~peios/authentication-operations/diagnosing).
