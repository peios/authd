---
title: Signing in at a Console
type: how-to
description: Sign in through the terminal client and understand its fallback behavior.
related:
  - peios/local-accounts/sessions-and-account-changes
  - peios/authentication/diagnosing
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

Credential input uses buffers that erase their contents when released. This
also applies to partial input when reading a credential from a pipe fails.
The input source and any copies made by the caller remain their owners'
responsibility.

If the account's home is unavailable, `login` reports the failure and starts
in `/`. A successful sign-in does not prove that the recorded home or shell is
usable. A shell that cannot be executed causes the client to fail.

## Named attempts and automatic sign-in

A managed console can select an account before presenting a prompt:

- **A named account:** a refusal ends that attempt.
- **`--try`:** a nonfatal refusal falls back to an account prompt.
- **`--try-no-password`:** an attempt that offers no credential collection;
  an account needing credentials falls back to the ordinary prompt.

A fallback is explained if the attempt already displayed a credential prompt
or message. If nothing was displayed, the client moves directly to the
account prompt. An unavailable authority or a caller that cannot originate
the logon ends the attempt: asking for another account would not repair that
failure.

The preliminary account lookup uses read and write timeouts. If the client
cannot set those timeouts, it treats the lookup as unavailable and continues
without claiming that the account exists or is absent.

These options do not bypass authentication. `authd` and the principal source
still decide whether to grant a token. The `-f` authentication bypass is not
supported.

Credential-free automatic sign-in requires an account whose credential policy
permits it. Its use is not restricted to one console by the account policy
alone. Keep such accounts limited to deliberate development or live image use.

## Managed console services

The shipped console seed defines the primary `login-console` service and
additional prompts on `tty1`, `tty2`, and `tty3` when those devices exist.
Images choose whether to apply that seed. The primary console's precedence
prevents a second prompt taking the same terminal; first-boot setup takes
precedence over ordinary prompts.

Peinit fixes `/dev/console` to its selected terminal when loading the service
configuration. Switching virtual consoles does not move that service or lock
the session left behind. Its [terminal ownership and exit
rules](~peios/services-and-jobs/execution-environment#system-console-aliases-and-logout)
control cleanup and the next prompt.

System Settings changes the selected account through the console service's
arguments. The next service start uses the changed arguments; it does not
replace an already running session or change the account's credential policy.

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

The browser banner is printed once per invocation. It contains configured
addresses and the machine's certificate fingerprint, not a health check of
the browser service. A reachable address still needs the certificate check
described in [Signing in from a
Browser](~peios/signing-in/open-the-desktop).

For all flags and environment details, read `login(1)`. For failures, use
[Diagnosing Authentication](~peios/authentication/diagnosing).
