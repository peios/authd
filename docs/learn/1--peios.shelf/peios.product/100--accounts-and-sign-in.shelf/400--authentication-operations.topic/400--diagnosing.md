---
title: Diagnosing Authentication
type: how-to
description: Locate failures in service readiness, credentials, policy, and session startup.
related:
  - peios/authentication-operations/audit-events
  - peios/authentication-policy/granting-access
---

Diagnose the stage that failed before changing account or machine policy. A
denied credential, a refused socket connection, and an unavailable principal
source are different failures.

## Before you start

Prepare the investigation:

- Keep a working administrator session open.
- Record the operation, account, client, and error text. Do not copy
  passwords or private keys into a log.
- Use read-only checks before restarting a service or changing policy.

## Locate the failing stage

Follow these steps:

1. Check whether the authority and local source are ready:

   ```sh
   svctl status authd
   svctl status lpsd
   ```

2. From an authorized administrator session, inspect the target account
   with `lps show <name>`. Check its state, logon types, credential policy,
   and available credential material.

3. Compare the failing operation with the symptom table. Inspect the
   relevant service diagnostics or event record before making a change.

4. Make one justified change through the appropriate interface, then
   repeat a fresh request through the original client.

## Match the symptom

The symptom identifies a useful next check:

| Symptom | Check | Do not infer |
|---|---|---|
| `lps` cannot connect | lpsd readiness and the admin socket's descriptor | Unix mode bits alone determine access |
| `lps` refuses the caller | The caller's active administrator membership or SYSTEM identity | Executing an administration command grants its rights |
| Sign-in source unavailable | Registration, source readiness, and connection diagnostics | The account does not exist |
| Credentials refused | Account state, permitted logon type, policy, and supplied proof | Every refusal reveals whether the name exists |
| Key works but console fails | Whether the account is key-only | Terminal `login` supports SSH key proof |
| Sign-in succeeds but home fails | Recorded path, parent directory, owner, and descriptor | Another sign-in will repair an existing directory |
| Registry edit appears ineffective | That setting's refresh boundary | Every setting is reread on each request |

## Separate connection permission from operation permission

Reaching `/run/logon.sock` does not authorize a client to originate every kind
of logon. The authority checks the connected caller and the requested
operation. Similarly, reaching the self-service socket does not authorize an
operation on someone else's account.

For originator refusals, inspect [Authentication
Policy](~peios/authentication-policy/granting-access). For registration
failures, inspect [Registering a Principal
Source](~peios/authentication-policy/registering-a-source).

## Handle failed changes carefully

If a connection is lost after an account change was submitted, inspect the
state before retrying. The operation might already have succeeded. If the
daemon reports a storage failure, preserve its diagnostics and investigate the
filesystem before making further account changes.

Do not delete the principal store to repair a startup failure. Read [The Local
Principal Store](~peios/authentication-operations/local-store) for why
replacing it changes the machine's identities.

## Check the result

A successful status query or account listing is only one part of the check.
Verify a fresh sign-in through the intended route and confirm the resulting
access before closing the administrator session used for repair.
