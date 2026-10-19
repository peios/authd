---
title: Authentication Events
type: concept
description: Use authority and source events to distinguish credential checks from granted logons.
related:
  - peios/authentication-operations/diagnosing
  - peios/terminal-sign-in/sessions-and-account-changes
---

Authentication events record what the authority and local source decided. They
complement diagnostic logs: a source checking a credential and an authority
delivering a token are separate outcomes.

## Follow the decision that matters

Use the event belonging to the stage you are investigating:

- **`authd.logon.attempted`:** the authority's outcome for a logon
  conversation, including whether a granted token reached the client.
- **`authd.service.attested`:** a request for a service identity and the
  authority's decision.
- **`authd.session.ended`:** the outcome of a session-end request.
- **`lpsd.credential.verified`:** the local source's credential check.
- **lpsd account, group, and credential events:** changes to the local
  store and credential material.

A successful credential check alone does not prove that the authority granted
a logon or that the client started a usable session. Inspect the authority
result and client diagnostics as well.

## Use the catalog for exact fields

The canonical event definitions are `authd.evman` and `lpsd.evman`, shipped
under `/usr/share/evman/`. Read them with `evman` for exact fields, tiers, and
outcome meanings. The source copies live under `docs/` in the authd
repository.

For example, the authority's logon event omits the proposed account name on
failure. Input supplied by a caller is not an authenticated identity. On
success, the event identifies the granted principal by its security identifier
(SID).

## Interpret incomplete evidence

An authority refusal, a transport failure, and a token that could not be
delivered are different outcomes. Preserve the recorded reason rather than
converting all of them into an incorrect-password count.

Event absence is not proof that nothing happened. Access to records, emission
policy for configurable tiers, and collection failures can affect what you can
see. Check service diagnostics when a required record could not be emitted.

Do not add credential values to diagnostic messages to investigate a failure.
Account and session identifiers, operation names, and the documented outcome
fields provide the correlation data.
