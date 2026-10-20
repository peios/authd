---
title: Registering a Principal Source
type: how-to
description: Configure a source identity and verify registration without widening its authority.
related:
  - peios/authentication/resolving-names
  - peios/authentication/service-startup
---

Register a principal source when authd must accept identities from that
service. A source connects to authd; the authority does not discover or trust
it merely because its process is running.

## Before you start

Check these prerequisites:

- Use an authorized machine-configuration route.
- Preserve an existing administrator session.
- Confirm that the source implements the Principal Source Interface and
  runs with the service identity named by its registration.

For the shipped local source, the supplied `lpsd-authd-registration.reg` seed
describes the expected configuration. Review that seed and `authd.regman`
before applying image policy.

## Configure and verify registration

Follow these steps:

1. Under `Machine\Software\Authd\Sources`, create or review the subkey for
   the source's service name. For the local source, that name is `lpsd`.

2. Verify that the service's token carries the corresponding service
   security identifier (SID).
   The subkey name identifies the permitted service; a source cannot
   establish its identity by claiming that name in a message.

3. Choose the source's numeric range and search order. If a fixed identity
   domain is required, configure its expected domain SID. Follow the types
   and constraints in the registry manual rather than copying another
   machine's generated domain.

4. Start or deliberately reconnect the source through service management
   after the authority is ready. Inspect its service status and diagnostics
   for an accepted registration.

5. Verify a lookup and a fresh permitted sign-in for an account from that
   source. A process that exists but has not registered cannot satisfy
   authentication requests.

For `lpsd`, readiness is reported after authd acknowledges registration. Its
service definition therefore depends on authd, not the reverse.

## Keep identity and membership authority distinct

A source's declared domain limits which identities it can assert. Numeric
range checks also prevent its relative identifiers from escaping into another
source's range.

`MayAssertForeignMemberships` concerns group membership assertions. It does
not authorize the source to authenticate identities in another domain. Grant
it only where the source is trusted to provide those memberships; the local
source has that role in the shipped configuration.

An absent or unusable Unix ID range does not cause authd to guess one. The
unconfigured projection uses the fallback identity number. Verify the
configured range before relying on numeric identity lookup.

## Changing a registered source

authd reads the allowlist during registration. A live registered source
retains its accepted domain, range, search order, and membership grants.
Editing or deleting its registry entry does not immediately revoke that
connection.

Plan reconnection when changing those settings. Reconnecting cannot change a
source domain already recorded during the running authd process's lifetime. A
source interruption can make identity queries and sign-ins unavailable, so use
an access route that does not depend on the source being changed.

The exact registry values belong to `Machine\Software\Authd\Sources` in
`authd.regman`; shared protocol requirements belong to the Principal Source
Interface specification.
