---
title: Authentication Services
type: concept
description: How the authority, local source, registry seeds, and service readiness fit together.
related:
  - peios/authentication-policy/registering-a-source
  - peios/authentication-operations/local-store
---

The authentication service set separates token creation from credential
storage. `authd` issues tokens, while `lpsd` owns local accounts and checks
their credentials. The service manager starts them from registry service
definitions.

## Readiness follows the protocol

The authority opens its client and source sockets before reporting ready. The
local source then connects to `/run/psi.sock`, registers, and waits for
acknowledgment before reporting its own readiness.

The shipped dependency points from `lpsd` to `authd`. authd does not wait for
every source before becoming ready, so authority readiness alone is not
evidence that a local account can sign in.

The service definitions and registration seed have distinct purposes:

| Seed | Purpose | Applied by |
|---|---|---|
| `authd-service.reg` | Start the authority with its required identity and privileges | Image or administrator policy |
| `authd-policy.reg` | Supply machine authentication-policy defaults | Image or administrator policy |
| `lpsd-service.reg` | Start the local source after the authority | Image or administrator policy |
| `lpsd-authd-registration.reg` | Permit the local source to register and define its range | Image or administrator policy |

These files are installed under `/usr/share/regim/`. Their presence does not
apply their contents. A machine missing a registration seed can run the
authority without accepting its intended principal source.

## Keep each service's authority narrow

authd runs with the authority needed to create tokens and establish their
security state. Its package also requires the appropriate signing tier. A
development binary that links successfully is not evidence that these runtime
requirements have been met.

lpsd uses a distinct virtual service account. It needs access to its store and
permission to emit audit events; it does not need token-creation or
token-installation privileges. Its store descriptor grants access to the lpsd
service identity and SYSTEM, not to every administrator.

`RequiredPrivileges` narrows the service token. It does not manufacture a
privilege that machine policy did not grant in the first place.

## Readiness is not a security-state handoff

The authority does not connect to a directory to fetch credentials. Sources
connect to it and verify credentials; local registry policy determines the
grants on the resulting tokens. A source's asserted identity is constrained
by its registration, including its domain and permitted foreign memberships.
A source trusted to assert an administrator membership can affect local grants
through that membership. Process separation does not make a compromised
source harmless.

The client receives a token and profile and starts its own session. authd does
not launch its shell or set up its terminal. Service attestation is a distinct
request made by the service manager.

Restarting authd interrupts new conversations but does not replace tokens
already held by processes. Kernel sessions survive while their token
references remain. Authority readiness does not certify that every source
has registered or that central access policies have been loaded: authd does
not distribute those policies.

## Inspect before restarting

Use service status and diagnostic output to distinguish an authority startup
failure from a source registration failure. Restarting either can interrupt
authentication requests. Keep a separate working administrator route while
investigating.

Read `authd(8)` and `lpsd(8)` for daemon behavior, then follow [Diagnosing
Authentication](~peios/authentication-operations/diagnosing) for common
symptoms. Contributor build instructions live in the repository's
`docs/building.md`.
