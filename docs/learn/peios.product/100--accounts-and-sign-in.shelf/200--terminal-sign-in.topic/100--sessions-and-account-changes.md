---
title: Sessions and Account Changes
type: concept
description: Why account changes do not revoke existing tokens and what ending a session does.
related:
  - peios/local-accounts/retiring-an-account
  - peios/authentication-client/self-service
---

A logon session groups work started with a granted identity. Its access tokens
contain the account information and machine policy evaluated when the tokens
were issued. Changing the stored account does not rewrite them.

## Stop new access and active work separately

Turning an account off, changing its password, removing a key, or removing a
group membership changes later authentication and token creation. A program
already running with a token can retain its previous access.

For an account retirement or suspected credential compromise, decide both
whether further sign-ins are permitted and whether existing sessions must end.
Neither action substitutes for the other.

## Ending a session

An authorized client asks `authd` to end a session. The authority finds
processes whose primary tokens belong to it, asks them to exit, and kills
survivors after a grace period. Repeated scans are bounded, so the result can
report processes that remain.

The kernel removes the session when its last token reference is released. An
external process holding a token reference can keep the session alive after
its ordinary processes have exited. Ending a session is not a promise that
every reference to its tokens has disappeared.

## Who can request it

A signed-in person can end their own eligible session. Ending another person's
session requires access granted by `SessionEndSecurity` under
`Machine\Generic\Authn\Policy`. SYSTEM, anonymous, and service sessions are
protected from this operation.

The library offers a permission query so an application can decide whether to
present an action. The actual request is checked again; a query is not a
reservation of authority.

If the requesting application belongs to the target session, authd replies
before ending its processes. Counts in that reply are prospective rather than
confirmed terminations. The application can disappear before it renders the
result.

Read `authd(8)` for termination behavior and the registry manual for
`Machine\Generic\Authn\Policy:SessionEndSecurity`. Application authors should
also read [Self-Service
Operations](~peios/authentication-client/self-service).
