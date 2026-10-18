---
title: Profiles and Claims
type: concept
description: How account profile preferences differ from security claims on issued tokens.
related:
  - peios/local-accounts/creating-an-account
  - peios/authentication-policy/granting-access
---

A profile tells a client how to start a session. Claims describe account
attributes that access rules can evaluate. Both are stored with the account,
but they serve different purposes.

## Profile preferences

The profile includes a home path, shell path, and display name. An
administrator changes it with `lps set`. For example:

```sh
lps set alice --display-name "Alice Chen"
lps show alice
```

The display name is presentation text. It is not a credential, an account
lookup key, or evidence of a different identity. A person can change their own
display name through the self-service account interface.

Changing a home path does not move files. Changing a shell affects later
sessions rather than replacing a running shell. Use absolute paths for homes
and shells; `login` rejects a relative profile path and uses its fallback.

Renaming an account with `lps rename` is a separate action. The account's
security identifier (SID), group memberships, and recorded home remain
unchanged.

## Claims used in access decisions

A claim has a name, a value type, and one or more values. An administrator can
set a claim such as a department:

```sh
lps claim set alice Department string Engineering
lps show alice
```

The claim has an effect only where an access rule evaluates it. A string named
`Administrator` does not grant administrator membership or a privilege by
itself.

Claims are copied into a token when it is issued. Changing a stored claim does
not change tokens that already exist. Test the intended access rule with a
fresh session after a claim change.

The complete claim types and command syntax belong to `lps(1)`. The machine's
privilege grants are described separately in [Granting
Access](~peios/authentication-policy/granting-access).
