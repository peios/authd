---
title: Using the Authentication Client
type: how-to
description: Build a C or Rust application against the Peios authentication
  client library.
related:
  - peios/authentication-client/conversations
  - peios/authentication-client/reading-identities
---

Use `libauth` to communicate with the authentication authority from your
application. C callers use `<peios/auth.h>`; Rust callers use `peios-auth`,
which wraps the same shared library.

## Before you start

Prepare the client dependencies:

- Install the `dev.peios.libauth` runtime and the
  `dev.peios.libauth-devel` software development kit (SDK).
- Use an account or service identity permitted to perform the operation.
- For Rust, add the `peios-auth` crate from the matching authd source
  revision.

## Link the application

For a C application with a `client.c` source file:

1. Include the public header in C:

   ```c
   #include <peios/auth.h>
   ```

2. Obtain compiler and linker flags through `pkg-config`:

   ```sh
   cc client.c -o client $(pkg-config --cflags --libs auth)
   ```

For Rust applications built with Cargo, make `auth.pc` discoverable through
`PKG_CONFIG_PATH`. For an explicit development build, set `PEIOS_AUTH_LIB_DIR`
to the directory containing `libauth.so`. At runtime, the loader must also
find `libauth.so.1`. A development shell can set `LD_LIBRARY_PATH` to that
directory.

## Drive an operation

Use this sequence for each operation:

1. Create a client. Default options use the system sockets. Supply explicit
   socket paths only when selecting a trusted authority or a test server.

2. Begin the operation. Input strings and buffers are copied before the
   call returns. A null C handle means the arguments were invalid. A
   connection failure instead produces an operation with an error result.

3. Call `peios_auth_operation_step()`. When it returns `PEIOS_AUTH_WAIT`,
   obtain the descriptor, event mask, and maximum wait from
   `peios_auth_operation_poll_info()`. Wait, then call `step()` again,
   including after a timeout. Never read, write, or close that descriptor.

4. At `PEIOS_AUTH_PROMPT`, display the round's messages before collecting
   answers. Submit answers in prompt order, with their original references
   and the current round ID. Answer a message-only round with an empty
   answer array. Clear caller-owned secret buffers after submission.

5. At a terminal state, inspect the typed result or error. If the operation
   granted a token, take it only when your program is ready to own the
   descriptor. Check `outcome_unknown` before offering to repeat a change.

6. Destroy the operation and client. Returned C views borrow the operation;
   copy any data needed after its next mutable call or destruction.

For blocking programs, `peios_auth_operation_wait()` performs the wait loop
until a prompt or terminal state. The Rust wrapper provides the same choice
through `Operation::step()` and `Operation::wait()`. Its result methods return
owned Rust data.

## Check the result

A completed permission query means that authd permitted the proposed action at
the time of the query. A completed logon provides a token and session profile.
Neither result changes the calling process's identity.

Use the public header for function signatures, constants, ownership rules, and
the application binary interface (ABI) contract. Keep each operation under one
caller's control; different operations can run concurrently.
