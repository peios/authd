#ifndef PEIOS_AUTH_H
#define PEIOS_AUTH_H

#include "auth-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct peios_auth_client peios_auth_client;
typedef struct peios_auth_operation peios_auth_operation;

/* ABI 1. Requests/options start with size = sizeof(object). Zero-initialize
 * them before setting fields. A NULL options pointer selects the system sockets
 * and a 90-second reply timeout. Zero timeout selects that default; explicit
 * timeouts are 1..86400000 milliseconds. Empty socket paths select defaults.
 * Overrides must name trusted authorities: they are intended for explicit
 * endpoint selection and tests, never untrusted environment variables.
 *
 * All pointers must be valid and correctly aligned for their declared types.
 * Input byte spans may use NULL only at length zero. Text is UTF-8 without NUL;
 * byte spans are not terminated. Inputs are copied before begin/respond return.
 * Callers own and must erase their credential buffers after use.
 *
 * create/begin return NULL for invalid arguments. Connection failures produce
 * an operation in FAILED state, with an inspectable error. Accessors/respond
 * return 0 on success or -1 for invalid arguments, index, type or state; on
 * failure outputs are untouched. step/wait return a state below, or -1 for an
 * invalid handle (wait also for an OS poll failure).
 *
 * Handles must not be used concurrently or after destroy. Different handles
 * can run concurrently. An operation is independent of its client after begin.
 * Operations must not be reused across fork. destroy accepts NULL and closes
 * sockets, unclaimed tokens and all library-owned buffers. Cancellation stops
 * communication; it cannot roll back a submitted request.
 *
 * All returned views borrow the operation until its next mutable call or
 * destruction. Do not free their pointers. Accessors copy only the view, not
 * the referenced bytes. take_token transfers a CLOEXEC descriptor to the
 * caller, who must close it; it returns -1 when no token is available.
 *
 * step is nonblocking and bounded. In WAIT, obtain poll_info, wait on its fd
 * for events with at most timeout_ms, then step again (also after timeout).
 * The descriptor is borrowed: never read/write/close it yourself. At PROMPT,
 * render messages before prompts; respond in prompt order with matching refs
 * and the current round. Empty prompt rounds require an empty response.
 * Human input time is excluded from reply timeouts. wait drives the same loop
 * synchronously until a prompt or terminal result, without rendering a UI.
 *
 * Errors have stable categories and a raw code: errno for transport errors,
 * PGSS denial for PGSS_DENIAL, LPS failure for LPS_DENIAL, otherwise zero.
 * Unknown denial codes are preserved. Check outcome_unknown before offering a
 * retry: any submitted mutating request can have taken effect without a reply.
 * No mutation is retried automatically. A successful query does not guarantee
 * that a later session-end request will still be authorised.
 *
 * Identity results retain outcome, incomplete sources and opaque next cursor.
 * Continue while next is nonempty, even if a page has no records. Field state
 * separates absent/withheld values from empty values. ClaimValue uses only the
 * member selected by ClaimView.value_type; unused members are zero/empty.
 * Session-end counts follow PGSS: ending the caller's session replies before
 * termination, so its counts are prospective rather than confirmed kills.
 *
 * LogonRequest.identifier is a UTF-8 username (identifier_type USERNAME).
 * supported_credentials is an OR of SUPPORT_* bits. required_credential_type
 * is PASSWORD, SSH_PUBLIC_KEY, or zero to use source policy. Empty tty and
 * remote_host are absent. SSH binding fields are all absent or all present:
 * connection is 16 nonzero-as-a-whole bytes, session is 16..64 bytes, and
 * username is nonempty UTF-8. These describe the authorised live transport.
 * Key.kind selects NAME (UTF-8 value), SID (binary value), or UNIX_ID (unix_id).
 * LookupRequest.kind can be ANY; EnumerateRequest.kind must be PRINCIPAL or
 * GROUP. A NULL group enumerates all; otherwise it names the group whose
 * members are requested. All record/item indices are zero-based.
 * Key enrollment takes an OpenSSH public-key line; removal takes its SHA256
 * fingerprint. These operations use the caller's account and prove credentials
 * through prompt rounds. No caller-supplied account name selects their subject.
 *
 * This API does not install tokens, change process identity, launch programs,
 * or read credentials from a terminal. ABI-compatible additions preserve the
 * layouts and meanings here; incompatible changes require a new SONAME.
 */
#define PEIOS_AUTH_WAIT 0
#define PEIOS_AUTH_PROMPT 1
#define PEIOS_AUTH_COMPLETE 2
#define PEIOS_AUTH_DENIED 3
#define PEIOS_AUTH_FAILED 4
#define PEIOS_AUTH_CANCELLED 5
#define PEIOS_AUTH_ERROR_UNAVAILABLE 1
#define PEIOS_AUTH_ERROR_TIMEOUT 2
#define PEIOS_AUTH_ERROR_PROTOCOL 3
#define PEIOS_AUTH_ERROR_IO 4
#define PEIOS_AUTH_ERROR_CANCELLED 5
#define PEIOS_AUTH_ERROR_PGSS_DENIAL 6
#define PEIOS_AUTH_ERROR_LPS_DENIAL 7

#define PEIOS_AUTH_MESSAGE_INFO 0
#define PEIOS_AUTH_MESSAGE_ERROR 1
#define PEIOS_AUTH_POLICY_DENIED 0
#define PEIOS_AUTH_POLICY_PASSWORD 1
#define PEIOS_AUTH_POLICY_SSH_PUBLIC_KEY 2
#define PEIOS_AUTH_POLICY_PASSWORD_OR_KEY 3
#define PEIOS_AUTH_POLICY_NO_CREDENTIAL 4
#define PEIOS_AUTH_PASSWORD 1
#define PEIOS_AUTH_SSH_PUBLIC_KEY 2
#define PEIOS_AUTH_SUPPORT_PASSWORD 1
#define PEIOS_AUTH_SUPPORT_SSH_PUBLIC_KEY 2
#define PEIOS_AUTH_IDENTIFIER_USERNAME 1
#define PEIOS_AUTH_LOGON_INTERACTIVE 2
#define PEIOS_AUTH_LOGON_NETWORK 3
#define PEIOS_AUTH_LOGON_BATCH 4
#define PEIOS_AUTH_LOGON_SERVICE 5
#define PEIOS_AUTH_LOGON_NETWORK_CLEARTEXT 8
#define PEIOS_AUTH_LOGON_NEW_CREDENTIALS 9
#define PEIOS_AUTH_LOGON_REMOTE_INTERACTIVE 10
#define PEIOS_AUTH_KEY_NAME 1
#define PEIOS_AUTH_KEY_SID 2
#define PEIOS_AUTH_KEY_UNIX_ID 3
#define PEIOS_AUTH_KIND_PRINCIPAL 1
#define PEIOS_AUTH_KIND_GROUP 2
#define PEIOS_AUTH_KIND_ANY 0
#define PEIOS_AUTH_FOUND 1
#define PEIOS_AUTH_NOT_FOUND 2
#define PEIOS_AUTH_UNAVAILABLE 3
#define PEIOS_AUTH_REFUSED 4
#define PEIOS_AUTH_MALFORMED 5
#define PEIOS_AUTH_FIELD_UNREPORTED 0
#define PEIOS_AUTH_FIELD_ABSENT 1
#define PEIOS_AUTH_FIELD_RESTRICTED 2
#define PEIOS_AUTH_FIELD_DECLINED 3
#define PEIOS_AUTH_FIELD_TOO_LARGE 4
#define PEIOS_AUTH_FIELD_PRESENT 5
#define PEIOS_AUTH_UNIX_ID (1u << 0)
#define PEIOS_AUTH_PRIMARY_GROUP (1u << 1)
#define PEIOS_AUTH_HOME (1u << 2)
#define PEIOS_AUTH_SHELL (1u << 3)
#define PEIOS_AUTH_DISPLAY_NAME (1u << 4)
#define PEIOS_AUTH_GROUPS (1u << 5)
#define PEIOS_AUTH_MEMBERS (1u << 6)
#define PEIOS_AUTH_CLAIMS (1u << 7)
#define PEIOS_AUTH_ENABLED (1u << 8)
#define PEIOS_AUTH_LOGON_TYPES (1u << 9)
#define PEIOS_AUTH_DESCRIPTION (1u << 10)
#define PEIOS_AUTH_CLAIM_INT64 1
#define PEIOS_AUTH_CLAIM_UINT64 2
#define PEIOS_AUTH_CLAIM_STRING 3
#define PEIOS_AUTH_CLAIM_SID 5
#define PEIOS_AUTH_CLAIM_BOOLEAN 6
#define PEIOS_AUTH_CLAIM_OCTET 16

#include "auth-functions.h"

#ifdef __cplusplus
}
#endif
#endif
