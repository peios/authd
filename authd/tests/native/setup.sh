#!/bin/bash
set -euo pipefail
if [[ ${PEIOS_DISPOSABLE_AUTH_TEST:-} != yes ]]; then
    echo 'This replaces authentication policy in a fresh disposable guest.' >&2
    exit 2
fi
export PATH=/lcl/bin:$PATH LD_LIBRARY_PATH=/lcl/lib
policy='Machine/Generic/Authn/Policy'
lpsd_sid=S-1-5-80-4242895835-3884168475-4287610261-1596539771-2019494472
probe_sid=S-1-5-80-4182887542-3645904977-1829149248-884727542-156609911
logon_sid=S-1-5-80-1620879550-4074347495-2921255969-754160354-1110531699
auth_cap=S-1-15-3-815189116-3587081081-2225730562-134748649-517842195-1560836879-2444240241-858498395
logon_cap=S-1-15-3-2664559683-3984555773-3951455780-2774143311-388146908-3231209892-793332285-791810559
reg new -p Machine/Software/Authd/Sources/lpsd
reg set Machine/Software/Authd/Sources/lpsd MayAssertForeignMemberships dword:1
reg set Machine/Software/Authd/Sources/lpsd UnixIDBase dword:1000000
reg set Machine/Software/Authd/Sources/lpsd UnixIDCount dword:1000000
reg set -p "$policy/Everyone" Privileges multi:SeChangeNotifyPrivilege
reg set -p "$policy/$lpsd_sid" Privileges multi:SeChangeNotifyPrivilege,SeAuditPrivilege
reg set "$policy/$lpsd_sid" Integrity sz:System
reg set -p "$policy/$probe_sid" Capabilities multi:peios.auth.authenticate
reg set -p "$policy/$logon_sid" Capabilities multi:peios.auth.logon
mkdir -p /var/state/lpsd
sd set /var/state/lpsd "O:${lpsd_sid}G:${lpsd_sid}D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;${lpsd_sid})"
svctl definition create authd --set ImagePath=/bin/bash --set Arguments=-c \
    --set 'Arguments=exec /lcl/sbin/authd >/run/authd.log 2>&1' \
    --set Identity=SYSTEM --set Readiness=Notify --set Provides=authn \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeCreateTokenPrivilege \
    --set RequiredPrivileges=SeTcbPrivilege --set RequiredPrivileges=SeRestorePrivilege \
    --set RequiredPrivileges=SeAuditPrivilege
svctl definition create lpsd --set ImagePath=/lcl/sbin/lpsd --set Identity=Service \
    --set RuntimeDirectories=lpsd --set Requires=authd --set Readiness=Notify \
    --set RequiredPrivileges=SeChangeNotifyPrivilege --set RequiredPrivileges=SeAuditPrivilege
svctl start lpsd
for account in dev-auth dev-state; do
    printf 'development-only-password\ndevelopment-only-password\n' |
        lps add "$account" --home "/home/$account" --shell /bin/bash
done
printf 'development-only-password\ndevelopment-only-password\n' |
    lps add dev-disabled --disabled --shell /bin/bash
lps add dev-none --no-password --no-prompt --shell /bin/bash
lps group create developers
lps group add dev-auth developers
lps claim set dev-auth Department string Engineering
descriptor="O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;${auth_cap})(A;;0x2;;;${logon_cap})(A;;0x4;;;${probe_sid})(OA;;0x8;c4abd379-a4d6-5910-bccf-9f01f9a4738f;;${probe_sid})(OA;;0x8;52508a99-75c5-5ea8-957f-7f1d15433b4e;;${probe_sid})"
reg set "$policy" AuthenticationSecurity "sz:$descriptor"
for entry in 'authn-probe allowed' 'authn-denied denied' 'authn-logon type-restricted'; do
    read -r service mode <<<"$entry"
    svctl definition create "$service" --set Type=Oneshot --set RestartPolicy=Never \
        --set ImagePath=/bin/bash --set Arguments=-c \
        --set "Arguments=exec /lcl/bin/authn-probe $mode >/run/$service/result 2>&1" \
        --set Identity=Service --set "RuntimeDirectories=$service" --set Requires=lpsd \
        --set RequiredPrivileges=SeChangeNotifyPrivilege
    svctl start "$service"
    output=$(<"/run/$service/result")
    printf '%s\n' "$output"
    case "$mode" in
        allowed) marker='NATIVE AUTHENTICATION: password, groups, claim ACEs, absence, no token/home, and denials passed' ;;
        denied) marker='NATIVE AUTHENTICATION: capability denial passed' ;;
        type-restricted) marker='NATIVE LOGON: caller logon-type restriction passed' ;;
    esac
    # svctl successfully waiting for an operation is not proof of a clean
    # service exit. Require the probe's final marker as well.
    if [[ "$output" != *"$marker" ]]; then
        echo "Native probe failed: $service" >&2
        exit 1
    fi
done
authn-probe ident-allowed
authn-probe ident-refresh
# A blanket grant must not defeat a Department-specific deny, even for SYSTEM.
reg set "$policy" AuthenticationSecurity "sz:O:SYG:SYD:(OD;;0x8;c4abd379-a4d6-5910-bccf-9f01f9a4738f;;SY)(A;;0xf;;;SY)"
authn-probe ident-restricted
reg set "$policy" AuthenticationSecurity "sz:$descriptor"
authn-probe no-local-state
authn-probe logon
authn-probe attest-denied
reg set "$policy" AuthenticationSecurity 'sz:O:SYG:SYD:'
authn-probe system-denied
reg set "$policy" AuthenticationSecurity sz:broken
authn-probe denied
reg set "$policy" AuthenticationSecurity "sz:$descriptor"
echo 'NATIVE AUTHENTICATION: fixture sequence passed'
