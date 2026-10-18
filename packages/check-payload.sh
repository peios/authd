#!/bin/sh
# Checks run against the exact staged payload before any package is committed.
set -eu
stage=${1:?staged payload required}
native=${2:?native mode required}
# Fail closed on distribution hardening, split-debug, and path-leak policy.
for record in \
    "authd:$stage/usr/sbin/authd:exe" \
    "lpsd:$stage/usr/sbin/lpsd:exe" \
    "lps:$stage/usr/bin/lps:exe" \
    "login:$stage/usr/bin/login:exe" \
    "nss:$stage/usr/lib/x86_64-linux-peios/libnss_peios.so.2:dso" \
    "libauth:$stage/usr/lib/x86_64-linux-peios/libauth.so.1:dso"; do
    component=${record%%:*}
    remain=${record#*:}
    elf=${remain%:*}
    kind=${record##*:}

    readelf -h "$elf" | grep -Eq 'Type:[[:space:]]+DYN'
    readelf -lW "$elf" | grep -q 'GNU_RELRO'
    if [ "$native" = true ]; then
        readelf -n "$elf" | grep -Eq 'x86 feature:.*IBT.*SHSTK'
    fi
    readelf -lW "$elf" | grep -Eq 'GNU_STACK[[:space:]].*RW[[:space:]]'
    readelf -dW "$elf" | grep -q 'BIND_NOW'
    if [ "$native" = true ]; then
        readelf -dW "$elf" | grep -q 'RELR'
    fi
    if readelf -dW "$elf" | grep -E '(RPATH|RUNPATH)' >/dev/null; then
        echo "authd: $elf carries an RPATH or RUNPATH" >&2
        exit 1
    fi
    if readelf -SW "$elf" | grep '\.debug_info' >/dev/null; then
        echo "authd: $elf still contains unsplit debug information" >&2
        exit 1
    fi
    if [ "$kind" = exe ]; then
        readelf -dW "$elf" | grep -Eq 'FLAGS_1.*PIE'
    else
        soname=libauth.so.1
        if [ "$component" = nss ]; then soname=libnss_peios.so.2; fi
        readelf -dW "$elf" | grep -F "[$soname]" >/dev/null
    fi

    build_id=$(readelf -n "$elf" | sed -n 's/^[[:space:]]*Build ID: //p' | head -1)
    build_id_prefix=$(printf %s "$build_id" | cut -c1-2)
    build_id_suffix=$(printf %s "$build_id" | cut -c3-)
    debug="$stage/debug/$component/usr/lib/debug/.build-id/$build_id_prefix/$build_id_suffix.debug"
    test -s "$debug"
    readelf -SW "$debug" | grep -q '\.debug_info'
    test "$(readelf -n "$debug" | sed -n 's/^[[:space:]]*Build ID: //p' | head -1)" = "$build_id"
    for forbidden in "$PWD" "${PWD%/execroot/*}"; do
        if grep -aF "$forbidden" "$elf" "$debug" >/dev/null; then
            echo "authd: build path $forbidden leaked into $elf or its debug file" >&2
            exit 1
        fi
    done
done

# NSS is loaded into unrelated processes: no additional dynamic runtime,
# and no exported compiler-runtime symbols that could interpose on the caller.
python3 - "$stage/usr/lib/x86_64-linux-peios/libnss_peios.so.2" <<'PY_NSS'
import re
import subprocess
import sys

elf = sys.argv[1]
dynamic = subprocess.check_output(["readelf", "-dW", elf], text=True)
needed = set(re.findall(r"\(NEEDED\).*\[(.*?)\]", dynamic))
if needed != {"libc.so.6", "ld-linux-x86-64.so.2"}:
    raise SystemExit(f"{elf}: unexpected NSS dependencies {sorted(needed)}")
symbols = subprocess.check_output(["readelf", "--dyn-syms", "--wide", elf], text=True)
for line in symbols.splitlines():
    fields = line.split()
    if len(fields) >= 8 and fields[4] in {"GLOBAL", "WEAK"} and fields[6] != "UND":
        if not fields[7].startswith("_nss_peios_"):
            raise SystemExit(f"{elf}: unexpected NSS export {fields[7]}")
PY_NSS

# Installed-payload smoke: public client CLI, prohibited login bypass, NSS ABI,
# seed syntax, and live-account script syntax all come from staged files.
"$stage/usr/bin/lps" --help >"$stage/lps-help"
grep -q 'usage: lps' "$stage/lps-help"
if "$stage/usr/bin/login" -f peios >"$stage/login-out" 2>"$stage/login-err"; then
    echo 'authd: login unexpectedly accepted -f' >&2
    exit 1
fi
grep -q 'not supported' "$stage/login-err"
readelf -Ws "$stage/usr/lib/x86_64-linux-peios/libnss_peios.so.2" |
    grep -q '_nss_peios_getpwnam_r'
python3 - "$stage/usr/share/regim" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
files = sorted(root.glob("*.reg"))
assert len(files) == 6, files
for path in files:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value.get("keys"), list) and value["keys"], path

# These are security boundaries, not documentation: prove the shipped seeds
# retain exactly the authority each process needs and no SYSTEM defaults.
expected = {
    "authd-service.reg": [
        "SeChangeNotifyPrivilege",
        "SeCreateTokenPrivilege",
        "SeTcbPrivilege",
        "SeRestorePrivilege",
        "SeAuditPrivilege",
    ],
    "lpsd-service.reg": ["SeChangeNotifyPrivilege", "SeAuditPrivilege"],
    "login-console.reg": [
        "SeChangeNotifyPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
    ],
    "lpsd-first-account.reg": ["SeChangeNotifyPrivilege"],
}
for filename, privileges in expected.items():
    value = json.loads((root / filename).read_text(encoding="utf-8"))
    services = [key for key in value["keys"] if "\\Services\\" in key["path"]]
    assert len(services) == (4 if filename == "login-console.reg" else 1), (filename, services)
    for service in services:
        values = {entry["name"]: entry for entry in service.get("values", [])}
        required = values["RequiredPrivileges"]
        assert required["type"] == "multi", (filename, required)
        assert required["data"] == privileges, (filename, required["data"])
        if filename == "login-console.reg":
            assert values["Arguments"]["data"][0] == "--console"
            if service["path"].split("\\")[-1] != "login-console":
                assert values["Arguments"]["data"] == ["--console"]
PY
/usr/bin/sh -n "$stage/usr/libexec/lpsd/first-account"
for manual in \
    "$stage/usr/share/man/man1/lps.1.gz" \
    "$stage/usr/share/man/man1/login.1.gz" \
    "$stage/usr/share/man/man8/authd.8.gz" \
    "$stage/usr/share/man/man8/lpsd.8.gz"; do
    gzip -t "$manual"
    gzip -cd "$manual" | grep '^\.TH ' >/dev/null
done
rm -f "$stage/lps-help" "$stage/login-out" "$stage/login-err"
