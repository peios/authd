#!/usr/bin/env python3
"""Check C/Rust layouts, exact public exports, SONAME, and a linked C caller.

The C compiler, `nm`, `readelf` and `rustc` are `$CC`, `$NM`, `$READELF` and
`$RUSTC` when set, as a hermetic build gives them, and found on `PATH` by those
names otherwise; rustc links with `$CC` when it is set.
"""

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).absolute().parents[1]

CALLER_SOURCE = r"""
#include <assert.h>
#include <string.h>
#include <peios/auth.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(peios_auth_abi_version() == 1);
    peios_auth_client_options options = {0};
    options.size = sizeof(options);
    options.logon_socket.data = (const uint8_t *)argv[1];
    options.logon_socket.len = strlen(argv[1]);
    peios_auth_client *client = peios_auth_client_create(&options);
    assert(client);
    peios_auth_logon_request bad = {0};
    assert(!peios_auth_logon_begin(client, &bad));
    peios_auth_operation *operation = peios_auth_session_end_query_begin(client, 42);
    assert(operation);
    peios_auth_client_destroy(client);
    assert(peios_auth_operation_wait(operation) == PEIOS_AUTH_FAILED);
    peios_auth_error_view error;
    assert(peios_auth_operation_error(operation, &error) == 0);
    assert(error.outcome_unknown == 0);
    assert(error.category == PEIOS_AUTH_ERROR_UNAVAILABLE);
    peios_auth_operation_destroy(operation);
    peios_auth_operation_destroy(NULL);
    peios_auth_client_destroy(NULL);
    return 0;
}
"""


def run(*args: str, env: Mapping[str, str] | None = None) -> str:
    """Capture a successful command; propagate failure with its captured output."""
    return subprocess.run(args, check=True, text=True, capture_output=True, env=env).stdout


def layout_sources() -> tuple[str, str, int]:
    """Generate independent C and Rust probes for each declared layout."""
    source = (ROOT / "auth-abi/src/lib.rs").read_text()
    structs = re.findall(r"pub struct (\w+)\s*\{(.*?)\}", source, re.S)
    c_lines = ["#include <stdio.h>", "#include <peios/auth.h>", "int main(void) {"]
    rust_lines = [
        "#[allow(dead_code)]",
        f'#[path = "{ROOT}/auth-abi/src/lib.rs"] mod abi;',
        "fn main() {",
    ]
    for name, body in structs:
        c_name = "peios_auth_" + re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        fields = re.findall(r"pub (\w+):", body)
        c_lines.append(f'printf("{name} %zu %zu", sizeof({c_name}), _Alignof({c_name}));')
        rust_lines.append(
            f'print!("{name} {{}} {{}}", size_of::<abi::{name}>(), align_of::<abi::{name}>());'
        )
        for field in fields:
            c_lines.append(f'printf(" %zu", offsetof({c_name}, {field}));')
            rust_lines.append(f'print!(" {{}}", std::mem::offset_of!(abi::{name}, {field}));')
        c_lines.append('puts("");')
        rust_lines.append("println!();")
    c_lines.append("}")
    rust_lines.append("}")
    return "\n".join(c_lines), "\n".join(rust_lines), len(structs)


def check_layouts(temporary: Path) -> int:
    """Compile and compare size, alignment, and field offsets in both languages."""
    c_source, rust_source, count = layout_sources()
    (temporary / "layout.c").write_text(c_source)
    (temporary / "layout.rs").write_text(rust_source)
    run(
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I" + str(ROOT / "libauth/include"),
        str(temporary / "layout.c"),
        "-o",
        str(temporary / "layout-c"),
    )
    linker = ["-Clinker=" + os.environ["CC"]] if "CC" in os.environ else []
    run(
        os.environ.get("RUSTC", "rustc"),
        *linker,
        "--edition=2024",
        str(temporary / "layout.rs"),
        "-o",
        str(temporary / "layout-rust"),
    )
    assert run(str(temporary / "layout-c")) == run(str(temporary / "layout-rust")), (
        "C/Rust layout mismatch"
    )
    return count


def check_caller(temporary: Path, library: Path) -> None:
    """Exercise the installed shared library through its public C interface."""
    (temporary / "caller.c").write_text(CALLER_SOURCE)
    run(
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I" + str(ROOT / "libauth/include"),
        str(temporary / "caller.c"),
        "-L" + str(library),
        "-lauth",
        "-o",
        str(temporary / "caller"),
    )
    environment = dict(os.environ)
    environment["LD_LIBRARY_PATH"] = str(library) + ":" + environment.get("LD_LIBRARY_PATH", "")
    run(str(temporary / "caller"), str(temporary / "absent.sock"), env=environment)


def main() -> None:
    """Verify installed symbols, layouts, and linked behavior in disposable files."""
    library = Path(sys.argv[1]).resolve()
    exports = run(os.environ.get("NM", "nm"), "-D", "--defined-only", str(library / "libauth.so.1"))
    actual = sorted(line.split()[-1] for line in exports.splitlines() if line.split())
    expected = (ROOT / "libauth/exports.txt").read_text().splitlines()
    assert actual == expected, (actual, expected)
    readelf = os.environ.get("READELF", "readelf")
    assert "[libauth.so.1]" in run(readelf, "-d", str(library / "libauth.so.1"))
    with tempfile.TemporaryDirectory(prefix="auth-abi-") as directory:
        temporary = Path(directory)
        count = check_layouts(temporary)
        check_caller(temporary, library)
    print(f"Verified {count} C/Rust layouts, {len(expected)} exports, SONAME and linked C caller")


if __name__ == "__main__":
    main()
