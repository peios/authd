#!/usr/bin/env python3
"""Check C/Rust layouts, exact public exports, SONAME and a linked C caller."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
library = Path(sys.argv[1]).resolve()

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout

exports = run("nm", "-D", "--defined-only", str(library / "libauth.so.1"))
actual = sorted(line.split()[-1] for line in exports.splitlines() if line.split())
expected = (root / "libauth/exports.txt").read_text().splitlines()
assert actual == expected, (actual, expected)
assert "[libauth.so.1]" in run("readelf", "-d", str(library / "libauth.so.1"))
source = (root / "auth-abi/src/lib.rs").read_text()
structs = re.findall(r"pub struct (\w+)\s*\{(.*?)\}", source, re.S)
c_lines = ['#include <stdio.h>', '#include <peios/auth.h>', 'int main(void) {']
rust_lines = ['#[allow(dead_code)]', f'#[path = "{root}/auth-abi/src/lib.rs"] mod abi;', 'fn main() {']
for name, body in structs:
    c_name = "peios_auth_" + re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    fields = re.findall(r"pub (\w+):", body)
    c_lines.append(f'printf("{name} %zu %zu", sizeof({c_name}), _Alignof({c_name}));')
    rust_lines.append(f'print!("{name} {{}} {{}}", size_of::<abi::{name}>(), align_of::<abi::{name}>());')
    for field in fields:
        c_lines.append(f'printf(" %zu", offsetof({c_name}, {field}));')
        rust_lines.append(f'print!(" {{}}", std::mem::offset_of!(abi::{name}, {field}));')
    c_lines.append('puts("");')
    rust_lines.append('println!();')
c_lines.append('}')
rust_lines.append('}')
with tempfile.TemporaryDirectory(prefix="auth-abi-") as directory:
    tmp = Path(directory)
    (tmp / "layout.c").write_text("\n".join(c_lines))
    (tmp / "layout.rs").write_text("\n".join(rust_lines))
    run("cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(root / "libauth/include"), str(tmp / "layout.c"), "-o", str(tmp / "layout-c"))
    run("rustc", "--edition=2024", str(tmp / "layout.rs"), "-o", str(tmp / "layout-rust"))
    assert run(str(tmp / "layout-c")) == run(str(tmp / "layout-rust")), "C/Rust layout mismatch"
    (tmp / "caller.c").write_text(r'''
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
''')
    run("cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(root / "libauth/include"), str(tmp / "caller.c"), "-L" + str(library), "-lauth", "-o", str(tmp / "caller"))
    environment = dict(os.environ)
    environment["LD_LIBRARY_PATH"] = str(library) + ":" + environment.get("LD_LIBRARY_PATH", "")
    run(str(tmp / "caller"), str(tmp / "absent.sock"), env=environment)
print(f"Verified {len(structs)} C/Rust layouts, {len(expected)} exports, SONAME and linked C caller")
