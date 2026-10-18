#!/usr/bin/python3
"""Stage and validate declared authentication artifacts before writing any PPK commit."""

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

sys.dont_write_bytecode = True
from licences import collect  # noqa: E402
from validate import validate  # noqa: E402

LIBDIR = "usr/lib/x86_64-linux-peios"
DESTINATIONS = {
    "authd": "usr/sbin/authd",
    "lpsd": "usr/sbin/lpsd",
    "lps": "usr/bin/lps",
    "login": "usr/bin/login",
    "nss": LIBDIR + "/libnss_peios.so.2",
    "libauth": LIBDIR + "/libauth.so.1",
}


def copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def split_debug(component: str, elf: Path, output: Path) -> None:
    notes = subprocess.check_output(["readelf", "-n", str(elf)], text=True)
    match = re.search(r"Build ID: ([0-9a-f]+)", notes)
    if not match:
        raise ValueError(f"missing build ID: {elf}")
    build_id = match.group(1)
    debug = (
        output / f"debug/{component}/usr/lib/debug/.build-id/{build_id[:2]}/{build_id[2:]}.debug"
    )
    debug.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["objcopy", "--only-keep-debug", elf, debug], check=True)
    subprocess.run(["strip", "--strip-unneeded", elf], check=True)
    subprocess.run(["objcopy", f"--add-gnu-debuglink={debug}", elf], check=True)


def source_files(inputs: list[Path]) -> list[Path]:
    files = set()
    for path in inputs:
        if path.is_dir():
            # Generated bindings and build-script source products, not compiled archives.
            files.update(
                p for p in path.rglob("*") if p.is_file() and p.suffix in {".rs", ".h", ".c"}
            )
        elif path.is_file():
            files.add(path)
        else:
            raise ValueError(f"missing declared input: {path}")
    return sorted(files)


def stage_data(sources: list[Path], output: Path, version: str) -> None:
    for source in sources:
        if source.parent == Path("docs/man"):
            section = source.suffix[1:]
            target = output / f"usr/share/man/man{section}/{source.name}.gz"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(gzip.compress(source.read_bytes(), compresslevel=9, mtime=0))
        elif source.parent == Path("registry.d"):
            copy(source, output / "usr/share/regim" / source.name)
        elif source == Path("libexec/first-account"):
            copy(source, output / "usr/libexec/lpsd/first-account")
        elif source.parent == Path("libauth/include/peios"):
            copy(source, output / "usr/include/peios" / source.name)
    (output / "var/state/lpsd").mkdir(parents=True)
    (output / LIBDIR / "libauth.so").symlink_to("libauth.so.1")
    pkgconfig = output / LIBDIR / "pkgconfig/auth.pc"
    pkgconfig.parent.mkdir()
    pkgconfig.write_text(
        f"prefix=/usr\nlibdir=/{LIBDIR}\nincludedir=${{prefix}}/include\n\n"
        "Name: auth\nDescription: Peios authentication client library\n"
        f"Version: {version}\nLibs: -L${{libdir}} -lauth\nCflags: -I${{includedir}}\n"
    )


def check_versions(sources: list[Path], version: str) -> None:
    manifests = [p for p in sources if p.name == "Cargo.toml" and len(p.parts) == 2]
    expected = set(tomllib.loads(Path("Cargo.toml").read_text())["workspace"]["members"])
    if {str(p.parent) for p in manifests} != expected:
        raise ValueError("incomplete workspace manifest inputs")
    for manifest in manifests:
        if tomllib.loads(manifest.read_text())["package"]["version"] != version:
            raise ValueError(f"source version differs from Bazel: {manifest}")


def main() -> None:
    spec = json.loads(Path(sys.argv[1]).read_text())
    output = Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    sources = [Path(path) for path in spec["sources"]]
    check_versions(sources, spec["version"])
    debug_inputs = set(sources)
    expressions = {}
    for name, component in spec["components"].items():
        elf = output / DESTINATIONS[name]
        copy(Path(component["binary"]), elf)
        split_debug(name, elf, output)
        inputs = source_files([Path(path) for path in component["inputs"]])
        debug_inputs.update(inputs)
        expressions[name] = collect(inputs, output / "licenses" / name)
        if name == "nss":
            expressions[name] += " AND (GPL-3.0-or-later WITH GCC-exception-3.1)"
            for notice in ("libgcc-COPYING3", "libgcc-COPYING.RUNTIME"):
                copy(Path("third-party") / notice, output / "licenses/nss/libgcc" / notice)
    # Only source inputs declared by Bazel enter debugsource; never walk a checkout or cache.
    debug_root = output / "usr/src/debug/dev.peios.authd"
    for source in sorted(debug_inputs):
        if source.is_relative_to(Path(spec["sdk"])) or source.suffix in {
            ".so",
            ".a",
            ".rlib",
            ".o",
        }:
            continue
        if source.is_absolute() or ".." in source.parts:
            raise ValueError(f"non-relative declared source: {source}")
        copy(source, debug_root / source)
    expressions["debugsource"] = collect(sorted(debug_inputs), output / "licenses/debugsource")
    for path in sorted(Path("packages/definitions").glob("*.json")):
        definition = json.loads(path.read_text())
        name = definition["package"]["name"]
        component = name.removeprefix("dev.peios.authd-").removeprefix("dev.peios.")
        component = component.removesuffix("-debuginfo")
        if component == "debuginfo":
            component = "authd"
        if component in expressions and definition["package"]["license"] != expressions[component]:
            raise ValueError(f"{path}: licence expression differs: {expressions[component]}")
    stage_data(sources, output, spec["version"])
    os.environ["RUSTC"] = str(Path(spec["rustc"]).absolute())
    validate(output, native=spec["native"], sdk=Path(spec["sdk"]))
    fingerprints = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(debug_inputs)
        if path.is_file()
    }
    record = {
        "version": spec["version"],
        "userspace_abi": "peios-native" if spec["native"] else "debian-development",
        "release_ready": False,
        "signed": False,
        "checks": "native-hardening-and-payload" if spec["native"] else "development-payload",
        "input_digest": hashlib.sha256(
            json.dumps(fingerprints, sort_keys=True).encode()
        ).hexdigest(),
        "licences": expressions,
    }
    (output / "build.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
