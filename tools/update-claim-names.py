#!/usr/bin/env python3
"""Verify or refresh the exact kernel-owned, dependency-free claim-name helper."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DESTINATION = ROOT / "auth-core/src/vendor"
REPOSITORY = "https://github.com/peios/kernel"
SOURCE = "security/pkm/kacs/kacs_core/claim_name.rs"
LICENSE = "LICENSES/preferred/MIT"


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), *args])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "update"))
    parser.add_argument("--kernel-root", type=Path)
    parser.add_argument("--commit")
    args = parser.parse_args()
    if args.action == "update":
        if args.kernel_root is None or not re.fullmatch(r"[0-9a-f]{40}", args.commit or ""):
            parser.error("update needs --kernel-root and a complete --commit")
        resolved = git(args.kernel_root, "rev-parse", "--verify", f"{args.commit}^{{commit}}")
        if resolved.decode().strip() != args.commit:
            parser.error("--commit must name the commit itself")
        source = git(args.kernel_root, "show", f"{args.commit}:{SOURCE}")
        license_text = git(args.kernel_root, "show", f"{args.commit}:{LICENSE}")
        origin = {
            "repository": REPOSITORY,
            "commit": args.commit,
            "source": SOURCE,
            "sha256": digest(source),
            "license": LICENSE,
            "license_sha256": digest(license_text),
        }
        DESTINATION.mkdir(parents=True, exist_ok=True)
        (DESTINATION / "claim_name.rs").write_bytes(source)
        (DESTINATION / "LICENSE.MIT").write_bytes(license_text)
        (DESTINATION / "ORIGIN.json").write_text(json.dumps(origin, indent=2) + "\n")
    else:
        origin = json.loads((DESTINATION / "ORIGIN.json").read_text())
        if (
            origin["repository"] != REPOSITORY
            or origin["source"] != SOURCE
            or origin["license"] != LICENSE
            or not re.fullmatch(r"[0-9a-f]{40}", origin["commit"])
            or origin["sha256"] != digest((DESTINATION / "claim_name.rs").read_bytes())
            or origin["license_sha256"] != digest((DESTINATION / "LICENSE.MIT").read_bytes())
        ):
            raise SystemExit("Claim-name snapshot differs from its exact provenance")
    print(f"Claim-name snapshot verified: {origin['commit']}")


if __name__ == "__main__":
    main()
