"""Validate installed ABI, CLI and security policy against the staged payload."""

import os
import subprocess
from pathlib import Path


def validate(stage: Path, *, native: bool, sdk: Path) -> None:
    environment = os.environ | {
        "LD_LIBRARY_PATH": str(stage.resolve() / "usr/lib/x86_64-linux-peios")
        + ":"
        + str(sdk.resolve() / "lib"),
    }
    subprocess.run(
        ["sh", "packages/check-payload.sh", str(stage), str(native).lower()],
        env=environment,
        check=True,
    )
    # The C caller uses the host compiler; Rust layouts use the selected Bazel toolchain.
    subprocess.run(
        ["python3", "tools/check-auth-abi.py", str(stage / "usr/lib/x86_64-linux-peios")],
        env=environment,
        check=True,
    )
