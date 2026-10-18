"""Verify package boundaries and policy metadata in the complete built store."""

import json
import tomllib
import unittest
from pathlib import Path


class FamilyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path("packages.store")
        index = json.loads((cls.root / "index.json").read_text())
        cls.packages = {p["name"].removeprefix("dev.peios."): p for p in index["packages"]}
        cls.manifests = {
            name: tomllib.loads((cls.root / info["manifest"]).read_text())["files"]
            for name, info in cls.packages.items()
        }

    def test_complete_family(self) -> None:
        self.assertEqual(len(self.packages), 16)
        self.assertIn("authd-source", self.packages)
        self.assertIn("authd-debugsource", self.packages)
        self.assertEqual(len([name for name in self.packages if name.endswith("-debuginfo")]), 6)
        self.assertEqual(len({p["version"] for p in self.packages.values()}), 1)
        for name, info in self.packages.items():
            self.assertFalse(info["release_ready"], name)
            if "build" in info:
                self.assertFalse(info["build"]["signed"])

    def test_live_account_is_separate(self) -> None:
        seed = "usr/share/regim/lpsd-first-account.reg"
        script = "usr/libexec/lpsd/first-account"
        for name, files in self.manifests.items():
            self.assertEqual(seed in files, name == "authd-live-account")
            self.assertEqual(script in files, name == "authd-live-account")
        self.assertNotIn("usr/sbin/lpsd", self.manifests["authd-live-account"])

    def test_sdk_split_and_trust_metadata(self) -> None:
        runtime, sdk = self.manifests["libauth"], self.manifests["libauth-devel"]
        libdir = "usr/lib/x86_64-linux-peios/"
        self.assertIn(libdir + "libauth.so.1", runtime)
        self.assertNotIn(libdir + "libauth.so.1", sdk)
        self.assertEqual(sdk[libdir + "libauth.so"], {"symlink": "libauth.so.1"})
        self.assertIn("usr/include/peios/auth.h", sdk)
        authd = self.packages["authd"]["package_metadata"]
        self.assertEqual(authd["signing"], {"usr/sbin/authd": "tcb.priv"})
        lpsd = self.packages["authd-lpsd"]["package_metadata"]
        self.assertIn("var/state/lpsd", lpsd["sd_overrides"])

    def test_debug_and_source_payloads(self) -> None:
        for name, files in self.manifests.items():
            if name.endswith("-debuginfo"):
                self.assertEqual(len([path for path in files if path.endswith(".debug")]), 1, name)
        source = self.manifests["authd-source"]
        self.assertIn("usr/src/authd/Cargo.lock", source)
        self.assertIn("usr/src/authd/packages/stage.py", source)
        self.assertIn("usr/src/authd/libauth/BUILD.bazel", source)
        self.assertIn("usr/src/authd/vendor/ppk/src/lib.rs", source)
        self.assertFalse(any("/bazel-out/" in path for path in source))
        for path in source:
            self.assertFalse(
                {".trail-cache", ".ruff_cache", "__pycache__", ".git", "target"}
                & set(Path(path).parts),
                path,
            )
        self.assertFalse(any("pekit" in path.lower() for path in source))


if __name__ == "__main__":
    unittest.main()
