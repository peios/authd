"""Missing or undeclared licence inputs must stop package assembly."""

import os
import tempfile
import unittest
from pathlib import Path

from licences import collect


class LicenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.previous)
        Path("Cargo.lock").write_text(
            '[[package]]\nname = "fixture"\nversion = "1.0.0"\n'
            'source = "registry+https://example.invalid/index"\n'
        )
        root = Path("external/fixture")
        root.mkdir(parents=True)
        self.manifest = root / "Cargo.toml"
        self.manifest.write_text(
            '[package]\nname = "fixture"\nversion = "1.0.0"\nlicense = "MIT OR Apache-2.0"\n'
        )
        self.notice = root / "LICENSE"
        self.notice.write_text("fixture licence")

    def test_notices_and_normalised_expression(self) -> None:
        expression = collect([self.manifest, self.notice], Path("out"))
        self.assertEqual(expression, "(Apache-2.0 OR MIT) AND MIT")
        self.assertEqual(Path("out/fixture-1.0.0/LICENSE").read_text(), "fixture licence")
        self.assertIn("fixture\t1.0.0", Path("out/crate-licenses.tsv").read_text())

    def test_undeclared_notice_is_not_read(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing declared licence"):
            collect([self.manifest], Path("out"))

    def test_unlocked_crate_is_rejected(self) -> None:
        Path("Cargo.lock").write_text("package = []\n")
        with self.assertRaisesRegex(ValueError, "absent from Cargo.lock"):
            collect([self.manifest, self.notice], Path("out"))

    def test_missing_expression_is_rejected(self) -> None:
        self.manifest.write_text('[package]\nname = "fixture"\nversion = "1.0.0"\n')
        with self.assertRaisesRegex(ValueError, "missing licence expression"):
            collect([self.manifest, self.notice], Path("out"))


if __name__ == "__main__":
    unittest.main()
