import itertools
import tempfile
import unittest
from pathlib import Path

import phase2b as build


class CompatibilityTests(unittest.TestCase):
    def test_only_complete_success_permits_qemu(self):
        names = ["14-library", "14-smoke", "15-library", "15-smoke"]
        for rows in itertools.product((None, 0, 1), repeat=4):
            matrix = {key: rc for key, rc in zip(names, rows) if rc is not None}
            self.assertEqual(build.matrix_ok(matrix), rows == (0, 0, 0, 0))

    def test_sdk_identity_and_each_wrong_component(self):
        args = ["10.3.1", build.TRIPLE, "GNU ld 2.36.1.20210621", build.TRIPLE + "/libc"]
        build.check_identity(*args)
        for pos, bad in enumerate(("11.3.1", "x86_64-linux-gnu", "GNU ld 2.38", "/usr")):
            trial = args.copy()
            trial[pos] = bad
            with self.assertRaises(ValueError):
                build.check_identity(*trial)

    def test_every_system_link_input_must_match(self):
        expected = {n: f"sdk/{n}" for n in build.RUNTIME}
        for smoke in (True, False):
            build.check_inputs(list(expected.values()), expected, smoke)
            for n in build.RUNTIME:
                if n == "crt1.o" and not smoke:
                    continue
                mixed = list(set(expected.values()) - {expected[n]}) + ["ubuntu/" + n]
                with self.assertRaises(ValueError):
                    build.check_inputs(mixed, expected, smoke)

    def test_external_header_and_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sdk = root / "sdk"
            sdk.mkdir()
            (root / "host").touch()
            (sdk / "header").touch()
            self.assertEqual(build.owned(sdk / "header", sdk), "header")
            (sdk / "link").symlink_to(root / "host")
            with self.assertRaises(ValueError):
                build.owned(sdk / "link", sdk)

    def test_real_checksum_rejection(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate"
            archive.write_bytes(b"wrong archive")
            result = subprocess.run(["sha256sum", "--check", "--strict"], input=f"{build.ARCHIVE_SHA}  {archive}\n",
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
