"""Regression tests for provider selection and guest/host library paths."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_elf_abi as abi  # noqa: E402


def provider(name, physical_path, logical_path=None, source="rootfs", sha256="same"):
    physical_path = Path(physical_path)
    return abi.Provider(
        name=name,
        logical_path=Path(logical_path or physical_path),
        physical_path=physical_path,
        sha256=sha256,
        elf_class="ELF64",
        machine="AArch64",
        source=source,
    )


class ProviderAmbiguityTests(unittest.TestCase):
    def make_index(self, root, first_data, second_data):
        first = root / "lib" / "first" / "libsample.so"
        second = root / "usr" / "lib" / "second" / "libsample.so"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(first_data)
        second.write_bytes(second_data)
        return {
            "libsample.so": [
                provider("libsample.so", first, sha256=abi.digest(first)),
                provider("libsample.so", second, sha256=abi.digest(second)),
            ]
        }

    def assert_ambiguous(self, root, index):
        obj_path = root / "bin" / "app"
        obj_path.parent.mkdir(parents=True, exist_ok=True)
        obj_path.write_bytes(b"not parsed by choose_provider")
        obj = provider("app", obj_path, source="target")
        with self.assertRaisesRegex(abi.AuditError, "ambiguous default-path providers"):
            abi.choose_provider(
                "libsample.so", obj, {}, [], index, root, [], False
            )

    def test_identical_bytes_at_different_paths_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assert_ambiguous(root, self.make_index(root, b"same", b"same"))

    def test_different_hashes_at_different_paths_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assert_ambiguous(root, self.make_index(root, b"first", b"second"))

    @unittest.skipUnless(os.name == "posix", "symlink behavior is exercised on Linux runner")
    def test_two_symlink_names_to_one_physical_file_are_one_provider(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "lib" / "libsample.so"
            alias = root / "usr" / "lib" / "libsample.so"
            actual.parent.mkdir(parents=True)
            alias.parent.mkdir(parents=True)
            actual.write_bytes(b"ELF placeholder; make_provider is mocked")
            alias.symlink_to("../../lib/libsample.so")

            def fake_make_provider(name, logical_path, physical_path, source):
                return provider(name, physical_path, logical_path, source, abi.digest(physical_path))

            with mock.patch.object(abi, "make_provider", side_effect=fake_make_provider):
                index = abi.index_rootfs(root)

            self.assertEqual(len(index["libsample.so"]), 1)
            self.assertEqual(index["libsample.so"][0].physical_path, actual)


class LoaderPathTests(unittest.TestCase):
    def test_absolute_rpath_is_guest_rootfs_even_for_external_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capsule-root"
            root.mkdir()
            obj = provider("external.so", Path(temp) / "artifacts" / "external.so", source="LD_LIBRARY_PATH")
            self.assertEqual(
                abi.mapped_rpath_entries(obj, "/usr/lib", root),
                [root / "usr/lib"],
            )

    def test_origin_uses_actual_object_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capsule-root"
            root.mkdir()
            actual = Path(temp) / "artifacts" / "lib" / "libexternal.so"
            obj = provider("libexternal.so", actual, source="LD_LIBRARY_PATH")
            self.assertEqual(
                abi.mapped_rpath_entries(obj, "$ORIGIN", root),
                [actual.parent],
            )

    def test_origin_parent_lib_uses_actual_object_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capsule-root"
            root.mkdir()
            actual = Path(temp) / "artifacts" / "bin" / "libexternal.so"
            obj = provider("libexternal.so", actual, source="LD_LIBRARY_PATH")
            self.assertEqual(
                abi.mapped_rpath_entries(obj, "$ORIGIN/../lib", root),
                [Path(os.path.abspath(actual.parent / "../lib"))],
            )

    def test_only_explicit_artifacts_directory_is_external_search_path(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "capsule-root"
            artifacts = base / "artifacts"
            (root / "usr/lib").mkdir(parents=True)
            artifacts.mkdir()
            library = artifacts / "libsample.so"
            library.write_bytes(b"external artifact provider")
            obj_path = base / "app"
            obj_path.write_bytes(b"not parsed by choose_provider")
            obj = provider("app", obj_path, source="target")

            with mock.patch.object(abi, "elf_identity", return_value=("ELF64", "AArch64")):
                selected, _ = abi.choose_provider(
                    "libsample.so", obj, {}, [], {}, root, [artifacts], False
                )

            self.assertEqual(selected.physical_path, library.resolve())
            self.assertEqual(selected.source, "LD_LIBRARY_PATH")

    def test_origin_cannot_escape_explicit_external_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "capsule-root"
            artifacts = base / "artifacts"
            outside = base / "outside"
            root.mkdir()
            artifacts.mkdir()
            outside.mkdir()
            (outside / "libsample.so").write_bytes(b"host library must not be used")
            obj_path = artifacts / "libexternal.so"
            obj_path.write_bytes(b"external object")
            obj = provider("libexternal.so", obj_path, source="LD_LIBRARY_PATH")

            with self.assertRaisesRegex(abi.AuditError, "outside the Capsule rootfs"):
                abi.choose_provider(
                    "libsample.so",
                    obj,
                    {"RPATH": "$ORIGIN/../outside"},
                    [],
                    {},
                    root,
                    [artifacts],
                    False,
                )


if __name__ == "__main__":
    unittest.main()
