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

    def test_only_exact_approved_artifact_is_external_provider(self):
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
                    "libsample.so", obj, {"RUNPATH": "$ORIGIN/artifacts"}, [], {},
                    root, {library.resolve()}, False
                )

            self.assertEqual(selected.physical_path, library.resolve())
            self.assertEqual(selected.source, "explicit-library")

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

            with self.assertRaisesRegex(abi.AuditError, "not an explicitly approved file"):
                abi.choose_provider(
                    "libsample.so",
                    obj,
                    {"RPATH": "$ORIGIN/../outside"},
                    [],
                    {},
                    root,
                    {obj_path.resolve()},
                    False,
                )

    @unittest.skipUnless(os.name == "posix", "Bazel solib symlink behavior is exercised on Linux runner")
    def test_bazel_solib_symlink_to_exact_approved_library_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "rootfs"
            root.mkdir()
            artifacts = base / "artifacts"
            artifacts.mkdir()
            approved = artifacts / "libtensorflowlite_c.so"
            approved.write_bytes(b"approved shared object")
            solib = base / "_solib_aarch64"
            solib.mkdir()
            alias = solib / "libtensorflowlite_c.so"
            alias.symlink_to(approved)
            obj_path = artifacts / "tflite_smoke"
            obj_path.write_bytes(b"smoke executable")
            obj = provider("tflite_smoke", obj_path, source="target")

            with mock.patch.object(abi, "elf_identity", return_value=("ELF64", "AArch64")):
                selected, _ = abi.choose_provider(
                    "libtensorflowlite_c.so", obj, {"RUNPATH": "$ORIGIN/../_solib_aarch64"}, [], {},
                    root, {approved.resolve()}, False
                )

            self.assertEqual(selected.physical_path, approved.resolve())
            self.assertEqual(selected.source, "explicit-library")

    @unittest.skipUnless(os.name == "posix", "symlink behavior is exercised on Linux runner")
    def test_bazel_solib_symlink_to_unrelated_library_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "rootfs"
            root.mkdir()
            artifacts = base / "artifacts"
            artifacts.mkdir()
            approved = artifacts / "libtensorflowlite_c.so"
            approved.write_bytes(b"approved")
            unrelated = base / "libunrelated.so"
            unrelated.write_bytes(b"host or unexpected provider")
            solib = base / "_solib_aarch64"
            solib.mkdir()
            (solib / "libunrelated.so").symlink_to(unrelated)
            obj_path = artifacts / "app"
            obj_path.write_bytes(b"app")
            obj = provider("app", obj_path, source="target")

            with self.assertRaisesRegex(abi.AuditError, "not an explicitly approved file"):
                abi.choose_provider(
                    "libunrelated.so", obj, {"RUNPATH": "$ORIGIN/../_solib_aarch64"}, [], {},
                    root, {approved.resolve()}, False
                )

    def test_host_ubuntu_library_is_rejected_even_when_path_is_explicitly_resolved(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "rootfs"
            root.mkdir()
            artifacts = base / "artifacts"
            artifacts.mkdir()
            host_lib = base / "artifacts/usr/lib/libc.so.6"
            host_lib.parent.mkdir(parents=True)
            host_lib.write_bytes(b"host Ubuntu libc")
            obj_path = artifacts / "app"
            obj_path.write_bytes(b"app")
            obj = provider("app", obj_path, source="target")

            with self.assertRaisesRegex(abi.AuditError, "not an explicitly approved file"):
                abi.choose_provider(
                    "libc.so.6", obj, {"RUNPATH": "$ORIGIN/usr/lib"}, [], {},
                    root, set(), False
                )

    def test_absent_runner_workspace_path_is_reported_and_not_searched_for_host_libs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "rootfs"
            root.mkdir()
            obj_path = base / "workspace/artifacts/libtensorflowlite_c.so"
            obj_path.parent.mkdir(parents=True)
            obj_path.write_bytes(b"target")
            obj = provider("libtensorflowlite_c.so", obj_path, source="target")
            diagnostics = []
            provider_path = root / "usr/lib/libsample.so"
            provider_path.parent.mkdir(parents=True)
            provider_path.write_bytes(b"Capsule library")
            fallback = provider("libsample.so", provider_path)
            with mock.patch.object(abi, "elf_identity", return_value=("ELF64", "AArch64")):
                selected, _ = abi.choose_provider(
                    "libsample.so", obj, {"RUNPATH": "$ORIGIN/.."}, [],
                    {"libsample.so": [fallback]}, root, set(), False, diagnostics
                )
            self.assertEqual(selected.source, "rootfs")
            self.assertTrue(any("canonical=" in line and "object-relative" in line for line in diagnostics))
            self.assertTrue(any("SKIP external miss" in line for line in diagnostics))


if __name__ == "__main__":
    unittest.main()
