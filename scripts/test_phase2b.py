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

    def test_foreign_second_link_input_is_fatal_even_when_expected_provider_is_present(self):
        sdk = Path("/sdk")
        for name in ("libstdc++.so.6.0.29", "crt1.o", "libgcc_s.so.1", "libc-2.35.so", "libpthread.a"):
            build.p2.check_system_link_input(sdk / name, sdk)
            with self.assertRaises(ValueError):
                build.p2.check_system_link_input(Path("/old") / name, sdk)

    def test_six_member_manifest_and_candidate_leak_detection(self):
        import hashlib
        import io
        import zipfile
        files = {name: b"public\n" for name in (build.p2.REPORT, *build.EXTRA, *build.public.TOOLCHAINS)}
        def verify(unexpected=False, corrupt=False):
            entries = files.copy()
            entries["SHA256SUMS"] = "".join(
                f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items()).encode()
            if unexpected:
                entries["work/private-diagnostics/actions.json"] = b"x"
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as out:
                for name, data in entries.items():
                    out.writestr(name, data)
            data = archive.getvalue()
            digest = "sha256:" + ("0" * 64 if corrupt else hashlib.sha256(data).hexdigest())
            with tempfile.TemporaryDirectory() as tmp:
                build.public.verify_zip(data, digest, Path(tmp), structure=build.p2.REPORT,
                                        extra_files=build.EXTRA, validate_structure=lambda p: self.assertEqual(p.read_bytes(), b"public\n"))
        verify()
        for options in ({"corrupt": True}, {"unexpected": True}):
            with self.assertRaises(ValueError):
                verify(**options)
        for private in (b"raw_command=foo", b"/home/runner/work/execution-root", b"github_pat_secret"):
            files[build.public.TOOLCHAINS[0]] = private
            with self.assertRaises(ValueError):
                verify()


    def test_compiler_sysroot_channel_and_directory_identity(self):
        collector = build.load("collect-bazel-toolchain.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sysroot = root / "sysroot"
            sysroot.mkdir()
            alias = root / "alias"
            alias.symlink_to(sysroot)
            def check(path, warn):
                compiler = root / "probe"
                compiler.write_text("#!/bin/sh\ncase \"$1\" in\n"
                                    "-dumpfullversion) echo 10.3.1;;\n-dumpmachine) echo aarch64-none-linux-gnu;;\n"
                                    f"-dumpspecs) echo specs;;\n-print-sysroot) echo '{path}'; {warn} >&2;;\n"
                                    "-\\#\\#\\#) echo '/bin/collect2 -o dummy';;\nesac\n")
                compiler.chmod(0o700)
                return collector.compare_tf2_probes(compiler, [str(compiler)], {"TF2_BEHAVIOR": "1"},
                                                    root, str(sysroot), gcc_version="10.3.1")
            self.assertTrue(check(alias, "echo warning"))
            self.assertFalse(check(root, "echo warning"))
            self.assertFalse(check(alias, 'echo "$TF2_BEHAVIOR"'))


    def test_assembler_only_plan_bound_to_pinned_sdk(self):
        collector = build.load("collect-bazel-toolchain.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sdk = root / "sdk"
            tools = sdk / "bin"
            tools.mkdir(parents=True)
            driver = tools / "aarch64-none-linux-gnu-gcc"
            expected = tools / "aarch64-none-linux-gnu-as"
            expected.write_bytes(b"known")
            alias = sdk / "as"
            alias.write_bytes(b"known")
            foreign = root / "as"
            foreign.write_bytes(b"known")
            for exe, valid in ((expected, True), (alias, True), (foreign, False)):
                self.assertEqual(collector.pinned_assembler_plan(f' "{exe}" -o src.o src.s', driver, root), valid)
            alias.write_bytes(b"other")
            self.assertFalse(collector.pinned_assembler_plan(f' "{alias}" -o src.o src.s', driver, root))

    def test_real_checksum_rejection(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "candidate"
            archive.write_bytes(b"wrong archive")
            result = subprocess.run(["sha256sum", "--check", "--strict"], input=f"{build.ARCHIVE_SHA}  {archive}\n",
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_build_events_require_complete_exact_execution_evidence(self):
        import json
        collector = build.load("collect-bazel-toolchain.py")
        graph = [{"argv": ["gcc", "-c", src]} for src in ("used.c", "analysis-only.c")]
        event = {"action": {"type": "CppCompile", "success": True, "commandLine": graph[0]["argv"]}}
        end = {"finished": {"exitCode": {"name": "SUCCESS"}}}
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "events"
            def check(records):
                f.write_text("\n".join(json.dumps(row) for row in records))
                return collector.executed_compiles(graph, f)
            self.assertEqual(check([event, end]), graph[:1])
            for records in ([event], [end], [{"action": dict(event["action"], commandLine=["gcc", "-c", "other.c"])}, end]):
                with self.assertRaises(ValueError):
                    check(records)

    def test_gcc_probes_restore_only_original_missing_source_aliases(self):
        collector = build.load("collect-bazel-toolchain.py")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ex, base, tf = (root / name for name in ("execroot", "base", "tensorflow"))
            ex.mkdir()
            tf.mkdir()
            rel = Path("external/dep/kernel.S")
            (base / rel).parent.mkdir(parents=True)
            (base / rel).write_bytes(b"assembly")
            (ex / "external").mkdir()
            collector.restore_probe_sources(["gcc", "-c", str(rel)], ex, tf, base)
            self.assertTrue((ex / rel).samefile(base / rel))
            with self.assertRaises(ValueError):
                collector.restore_probe_sources(["gcc", "-c", "external/dep/missing.S"], ex, tf, base)
            with self.assertRaises(ValueError):
                collector.restore_probe_sources(["gcc", "-c", "bazel-out/generated.c"], ex, tf, base)

    def test_guest_opens_require_guest_path_and_all_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "guest"
            root.mkdir()
            headers = b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\0"
            lib = root / "libc-2.33.so"
            lib.write_bytes(headers)
            exe = Path(tmp) / "smoke"
            exe.write_bytes(headers + b"smoke")
            foreign = Path(tmp) / "other"
            foreign.write_bytes(headers)
            expected = {p: build.abi.digest(p) for p in (lib, exe)}
            def check(paths):
                log = "\n".join(f'123 openat(AT_FDCWD, "name", O_RDONLY) = 3<{p}>' for p in paths)
                build.verify_guest_opens(log, expected, root, {exe})
            check([exe, lib])
            for paths in ([exe], [exe, foreign], [exe, lib, foreign]):
                with self.assertRaises(ValueError):
                    check(paths)
            lib.write_bytes(headers + b"changed")
            with self.assertRaises(ValueError):
                check([exe, lib])


if __name__ == "__main__":
    unittest.main()
