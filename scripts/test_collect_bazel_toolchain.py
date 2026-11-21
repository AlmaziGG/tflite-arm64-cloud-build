#!/usr/bin/env python3
"""Local regression tests for private Bazel toolchain diagnostics."""

import importlib.util
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module("collect_bazel_toolchain", "collect-bazel-toolchain.py")
sanitizer = load_module("sanitize_toolchain_report", "sanitize-toolchain-report.py")


class CollectorTests(unittest.TestCase):
    def test_compile_and_link_actions_are_parsed_separately(self):
        fixture = """action 'compile':
  Mnemonic: CppCompile
  Target: //tensorflow/lite/c:sample
  Command Line: (exec /tool/bin/aarch64-gcc -c source.c)
  Environment Variables:
    PATH=/tool/bin

action 'link':
  Mnemonic: CppLink
  Target: //tensorflow/lite/c:sample
  Command Line: (exec /tool/bin/aarch64-g++ @link.params)
"""
        actions = collector.split_actions(fixture)
        self.assertEqual(len(actions["CppCompile"]), 1)
        self.assertEqual(len(actions["CppLink"]), 1)
        self.assertEqual(actions["CppCompile"][0]["argv"][0], "/tool/bin/aarch64-gcc")
        self.assertEqual(actions["CppLink"][0]["argv"][-1], "@link.params")
        self.assertEqual(actions["CppCompile"][0]["target"], "//tensorflow/lite/c:sample")

    def test_response_files_and_sysroot_forms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "args.rsp").write_text('--sysroot="/capsule/sysroot" -isysroot /capsule/sdk -c x.c')
            expanded, missing = collector.expand_response_files(
                ["compiler", "@args.rsp"], root, root, root
            )
        self.assertEqual(missing, [])
        self.assertEqual(
            collector.extract_sysroots(expanded),
            ["/capsule/sysroot", "-isysroot /capsule/sdk"],
        )

    def test_absent_and_unresolved_response_file_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expanded, missing = collector.expand_response_files(["cc", "@missing.rsp"], root, root, root)
        self.assertEqual(missing, ["missing.rsp"])
        self.assertEqual(collector.extract_sysroots(["cc", "-c", "x.c"]), [])

    def test_wrapper_dry_run_identifies_compiler_token(self):
        output = 'COLLECT_GCC="/opt/cross/bin/aarch64-linux-gnu-gcc"\n'
        self.assertEqual(
            collector.compiler_tokens_from_dry_run(output),
            ["/opt/cross/bin/aarch64-linux-gnu-gcc"],
        )

    def test_actual_linker_is_resolved_from_driver_dry_run(self):
        dry_run = '''COLLECT_GCC="/tool/bin/aarch64-linux-gnu-g++"
/tool/libexec/gcc/aarch64-linux-gnu/11/collect2 -plugin /tool/plugin.so
 /tool/bin/aarch64-linux-gnu-ld -plugin /tool/plugin.so -o smoke
'''
        known = {
            "/tool/bin/aarch64-linux-gnu-ld": "/tool/bin/aarch64-linux-gnu-ld",
        }
        selection = collector.linker_selection_from_dry_run(
            dry_run,
            "/tool/bin/aarch64-linux-gnu-ld",
            lambda token: known.get(token),
        )
        self.assertEqual(selection["selected"], "/tool/bin/aarch64-linux-gnu-ld")
        self.assertEqual(selection["reason"], "unique direct linker executable in compiler-driver dry-run")
        self.assertEqual(len(selection["helpers"]), 1)
        self.assertIn("collect2", selection["helpers"][0])

    def test_linker_candidate_alone_does_not_prove_selection(self):
        selection = collector.linker_selection_from_dry_run(
            "COLLECT_GCC=compiler\ncollect2 -o smoke\n",
            "/tool/bin/ld",
            lambda token: "/tool/bin/ld" if token == "/tool/bin/ld" else None,
        )
        self.assertIsNone(selection["selected"])
        self.assertEqual(selection["reason"], "no direct linker command found in compiler-driver dry-run")

    def test_library_failure_does_not_prevent_smoke_diagnostic_attempt(self):
        diagnostics_script = (SCRIPTS / "collect-diagnostics.sh").read_text(encoding="utf-8")
        target_loop = re.search(
            r"for target in (?P<targets>.*?)\s*;\s*do(?P<body>.*?)\ndone",
            diagnostics_script,
            re.DOTALL,
        )
        self.assertIsNotNone(target_loop, "production diagnostics loop must include both targets")
        targets = re.findall(r"'([^']+)'", target_loop.group("targets"))
        self.assertEqual(targets, [
            "//tensorflow/lite/c:libtensorflowlite_c.so",
            "//tensorflow/lite/c/cloud_smoke:tflite_smoke",
        ])
        self.assertIn('attempt_command "Bazel toolchain collector for $name"', target_loop.group("body"))

        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is unavailable; this integration regression runs on the Ubuntu Actions runner")
        function_defs = []
        for name in ("fail_diagnostic", "attempt_command"):
            found = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}", diagnostics_script)
            self.assertIsNotNone(found, f"production {name} function must remain available")
            function_defs.append(found.group(0))
        harness = "\n".join(function_defs) + r'''
diagnostic_status=0
attempt_target() {
  if [[ "$1" == library ]]; then return 23; fi
  printf 'DIAGNOSED:%s\n' "$1"
}
attempt_command library attempt_target library
attempt_command smoke attempt_target smoke
[[ "$diagnostic_status" -eq 1 ]]
'''
        completed = subprocess.run([bash, "-c", harness], text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("DIAGNOSTIC FAILURE: library (exit=23)", completed.stderr)
        self.assertIn("DIAGNOSED:smoke", completed.stdout)

    def test_public_artifact_contains_only_sanitized_target_reports(self):
        workflow = (SCRIPTS.parent / ".github/workflows/build-tflite-arm64.yml").read_text(encoding="utf-8")
        diagnostics = (SCRIPTS / "collect-diagnostics.sh").read_text(encoding="utf-8")
        finalizer = (SCRIPTS / "finalize.sh").read_text(encoding="utf-8")
        self.assertIn("artifacts/toolchain-library-sanitized.txt", workflow)
        self.assertIn("artifacts/toolchain-smoke-sanitized.txt", workflow)
        self.assertNotIn("actions-library.txt", workflow)
        self.assertNotIn("actions-smoke.txt", workflow)
        self.assertIn('private_diagnostics="$WORK/private-diagnostics"', diagnostics)
        self.assertIn('actions="$private_diagnostics/actions-$name.txt"', diagnostics)
        self.assertIn('report="$private_diagnostics/toolchain-$name.txt"', diagnostics)
        self.assertIn('public_report="$ARTIFACTS/toolchain-$name-sanitized.txt"', diagnostics)
        self.assertNotIn("toolchain-library.txt", workflow)
        self.assertNotIn("toolchain-smoke.txt", workflow)
        self.assertIn("toolchain-library-sanitized.txt", finalizer)
        self.assertIn("toolchain-smoke-sanitized.txt", finalizer)
        self.assertNotIn("actions-library.txt", finalizer)
        self.assertNotIn("actions-smoke.txt", finalizer)
        self.assertNotIn("toolchain-library.txt", finalizer)
        self.assertNotIn("toolchain-smoke.txt", finalizer)

    def test_malformed_action_is_reported_not_dropped(self):
        fixture = """action 'bad':
  Mnemonic: CppCompile
  Command Line: (exec compiler -DNAME=\"unterminated)
"""
        action = collector.split_actions(fixture)["CppCompile"][0]
        self.assertIn("parse_error", action)
        self.assertEqual(action["argv"], [])

    def test_public_projection_omits_commands_and_redacts_secrets(self):
        private = """Bazel C++ toolchain diagnostic
external_repository[aarch64_linux_toolchain]=/runner/toolchain
[CppCompile #1]
  action_target=//pkg:target
  compiler_resolution_status=NOT RESOLVED: wrapper dry-run failed
action_dump=environment ACTION_SECRET=long-private-value
raw_command=/runner/private/cc --token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
raw_bearer=Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
private_action=/runner/private/actions-library.txt
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "private.txt", root / "public.txt"
            source.write_text(private)
            sanitizer.sanitize(source, destination)
            result = destination.read_text()
        self.assertIn("action_target=//pkg:target", result)
        self.assertIn("compiler_resolution_status=NOT RESOLVED", result)
        self.assertNotIn("raw_command", result)
        self.assertNotIn("action_dump", result)
        self.assertNotIn("private_action", result)
        self.assertNotIn("ACTION_SECRET", result)
        self.assertNotIn("ghp_", result)
        self.assertNotIn("Bearer", result)
        self.assertNotIn("aaaaaaaa", result)


if __name__ == "__main__":
    unittest.main()
