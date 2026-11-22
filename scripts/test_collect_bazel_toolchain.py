#!/usr/bin/env python3
"""Regression tests for the Bazel JSONPROTO toolchain diagnostics path."""

import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
FIXTURE = SCRIPTS / "fixtures" / "actiongraph-sample.json"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module("collect_bazel_toolchain", "collect-bazel-toolchain.py")
sanitizer = load_module("sanitize_toolchain_report", "sanitize-toolchain-report.py")


def fixture_graph():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class JsonProtoCollectorTests(unittest.TestCase):
    def test_fixture_matches_observed_actiongraph_container_shape(self):
        document = fixture_graph()
        self.assertEqual(set(document), {"actions", "artifacts", "configuration", "depSetOfFiles", "pathFragments", "ruleClasses", "targets"})
        action = document["actions"][0]
        self.assertIsInstance(action["mnemonic"], str)
        self.assertIsInstance(action["targetId"], int)
        self.assertIsInstance(action["arguments"], list)
        self.assertIsInstance(action["environmentVariables"][0], dict)
        self.assertIsInstance(action["configurationId"], int)
        self.assertIsInstance(action["paramFiles"][0]["arguments"], list)

    def test_target_mapping_and_root_library_link_selection(self):
        actions, errors, labels = collector.validate_action_graph(fixture_graph())
        links, groups = collector.select_actions(actions, "library")
        self.assertEqual(errors, [])
        self.assertEqual(labels[1], "//tensorflow/lite/c:libtensorflowlite_c.so")
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["target"], collector.ROOT_LINK_LABELS["library"])
        self.assertNotEqual(links[0]["target_id"], 2)
        self.assertEqual(sum(count for _, _, count in groups), 1)

    def test_smoke_compile_and_link_selection(self):
        actions, errors, _ = collector.validate_action_graph(fixture_graph())
        links, groups = collector.select_actions(actions, "smoke")
        self.assertEqual(errors, [])
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["target"], collector.ROOT_LINK_LABELS["smoke"])
        self.assertEqual(sum(count for _, _, count in groups), 2)
        self.assertEqual(len(groups), 1)

    def test_exact_argv_boundaries_are_not_shell_split(self):
        actions, errors, _ = collector.validate_action_graph(fixture_graph())
        argv = actions["CppCompile"][0]["argv"]
        self.assertEqual(errors, [])
        self.assertIn("-DNAME=value with spaces", argv)
        self.assertNotIn("-DNAME=value", argv)
        self.assertNotIn("spaces", argv)

    def test_param_file_is_expanded_in_place(self):
        actions, errors, _ = collector.validate_action_graph(fixture_graph())
        argv = actions["CppCompile"][0]["argv"]
        self.assertEqual(errors, [])
        self.assertLess(argv.index("--sysroot"), argv.index("-march=armv8-a"))
        self.assertLess(argv.index("-march=armv8-a"), argv.index("-c"))
        self.assertEqual(actions["CppCompile"][0]["param_file_status"], "RESOLVED")

    def test_nested_response_records_and_argument_quoting(self):
        expanded, errors = collector.expand_jsonproto_param_files(["cc", "@outer"], {
            "outer": ["-DNAME=one value", "@inner"], "inner": ["--sysroot=/sys"]})
        self.assertEqual(errors, [])
        self.assertEqual(expanded, ["cc", "-DNAME=one value", "--sysroot=/sys"])
        separated, errors = collector.expand_jsonproto_param_files(
            ["cc", "--param_file", "outer"], {"outer": ["-c", "source file.c"]})
        self.assertEqual(errors, [])
        self.assertEqual(separated, ["cc", "-c", "source file.c"])

    def test_missing_cycle_and_depth_limited_response_records_fail_closed(self):
        _, missing = collector.expand_jsonproto_param_files(["cc", "@missing"], {})
        self.assertTrue(missing)
        _, cycle = collector.expand_jsonproto_param_files(["cc", "@a"], {"a": ["@b"], "b": ["@a"]})
        self.assertTrue(any("cycle" in item for item in cycle))
        nested = {f"p{i}": [f"@p{i + 1}"] for i in range(10)}
        nested["p10"] = ["-c"]
        _, deep = collector.expand_jsonproto_param_files(["cc", "@p0"], nested, max_depth=3)
        self.assertTrue(any("depth" in item for item in deep))

    def test_unreferenced_param_records_are_not_appended_or_claimed_complete(self):
        graph = fixture_graph()
        graph["actions"][0]["arguments"].remove("@bazel-out/k8-fastbuild/bin/lib_unit.params")
        actions, errors, _ = collector.validate_action_graph(graph)
        self.assertEqual(errors, [])
        action = actions["CppCompile"][0]
        self.assertEqual(action["argv"][-1], "obj/lib_unit.o")
        self.assertEqual(action["param_file_unreferenced_count"], 1)
        self.assertIn("NOT RESOLVED", action["param_file_status"])

    def test_structured_environment_records(self):
        actions, errors, _ = collector.validate_action_graph(fixture_graph())
        self.assertEqual(errors, [])
        self.assertEqual(actions["CppCompile"][0]["environment"]["SYSROOT"], "/synthetic/sysroot")
        self.assertTrue(actions["CppCompile"][0]["env_captured"])

    def test_sysroot_flag_forms(self):
        self.assertEqual(collector.extract_sysroots(["cc", "--sysroot", "/a", "--sysroot=/b", "-isysroot", "/c", "-isysroot/d", "-isysroot=/e"]), ["/a", "/b", "-isysroot /c", "/d", "/e"])

    def test_different_toolchain_signatures_form_distinct_groups(self):
        graph = fixture_graph()
        second = json.loads(json.dumps(graph["actions"][0]))
        second["targetId"] = 2
        second["actionKey"] = "different-toolchain-signature"
        second["arguments"].append("-mcpu=different")
        graph["actions"].append(second)
        actions, errors, _ = collector.validate_action_graph(graph)
        _, groups = collector.select_actions(actions, "library")
        self.assertEqual(errors, [])
        self.assertEqual(len(groups), 2)

    def test_malformed_action_field_is_reported_not_dropped_silently(self):
        graph = fixture_graph()
        graph["actions"][0]["arguments"] = "compiler -c unit.c"
        actions, errors, _ = collector.validate_action_graph(graph)
        self.assertTrue(any("arguments" in error for error in errors))
        self.assertEqual(len(actions["CppCompile"]), 2)

    def test_malformed_json_and_param_records_are_rejected(self):
        with self.assertRaises(json.JSONDecodeError):
            collector.parse_action_graph('{"actions":')
        graph = fixture_graph()
        graph["actions"][0]["paramFiles"] = [{"execPath": "bad.rsp", "arguments": "not-an-array"}]
        actions, errors, _ = collector.validate_action_graph(graph)
        self.assertTrue(any("paramFiles" in error for error in errors))
        self.assertEqual(len(actions["CppCompile"]), 2)

    def test_missing_fields_empty_actions_and_unknown_target_id(self):
        with self.assertRaises(ValueError):
            collector.validate_action_graph({"actions": []})
        empty, errors, _ = collector.validate_action_graph({"actions": [], "targets": []})
        self.assertEqual(empty["CppLink"], [])
        self.assertEqual(errors, [])
        graph = fixture_graph()
        graph["actions"][0]["targetId"] = 987654
        _, errors, _ = collector.validate_action_graph(graph)
        self.assertTrue(any("unknown targetId" in error for error in errors))

    def test_empty_graph_has_no_selected_root_actions(self):
        actions, _, _ = collector.validate_action_graph({"actions": [], "targets": []})
        links, compiles = collector.select_actions(actions, "library")
        self.assertEqual(links, [])
        self.assertEqual(compiles, [])


class IntegrationAndSecurityTests(unittest.TestCase):
    def test_wrapper_dry_run_identifies_compiler(self):
        self.assertEqual(collector.compiler_tokens_from_dry_run('COLLECT_GCC="/opt/cross/bin/aarch64-linux-gnu-gcc"\n'), ["/opt/cross/bin/aarch64-linux-gnu-gcc"])

    def test_actual_linker_requires_direct_dry_run_evidence(self):
        path = "/tool/bin/aarch64-linux-gnu-ld"
        dry_run = 'COLLECT_GCC="/tool/bin/aarch64-linux-gnu-g++"\n/tool/libexec/collect2 -o smoke\n' + path + " -o smoke\n"
        result = collector.linker_selection_from_dry_run(dry_run, path, lambda token: path if token == path else None)
        self.assertEqual(result["selected"], path)
        self.assertEqual(len(result["helpers"]), 1)
        no_proof = collector.linker_selection_from_dry_run("COLLECT_GCC=compiler\ncollect2 -o smoke\n", path, lambda _: path)
        self.assertIsNone(no_proof["selected"])

    def test_production_wrapper_resolution_uses_dry_run_compiler_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper = root / "cc_wrapper"
            compiler = root / "aarch64-linux-gnu-gcc"
            wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            compiler.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            wrapper.chmod(0o755)
            compiler.chmod(0o755)
            previous = collector.run
            collector.run = lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0], 0, stdout=f'COLLECT_GCC="{compiler}"\n')
            try:
                actual, result, evidence, tokens = collector.discover_actual_compiler(
                    wrapper, [str(wrapper), "-c", "source.c"], {}, root, root, root, root, [root]
                )
            finally:
                collector.run = previous
        self.assertEqual(actual, compiler.resolve())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(evidence, "wrapper dry-run")
        self.assertEqual(tokens, [str(compiler)])

    def test_library_and_smoke_errors_are_independent_in_production_loop(self):
        script = (SCRIPTS / "collect-diagnostics.sh").read_text(encoding="utf-8")
        self.assertIn("for name in library smoke; do", script)
        self.assertIn('actions="$private_diagnostics/actions-$name.json"', script)
        self.assertIn('action_stderr="$private_diagnostics/actions-$name.stderr"', script)
        self.assertIn("--output=jsonproto --include_param_files", script)
        self.assertNotIn("--output=text", script)
        self.assertIn('"$collector_output_base" "$report" "$name"', script)
        self.assertIn('fail_diagnostic "$name JSONPROTO query (exit=$rc)"', script)
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash unavailable; full shell regression runs on Ubuntu Actions runner")
        function_defs = []
        for name in ("fail_diagnostic", "attempt_command"):
            match = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}", script)
            self.assertIsNotNone(match, f"production {name} function not found")
            function_defs.append(match.group(0))
        harness = "\n".join(function_defs) + "\n" + (
            "diagnostic_status=0; target_probe(){ if [[ $1 == library ]]; then return 23; "
            "else echo DIAGNOSED:$1; fi; }; "
            "attempt_command library target_probe library; attempt_command smoke target_probe smoke; "
            "[[ $diagnostic_status == 1 ]]"
        )
        completed = subprocess.run([bash, "-c", harness], text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("DIAGNOSED:smoke", completed.stdout)

    def test_workflow_uploads_allowlisted_sanitized_outputs_only(self):
        workflow = (SCRIPTS.parent / ".github/workflows/diagnose-bazel-jsonproto.yml").read_text(encoding="utf-8")
        self.assertIn("artifacts/toolchain-library-sanitized.txt", workflow)
        self.assertIn("artifacts/toolchain-smoke-sanitized.txt", workflow)
        self.assertIn("artifacts/SHA256SUMS", workflow)
        self.assertIn("bash ./scripts/prepare-capsule-rootfs.sh", workflow)
        self.assertNotIn("actions-library.json", workflow)
        self.assertNotIn("actions-smoke.json", workflow)
        self.assertIn("work/private-diagnostics", workflow)
        upload = workflow.split("- name: Upload validated structural and sanitized reports", 1)[1].split("- name:", 1)[0]
        self.assertIn("artifacts/bazel-jsonproto-structure-report.txt", upload)
        self.assertNotIn("work/", upload)

    def test_sanitizer_allowlist_redacts_actions_paths_and_secrets(self):
        private = """Bazel C++ toolchain diagnostic
external_repository[aarch64_linux_toolchain]=/home/runner/private/toolchain
action_selection_compile_total=1476
compile_configuration_consistency=CONSISTENT
[CppCompile #1]
  action_target=//pkg:target
  action_source=Bazel 6.5.0 JSONPROTO Cpp action
  action_target_id=42
  action_configuration_id=7
  action_launcher_token=/home/runner/private/toolchain/bin/aarch64-gcc
  compiler_resolution_status=RESOLVED: wrapper dry-run
  actual_compiler=/home/runner/private/toolchain/bin/aarch64-gcc
  explicit_action_sysroot_arguments=['/home/runner/private/sysroot']
  action_env[PATH]=/private/path; ACTION_SECRET=long-private-value
raw_json={"arguments":["/private/secret"]}
raw_command=/home/runner/private/cc --token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
raw_bearer=Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
response_file_contents=private data
"""
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "private.txt", Path(directory) / "public.txt"
            source.write_text(private, encoding="utf-8")
            sanitizer.sanitize(source, destination)
            public = destination.read_text(encoding="utf-8")
        self.assertIn("action_target=//pkg:target", public)
        self.assertIn("compiler_resolution_status=RESOLVED", public)
        self.assertIn("action_launcher_token_executable=aarch64-gcc", public)
        self.assertIn("actual_compiler_executable=aarch64-gcc", public)
        for secret in ("/home/runner/", "ACTION_SECRET", "raw_json", "raw_command", "ghp_", "Bearer", "response_file_contents", "private data", "action_env[PATH]"):
            self.assertNotIn(secret, public)


if __name__ == "__main__":
    unittest.main()
