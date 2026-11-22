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


def target_graph(target_name):
    graph = fixture_graph()
    target_ids = {1, 2} if target_name == "library" else {3, 4}
    graph["actions"] = [action for action in graph["actions"] if action["targetId"] in target_ids]
    graph["targets"] = [target for target in graph["targets"] if target["id"] in target_ids]
    return graph


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
        actions, errors, labels = collector.validate_action_graph(target_graph("library"))
        links, groups = collector.select_actions(actions, "library")
        self.assertEqual(errors, [])
        self.assertEqual(labels[1], "//tensorflow/lite/c:libtensorflowlite_c.so")
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["target"], collector.ROOT_LINK_LABELS["library"])
        self.assertNotEqual(links[0]["target_id"], 2)
        self.assertEqual(sum(count for _, _, count in groups), 1)

    def test_smoke_compile_and_link_selection(self):
        actions, errors, _ = collector.validate_action_graph(target_graph("smoke"))
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
        self.assertLess(argv.index("-c"), argv.index("--sysroot"))
        self.assertLess(argv.index("--sysroot"), argv.index("-march=armv8-a"))
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
        graph = target_graph("library")
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

    def test_action_replay_uses_captured_environment_without_runner_leakage(self):
        replay = collector.action_environment_for_replay(
            {"PATH": "/pinned/tool/bin", "LANG": "C", "PRIVATE_TOKEN": "secret"},
            {"PATH": "/action/bin", "SDKROOT": "/action/sdk"},
            captured=True, clear_environment=False)
        self.assertEqual(replay, {"PATH": "/action/bin", "LANG": "C", "PRIVATE_TOKEN": "secret", "SDKROOT": "/action/sdk"})
        isolated = collector.action_environment_for_replay(
            {"PATH": "/ignored", "RUNNER_SECRET": "never-inherit"},
            {"PATH": "/explicit/bin", "REMOVE_ME": "<UNSET>"},
            captured=False, clear_environment=True)
        self.assertEqual(isolated, {"PATH": "/explicit/bin"})
        unknown = collector.action_environment_for_replay(
            None, {"CUSTOM": "value"}, captured=False, clear_environment=False)
        self.assertEqual(unknown, {"CUSTOM": "value"})

    def test_actual_linker_requires_direct_dry_run_evidence(self):
        path = "/tool/bin/aarch64-linux-gnu-ld"
        dry_run = 'COLLECT_GCC="/tool/bin/aarch64-linux-gnu-g++"\n/tool/libexec/collect2 -o smoke\n' + path + " -o smoke\n"
        result = collector.linker_selection_from_dry_run(dry_run, path, lambda token: path if token == path else None)
        self.assertEqual(result["selected"], path)
        self.assertEqual(len(result["helpers"]), 1)
        no_proof = collector.linker_selection_from_dry_run("COLLECT_GCC=compiler\ncollect2 -o smoke\n", path, lambda _: path)
        self.assertIsNone(no_proof["selected"])

    def test_execve_trace_proves_actual_linker_after_collect2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collect2 = root / "collect2"
            linker = root / "aarch64-none-linux-gnu-ld"
            for path in (collect2, linker):
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            trace = (f'execve("{collect2}", ["collect2"], 0x0, 0) = 0\n'
                     f'execve("{linker}", ["{linker}"], 0x0, 0) = 0\n')
            result = collector.resolve_linker_from_execve_trace(trace, root)
        self.assertEqual(result["selected"], str(linker.resolve()))
        self.assertEqual(result["helpers"], [str(collect2)])

    def test_collect2_candidate_alone_does_not_prove_linker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collect2 = root / "collect2"
            collect2.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            collect2.chmod(0o755)
            result = collector.resolve_linker_from_execve_trace(
                f'execve("{collect2}", ["collect2"], 0x0, 0) = 0\n', root)
        self.assertIsNone(result["selected"])
        self.assertIn("no recognized linker", result["reason"])

    def test_trace_rejects_ambiguous_and_unrecognized_linker_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second, unknown = (root / "aarch64-linux-ld", root / "ld.lld", root / "mystery-link")
            for path in (first, second, unknown):
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            ambiguous = (f'execve("{first}", [], 0x0, 0) = 0\n'
                         f'execve("{second}", [], 0x0, 0) = 0\n')
            unknown_trace = f'execve("{unknown}", [], 0x0, 0) = 0\n'
            ambiguous_result = collector.resolve_linker_from_execve_trace(ambiguous, root)
            unknown_result = collector.resolve_linker_from_execve_trace(unknown_trace, root)
        self.assertIsNone(ambiguous_result["selected"])
        self.assertIn("multiple distinct", ambiguous_result["reason"])
        self.assertIsNone(unknown_result["selected"])

    def test_execve_parser_ignores_failed_exec_attempts(self):
        trace = 'execve("/missing/ld", [], 0x0, 0) = -1 ENOENT (No such file)\n'
        self.assertEqual(collector.successful_execve_paths(trace), [])

    def test_link_output_redirect_requires_one_separated_output_operand(self):
        redirected, reason = collector.redirect_link_output(["g++", "-shared", "-o", "out.so", "a.o"], "/private/probe.so")
        self.assertEqual(redirected, ["g++", "-shared", "-o", "/private/probe.so", "a.o"])
        self.assertIn("1 recognized link output(s) redirected", reason)
        redirected_map, map_reason = collector.redirect_link_output(
            ["g++", "-o", "out", "-Wl,-Map,original.map", "a.o"], "/private/probe/probe-output")
        self.assertIn("-Wl,-Map,/private/probe/probe-extra-1.map", redirected_map)
        self.assertIn("2 recognized link output(s) redirected", map_reason)
        result, reason = collector.redirect_link_output(["g++", "-o", "a", "-o", "b"], "/private/x")
        self.assertIsNone(result)
        self.assertIn("found 2", reason)

    def test_linker_identity_and_aarch64_target_marker(self):
        self.assertEqual(collector.linker_implementation("GNU ld (GNU Binutils) 2.38", "/x/aarch64-linux-ld"), "GNU ld")
        self.assertEqual(collector.linker_implementation("LLD 17.0", "/x/ld.lld"), "LLVM LLD")
        self.assertEqual(collector.linker_implementation("unknown linker", "/x/strange"), "UNRESOLVED")
        self.assertEqual(collector.linker_target_architecture("Supported emulations: aarch64linux"), "AArch64 supported")
        self.assertEqual(collector.linker_target_architecture("Supported emulations: elf_x86_64"), "not confirmed by linker -V")

    def test_sysroot_normalizes_inside_toolchain_and_hides_outside_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "toolchain"
            inside = root / "aarch64-none-linux-gnu" / "libc"
            outside = Path(directory) / "runner" / "secret-sysroot"
            inside.mkdir(parents=True)
            outside.mkdir(parents=True)
            identity, status = collector.normalize_sysroot_identity(str(inside), {"aarch64_linux_toolchain": root})
            external_identity, external_status = collector.normalize_sysroot_identity(str(outside), {"aarch64_linux_toolchain": root})
        self.assertEqual(identity, "aarch64_linux_toolchain/aarch64-none-linux-gnu/libc")
        self.assertEqual(status, "RELATIVE_TO_PINNED_TOOLCHAIN_ROOT")
        self.assertEqual(external_identity, "basename:secret-sysroot")
        self.assertEqual(external_status, "BASENAME_ONLY_OUTSIDE_PINNED_TOOLCHAIN_ROOT")
        self.assertNotIn(str(root.parent), external_identity)

    def test_empty_default_sysroot_remains_distinct_from_missing(self):
        empty = collector.normalize_sysroot_identity("", {})
        missing = collector.normalize_sysroot_identity(None, {})
        self.assertEqual(empty, ("<empty>", "EMPTY_VALUE"))
        self.assertEqual(missing, ("<unresolved>", "NOT_RESOLVED"))

    def test_effective_sysroot_provenance_and_explicit_override(self):
        action = collector.decide_effective_sysroot([], [], True, True, [], "/configured/sysroot")
        override = collector.decide_effective_sysroot(["/action/sysroot"], [], True, True, [], "/configured/sysroot")
        self.assertEqual(action, ("/configured/sysroot", "RESOLVED", "compiler default/configuration under captured no-override action environment"))
        self.assertEqual(override, ("/action/sysroot", "RESOLVED", "JSONPROTO action arguments or matched paramFiles"))
        self.assertNotEqual(action[2], override[2])

    def test_sysroot_in_response_file_and_environment_overrides_fail_closed(self):
        actions, errors, _ = collector.validate_action_graph(fixture_graph())
        self.assertEqual(errors, [])
        rsp_paths = collector.extract_sysroot_paths(actions["CppCompile"][0]["argv"])
        self.assertEqual(rsp_paths, ["/synthetic/sysroot"])
        env_override = collector.decide_effective_sysroot([], ["SYSROOT=<private>"], True, True, [], "/default")
        unreviewed = collector.decide_effective_sysroot([], [], True, True, [], "/default", ["CUSTOM_COMPILER_MODE"])
        self.assertEqual(env_override[1], "NOT RESOLVED")
        self.assertEqual(unreviewed[1], "NOT RESOLVED")

    def test_all_explicit_sysroot_forms_are_preserved_from_effective_argv(self):
        values = collector.extract_sysroot_paths(
            ["cc", "--sysroot", "/one", "--sysroot=/two", "-isysroot", "/three", "-isysroot=/four"])
        self.assertEqual(values, ["/one", "/two", "/three", "/four"])

    def test_wrapper_dry_run_sysroot_is_separate_provenance(self):
        result = collector.decide_effective_sysroot([], [], True, False, ["/wrapper/sysroot"], "/default")
        self.assertEqual(result, ("/wrapper/sysroot", "RESOLVED", "wrapper dry-run final compiler arguments (-###)"))

    def test_default_sysroot_empty_is_resolved_but_unset_environment_is_not(self):
        empty_default = collector.decide_effective_sysroot([], [], True, True, [], "")
        missing_environment = collector.decide_effective_sysroot([], [], False, True, [], "/default")
        wrapper_unknown = collector.decide_effective_sysroot([], [], True, False, [], "/default")
        self.assertEqual(empty_default[0:2], ("", "RESOLVED"))
        self.assertEqual(missing_environment[1], "NOT RESOLVED")
        self.assertEqual(wrapper_unknown[1], "NOT RESOLVED")

    def test_unresolved_critical_diagnostics_cannot_return_success(self):
        self.assertEqual(collector.diagnostic_exit_code(0, []), 0)
        self.assertEqual(collector.diagnostic_exit_code(0, ["linker-resolution: unresolved"]), 1)
        self.assertEqual(collector.diagnostic_exit_code(1, []), 1)

    def test_sanitizer_publishes_normalized_sysroot_and_linker_identity_only(self):
        private = """[CppLink #1]
  actual_selected_linker=/home/runner/tool/bin/aarch64-none-linux-gnu-ld
  actual_linker_basename=aarch64-none-linux-gnu-ld
  actual_linker_implementation=GNU ld
  actual_linker_version=GNU ld (GNU Binutils) 2.38.20220708
  actual_linker_target_architecture=AArch64 supported
  linker_evidence=successful linker execve observed by strace while replaying captured CppLink argv with recognized outputs redirected to private paths
  linker_resolution_status=RESOLVED: actual linker executable evidence recorded
  compiler_default_sysroot_identity=aarch64_linux_toolchain/aarch64-none-linux-gnu/libc
  compiler_default_sysroot_normalization_status=RELATIVE_TO_PINNED_TOOLCHAIN_ROOT
  compiler_default_sysroot_provenance=actual compiler -print-sysroot with sysroot/compiler-selection environment overrides cleared
  effective_sysroot_identity=aarch64_linux_toolchain/aarch64-none-linux-gnu/libc
  effective_sysroot_normalization_status=RELATIVE_TO_PINNED_TOOLCHAIN_ROOT
  effective_sysroot_provenance=compiler default/configuration under captured no-override action environment
  action_env[PATH]=/home/runner/private/tool/bin
  linker_trace_private_file=/home/runner/private/raw-execve.log
"""
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "private.txt", Path(directory) / "public.txt"
            source.write_text(private, encoding="utf-8")
            sanitizer.sanitize(source, destination)
            public = destination.read_text(encoding="utf-8")
        self.assertIn("actual_linker_basename=aarch64-none-linux-gnu-ld", public)
        self.assertIn("actual_linker_implementation=GNU ld", public)
        self.assertIn("actual_linker_version=GNU ld (GNU Binutils) 2.38.20220708", public)
        self.assertIn("actual_linker_target_architecture=AArch64 supported", public)
        self.assertIn("effective_sysroot_identity=aarch64_linux_toolchain/aarch64-none-linux-gnu/libc", public)
        for forbidden in ("/home/runner/", "raw-execve", "action_env[PATH]", "private/tool"):
            self.assertNotIn(forbidden, public)

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

    def test_sanitizer_redacts_runner_paths_after_colon_in_search_dirs(self):
        private = """=== Actual compiler metadata (wrapper paths excluded) ===
$ /private/toolchain/bin/aarch64-gcc -print-search-dirs
install: /usr/lib/gcc-cross/aarch64-linux-gnu/11/
programs: =/usr/lib/gcc-cross/aarch64-linux-gnu/11/:/home/runner/work/private/gcc/bin
libraries: =/usr/lib/aarch64-linux-gnu:/home/runner/work/private/sysroot/lib
(exit=0)
"""
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "private.txt", Path(directory) / "public.txt"
            source.write_text(private, encoding="utf-8")
            sanitizer.sanitize(source, destination)
            public = destination.read_text(encoding="utf-8")
        self.assertIn("compiler_programs:", public)
        self.assertIn("compiler_libraries:", public)
        self.assertNotIn("/home/runner/", public)
        self.assertNotIn("/private/toolchain/", public)


if __name__ == "__main__":
    unittest.main()
