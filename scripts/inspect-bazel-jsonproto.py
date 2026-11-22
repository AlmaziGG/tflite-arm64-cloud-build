#!/usr/bin/env python3
"""Collect private Bazel JSONPROTO and publish only structural aggregates."""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
from pathlib import Path


BAZEL_VERSION = "6.5.0"
TARGETS = (
    ("library", "//tensorflow/lite/c:libtensorflowlite_c.so"),
    ("smoke", "//tensorflow/lite/c/cloud_smoke:tflite_smoke"),
)
EXPRESSIONS = ("direct", "deps")
FLAG_MODES = (
    ("none", ()),
    ("commandline", ("--include_commandline",)),
    ("paramfiles", ("--include_param_files",)),
    ("commandline-paramfiles", ("--include_commandline", "--include_param_files")),
)
MAX_JSON_BYTES = 512 * 1024 * 1024
MAX_SHAPE_ROWS = 500
MAX_WALK_NODES = 1_000_000
FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def normalized_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def safe_field_name(value):
    value = str(value)
    return value if FIELD_NAME.fullmatch(value) else "<nonstandard-field-name>"


def walk_shapes(value, path="$", depth=0, counter=None, budget=None):
    if counter is None:
        counter = collections.Counter()
    if budget is None:
        budget = [MAX_WALK_NODES]
    if budget[0] <= 0:
        return counter
    budget[0] -= 1
    counter[(path, json_type(value))] += 1
    if depth >= 32:
        counter[(path + ".<depth-limit>", "truncated")] += 1
    elif isinstance(value, dict):
        for key, child in value.items():
            walk_shapes(child, f"{path}.{safe_field_name(key)}", depth + 1, counter, budget)
    elif isinstance(value, list):
        for child in value:
            walk_shapes(child, path + "[*]", depth + 1, counter, budget)
    if budget[0] == 0:
        counter[("$", "<walk-limit-reached>")] += 1
    return counter


def find_named_arrays(value, expected, path="$", depth=0):
    expected = normalized_key(expected)
    found = []
    if depth >= 32:
        return found
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{safe_field_name(key)}"
            if normalized_key(key) == expected and isinstance(child, list):
                found.append((child_path, child))
            found.extend(find_named_arrays(child, expected, child_path, depth + 1))
    elif isinstance(value, list):
        for child in value:
            found.extend(find_named_arrays(child, expected, path + "[*]", depth + 1))
    return found


def find_fields(value, accepted, path="$", depth=0):
    accepted = {normalized_key(key) for key in accepted}
    found = []
    if depth >= 32:
        return found
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{safe_field_name(key)}"
            if normalized_key(key) in accepted:
                found.append((child_path, child))
            found.extend(find_fields(child, accepted, child_path, depth + 1))
    elif isinstance(value, list):
        for child in value:
            found.extend(find_fields(child, accepted, path + "[*]", depth + 1))
    return found


def describe_document(document):
    action_arrays = find_named_arrays(document, "actions")
    target_arrays = find_named_arrays(document, "targets")
    actions = [item for _, values in action_arrays for item in values if isinstance(item, dict)]
    action_entries = sum(len(values) for _, values in action_arrays)
    target_entries = sum(len(values) for _, values in target_arrays)

    target_ids = set()
    target_ids_with_label = set()
    target_records = 0
    target_records_with_id = 0
    target_records_with_label = 0
    target_records_with_both = 0
    target_id_fields = collections.Counter()
    target_label_fields = collections.Counter()
    for _, records in target_arrays:
        for target in records:
            if not isinstance(target, dict):
                continue
            target_records += 1
            has_id = False
            has_label = False
            for key, value in target.items():
                key_type = normalized_key(key)
                if key_type in ("id", "targetid") and isinstance(value, (int, str)):
                    target_ids.add(value)
                    target_id_fields[safe_field_name(key)] += 1
                    has_id = True
                if key_type in ("label", "targetlabel"):
                    target_label_fields[safe_field_name(key)] += 1
                    has_label = True
            target_records_with_id += int(has_id)
            target_records_with_label += int(has_label)
            target_records_with_both += int(has_id and has_label)
            if has_id and has_label:
                for key, value in target.items():
                    if normalized_key(key) in ("id", "targetid") and isinstance(value, (int, str)):
                        target_ids_with_label.add(value)

    action_counts = collections.Counter()
    action_target_refs = 0
    matching_action_target_refs = 0
    matching_action_target_refs_with_label = 0
    action_field_types = collections.Counter()
    for action in actions:
        mnemonic = next(
            (value for key, value in action.items()
             if normalized_key(key) == "mnemonic" and isinstance(value, str)),
            None,
        )
        if mnemonic in ("CppCompile", "CppLink"):
            action_counts[mnemonic] += 1
        else:
            action_counts["other_or_missing"] += 1
        for key, value in action.items():
            action_field_types[(safe_field_name(key), json_type(value))] += 1
            if normalized_key(key) == "targetid" and isinstance(value, (int, str)):
                action_target_refs += 1
                matching_action_target_refs += int(value in target_ids)
                matching_action_target_refs_with_label += int(value in target_ids_with_label)

    argument_fields = find_fields(document, ("arguments", "commandLine"))
    environment_fields = find_fields(document, ("environmentVariables", "environmentVariable"))
    param_fields = find_fields(document, ("paramFiles", "parameterFiles"))
    shapes = walk_shapes(document)
    profile = (
        tuple(sorted((path, kind, count) for (path, kind), count in shapes.items())),
        tuple(sorted(action_counts.items())),
        tuple(sorted(action_field_types.items())),
        tuple(sorted(target_id_fields.items())),
        tuple(sorted(target_label_fields.items())),
        len(target_ids),
        len(target_ids_with_label),
        action_target_refs,
        matching_action_target_refs,
        matching_action_target_refs_with_label,
    )
    return {
        "action_arrays": action_arrays,
        "target_arrays": target_arrays,
        "actions": actions,
        "action_entries": action_entries,
        "action_counts": action_counts,
        "target_ids": target_ids,
        "target_ids_with_label": target_ids_with_label,
        "target_records": target_records,
        "target_entries": target_entries,
        "target_records_with_id": target_records_with_id,
        "target_records_with_label": target_records_with_label,
        "target_records_with_both": target_records_with_both,
        "target_id_fields": target_id_fields,
        "target_label_fields": target_label_fields,
        "action_target_refs": action_target_refs,
        "matching_action_target_refs": matching_action_target_refs,
        "matching_action_target_refs_with_label": matching_action_target_refs_with_label,
        "argument_fields": argument_fields,
        "environment_fields": environment_fields,
        "param_fields": param_fields,
        "shapes": shapes,
        "profile": profile,
    }


def field_list(fields):
    return ", ".join(
        f"{path}:{json_type(value)}" for path, value in fields
    ) or "<none>"


def format_structure(query_name, target_label, flags, result):
    lines = [
        f"QUERY {query_name}",
        f"target={target_label}",
        f"flags={','.join(flags) if flags else '<none>'}",
        f"expression_kind={'deps(TARGET)' if '-deps-' in query_name else 'TARGET'}",
        f"bazel_exit={result['exit_code']}",
        f"json_status={result['json_status']}",
        f"json_output_present={'true' if result['json_bytes'] > 0 else 'false'}",
        f"private_json_bytes={result['json_bytes']}",
        f"private_stderr_bytes={result['stderr_bytes']}",
    ]
    document = result.get("document")
    if not result.get("parsed"):
        lines.append("structure=NOT AVAILABLE; request failed or JSON was malformed")
        return lines, None

    lines.append(f"json_root_type={json_type(document)}")
    if isinstance(document, dict):
        lines.append("top_level_fields=" + (", ".join(
            f"{safe_field_name(key)}:{json_type(value)}" for key, value in sorted(document.items())
        ) or "<none>"))
    else:
        lines.append("top_level_fields=<not an object>")

    summary = describe_document(document)
    lines.append(f"actions_field_present={'true' if summary['action_arrays'] else 'false'}")
    lines.append(f"actions_field_type={'array' if summary['action_arrays'] else '<absent>'}")
    lines.append(f"action_entries={summary['action_entries']}")
    lines.append(f"action_records_with_object_shape={len(summary['actions'])}")
    lines.append(f"CppCompile={summary['action_counts']['CppCompile']}")
    lines.append(f"CppLink={summary['action_counts']['CppLink']}")
    lines.append(f"other_or_missing_mnemonic={summary['action_counts']['other_or_missing']}")
    lines.append(f"targets_field_present={'true' if summary['target_arrays'] else 'false'}")
    lines.append(f"targets_field_type={'array' if summary['target_arrays'] else '<absent>'}")
    lines.append(f"target_entries={summary['target_entries']}")
    lines.append(f"target_records={summary['target_records']}")
    lines.append(f"unique_target_ids={len(summary['target_ids'])}")
    lines.append(f"target_records_with_id={summary['target_records_with_id']}")
    lines.append(f"target_records_with_label={summary['target_records_with_label']}")
    lines.append(f"target_records_with_both_id_and_label={summary['target_records_with_both']}")
    lines.append(
        "action_target_id_reference_matches="
        f"{summary['matching_action_target_refs']}/{summary['action_target_refs']}"
    )
    lines.append(
        "action_target_id_reference_matches_with_label="
        f"{summary['matching_action_target_refs_with_label']}/{summary['action_target_refs']}"
    )
    lines.append("target_id_field_names=" + (", ".join(sorted(summary["target_id_fields"])) or "<none>"))
    lines.append("target_label_field_names=" + (", ".join(sorted(summary["target_label_fields"])) or "<none>"))
    lines.append("arguments_fields=" + field_list(summary["argument_fields"]))
    lines.append("environment_fields=" + field_list(summary["environment_fields"]))
    lines.append("param_file_fields=" + field_list(summary["param_fields"]))
    lines.append("structural_schema (field path, JSON type, occurrence count; values omitted):")
    for (path, kind), count in sorted(summary["shapes"].items())[:MAX_SHAPE_ROWS]:
        lines.append(f"  {path}: {kind} x{count}")
    if len(summary["shapes"]) > MAX_SHAPE_ROWS:
        lines.append(f"  ... {len(summary['shapes']) - MAX_SHAPE_ROWS} additional shape rows omitted")
    lines.append("identifier, label, argument, environment and param-file values=OMITTED")
    return lines, summary["profile"]


def safe_env():
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "JAVA_HOME", "BAZELISK_HOME")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env["USE_BAZEL_VERSION"] = BAZEL_VERSION
    return env


def run_one(bazel, tf_root, output_root, private_dir, target_name, target, expression_kind, flag_mode, flags):
    expression_target = target if expression_kind == "direct" else f"deps({target})"
    expression = f'mnemonic("CppCompile|CppLink", {expression_target})'
    query_name = f"{target_name}-{expression_kind}-{flag_mode}"
    raw_path = private_dir / f"{query_name}.json"
    stderr_path = private_dir / f"{query_name}.stderr"
    command = [
        str(bazel), f"--output_user_root={output_root}", "aquery",
        "--config=elinux_aarch64", "-c", "opt", "--jobs=2",
        f"--repository_cache={tf_root.parent / 'repository-cache'}",
        "--output=jsonproto", *flags, expression,
    ]
    return_code = 1
    status = "NOT AVAILABLE"
    document = None
    parsed = False
    try:
        with raw_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
            os.chmod(raw_path, 0o600)
            os.chmod(stderr_path, 0o600)
            completed = subprocess.run(
                command,
                cwd=tf_root,
                env=safe_env(),
                stdout=stdout_stream,
                stderr=stderr_stream,
                timeout=900,
                check=False,
            )
        return_code = completed.returncode
        if raw_path.stat().st_size > MAX_JSON_BYTES:
            status = "REJECTED: private JSON exceeds inspection limit"
        else:
            try:
                document = json.loads(raw_path.read_text(encoding="utf-8"))
                if not isinstance(document, dict):
                    status = f"INVALID ROOT TYPE ({json_type(document)})"
                elif return_code == 0:
                    status = "PARSED"
                    parsed = True
                else:
                    status = "PARSED_WITH_AQUERY_FAILURE"
                    parsed = True
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                status = f"INVALID JSON ({type(exc).__name__})"
    except subprocess.TimeoutExpired:
        status = "TIMEOUT (900 seconds); stderr retained privately"
    except OSError as exc:
        status = f"PROCESS ERROR ({type(exc).__name__}); details withheld"

    json_bytes = raw_path.stat().st_size if raw_path.exists() else 0
    stderr_bytes = stderr_path.stat().st_size if stderr_path.exists() else 0
    result = {
        "exit_code": return_code,
        "json_status": status,
        "json_bytes": json_bytes,
        "stderr_bytes": stderr_bytes,
        "document": document,
        "parsed": parsed,
    }
    lines, profile = format_structure(query_name, target, flags, result)
    return query_name, lines, profile, (return_code == 0 and parsed)


def is_safe_report_text(text):
    if not text or len(text) > 4 * 1024 * 1024:
        return False
    forbidden = re.compile(
        r"(?i)(?:[A-Z]:\\|/(?:home|tmp|runner|Users|work)/|"
        r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"Bearer\s+\S+|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}))"
    )
    if forbidden.search(text):
        return False

    targets = {label for _, label in TARGETS}
    lines = text.splitlines()
    if lines[:3] != [
        "Bazel 6.5.0 JSONPROTO structural diagnostics",
        "Observed query structure only; values, argv, environment contents and param-file contents are omitted.",
        "Include-flag comparisons are based on value-free structural profiles from real query results.",
    ]:
        return False
    query_re = re.compile(r"QUERY (?:library|smoke)-(?:direct|deps)-(?:none|commandline|paramfiles|commandline-paramfiles)\Z")
    group_re = re.compile(r"QUERY GROUP (?:library|smoke)-(?:direct|deps)\Z")
    safe_line = re.compile(
        r"(?:Bazel 6\.5\.0 JSONPROTO structural diagnostics|"
        r"Observed query structure only; values, argv, environment contents and param-file contents are omitted\.|"
        r"Include-flag comparisons are based on value-free structural profiles from real query results\.|"
        r"QUERY .+|QUERY GROUP (?:library|smoke)-(?:direct|deps)|target=.+|flags=.+|expression_kind=.+|bazel_exit=-?\d+|"
        r"json_status=[A-Za-z0-9_ ();:-]+|json_output_present=(?:true|false)|"
        r"private_json_bytes=\d+|private_stderr_bytes=\d+|structure=.+|"
        r"json_root_type=(?:array|object|string|number|boolean|null|unknown)|"
        r"top_level_fields=.+|(?:actions|targets)_field_present=(?:true|false)|"
        r"(?:actions|targets)_field_type=(?:array|<absent>)|"
        r"action_entries=\d+|action_records_with_object_shape=\d+|CppCompile=\d+|CppLink=\d+|other_or_missing_mnemonic=\d+|"
        r"target_entries=\d+|target_records=\d+|unique_target_ids=\d+|target_records_with_id=\d+|"
        r"target_records_with_label=\d+|target_records_with_both_id_and_label=\d+|"
        r"action_target_id_reference_matches=\d+/\d+|action_target_id_reference_matches_with_label=\d+/\d+|"
        r"target_(?:id|label)_field_names=(?:[A-Za-z][A-Za-z0-9_]{0,63}(?:, [A-Za-z][A-Za-z0-9_]{0,63})*|<none>)|"
        r"(?:arguments|environment|param_file)_fields=(?:<none>|(?:\$|\$\.[A-Za-z0-9_.$<>\[\]*:-]+):(?:array|object|string|number|boolean|null)(?:, .+)*)|"
        r"structural_schema \(field path, JSON type, occurrence count; values omitted\):|"
        r"  \$[A-Za-z0-9_.$<>\[\]*:-]*: (?:array|object|string|number|boolean|null|truncated|unknown) x\d+|"
        r"  \.\.\. \d+ additional shape rows omitted|"
        r"identifier, label, argument, environment and param-file values=OMITTED|"
        r"Include flag structural comparison:|"
        r"  mode=(?:none|commandline|paramfiles|commandline-paramfiles); same_value-free_structure_as_none=(?:true|false|unavailable)|"
        r"<none>)"
    )
    for line in lines:
        if line.startswith("target=") and line[7:] not in targets:
            return False
        if line.startswith("QUERY ") and not (query_re.fullmatch(line) or group_re.fullmatch(line)):
            return False
        if line and not safe_line.fullmatch(line):
            return False
    return sum(bool(query_re.fullmatch(line)) for line in lines) == 16


def validate_report(path):
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        print("SAFE REPORT CHECK FAILED: report missing or unreadable", file=sys.stderr)
        return 1
    if not is_safe_report_text(content):
        print("SAFE REPORT CHECK FAILED: report violates structural-report allowlist", file=sys.stderr)
        return 1
    print("SAFE REPORT CHECK PASSED")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-report", type=Path)
    parser.add_argument("--tensorflow", type=Path)
    parser.add_argument("--bazel", type=Path)
    parser.add_argument("--output-user-root", type=Path)
    parser.add_argument("--private-dir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)

    if args.validate_report is not None:
        return validate_report(args.validate_report)
    required = (args.tensorflow, args.bazel, args.output_user_root, args.private_dir, args.report)
    if any(value is None for value in required):
        parser.error("collection mode requires --tensorflow, --bazel, --output-user-root, --private-dir and --report")
    if not args.tensorflow.is_dir() or not (args.tensorflow / ".git").exists():
        print("ERROR: pinned TensorFlow workspace is unavailable", file=sys.stderr)
        return 2
    if not args.bazel.is_file():
        print("ERROR: pinned Bazelisk executable is unavailable", file=sys.stderr)
        return 2
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        print("ERROR: RUNNER_TEMP is not set; refusing to store private JSONPROTO", file=sys.stderr)
        return 2
    private_resolved = args.private_dir.resolve()
    temp_resolved = Path(runner_temp).resolve()
    report_resolved = args.report.resolve()
    if private_resolved == temp_resolved or temp_resolved not in private_resolved.parents:
        print("ERROR: private diagnostics directory must be below RUNNER_TEMP", file=sys.stderr)
        return 2
    if private_resolved in report_resolved.parents or report_resolved.parent in private_resolved.parents:
        print("ERROR: private diagnostics and public report paths must not overlap", file=sys.stderr)
        return 2

    try:
        args.private_dir.mkdir(parents=True, exist_ok=True)
        args.private_dir.chmod(0o700)
        args.report.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: unable to prepare diagnostic directories ({type(exc).__name__})", file=sys.stderr)
        return 2

    report_lines = [
        "Bazel 6.5.0 JSONPROTO structural diagnostics",
        "Observed query structure only; values, argv, environment contents and param-file contents are omitted.",
        "Include-flag comparisons are based on value-free structural profiles from real query results.",
        "",
    ]
    overall_success = True
    for target_name, target in TARGETS:
        for expression_kind in EXPRESSIONS:
            query_rows = []
            for flag_mode, flags in FLAG_MODES:
                try:
                    query_name, lines, profile, succeeded = run_one(
                        args.bazel, args.tensorflow, args.output_user_root,
                        args.private_dir, target_name, target,
                        expression_kind, flag_mode, flags,
                    )
                except Exception as exc:
                    # Do not print exception text: it can contain paths or input fragments.
                    query_name = f"{target_name}-{expression_kind}-{flag_mode}"
                    lines = [
                        f"QUERY {query_name}",
                        f"target={target}",
                        f"flags={','.join(flags) if flags else '<none>'}",
                        f"expression_kind={'deps(TARGET)' if expression_kind == 'deps' else 'TARGET'}",
                        "bazel_exit=1",
                        f"json_status=PROCESS ERROR ({type(exc).__name__}); details withheld",
                        "json_output_present=false",
                        "private_json_bytes=0",
                        "private_stderr_bytes=0",
                        "structure=NOT AVAILABLE; request failed or JSON was malformed",
                    ]
                    profile = None
                    succeeded = False
                query_rows.append((flag_mode, lines, profile, succeeded))
                state = "collected" if succeeded else "failed or malformed"
                print(f"JSONPROTO query {query_name}: {state}")
                overall_success = succeeded and overall_success

            baseline = query_rows[0][2]
            report_lines.append(f"QUERY GROUP {target_name}-{expression_kind}")
            report_lines.append("Include flag structural comparison:")
            for flag_mode, _, profile, _ in query_rows:
                if baseline is None or profile is None:
                    equivalent = "unavailable"
                else:
                    equivalent = "true" if profile == baseline else "false"
                report_lines.append(
                    f"  mode={flag_mode}; same_value-free_structure_as_none={equivalent}"
                )
            report_lines.append("")
            for _, lines, _, _ in query_rows:
                report_lines.extend(lines)
                report_lines.append("")

    report_text = "\n".join(report_lines) + "\n"
    try:
        args.report.write_text(report_text, encoding="utf-8")
        args.report.chmod(0o600)
    except OSError as exc:
        print(f"ERROR: unable to write structural report ({type(exc).__name__})", file=sys.stderr)
        return 2
    if not is_safe_report_text(report_text):
        print("ERROR: generated structural report failed its internal allowlist", file=sys.stderr)
        return 1
    print("Safe structural report generated.")
    return 0 if overall_success else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        print(f"JSONPROTO inspector failed ({type(exc).__name__}); details withheld", file=sys.stderr)
        raise SystemExit(1)
