#!/usr/bin/env python3
"""Extract a small, redacted public subset from a private toolchain report."""

import re
import sys
from pathlib import Path


SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|authorization|cookie|credential)[A-Za-z0-9_-]*)"
    r"([=:]\s*)[^\s,;]+"
)
TOKEN_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9._-]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{48,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)https?://[^/\s:@]+:[^/@\s]+@"),
)


def redact(value):
    value = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + "[REDACTED]", value)
    for pattern in TOKEN_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def sanitize(source, destination):
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    output = [
        "Sanitized Bazel ARM64 toolchain diagnostics",
        "Raw action command lines and environment values are intentionally omitted.",
        "Only selected compiler, sysroot, search-path, linker, and toolchain identity fields are included.",
    ]
    action_fields = (
        "action_target=", "action_source=", "argv_parse_status=",
        "action_launcher_token=", "resolved_action_launcher=", "compiler_wrapper=",
        "actual_compiler=", "explicit_action_sysroot_arguments=",
        "effective_sysroot_assessment=", "compiler_default_configured_sysroot=",
        "wrapper_or_environment_sysroot=", "actual_selected_linker=",
        "CppLink_linker_candidate_path=", "linker_evidence=", "linker_driver_helper=",
        "compiler_resolution_status=", "effective_sysroot_status=", "linker_resolution_status=",
        "action_environment_status=", "action_sysroot_status=", "wrapper_dry_run_sysroot_arguments=",
        "actual_compiler_identification_evidence=", "linker_identification=",
        "CppLink_action_specific_print_prog_name_token=", "CppLink_action_specific_print_prog_name_exit=",
        "CppLink_linker_candidate_version_exit=", "actual_linker_version_exit=",
        "response_file_status=", "compiler_default_sysroot_status=",
        "compiler_search_directories_status=", "compiler_default_linker_status=",
        "compiler_metadata_status=", "toolchain_repository_status[",
    )
    for line in lines:
        repo = re.match(r"external_repository\[(local_config_embedded_arm|aarch64_linux_toolchain)\]=(.*)$", line)
        if repo:
            output.append(f"external_repository[{repo.group(1)}]={redact(repo.group(2))}")
        elif re.match(r"FATAL_DIAGNOSTIC_ERROR=[A-Za-z_]+$", line):
            output.append(redact(line.strip()))
        elif line.startswith("diagnostic_status="):
            output.append(redact(line.strip()))
        elif re.match(r"toolchain_repository_status\[(local_config_embedded_arm|aarch64_linux_toolchain)\]=", line):
            output.append(redact(line.strip()))

    current_action = None
    metadata_mode = None
    for line in lines:
        action = re.match(r"\[(CppCompile|CppLink) #(\d+)\]", line)
        if action:
            current_action = f"{action.group(1)} #{action.group(2)}"
            output.append(f"\nACTION {current_action}")
            metadata_mode = None
            continue
        if line.startswith("=== Actual compiler metadata"):
            current_action = None
            output.append("\nCOMPILER METADATA")
            metadata_mode = None
            continue
        metadata = re.match(r"--- actual compiler used by (CppCompile|CppLink): (.+) ---", line)
        if metadata:
            output.append(f"actual_compiler[{metadata.group(1)}]={redact(metadata.group(2))}")
            metadata_mode = None
            continue
        if current_action:
            normalized = line.strip()
            if normalized.startswith(action_fields):
                output.append(redact(normalized))
            if normalized.startswith("argv_parse_detail="):
                # Details are restricted to parser-generated categories, never
                # the source command line.
                category = normalized.partition("=")[2]
                if category in ("unbalanced command quoting", "empty command", "missing command line"):
                    output.append(f"argv_parse_detail={category}")
            if normalized.startswith("CppLink_linker_candidate_version:"):
                metadata_mode = "linker_candidate_version"
                continue
            if normalized.startswith("CppLink_linker_candidate_version_exit=") or normalized.startswith("actual_linker_version_exit="):
                metadata_mode = None
                continue
            if normalized.startswith("actual_selected_linker=") and "UNRESOLVED" not in normalized:
                metadata_mode = "actual_linker_version"
                continue
            if normalized.startswith("linker_evidence="):
                continue
            if metadata_mode in ("linker_candidate_version", "actual_linker_version") and line.strip():
                label = "linker_candidate_version" if metadata_mode == "linker_candidate_version" else "actual_linker_version"
                output.append(f"{label}={redact(line.strip())}")
            continue
        if line.startswith("$ "):
            if line.endswith(" --version"):
                metadata_mode = "compiler_version"
            elif line.endswith(" -dumpmachine"):
                metadata_mode = "target_triple"
            elif line.endswith(" -print-search-dirs"):
                metadata_mode = "search_dirs"
            else:
                metadata_mode = None
            continue
        if line.startswith("compiler_default_configured_sysroot="):
            output.append(redact(line.strip()))
        elif line.startswith("compiler_reported_default_linker="):
            output.append(redact(line.strip()))
        elif metadata_mode == "compiler_version" and line.strip() and not line.startswith("(exit="):
            output.append(f"compiler_version={redact(line.strip())}")
            metadata_mode = None
        elif metadata_mode == "target_triple" and line.strip() and not line.startswith("(exit="):
            output.append(f"target_triple={redact(line.strip())}")
            metadata_mode = None
        elif metadata_mode == "search_dirs" and line.strip().startswith(("install:", "programs:", "libraries:")):
            output.append(f"compiler_{redact(line.strip())}")
        elif line.startswith("(exit="):
            metadata_mode = None

    destination.write_text("\n".join(output) + "\n", encoding="utf-8")


def main(argv):
    if len(argv) != 3:
        print("usage: sanitize-toolchain-report.py PRIVATE_REPORT PUBLIC_REPORT", file=sys.stderr)
        return 2
    source, destination = map(Path, argv[1:])
    try:
        if not source.is_file():
            raise OSError(f"private report is missing: {source}")
        sanitize(source, destination)
    except OSError as exc:
        print(f"sanitization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
