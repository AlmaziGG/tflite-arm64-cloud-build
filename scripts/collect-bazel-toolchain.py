#!/usr/bin/env python3
"""Record compiler/linker evidence from Bazel's CppCompile and CppLink actions."""

import ast
import os
import re
import shlex
import shutil
import subprocess
import sys
import traceback
import json
import hashlib
import tempfile
from pathlib import Path


def run(args, *, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env)


def extract_sysroots(argv):
    values = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--sysroot":
            if i + 1 < len(argv):
                values.append(argv[i + 1])
                i += 2
                continue
            values.append("<MISSING_ARGUMENT>")
        elif arg.startswith("--sysroot="):
            values.append(arg.split("=", 1)[1] or "<EMPTY>")
        elif arg == "-isysroot":
            if i + 1 < len(argv):
                values.append(f"-isysroot {argv[i + 1]}")
                i += 2
                continue
            values.append("-isysroot <MISSING_ARGUMENT>")
        elif arg.startswith("-isysroot") and len(arg) > len("-isysroot"):
            value = arg[len("-isysroot"):]
            values.append(value[1:] if value.startswith("=") else value)
        i += 1
    return values


def extract_sysroot_paths(argv):
    """Return only sysroot path operands, preserving their argv order."""
    values = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--sysroot", "-isysroot"):
            if index + 1 < len(argv):
                values.append(argv[index + 1])
                index += 2
                continue
            values.append("<MISSING_ARGUMENT>")
        elif arg.startswith("--sysroot="):
            values.append(arg.split("=", 1)[1] or "<EMPTY>")
        elif arg.startswith("-isysroot="):
            values.append(arg.split("=", 1)[1] or "<EMPTY>")
        elif arg.startswith("-isysroot") and len(arg) > len("-isysroot"):
            values.append(arg[len("-isysroot"):])
        index += 1
    return values


def normalize_sysroot_identity(value, toolchain_roots, *, base=None):
    """Return a public-safe sysroot identity without leaking runner paths."""
    if value == "":
        return "<empty>", "EMPTY_VALUE"
    if value in (None, "<EMPTY>", "<MISSING_ARGUMENT>"):
        return "<unresolved>", "NOT_RESOLVED"
    path = Path(value)
    if not path.is_absolute():
        if base is None:
            return f"basename:{path.name or '<root>'}", "BASENAME_ONLY_RELATIVE_PATH"
        path = base / path
    resolved = path.resolve(strict=False)
    for name, root in toolchain_roots.items():
        root_resolved = Path(root).resolve(strict=False)
        try:
            relative = resolved.relative_to(root_resolved)
            suffix = relative.as_posix() or "."
            return f"{name}/{suffix}", "RELATIVE_TO_PINNED_TOOLCHAIN_ROOT"
        except ValueError:
            continue
    basename = resolved.name or "<root>"
    return f"basename:{basename}", "BASENAME_ONLY_OUTSIDE_PINNED_TOOLCHAIN_ROOT"


def decide_effective_sysroot(explicit_paths, environment_hints, environment_captured,
                             launcher_is_transparent, wrapper_paths, default_sysroot,
                             unknown_environment_keys=()):
    """Conservatively resolve the action sysroot and its evidence source."""
    if unknown_environment_keys:
        return None, "NOT RESOLVED", "unreviewed action environment keys may alter compiler/wrapper behavior"
    wrapper_values = list(dict.fromkeys(wrapper_paths))
    explicit_values = list(dict.fromkeys(explicit_paths))
    if wrapper_values:
        if len(wrapper_values) == 1 and not any(v.startswith("<") for v in wrapper_values):
            return wrapper_values[0], "RESOLVED", "wrapper dry-run final compiler arguments (-###)"
        return None, "NOT RESOLVED", "wrapper dry-run exposed conflicting or malformed sysroot arguments"
    if explicit_values:
        if len(explicit_values) == 1 and not any(v.startswith("<") for v in explicit_values):
            if environment_hints:
                return None, "NOT RESOLVED", "environment/compiler-selection overrides may supersede action sysroot"
            return explicit_values[0], "RESOLVED", "JSONPROTO action arguments or matched paramFiles"
        return None, "NOT RESOLVED", "action contains conflicting or malformed explicit sysroot values"
    if environment_hints:
        return None, "NOT RESOLVED", "captured environment contains sysroot or compiler-selection overrides"
    if not environment_captured:
        return None, "NOT RESOLVED", "Bazel did not expose the action environment"
    if not launcher_is_transparent:
        return None, "NOT RESOLVED", "non-transparent compiler wrapper may inject sysroot or specs"
    if default_sysroot is None:
        return None, "NOT RESOLVED", "compiler default/configured sysroot probe failed"
    return default_sysroot, "RESOLVED", "compiler default/configuration under captured no-override action environment"


def compare_tf2_probes(driver, argv, env, cwd, default, probe=run, *, gcc_version="11.3.1", evidence=None):
    """Only called for a direct pinned ARM GCC with one unreviewed key."""
    if env.get("TF2_BEHAVIOR") != "1" or not default:
        return False
    def reject(flag, reason):
        if evidence is not None:
            evidence.append(f"{flag} {reason}")
        return False
    without = env.copy()
    del without["TF2_BEHAVIOR"]
    for args in (["-dumpfullversion"], ["-dumpmachine"], ["-dumpspecs"],
                 [*argv[1:], "-print-sysroot"], [*argv[1:], "-###"]):
        pair = [probe([str(driver), *args], cwd=cwd, env=e) for e in (env, without)]
        if any(p.returncode or not p.stdout.strip() for p in pair):
            return reject(args[-1], "unsuccessful")
        a, b = (p.stdout.strip() for p in pair)
        if args[-1] == "-###":
            # GCC generates a fresh name for each temporary assembler or LTO file.
            pattern = r"/tmp/cc[A-Za-z0-9]{6}(?=[.][\w.]+(?:\s|\"|$))"
            a, b = (re.sub(pattern, "/tmp/<gcc-temp>", x) for x in (a, b))
            if not re.search(r"(?:/cc1(?:plus)?|/collect2)(?:\"|\s)", a):
                return False
        if a != b:
            return reject(args[-1], "different")
        expected = {"-dumpfullversion": gcc_version, "-dumpmachine": "aarch64-none-linux-gnu",
                    "-print-sysroot": default}
        if args[-1] in expected and a != expected[args[-1]]:
            return reject(args[-1], "unexpected")
    return True


def replay_findings(argv, cwd, diagnostic):
    outputs = {i + 1 for i, arg in enumerate(argv[:-1]) if arg == "-o"}
    inputs = [arg for i, arg in enumerate(argv) if i not in outputs and
              not arg.startswith("-") and arg.endswith((".o", ".lo", ".a", ".so"))]
    missing = [arg for arg in inputs if not (cwd / arg).is_file()]
    findings = []
    for signature, label in (("multiple definition of", "duplicate-definitions"),
                             ("cannot find", "missing-link-input"), ("No such file", "missing-file"),
                             ("undefined reference", "undefined-reference"),
                             ("cannot open output", "output-open-error")):
        if signature in diagnostic:
            findings.append(label)
    if any("fastbuild/" in arg and arg in diagnostic for arg in missing):
        findings.append("missing-fastbuild-input-named-by-linker")
    return (f"inputs={len(inputs)},missing={len(missing)},duplicate_inputs={len(inputs)-len(set(inputs))},"
            f"output_options={len(outputs)},errors={'+'.join(findings) or 'none-classified'}")


def redirect_link_output(argv, output_path):
    """Copy link argv while redirecting recognized output files into the probe dir."""
    result = list(argv)
    found = []
    index = 0
    while index < len(result):
        if result[index] == "-o":
            if index + 1 >= len(result):
                return None, "found -o without an output operand"
            found.append(index + 1)
            index += 2
            continue
        index += 1
    if not found:
        return None, "expected at least one separated -o output operand; found none"
    output_path = Path(output_path)
    # Preserve argument order and the linker's last-output-wins behavior while
    # ensuring every original output path is replaced by a private probe path.
    for output_index, operand_index in enumerate(found):
        if output_index == len(found) - 1:
            replacement = output_path
        else:
            suffix = Path(result[operand_index]).suffix
            replacement = output_path.parent / f"probe-output-{output_index + 1}{suffix}"
        result[operand_index] = str(replacement)
    output_count = len(found)
    extra_output_options = {"-Map", "--Map", "--dependency-file", "-MF", "--out-implib"}
    extra_inline_prefixes = ("-Map=", "--Map=", "--dependency-file=", "--out-implib=")
    extra_wl_names = {"-Map", "--Map", "--dependency-file", "--out-implib"}
    next_index = 0

    def private_extra(original):
        nonlocal next_index
        next_index += 1
        suffix = Path(original).suffix
        return str(output_path.parent / f"probe-extra-{next_index}{suffix}")

    index = 0
    while index < len(result):
        arg = result[index]
        if arg in extra_output_options and index + 1 < len(result):
            result[index + 1] = private_extra(result[index + 1])
            output_count += 1
            index += 2
            continue
        matched = next((prefix for prefix in extra_inline_prefixes if arg.startswith(prefix)), None)
        if matched:
            result[index] = matched + private_extra(arg[len(matched):])
            output_count += 1
            index += 1
            continue
        if arg.startswith("-Wl,"):
            parts = arg.split(",")
            for part_index in range(1, len(parts)):
                part = parts[part_index]
                if part in extra_wl_names and part_index + 1 < len(parts):
                    parts[part_index + 1] = private_extra(parts[part_index + 1])
                    output_count += 1
                    part_index += 1
                    continue
                inline = next((name + "=" for name in extra_wl_names if part.startswith(name + "=")), None)
                if inline:
                    parts[part_index] = inline + private_extra(part[len(inline):])
                    output_count += 1
            result[index] = ",".join(parts)
        index += 1
    return result, f"{output_count} recognized link output(s) redirected to private probe paths"


def successful_execve_paths(trace_text):
    """Parse successful execve paths from strace output; arguments stay private."""
    paths = []
    pattern = re.compile(r'execve\(("(?:\\.|[^"\\])*"), .*\)\s+=\s+0\s*$')
    for line in trace_text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        try:
            path = ast.literal_eval(match.group(1))
        except (SyntaxError, ValueError):
            continue
        if isinstance(path, str):
            paths.append(path)
    return paths


def resolve_linker_from_execve_trace(trace_text, cwd):
    """Resolve one linker executable observed in successful execve records."""
    observed = successful_execve_paths(trace_text)
    linkers = []
    helpers = []
    for item in observed:
        name = Path(item).name
        if re.fullmatch(r"(?:[A-Za-z0-9_.+-]+-)?ld(?:\.bfd|\.gold|\.lld)?", name):
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = Path(cwd) / candidate
            resolved = candidate.resolve(strict=False)
            if resolved.is_file() and os.access(resolved, os.X_OK):
                linkers.append((item, str(resolved)))
        elif name == "collect2" or name.endswith("/collect2"):
            helpers.append(item)
    unique = {real for _, real in linkers}
    if len(unique) == 1:
        actual = next(iter(unique))
        observed_path = next((seen for seen, real in linkers if real == actual), actual)
        return {"selected": actual, "observed": observed_path, "helpers": helpers,
                "linker_paths": sorted(unique), "reason": "one linker executable observed in successful execve trace"}
    if len(unique) > 1:
        reason = "trace observed multiple distinct linker executables"
    elif observed:
        reason = "trace completed but no recognized linker executable was observed"
    else:
        reason = "trace contained no parseable successful execve records"
    return {"selected": None, "observed": None, "helpers": helpers,
            "linker_paths": sorted(unique), "reason": reason}


def linker_implementation(version_text, executable):
    text = version_text.lower()
    name = Path(executable).name.lower()
    if "lld" in text or name.endswith("ld.lld"):
        return "LLVM LLD"
    if "gold" in text or name.endswith("ld.gold"):
        return "GNU gold"
    if "gnu ld" in text or "gnu binutils" in text or name.endswith(("-ld", "ld", "ld.bfd")):
        return "GNU ld"
    return "UNRESOLVED"


def linker_target_architecture(version_output):
    return "AArch64 supported" if re.search(r"aarch64", version_output, re.I) else "not confirmed by linker -V"


def diagnostic_exit_code(existing_code, failure_categories):
    """Critical diagnostic findings can never be converted into SUCCESS."""
    return 1 if existing_code or failure_categories else 0


def extract_sysroots_text(text):
    values = []
    pattern = re.compile(
        r"(--sysroot(?:=|\s+)|-isysroot(?:=|\s+))(?:\"([^\"]+)\"|'([^']+)'|([^\s'\",]+))"
    )
    for match in pattern.finditer(text):
        value = next(group for group in match.groups()[1:] if group is not None)
        prefix = match.group(1)
        values.append(f"{prefix}{value}" if prefix.endswith("=") else f"{prefix.strip()} {value}")
    return list(dict.fromkeys(values))


def env_sysroots(environment):
    if environment is None:
        return []
    values = []
    for key in ("SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX", "COMPILER_PATH"):
        if environment.get(key) and environment[key] != "<UNSET>":
            values.append(f"{key}={environment[key]} (may redirect compiler/sysroot selection)")
    for key in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS"):
        if environment.get(key):
            try:
                flags = shlex.split(environment[key], posix=True)
            except ValueError:
                values.append(f"{key}=<unparseable; may contain sysroot flags>")
                continue
            values.extend(f"{key}:{value}" for value in extract_sysroots(flags))
    return values


def launcher_environment(argv, launcher):
    """Return leading `env KEY=VALUE ...` assignments and whether env -i is used."""
    if launcher.name != "env":
        return {}, False
    values = {}
    clear_environment = False
    i = 1
    while i < len(argv):
        item = argv[i]
        if item in ("-i", "--ignore-environment"):
            clear_environment = True
            i += 1
            continue
        if item in ("-u", "--unset") and i + 1 < len(argv):
            values[argv[i + 1]] = "<UNSET>"
            i += 2
            continue
        if item.startswith("--unset="):
            values[item.split("=", 1)[1]] = "<UNSET>"
            i += 1
            continue
        if "=" in item and not item.startswith("-"):
            key, value = item.split("=", 1)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                values[key] = value
                i += 1
                continue
        break
    return values, clear_environment


def action_environment_for_replay(environment, launcher_values, *, captured, clear_environment):
    """Build only the environment the captured action/launcher specifies.

    In particular, do not let runner-only variables leak into the replay of an
    action that used ``env -i`` or whose environment was not captured.
    """
    if clear_environment:
        result = {}
    elif captured:
        result = dict(environment or {})
    else:
        result = {}
    for key, value in launcher_values.items():
        if value == "<UNSET>":
            result.pop(key, None)
        else:
            result[key] = value
    return result


def looks_like_wrapper(path):
    try:
        with open(path, "rb") as stream:
            prefix = stream.read(256)
    except OSError:
        return True
    return (
        prefix.startswith(b"#!")
        or path.name.lower() in ("env", "ccache", "sccache")
        or "wrapper" in path.name.lower()
        or "wrap_cc" in path.name.lower()
    )


def compiler_tokens_from_dry_run(output):
    tokens = []
    for line in output.splitlines():
        collect_gcc = re.search(r"\bCOLLECT_GCC=(?:\"([^\"]+)\"|'([^']+)'|(\S+))", line)
        if collect_gcc:
            tokens.append(next(group for group in collect_gcc.groups() if group))
        try:
            argv = shlex.split(line, posix=True)
        except ValueError:
            continue
        for token in argv:
            if token.startswith("COLLECT_GCC="):
                tokens.append(token.split("=", 1)[1])
            elif re.search(r"(?:^|/)(?:aarch64[^/]*-(?:gcc|g\+\+)|clang\+\+?|gcc|g\+\+)$", token):
                tokens.append(token)
    return list(dict.fromkeys(tokens))


def linker_selection_from_dry_run(output, action_candidate, resolver, dry_run_succeeded=True):
    """Resolve an actual linker only from a unique direct linker command in -### output.

    `-print-prog-name=ld` supplies a candidate, never proof. `collect2` is
    retained as a driver helper and excluded from the actual linker tokens.
    """
    lines = [line for line in output.splitlines()
             if re.search(r"(?:^|[/\\\s\"])(?:[^/\\\s\"]*[-])?ld(?:\.bfd|\.gold|\.lld)?(?:[\s\"]|$)", line)]
    helpers = [line for line in output.splitlines()
               if re.search(r"(?:^|[/\\\s\"])(?:[^/\\\s\"]*[/\\])?collect2(?:[\s\"]|$)", line)]
    tokens = set()
    for line in lines:
        try:
            for item in shlex.split(line, posix=True):
                base = Path(item).name
                if (base in ("ld", "ld.bfd", "ld.gold", "ld.lld")
                        or re.fullmatch(r".+-ld(?:\.bfd|\.gold|\.lld)?", base)):
                    tokens.add(item)
        except ValueError:
            continue
    resolved = set()
    unresolved = []
    for item in tokens:
        result = resolver(item)
        if result:
            resolved.add(result)
        else:
            unresolved.append(item)
    selected = None
    reason = "no direct linker command found in compiler-driver dry-run"
    if not dry_run_succeeded:
        reason = "compiler-driver dry-run returned nonzero"
    elif lines:
        if len(resolved) != 1 or unresolved:
            reason = "dry-run did not resolve exactly one linker executable"
        else:
            selected = next(iter(resolved))
            if action_candidate and selected != action_candidate:
                reason = "direct dry-run linker differs from the action-specific candidate"
                selected = None
            else:
                reason = "unique direct linker executable in compiler-driver dry-run"
    return {
        "lines": lines,
        "helpers": helpers,
        "tokens": sorted(tokens),
        "resolved": resolved,
        "unresolved": unresolved,
        "selected": selected,
        "reason": reason,
    }


def resolve_executable(token, tf_root, output_base, execution_root, toolchain_paths):
    candidate = Path(token)
    probes = [candidate] if candidate.is_absolute() else [
        tf_root / candidate, execution_root / candidate, output_base / candidate
    ]
    for probe in probes:
        if probe.is_file() and os.access(probe, os.X_OK):
            return probe.resolve()
    if candidate.name in ("env", "ccache", "sccache") and not candidate.is_absolute():
        located = shutil.which(candidate.name)
        if located:
            return Path(located).resolve()
    matches = set()
    for repository in toolchain_paths:
        if not repository.is_dir():
            continue
        patterns = [candidate.name]
        if candidate.name == "ld":
            patterns = ["ld", "*-ld", "ld.bfd", "*-ld.bfd"]
        elif candidate.name in ("ld.bfd", "ld.gold", "ld.lld"):
            patterns.append("*-" + candidate.name)
        for pattern in patterns:
            for path in repository.rglob(pattern):
                basename_matches = path.name == candidate.name
                if candidate.name == "ld":
                    basename_matches = bool(re.fullmatch(r"(?:[A-Za-z0-9_.+-]+-)?ld(?:\.bfd)?", path.name))
                elif candidate.name in ("ld.bfd", "ld.gold", "ld.lld"):
                    basename_matches = path.name == candidate.name or path.name.endswith("-" + candidate.name)
                if basename_matches and path.is_file() and os.access(path, os.X_OK):
                    matches.add(path.resolve())
    return next(iter(matches)) if len(matches) == 1 else None


def action_driver(action, tf_root, output_base, execution_root, toolchain_paths):
    argv = action.get("argv", [])
    if not argv:
        return None
    token = argv[0]
    path = resolve_executable(token, tf_root, output_base, execution_root, toolchain_paths)
    return (token, path, argv)


def log_command(stream, label, args, *, cwd=None, env=None):
    result = run(args, cwd=cwd, env=env)
    print(f"$ {' '.join(map(str, args))}\n{result.stdout.rstrip()}\n(exit={result.returncode})", file=stream)
    return result


def trace_linker_execution(launcher, argv, env, cwd, private_dir, target_name, *, environment_captured):
    """Trace a replay of the captured CppLink argv with only -o redirected."""
    if not environment_captured:
        return {"selected": None, "reason": "Bazel JSONPROTO did not expose the CppLink action environment",
                "trace_path": None, "action_exit": None, "output_redirect_status": "NOT ATTEMPTED"}
    tracer = shutil.which("strace")
    if not tracer:
        return {"selected": None, "reason": "strace is unavailable on the runner",
                "trace_path": None, "action_exit": None, "output_redirect_status": "NOT ATTEMPTED"}
    private_dir = Path(private_dir)
    private_dir.mkdir(parents=True, exist_ok=True)
    probe_dir = Path(tempfile.mkdtemp(prefix=f"{target_name}-link-probe-", dir=private_dir))
    trace_path = private_dir / f"{target_name}-linker-execve.private.log"
    output_path = probe_dir / f"linker-probe-output-{target_name}"
    probe_argv, output_status = redirect_link_output(argv, output_path)
    if probe_argv is None:
        return {"selected": None, "reason": output_status, "trace_path": None,
                "action_exit": None, "output_redirect_status": output_status}
    trace_cmd = [tracer, "-f", "-qq", "-e", "trace=execve", "-s", "4096",
                 "-o", str(trace_path), "--", str(launcher), *probe_argv[1:]]
    try:
        result = run(trace_cmd, cwd=cwd, env=env)
    except OSError as exc:
        return {"selected": None, "reason": f"strace invocation failed ({type(exc).__name__})",
                "trace_path": str(trace_path), "action_exit": None,
                "output_redirect_status": output_status}
    try:
        trace_text = trace_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"selected": None, "reason": f"private execve trace could not be read ({type(exc).__name__})",
                "trace_path": str(trace_path), "action_exit": result.returncode,
                "output_redirect_status": output_status}
    (probe_dir / "driver.private.log").write_text(result.stdout, encoding="utf-8")
    selection = resolve_linker_from_execve_trace(trace_text, cwd)
    return {**selection, "trace_path": str(trace_path), "action_exit": result.returncode,
            "findings": replay_findings(argv, cwd, result.stdout),
            "output_redirect_status": output_status}


def discover_actual_compiler(launcher, argv, env, cwd, tf_root, output_base, execution_root, toolchain_paths):
    """Resolve a wrapper's child compiler only from its successful action dry-run."""
    if not looks_like_wrapper(launcher):
        return launcher, None, "direct action executable", None
    dry_run = run([str(launcher), *argv[1:], "-###"], cwd=cwd, env=env)
    tokens = compiler_tokens_from_dry_run(dry_run.stdout)
    resolved = {
        path for token in tokens
        if (path := resolve_executable(token, tf_root, output_base, execution_root, toolchain_paths))
    }
    if dry_run.returncode == 0 and len(resolved) == 1:
        return next(iter(resolved)), dry_run, "wrapper dry-run", tokens
    return None, dry_run, "UNRESOLVED: wrapper dry-run did not prove one compiler", tokens


ROOT_LINK_LABELS = {
    "library": "//tensorflow/lite/c:libtensorflowlite_c.so",
    "smoke": "//tensorflow/lite/c/cloud_smoke:tflite_smoke",
}
RELEVANT_ENVIRONMENT = {
    "PATH", "CC", "CXX", "LD", "SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX",
    "COMPILER_PATH", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
}


def validate_action_graph(document):
    """Validate the Bazel 6.5.0 ActionGraphContainer records used by this tool."""
    if not isinstance(document, dict):
        raise ValueError("JSONPROTO root must be an object")
    actions = document.get("actions")
    targets = document.get("targets")
    if not isinstance(actions, list) or not isinstance(targets, list):
        raise ValueError("JSONPROTO must contain actions and targets arrays")
    target_labels = {}
    for target in targets:
        if (not isinstance(target, dict) or not isinstance(target.get("id"), int)
                or isinstance(target.get("id"), bool) or not isinstance(target.get("label"), str)):
            raise ValueError("malformed target record: expected numeric id and string label")
        if target["id"] in target_labels:
            raise ValueError(f"duplicate target id {target['id']}")
        target_labels[target["id"]] = target["label"]
    normalized = {"CppCompile": [], "CppLink": []}
    errors = []
    for index, record in enumerate(actions):
        if not isinstance(record, dict):
            errors.append(f"action[{index}] is not an object")
            continue
        mnemonic = record.get("mnemonic")
        if not isinstance(mnemonic, str):
            errors.append(f"action[{index}] has missing or invalid mnemonic")
            continue
        if mnemonic not in normalized:
            continue
        action_id = record.get("targetId")
        if not isinstance(action_id, int) or isinstance(action_id, bool):
            errors.append(f"action[{index}] has missing or invalid targetId")
            continue
        label = target_labels.get(action_id)
        if label is None:
            errors.append(f"action[{index}] references unknown targetId {action_id}")
            continue
        args = record.get("arguments")
        if not isinstance(args, list) or not args or not all(isinstance(arg, str) for arg in args):
            errors.append(f"action[{index}] has missing, empty, or malformed arguments")
            continue
        env_records = record.get("environmentVariables", [])
        if not isinstance(env_records, list):
            errors.append(f"action[{index}] environmentVariables is not an array")
            continue
        environment = {}
        env_malformed = False
        for item in env_records:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str) or not isinstance(item.get("value"), str):
                env_malformed = True
                break
            if item["key"] in environment and environment[item["key"]] != item["value"]:
                env_malformed = True
                break
            environment[item["key"]] = item["value"]
        if env_malformed:
            errors.append(f"action[{index}] has malformed environmentVariables records")
            continue
        configuration_id = record.get("configurationId")
        if not isinstance(configuration_id, int) or isinstance(configuration_id, bool):
            errors.append(f"action[{index}] has missing or invalid configurationId")
            continue
        param_files = record.get("paramFiles", [])
        if not isinstance(param_files, list):
            errors.append(f"action[{index}] paramFiles is not an array")
            continue
        param_map = {}
        malformed_param = False
        for item in param_files:
            if (not isinstance(item, dict) or not isinstance(item.get("execPath"), str) or not item.get("execPath")
                    or not isinstance(item.get("arguments"), list)
                    or not all(isinstance(arg, str) for arg in item.get("arguments", []))):
                malformed_param = True
                break
            if item["execPath"] in param_map:
                malformed_param = True
                break
            param_map[item["execPath"]] = item["arguments"]
        if malformed_param:
            errors.append(f"action[{index}] has malformed or duplicate paramFiles records")
            continue
        execution_args = args
        response_check = None
        if mnemonic == "CppLink" and len(param_map) == 1:
            # Bazel 6.5 LinkCommandLine.arguments() gives getRawLinkArgv().
            # getCommandLine(expander) actually executes driver + @params.
            # Accept this representation only on complete, ordered equality.
            path, body = next(iter(param_map.items()))
            refs = [arg for arg in args[1:] if arg.startswith("@")]
            if refs == ["@" + path] and [arg for arg in args[1:] if arg != refs[0]] == body:
                execution_args = [args[0], *refs]
                response_check = (path, body)
        expanded, unresolved = expand_jsonproto_param_files(execution_args, param_map)
        referenced = referenced_param_files(args, param_map)
        unreferenced = set(param_map) - referenced
        if unreferenced:
            unresolved.append("one or more paramFiles records are not referenced by action arguments")
        normalized[mnemonic].append({
            "argv": expanded,
            "link_response_check": response_check,
            "target": label,
            "target_id": action_id,
            "configuration_id": configuration_id,
            "environment": environment,
            "env_captured": "environmentVariables" in record,
            "param_file_status": "NOT RESOLVED: response-file references or record associations are incomplete" if unresolved else "RESOLVED",
            "param_file_count": len(param_map),
            "param_file_reference_count": len(referenced),
            "param_file_unreferenced_count": len(unreferenced),
            "action_key": record.get("actionKey") if isinstance(record.get("actionKey", ""), str) else "",
            "argv_unresolved": unresolved,
        })
    return normalized, errors, target_labels


def parse_action_graph(text):
    """Parse JSONPROTO and validate the observed ActionGraphContainer shape."""
    document = json.loads(text)
    return validate_action_graph(document)


def referenced_param_files(argv, param_files):
    """Find exact response-file references, including references nested in records."""
    used = set()
    pending = list(argv)
    while pending:
        item = pending.pop(0)
        reference = None
        if item.startswith("@") and len(item) > 1:
            reference = item[1:]
        elif item.startswith("--param_file="):
            reference = item.split("=", 1)[1]
        elif item in ("--param_file", "--param-file") and pending:
            reference = pending.pop(0)
        if reference in param_files and reference not in used:
            used.add(reference)
            pending.extend(param_files[reference])
    return used


def expand_jsonproto_param_files(argv, param_files, *, max_depth=8):
    """Expand only argv references matched exactly to Bazel paramFiles records."""
    unresolved = []

    def expand(items, stack, depth):
        if depth > max_depth:
            unresolved.append("nesting depth exceeded")
            return list(items)
        output = []
        index = 0
        while index < len(items):
            item = items[index]
            reference = None
            if item.startswith("@") and len(item) > 1:
                reference = item[1:]
            elif item.startswith("--param_file="):
                reference = item.split("=", 1)[1]
            elif item in ("--param_file", "--param-file"):
                if index + 1 < len(items):
                    reference = items[index + 1]
                    index += 1
                else:
                    unresolved.append(f"missing path after {item}")
                    output.append(item)
                    index += 1
                    continue
            if reference is None:
                output.append(item)
                index += 1
                continue
            if reference in stack:
                unresolved.append(f"cycle at {reference}")
                output.append(item)
                index += 1
                continue
            if reference not in param_files:
                unresolved.append(f"no paramFiles record for {reference}")
                output.append(item)
                index += 1
                continue
            output.extend(expand(param_files[reference], stack | {reference}, depth + 1))
            index += 1
        return output

    return expand(argv, set(), 0), unresolved


def action_signature(action):
    """Return a conservative toolchain signature, excluding source/output operands."""
    args = action["argv"]
    relevant = []
    prefixes = ("--sysroot=", "-isysroot", "-B", "--gcc-toolchain=", "--target=", "-fuse-ld=",
                "-march=", "-mcpu=", "-mabi=", "-mfpu=", "-mfloat-abi=", "-stdlib=", "-resource-dir=")
    for index, arg in enumerate(args[1:], 1):
        if arg in ("--sysroot", "-isysroot", "-target", "--target", "-B", "--gcc-toolchain",
                   "-march", "-mcpu", "-mabi", "-mfpu", "-mfloat-abi", "-fuse-ld", "-resource-dir"):
            relevant.extend(args[index:index + 2])
        elif arg.startswith(prefixes):
            relevant.append(arg)
    env_projection = {key: action["environment"].get(key, "") for key in sorted(RELEVANT_ENVIRONMENT)}
    digest = hashlib.sha256(json.dumps(env_projection, sort_keys=True).encode()).hexdigest()
    return (action["configuration_id"], args[0], tuple(relevant), digest)


def select_actions(actions, target_name):
    root_label = ROOT_LINK_LABELS[target_name]
    links = [item for item in actions["CppLink"] if item["target"] == root_label]
    compiles = actions["CppCompile"]
    groups = {}
    for item in compiles:
        groups.setdefault(action_signature(item), []).append(item)
    representatives = []
    for signature, members in sorted(groups.items(), key=lambda entry: repr(entry[0])):
        chosen = min(members, key=lambda item: (item["target"], item["action_key"], item["argv"][0]))
        representatives.append((signature, chosen, len(members)))
    return links, representatives


def main(argv):
    if len(argv) != 6:
        print("usage: collect-bazel-toolchain.py JSONPROTO TF_ROOT OUTPUT_BASE REPORT TARGET", file=sys.stderr)
        return 2
    actions_file, tf_root, output_base, report = map(Path, argv[1:5])
    target_name = argv[5]
    if target_name not in ROOT_LINK_LABELS:
        print("target must be library or smoke", file=sys.stderr)
        return 2
    try:
        actions, graph_errors, _ = parse_action_graph(actions_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            f"Bazel JSONPROTO toolchain diagnostic\njson_status=NOT RESOLVED ({type(exc).__name__})\n"
            f"collector_failure_category[jsonproto-parse]={type(exc).__name__}\ncollector_exit_code=1\n",
            encoding="utf-8")
        print(f"JSONPROTO could not be parsed or validated ({type(exc).__name__}); private report has details", file=sys.stderr)
        return 1
    execution_root = output_base / "execroot" / "org_tensorflow"
    repo_specs = (("generated_repository", "local_config_embedded_arm"),
                  ("external_repository", "aarch64_linux_toolchain"))
    toolchain_paths = []
    toolchain_roots = {}
    return_code = 0
    failure_categories = []
    default_sysroot_cache = {}

    def mark_failure(category, detail):
        failure_categories.append(f"{category}: {detail}")

    with report.open("w", encoding="utf-8") as stream:
        print("Bazel C++ toolchain diagnostic", file=stream)
        print(f"actions_file={actions_file.resolve()}", file=stream)
        print(f"tensorflow_workspace={tf_root.resolve()}", file=stream)
        print(f"bazel_output_base={output_base.resolve()}", file=stream)
        print(f"bazel_execution_root={execution_root.resolve(strict=False)}", file=stream)
        for repo_kind, repo_name in repo_specs:
            candidates = [
                output_base / "external" / repo_name,
                execution_root / "external" / repo_name,
                tf_root / "external" / repo_name,
            ]
            resolved = next((p.resolve() for p in candidates if p.exists()), None)
            print(f"{repo_kind}[{repo_name}]="
                  f"{resolved if resolved else '<UNRESOLVED>'}", file=stream)
            for path in candidates:
                print(f"  candidate={path} -> {path.resolve(strict=False)}; exists={path.exists()}", file=stream)
            if resolved:
                toolchain_paths.append(resolved)
                toolchain_roots[repo_name] = resolved
            else:
                print(f"ERROR: external repository {repo_name} not resolved", file=stream)
                print(f"toolchain_repository_status[{repo_kind}:{repo_name}]=NOT RESOLVED: repository path not found", file=stream)
                mark_failure("toolchain-repository", f"{repo_kind}:{repo_name} not resolved")
                return_code = 1
            if resolved:
                print(f"toolchain_repository_status[{repo_kind}:{repo_name}]=RESOLVED: repository path found", file=stream)

        for error in graph_errors:
            print(f"json_action_graph_error={error}", file=stream)
            mark_failure("jsonproto-structure", error)
            return_code = 1
        root_links, compile_groups = select_actions(actions, target_name)
        compile_total = len(actions["CppCompile"])
        print(f"target_name={target_name}", file=stream)
        print(f"action_selection_root_link_count={len(root_links)}", file=stream)
        print(f"action_selection_compile_total={compile_total}", file=stream)
        print(f"action_selection_cpp_link_total={len(actions['CppLink'])}", file=stream)
        print(f"action_selection_compile_signature_groups={len(compile_groups)}", file=stream)
        print("compile_signature_grouping=configurationId,launcher,sysroot/toolchain flags,and hash of relevant environment keys", file=stream)
        compile_configurations = sorted({item["configuration_id"] for item in actions["CppCompile"]})
        link_configurations = sorted({item["configuration_id"] for item in root_links})
        print(f"action_selection_compile_configurations={compile_configurations}", file=stream)
        print(f"action_selection_root_link_configurations={link_configurations}", file=stream)
        config_overlap = bool(set(compile_configurations) & set(link_configurations))
        if set(compile_configurations) == set(link_configurations) and link_configurations:
            consistency = "CONSISTENT"
        elif config_overlap:
            consistency = "MULTIPLE CONFIGURATIONS: compiler groups retained separately; root-link configuration is listed independently"
        else:
            consistency = "NOT RESOLVED: no compile configuration matches the root-link configuration"
        print(f"compile_configuration_consistency={consistency}", file=stream)
        if not config_overlap:
            mark_failure("configuration-consistency", "no compile configuration matches root CppLink")
            return_code = 1
        selected = {
            "CppCompile": [item for _, item, _ in compile_groups],
            "CppLink": root_links,
        }
        for signature, action, member_count in compile_groups:
            print(f"compile_signature_group_configuration={signature[0]} count={member_count} launcher_token={action['argv'][0]}", file=stream)
        if compile_total == 0:
            print("ERROR: no CppCompile actions found for target dependency closure", file=stream)
            mark_failure("action-selection", "no CppCompile actions in dependency closure")
            return_code = 1
        if len(root_links) != 1:
            print(f"ERROR: expected exactly one CppLink for root label {ROOT_LINK_LABELS[target_name]}; found {len(root_links)}", file=stream)
            mark_failure("action-selection", f"expected one root CppLink, found {len(root_links)}")
            return_code = 1
        drivers = {}
        for mnemonic in ("CppCompile", "CppLink"):
            print(f"\n=== {mnemonic} selected JSONPROTO actions ===", file=stream)
            action_list = selected[mnemonic]
            if not action_list:
                print(f"ERROR: no selected {mnemonic} actions found in Bazel JSONPROTO", file=stream)
                print(f"diagnostic_status=NOT RESOLVED: no {mnemonic} action records in aquery output", file=stream)
                mark_failure("action-selection", f"no selected {mnemonic} action")
                return_code = 1
            for number, action in enumerate(action_list, start=1):
                # Raw argv remains private in this report. Public sanitization
                # consumes only the structured fields below.
                print(f"[{mnemonic} #{number}]", file=stream)
                print(f"  action_target={action.get('target', '<not exposed>')}", file=stream)
                print("  action_source=Bazel 6.5.0 JSONPROTO Cpp action", file=stream)
                print(f"  action_target_id={action['target_id']}", file=stream)
                print(f"  action_configuration_id={action['configuration_id']}", file=stream)
                print(f"  response_file_records={action['param_file_count']}", file=stream)
                print(f"  response_file_references_matched={action['param_file_reference_count']}", file=stream)
                print(f"  response_file_records_unreferenced={action['param_file_unreferenced_count']}", file=stream)
                environment = action["environment"]
                print(f"  action_environment_status={'captured by aquery' if action.get('env_captured') else 'NOT EXPOSED by aquery; effective sysroot may be unresolved'}", file=stream)
                if environment is not None:
                    relevant_keys = (
                        "PATH", "CC", "CXX", "LD", "SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX",
                        "COMPILER_PATH", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                    )
                    for key in relevant_keys:
                        if key in environment:
                            print(f"  action_env[{key}]={environment[key]}", file=stream)
                child_env = {}
                expanded_argv = action["argv"]
                unresolved_response_files = action["argv_unresolved"]
                if unresolved_response_files:
                    print("  response_file_status=NOT RESOLVED: one or more referenced response files could not be read", file=stream)
                    print(f"  response_files_unresolved_count={len(unresolved_response_files)}", file=stream)
                    mark_failure("response-files", f"{mnemonic} action #{number} has unresolved param-file references")
                    return_code = 1
                else:
                    print(f"  response_file_status={action['param_file_status']}", file=stream)
                sysroots = extract_sysroots(expanded_argv)
                print(f"  explicit_action_sysroot_arguments={sysroots if sysroots else '<none specified>'}", file=stream)
                print(f"  explicit_action_sysroot_provenance={'JSONPROTO arguments/paramFiles' if sysroots else '<no explicit value>'}", file=stream)
                print(f"  action_sysroot_status={'explicit action argument(s)' if sysroots else 'no explicit --sysroot/-isysroot argument'}", file=stream)
                if not sysroots:
                    print("  explicit_action_sysroot_value=<none specified>", file=stream)
                driver = action_driver(action, tf_root, output_base, execution_root, toolchain_paths)
                if driver is None:
                    print(f"  action_compiler_driver=UNRESOLVED ({action['argv'][0] if action['argv'] else '<empty argv>'})", file=stream)
                    print("  compiler_resolution_status=NOT RESOLVED: action command has no executable token", file=stream)
                    mark_failure("compiler-resolution", f"{mnemonic} action #{number} has no executable token")
                    return_code = 1
                    continue
                token, launcher, full_argv = driver
                print(f"  action_launcher_token={token}", file=stream)
                print(f"  resolved_action_launcher={launcher}", file=stream)
                if launcher is None:
                    print("  compiler_resolution_status=NOT RESOLVED: action launcher path could not be resolved in pinned toolchain repositories", file=stream)
                    print("  effective_sysroot_status=NOT RESOLVED: compiler executable is unknown", file=stream)
                    if mnemonic == "CppLink":
                        print("  linker_resolution_status=NOT RESOLVED: CppLink compiler driver is unknown", file=stream)
                        mark_failure("linker-resolution", f"{mnemonic} action #{number} compiler driver unresolved")
                    mark_failure("compiler-resolution", f"{mnemonic} action #{number} launcher unresolved")
                    return_code = 1
                    continue
                cli_environment, clears_environment = launcher_environment(expanded_argv, launcher)
                if cli_environment:
                    for key in ("PATH", "CC", "CXX", "LD", "SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX",
                                "COMPILER_PATH", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS"):
                        if key in cli_environment:
                            print(f"  launcher_env[{key}]={cli_environment[key]}", file=stream)
                if clears_environment:
                    print("  launcher_environment_reset=yes (env -i/--ignore-environment)", file=stream)
                    effective_environment = {k: v for k, v in cli_environment.items() if v != "<UNSET>"}
                else:
                    effective_environment = dict(environment or {})
                    for key, value in cli_environment.items():
                        if value == "<UNSET>":
                            effective_environment.pop(key, None)
                        else:
                            effective_environment[key] = value
                # Replay and compiler dry-runs use exactly the captured action
                # environment after leading env(1) assignments/unsets. No
                # ambient GitHub runner variables are inherited.
                child_env = action_environment_for_replay(
                    environment, cli_environment,
                    captured=action.get("env_captured", False),
                    clear_environment=clears_environment,
                )
                env_sysroot_values = env_sysroots(effective_environment)
                print(f"  wrapper_or_environment_sysroot={env_sysroot_values if env_sysroot_values else '<no sysroot hints in captured action/launcher variables>'}", file=stream)
                environment_is_captured = action.get("env_captured", False) or clears_environment
                is_wrapper = looks_like_wrapper(launcher)
                if is_wrapper:
                    print(f"  compiler_wrapper={launcher}", file=stream)
                    actual_compiler, wrapper_dry_run, compiler_evidence, compiler_tokens = discover_actual_compiler(
                        launcher, expanded_argv, child_env, execution_root,
                        tf_root, output_base, execution_root, toolchain_paths
                    )
                    print(f"  actual_compiler_identification_evidence={compiler_evidence}", file=stream)
                    print(f"  wrapper_dry_run_exit={wrapper_dry_run.returncode if wrapper_dry_run else '<not run>'}", file=stream)
                    print(f"  wrapper_dry_run_compiler_tokens={compiler_tokens if compiler_tokens is not None else '<not applicable>'}", file=stream)
                    if wrapper_dry_run:
                        print(wrapper_dry_run.stdout.rstrip(), file=stream)
                else:
                    actual_compiler = launcher
                    wrapper_dry_run = None
                    print(f"  actual_compiler={actual_compiler} (direct C++ action executable)", file=stream)
                if actual_compiler is None:
                    print("  actual_compiler=NOT RESOLVED", file=stream)
                    print("  compiler_resolution_status=NOT RESOLVED: wrapper dry-run did not prove one executable", file=stream)
                    mark_failure("compiler-resolution", f"{mnemonic} action #{number} wrapper did not prove a compiler")
                    return_code = 1
                else:
                    print(f"  actual_compiler={actual_compiler}", file=stream)
                    print("  compiler_resolution_status=RESOLVED: action executable or wrapper dry-run", file=stream)
                    drivers[(mnemonic, str(actual_compiler), repr(sorted(effective_environment.items()))) ] = (
                        actual_compiler, action, effective_environment, environment_is_captured
                    )

                # Probe the compiler default once per actual compiler. This is
                # deliberately separate from the effective Cpp action value.
                default_sysroot = None
                default_sysroot_result = None
                if actual_compiler is not None:
                    compiler_key = str(actual_compiler)
                    if compiler_key not in default_sysroot_cache:
                        default_env = {key: child_env[key] for key in ("PATH", "LANG", "LC_ALL", "HOME")
                                       if key in child_env}
                        result = run([compiler_key, "-print-sysroot"], cwd=execution_root, env=default_env)
                        default_sysroot_cache[compiler_key] = (result.stdout.strip() if result.returncode == 0 else None,
                                                               result.returncode)
                    default_sysroot, default_rc = default_sysroot_cache[compiler_key]
                    default_sysroot_result = default_rc
                    identity, normalization = normalize_sysroot_identity(
                        default_sysroot,
                        {"aarch64_linux_toolchain": toolchain_roots["aarch64_linux_toolchain"]}
                        if "aarch64_linux_toolchain" in toolchain_roots else {},
                        base=execution_root)
                    print(f"  compiler_default_configured_sysroot={default_sysroot if default_sysroot is not None else '<probe failed>'}", file=stream)
                    print(f"  compiler_default_sysroot_identity={identity}", file=stream)
                    print(f"  compiler_default_sysroot_normalization_status={normalization}", file=stream)
                    print("  compiler_default_sysroot_provenance=actual compiler -print-sysroot with sysroot/compiler-selection environment overrides cleared", file=stream)
                    if default_rc:
                        print("  compiler_default_sysroot_status=NOT RESOLVED: -print-sysroot probe failed", file=stream)
                        mark_failure("default-sysroot-probe", f"{mnemonic} action #{number} compiler -print-sysroot exit={default_rc}")
                        return_code = 1
                    else:
                        print("  compiler_default_sysroot_status=RESOLVED: compiler-reported default/configured value only", file=stream)

                # Resolve effective action sysroot only when action, response
                # files, captured environment, launcher and compiler probe agree.
                wrapper_sysroots = []
                if wrapper_dry_run:
                    wrapper_sysroots = extract_sysroots_text(wrapper_dry_run.stdout)
                print(f"  wrapper_dry_run_sysroot_arguments={wrapper_sysroots if wrapper_sysroots else '<none exposed>'}", file=stream)
                wrapper_paths = []
                for value in wrapper_sysroots:
                    if "=" in value:
                        wrapper_paths.append(value.split("=", 1)[1])
                    elif " " in value:
                        wrapper_paths.append(value.split(" ", 1)[1])
                unreviewed_environment_keys = sorted(
                    set(effective_environment)
                    - (RELEVANT_ENVIRONMENT | {"LANG", "LC_ALL", "HOME", "TMPDIR", "TMP", "TEMP", "PWD", "LD_LIBRARY_PATH", "LD_PRELOAD", "SOURCE_DATE_EPOCH"})
                )
                print(f"  unreviewed_action_environment_key_names={','.join(unreviewed_environment_keys) if unreviewed_environment_keys else '<none>'}", file=stream)
                tf2_evidence = []
                tf2_verified = (unreviewed_environment_keys == ["TF2_BEHAVIOR"] and
                                not any(child_env.get(k) for k in ("LD_LIBRARY_PATH", "LD_PRELOAD")) and
                                not is_wrapper and environment_is_captured and not unresolved_response_files and
                                "aarch64_linux_toolchain" in toolchain_roots and
                                launcher.is_relative_to(toolchain_roots["aarch64_linux_toolchain"]) and
                                launcher == (toolchain_roots["aarch64_linux_toolchain"] / "bin/aarch64-none-linux-gnu-gcc").resolve() and
                                compare_tf2_probes(launcher, expanded_argv, child_env, execution_root, default_sysroot,
                                                   gcc_version="10.3.1" if os.environ.get("CAPSULE_ARMGNU103") == "1" else "11.3.1",
                                                   evidence=tf2_evidence))
                for detail in tf2_evidence:
                    print(f"tf2_comparison={detail}", file=stream)
                if tf2_verified:
                    unreviewed_environment_keys = []
                effective_value, effective_status, sysroot_provenance = decide_effective_sysroot(
                    extract_sysroot_paths(expanded_argv),
                    env_sysroot_values,
                    environment_is_captured,
                    (not is_wrapper or launcher.name == "env"),
                    wrapper_paths,
                    default_sysroot if default_sysroot_result == 0 else None,
                    unknown_environment_keys=unreviewed_environment_keys,
                )
                if tf2_verified and effective_status == "RESOLVED":
                    sysroot_provenance += "; matched GCC version, triple, specs, action -print-sysroot and -### with/without TF2_BEHAVIOR"
                effective_identity, effective_normalization = normalize_sysroot_identity(
                    effective_value,
                    {"aarch64_linux_toolchain": toolchain_roots["aarch64_linux_toolchain"]}
                    if "aarch64_linux_toolchain" in toolchain_roots else {},
                    base=execution_root)
                print(f"  effective_sysroot_assessment={effective_status}: {sysroot_provenance}", file=stream)
                print(f"  effective_sysroot_identity={effective_identity}", file=stream)
                print(f"  effective_sysroot_normalization_status={effective_normalization}", file=stream)
                print(f"  effective_sysroot_provenance={sysroot_provenance}", file=stream)
                print(f"  effective_sysroot_status={effective_status}: {sysroot_provenance}", file=stream)
                if effective_status != "RESOLVED":
                    mark_failure("effective-sysroot", f"{mnemonic} action #{number}: {sysroot_provenance}")
                    return_code = 1

                if mnemonic == "CppLink":
                    print("  linker_identification=CppLink launcher dry-run of this captured action (-###)", file=stream)
                    dry_run = wrapper_dry_run or run(
                        [str(launcher), *expanded_argv[1:], "-###"], cwd=execution_root, env=child_env
                    )
                    print(dry_run.stdout.rstrip(), file=stream)
                    print(f"  linker_dry_run_exit={dry_run.returncode}", file=stream)
                    # Probe the candidate for this exact link action before
                    # comparing it with the linker proven by the dry-run.
                    action_linker_probe = run(
                        [str(launcher), *expanded_argv[1:], "-print-prog-name=ld"], cwd=execution_root, env=child_env
                    )
                    action_linker_token = action_linker_probe.stdout.strip().splitlines()[-1] if action_linker_probe.stdout.strip() else ""
                    action_linker_path = resolve_executable(
                        action_linker_token, tf_root, output_base, execution_root, toolchain_paths
                    ) if action_linker_token else None
                    print(f"  CppLink_action_specific_print_prog_name_exit={action_linker_probe.returncode}", file=stream)
                    print(f"  CppLink_action_specific_print_prog_name_token={action_linker_token or '<empty>'}", file=stream)
                    print(f"  CppLink_linker_candidate_path={action_linker_path or '<UNRESOLVED>'}", file=stream)
                    if action_linker_probe.returncode:
                        mark_failure("linker-candidate-probe", f"CppLink action #{number} -print-prog-name=ld exit={action_linker_probe.returncode}")
                        return_code = 1
                    if action_linker_path:
                        candidate_version = run([str(action_linker_path), "--version"])
                        print("  CppLink_linker_candidate_version:", file=stream)
                        print(candidate_version.stdout.rstrip(), file=stream)
                        print(f"  CppLink_linker_candidate_version_exit={candidate_version.returncode}", file=stream)
                        if candidate_version.returncode:
                            mark_failure("linker-candidate-version", f"CppLink action #{number} candidate --version exit={candidate_version.returncode}")
                            return_code = 1
                    else:
                        print("  CppLink_linker_candidate_version=UNRESOLVED", file=stream)
                    selection = linker_selection_from_dry_run(
                        dry_run.stdout,
                        action_linker_path,
                        lambda item: resolve_executable(item, tf_root, output_base, execution_root, toolchain_paths),
                        dry_run_succeeded=(dry_run.returncode == 0),
                    )
                    if selection["helpers"]:
                        print("  linker_driver_helper=collect2 (not the actual linker)", file=stream)
                        for line in selection["helpers"]:
                            print(f"    {line}", file=stream)
                    # -### is useful evidence about the driver's plan, but it
                    # does not execute the linker. Only the successful execve
                    # trace of this action-compatible replay resolves actual.
                    print(f"  dry_run_linker_selection_candidate={selection['selected'] or '<not proven by -###>'}", file=stream)
                    response_check = action["link_response_check"]
                    if response_check:
                        response_path, expected = response_check
                        disk_path = execution_root / response_path
                        try:
                            disk_args = shlex.split(disk_path.read_text(encoding="utf-8"))
                        except (OSError, UnicodeError, ValueError):
                            disk_args = None
                        if disk_args != expected:
                            mark_failure("response-files", "root link response disagrees with on-disk build input")
                            print("  linker_resolution_status=NOT RESOLVED: built response file unavailable or changed", file=stream)
                            continue
                        print("  response_file_status=verified identical ordered arguments in JSONPROTO and build response file", file=stream)
                    if unresolved_response_files:
                        print("  linker_resolution_status=NOT RESOLVED: incomplete parameter file evidence", file=stream)
                        continue
                    trace_result = trace_linker_execution(
                        launcher, expanded_argv, child_env, execution_root,
                        report.parent / "linker-exec-traces", f"{target_name}-{number}",
                        environment_captured=environment_is_captured)
                    print(f"  linker_trace_status={'RESOLVED' if trace_result['selected'] else 'NOT RESOLVED'}", file=stream)
                    print(f"  linker_trace_action_exit={trace_result.get('action_exit')}", file=stream)
                    if "findings" in trace_result:
                        print(f"  replay_findings={trace_result['findings']}", file=stream)
                    print(f"  linker_trace_output_redirect_status={trace_result['output_redirect_status']}", file=stream)
                    if trace_result.get("trace_path"):
                        print(f"  linker_trace_private_file={trace_result['trace_path']}", file=stream)
                    if trace_result.get("helpers"):
                        print("  linker_trace_driver_helper=collect2 (not the actual linker)", file=stream)
                    selected_linker = trace_result["selected"]
                    linker_evidence = "successful linker execve observed by strace while replaying captured CppLink argv with recognized outputs redirected to private paths"
                    if selected_linker:
                        print(f"  actual_linker_observed_execve={trace_result['observed']}", file=stream)
                        print(f"  linker_trace_reason={trace_result['reason']}", file=stream)
                        if selection["selected"] and selection["selected"] != selected_linker:
                            print("  linker_dry_run_vs_trace=DIFFERENT: actual resolution uses the executed trace", file=stream)
                        if trace_result.get("action_exit") != 0:
                            mark_failure("linker-trace-execution", f"{mnemonic} action #{number} replay exited {trace_result.get('action_exit')}")
                            return_code = 1
                    else:
                        trace_reason = trace_result["reason"]
                        print(f"  actual_selected_linker=UNRESOLVED; dry-run: {selection['reason']}; trace: {trace_reason}", file=stream)
                        print(f"  linker_resolution_status=NOT RESOLVED: {trace_reason}", file=stream)
                        mark_failure("linker-resolution", f"{mnemonic} action #{number}: {trace_reason}")
                        return_code = 1
                    if selected_linker:
                        print(f"  actual_selected_linker={selected_linker}", file=stream)
                        print(f"  linker_evidence={linker_evidence}", file=stream)
                        linker_version = run([str(selected_linker), "--version"])
                        linker_target = run([str(selected_linker), "-V"])
                        implementation = linker_implementation(linker_version.stdout, selected_linker)
                        target_architecture = linker_target_architecture(linker_target.stdout)
                        first_version_line = next((line.strip() for line in linker_version.stdout.splitlines() if line.strip()), "<empty>")
                        print(f"  actual_linker_basename={Path(selected_linker).name}", file=stream)
                        print(f"  actual_linker_implementation={implementation}", file=stream)
                        print(f"  actual_linker_version={first_version_line}", file=stream)
                        print(f"  actual_linker_target_architecture={target_architecture}", file=stream)
                        identity_status = "RESOLVED" if linker_version.returncode == 0 and implementation != "UNRESOLVED" else "NOT RESOLVED"
                        print(f"  actual_linker_identity_status={identity_status}", file=stream)
                        print(f"  actual_linker_version_exit={linker_version.returncode}", file=stream)
                        print(f"  actual_linker_target_probe_exit={linker_target.returncode}", file=stream)
                        if identity_status != "RESOLVED":
                            mark_failure("linker-identity", f"{mnemonic} action #{number}: linker version/implementation unresolved")
                            return_code = 1
                        print("  linker_resolution_status=RESOLVED: actual linker executable evidence recorded", file=stream)
                    if dry_run.returncode:
                        print("  WARNING: CppLink dry-run returned nonzero; direct dry-run evidence is unavailable", file=stream)
                        mark_failure("linker-dry-run", f"{mnemonic} action #{number} -### exit={dry_run.returncode}")
                        return_code = 1
        print("\n=== Actual compiler metadata (wrapper paths excluded) ===", file=stream)
        if not drivers:
            print("ERROR: no actual compiler executable was proven from Bazel C++ actions", file=stream)
            mark_failure("compiler-resolution", "no compiler executable proved from any selected action")
            return_code = 1
        for (mnemonic, _, _), (compiler, action, environment, env_captured) in sorted(drivers.items()):
            print(f"\n--- actual compiler used by {mnemonic}: {compiler} ---", file=stream)
            probe_env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "HOME") if key in os.environ}
            if env_captured and environment is not None:
                probe_env.update({key: value for key, value in environment.items() if key in RELEVANT_ENVIRONMENT})
            for label, args in (
                ("version", [str(compiler), "--version"]),
                ("verbose version", [str(compiler), "-v"]),
                ("target triple", [str(compiler), "-dumpmachine"]),
            ):
                if log_command(stream, label, args, env=probe_env).returncode:
                    print(f"compiler_metadata_status=NOT RESOLVED: {label} probe failed", file=stream)
                    mark_failure("compiler-metadata", f"{mnemonic} {label} probe failed")
                    return_code = 1
            default_value, default_exit = default_sysroot_cache.get(str(compiler), (None, None))
            default_identity, default_normalization = normalize_sysroot_identity(
                default_value, {"aarch64_linux_toolchain": toolchain_roots["aarch64_linux_toolchain"]}
                if "aarch64_linux_toolchain" in toolchain_roots else {},
                base=execution_root)
            print(f"compiler_default_configured_sysroot={default_value if default_value is not None else '<probe failed>'}", file=stream)
            print(f"compiler_default_sysroot_identity={default_identity}", file=stream)
            print(f"compiler_default_sysroot_normalization_status={default_normalization}", file=stream)
            print("compiler_default_sysroot_provenance=actual compiler -print-sysroot with sysroot/compiler-selection environment overrides cleared", file=stream)
            if default_exit is None or default_exit:
                print("compiler_default_sysroot_status=NOT RESOLVED: -print-sysroot probe failed or was not collected", file=stream)
                mark_failure("default-sysroot-probe", f"{mnemonic} default sysroot probe unavailable/exit={default_exit}")
                return_code = 1
            else:
                print("compiler_default_sysroot_status=RESOLVED: compiler-reported default/configured value only", file=stream)
            if log_command(stream, "compiler search directories", [str(compiler), "-print-search-dirs"], env=probe_env).returncode:
                print("compiler_search_directories_status=NOT RESOLVED: probe failed", file=stream)
                mark_failure("compiler-metadata", f"{mnemonic} -print-search-dirs probe failed")
                return_code = 1
            reported_linker = log_command(stream, "compiler-reported default linker (informational only; not proof of CppLink selection)",
                                          [str(compiler), "-print-prog-name=ld"], env=probe_env)
            print(f"compiler_reported_default_linker={reported_linker.stdout.strip() or '<empty>'}", file=stream)
            if reported_linker.returncode:
                print("compiler_default_linker_status=NOT RESOLVED: informational probe failed", file=stream)
                mark_failure("compiler-metadata", f"{mnemonic} -print-prog-name=ld probe failed")
                return_code = 1
        return_code = diagnostic_exit_code(return_code, failure_categories)
        for category in failure_categories:
            print(f"collector_failure_category={category}", file=stream)
        print(f"collector_exit_code={return_code}", file=stream)
        stream.flush()
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except SystemExit:
        raise
    except Exception as exc:  # Keep traceback in the private report only.
        if len(sys.argv) >= 5:
            try:
                with open(sys.argv[4], "a", encoding="utf-8") as report_stream:
                    print(f"FATAL_DIAGNOSTIC_ERROR={type(exc).__name__}", file=report_stream)
                    print(f"collector_failure_category=fatal-exception: {type(exc).__name__}", file=report_stream)
                    print("collector_exit_code=1", file=report_stream)
                    traceback.print_exc(file=report_stream)
            except OSError:
                pass
        print(f"toolchain collector failed ({type(exc).__name__}); private report has details", file=sys.stderr)
        raise SystemExit(1)
