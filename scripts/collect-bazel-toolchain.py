#!/usr/bin/env python3
"""Record compiler/linker evidence from Bazel's CppCompile and CppLink actions."""

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


def run(args, *, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env)


def split_actions(text):
    """Return Bazel text-aquery action blocks keyed by Cpp mnemonic."""
    blocks = re.split(r"(?m)(?=^action ')", text)
    found = {"CppCompile": [], "CppLink": []}
    for block in blocks:
        mnemonic = re.search(r"(?m)^\s*Mnemonic:\s*(CppCompile|CppLink)\s*$", block)
        command = re.search(r"(?m)^\s*Command Line:\s*(.*)$", block)
        environment = re.search(r"(?m)^\s*(?:Environment Variables|Environment):\s*(.*)$", block)
        if not mnemonic or not command:
            continue
        raw = command.group(1).strip()
        # Bazel prints `(exec <argv...>)` in text mode. Strip only this wrapper;
        # preserve the argument boundaries with shlex below.
        if raw.startswith("(exec ") and raw.endswith(")"):
            raw = raw[6:-1]
        env_raw = None
        if environment:
            # In Bazel's text aquery output the environment header is commonly
            # followed by indented KEY=VALUE lines. Capture the whole section,
            # stopping at the next action field rather than assuming a single
            # line. This is needed to see sysroot and compiler-search overrides.
            env_lines = [environment.group(1)] if environment.group(1).strip() else []
            for line in block[environment.end():].splitlines():
                if not line.strip():
                    if env_lines:
                        break
                    continue
                if not line[:1].isspace() or re.match(r"^\s+[A-Za-z][A-Za-z0-9 _-]*:\s*", line):
                    break
                env_lines.append(line.strip())
            env_raw = "\n".join(env_lines)
        try:
            argv = shlex.split(raw, posix=True)
        except ValueError:
            found[mnemonic.group(1)].append({
                "raw": raw, "argv": [], "parse_error": "unbalanced command quoting",
                "env_raw": env_raw,
            })
            continue
        found[mnemonic.group(1)].append({
            "raw": raw, "argv": argv,
            "env_raw": env_raw,
            "env_captured": environment is not None,
        })
    return found


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
            values.append(arg[len("-isysroot"):])
        i += 1
    return values


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


def parse_action_environment(raw):
    """Parse Bazel's textual KEY=VALUE environment list without logging secrets."""
    if raw is None:
        return None
    variables = {}
    for line in raw.splitlines():
        line = line.strip().strip("[]")
        if re.search(r",\s*[A-Za-z_][A-Za-z0-9_]*=", line):
            for match in re.finditer(r"(?:^|,\s*)([A-Za-z_][A-Za-z0-9_]*)=([^,\]]*)", line):
                variables[match.group(1)] = match.group(2).strip().strip("'\"")
            continue
        assignment = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if assignment:
            variables[assignment.group(1)] = assignment.group(2).strip().strip("'\"")
    return variables


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


def expand_response_files(argv, execution_root, tf_root, output_base, depth=0):
    if depth > 8:
        return argv, ["response-file nesting exceeded limit"]
    expanded = []
    unresolved = []
    for arg in argv:
        if not arg.startswith("@") or arg == "@":
            expanded.append(arg)
            continue
        response_name = arg[1:]
        if response_name.startswith("@"):
            expanded.append(response_name)
            continue
        candidate = Path(response_name)
        probes = [candidate] if candidate.is_absolute() else [
            execution_root / candidate, tf_root / candidate, output_base / candidate
        ]
        response_path = next((path for path in probes if path.is_file()), None)
        if response_path is None:
            unresolved.append(response_name)
            expanded.append(arg)
            continue
        try:
            contents = shlex.split(response_path.read_text(errors="replace"), posix=True)
        except ValueError:
            unresolved.append(f"{response_path} (unbalanced quoting)")
            expanded.append(arg)
            continue
        nested, nested_unresolved = expand_response_files(
            contents, execution_root, tf_root, output_base, depth + 1
        )
        expanded.extend(nested)
        unresolved.extend(nested_unresolved)
    return expanded, unresolved


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


def main(argv):
    if len(argv) != 5:
        print("usage: collect-bazel-toolchain.py ACTIONS TF_ROOT OUTPUT_BASE REPORT", file=sys.stderr)
        return 2
    actions_file, tf_root, output_base, report = map(Path, argv[1:])
    text = actions_file.read_text(errors="replace")
    execution_root = output_base / "execroot" / "org_tensorflow"
    repo_names = ("local_config_embedded_arm", "aarch64_linux_toolchain")
    toolchain_paths = []
    return_code = 0
    with report.open("w", encoding="utf-8") as stream:
        print("Bazel C++ toolchain diagnostic", file=stream)
        print(f"actions_file={actions_file.resolve()}", file=stream)
        print(f"tensorflow_workspace={tf_root.resolve()}", file=stream)
        print(f"bazel_output_base={output_base.resolve()}", file=stream)
        print(f"bazel_execution_root={execution_root.resolve(strict=False)}", file=stream)
        for repo_name in repo_names:
            candidates = [
                output_base / "external" / repo_name,
                execution_root / "external" / repo_name,
                tf_root / "external" / repo_name,
            ]
            resolved = next((p.resolve() for p in candidates if p.exists()), None)
            print(f"external_repository[{repo_name}]="
                  f"{resolved if resolved else '<UNRESOLVED>'}", file=stream)
            for path in candidates:
                print(f"  candidate={path} -> {path.resolve(strict=False)}; exists={path.exists()}", file=stream)
            if resolved:
                toolchain_paths.append(resolved)
            else:
                print(f"ERROR: external repository {repo_name} not resolved", file=stream)
                return_code = 1

        actions = split_actions(text)
        drivers = {}
        for mnemonic in ("CppCompile", "CppLink"):
            print(f"\n=== {mnemonic} action command lines ===", file=stream)
            action_list = actions[mnemonic]
            if not action_list:
                print(f"ERROR: no {mnemonic} actions found in Bazel aquery output", file=stream)
                return_code = 1
            for number, action in enumerate(action_list, start=1):
                print(f"[{mnemonic} #{number}] {action.get('raw', '<unparsed>')}", file=stream)
                if action.get("parse_error"):
                    print(f"  argv_parse=UNRESOLVED ({action['parse_error']})", file=stream)
                    return_code = 1
                    continue
                environment = parse_action_environment(action.get("env_raw"))
                print(f"  action_environment_status={'captured by aquery' if action.get('env_captured') else 'NOT EXPOSED by aquery; effective sysroot may be unresolved'}", file=stream)
                if environment is not None:
                    relevant_keys = (
                        "PATH", "CC", "CXX", "LD", "SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX",
                        "COMPILER_PATH", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                    )
                    for key in relevant_keys:
                        if key in environment:
                            print(f"  action_env[{key}]={environment[key]}", file=stream)
                child_env = None
                if environment is not None:
                    child_env = os.environ.copy()
                    child_env.update(environment)
                expanded_argv, unresolved_response_files = expand_response_files(
                    action["argv"], execution_root, tf_root, output_base
                )
                if unresolved_response_files:
                    print(f"  response_files_unresolved={unresolved_response_files}", file=stream)
                    return_code = 1
                sysroots = extract_sysroots(expanded_argv)
                print(f"  explicit_action_sysroot_arguments={sysroots if sysroots else '<none specified>'}", file=stream)
                print(f"  action_sysroot_status={'explicit action argument(s)' if sysroots else 'no explicit --sysroot/-isysroot argument'}", file=stream)
                driver = action_driver(action, tf_root, output_base, execution_root, toolchain_paths)
                if driver is None:
                    print(f"  action_compiler_driver=UNRESOLVED ({action['argv'][0] if action['argv'] else '<empty argv>'})", file=stream)
                    return_code = 1
                    continue
                token, launcher, full_argv = driver
                print(f"  action_launcher_token={token}", file=stream)
                print(f"  resolved_action_launcher={launcher}", file=stream)
                if launcher is None:
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
                    print("  actual_compiler=UNRESOLVED; wrapper path is not reported as the compiler", file=stream)
                    return_code = 1
                else:
                    drivers[(mnemonic, str(actual_compiler), repr(sorted(effective_environment.items()))) ] = (
                        actual_compiler, action, effective_environment, environment_is_captured
                    )

                # Effective sysroot is a separate conclusion from the compiler's
                # configured default. Do not apply that default when wrapper or
                # action-environment evidence is incomplete.
                wrapper_sysroots = []
                if wrapper_dry_run:
                    wrapper_sysroots = extract_sysroots_text(wrapper_dry_run.stdout)
                if is_wrapper:
                    print(f"  wrapper_dry_run_sysroot_arguments={wrapper_sysroots if wrapper_sysroots else '<none exposed>'}", file=stream)
                    if wrapper_sysroots:
                        effective = f"wrapper dry-run reported {wrapper_sysroots}"
                    elif env_sysroot_values:
                        effective = f"UNRESOLVED: wrapper/environment-provided sysroot hints {env_sysroot_values} were not confirmed in wrapper dry-run"
                    elif launcher.name == "env" and environment_is_captured and not env_sysroot_values:
                        effective = "compiler default/configured sysroot applies under captured transparent env launcher"
                    else:
                        effective = "UNRESOLVED: wrapper/environment may inject a sysroot not visible in the dry-run"
                elif sysroots:
                    effective = f"explicit action sysroot {sysroots}"
                elif env_sysroot_values:
                    effective = f"UNRESOLVED: action environment contains sysroot hints {env_sysroot_values}"
                elif not action.get("env_captured"):
                    effective = "UNRESOLVED: Bazel action environment was not exposed"
                elif environment and any(environment.get(key) for key in ("GCC_EXEC_PREFIX", "COMPILER_PATH")):
                    effective = "UNRESOLVED: compiler search environment may redirect sysroot/tool selection"
                else:
                    effective = "compiler default/configured sysroot applies (no wrapper or sysroot override exposed)"
                print(f"  effective_sysroot_assessment={effective}", file=stream)
                if effective.startswith("UNRESOLVED"):
                    return_code = 1

                if mnemonic == "CppLink":
                    print("  linker_identification=CppLink launcher dry-run of this captured action (-###)", file=stream)
                    dry_run = wrapper_dry_run or run(
                        [str(launcher), *expanded_argv[1:], "-###"], cwd=execution_root, env=child_env
                    )
                    print(dry_run.stdout.rstrip(), file=stream)
                    linker_lines = [line for line in dry_run.stdout.splitlines()
                                    if re.search(r"(?:^|[/\\\s\"])(?:[^/\\\s\"]*[-])?ld(?:\.bfd|\.gold|\.lld)?(?:[\s\"]|$)", line)]
                    print(f"  linker_dry_run_exit={dry_run.returncode}", file=stream)
                    collect2_lines = [line for line in dry_run.stdout.splitlines()
                                      if re.search(r"(?:^|[/\\\s\"])(?:[^/\\\s\"]*[/\\])?collect2(?:[\s\"]|$)", line)]
                    if collect2_lines:
                        print("  linker_driver_helper=collect2 (not the actual linker)", file=stream)
                        for line in collect2_lines:
                            print(f"    {line}", file=stream)

                    # This action-specific query is always recorded as a
                    # candidate. It is not by itself proof that the linker was
                    # selected for the captured action.
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
                        return_code = 1
                    candidate_version = None
                    if action_linker_path:
                        candidate_version = run([str(action_linker_path), "--version"])
                        print("  CppLink_linker_candidate_version:", file=stream)
                        print(candidate_version.stdout.rstrip(), file=stream)
                        print(f"  CppLink_linker_candidate_version_exit={candidate_version.returncode}", file=stream)
                        if candidate_version.returncode:
                            return_code = 1
                    else:
                        print("  CppLink_linker_candidate_version=UNRESOLVED", file=stream)

                    linker_tokens = set()
                    for line in linker_lines:
                        try:
                            for item in shlex.split(line, posix=True):
                                base = Path(item).name
                                if (base in ("ld", "ld.bfd", "ld.gold", "ld.lld")
                                        or re.fullmatch(r".+-ld(?:\.bfd|\.gold|\.lld)?", base)):
                                    linker_tokens.add(item)
                        except ValueError:
                            continue
                    resolved_linkers = set()
                    unresolved_linkers = []
                    for item in linker_tokens:
                        linker_path = resolve_executable(item, tf_root, output_base, execution_root, toolchain_paths)
                        if linker_path:
                            resolved_linkers.add(linker_path)
                        else:
                            unresolved_linkers.append(item)

                    if linker_lines:
                        print("  selected_linker_command_lines:", file=stream)
                        for line in linker_lines:
                            print(f"    {line}", file=stream)
                        if len(resolved_linkers) == 1 and not unresolved_linkers:
                            selected_linker = next(iter(resolved_linkers))
                            if action_linker_path and selected_linker != action_linker_path:
                                print(f"  actual_selected_linker=UNRESOLVED; -### reports {selected_linker}, action-specific driver query reports {action_linker_path}", file=stream)
                                return_code = 1
                            else:
                                print(f"  actual_selected_linker={selected_linker}", file=stream)
                                print("  linker_evidence=direct linker executable in captured CppLink -### output", file=stream)
                            linker_version = run([str(selected_linker), "--version"])
                            print(linker_version.stdout.rstrip(), file=stream)
                            print(f"  actual_linker_version_exit={linker_version.returncode}", file=stream)
                            if linker_version.returncode:
                                return_code = 1
                        else:
                            print(f"  actual_selected_linker=UNRESOLVED; tokens={sorted(linker_tokens)}; unresolved={unresolved_linkers}", file=stream)
                            return_code = 1
                    else:
                        print("  actual_selected_linker=UNRESOLVED; action-specific -print-prog-name=ld is only a candidate, and -### did not prove the selected linker", file=stream)
                        return_code = 1
                    if dry_run.returncode:
                        print("  WARNING: CppLink dry-run returned nonzero; linker selection is incomplete", file=stream)
                        return_code = 1

        print("\n=== Actual compiler metadata (wrapper paths excluded) ===", file=stream)
        if not drivers:
            print("ERROR: no actual compiler executable was proven from Bazel C++ actions", file=stream)
            return_code = 1
        for (mnemonic, _, _), (compiler, action, environment, env_captured) in sorted(drivers.items()):
            print(f"\n--- actual compiler used by {mnemonic}: {compiler} ---", file=stream)
            probe_env = os.environ.copy()
            if env_captured and environment is not None:
                probe_env.update(environment)
            for label, args in (
                ("version", [str(compiler), "--version"]),
                ("verbose version", [str(compiler), "-v"]),
                ("target triple", [str(compiler), "-dumpmachine"]),
            ):
                if log_command(stream, label, args, env=probe_env).returncode:
                    return_code = 1
            default_env = probe_env.copy()
            for key in ("SYSROOT", "SDKROOT", "GCC_EXEC_PREFIX", "COMPILER_PATH"):
                default_env.pop(key, None)
            default_sysroot = log_command(
                stream, "compiler default/configured sysroot (sysroot-injecting environment cleared; not the action-effective value)",
                [str(compiler), "-print-sysroot"], env=default_env
            )
            print(f"compiler_default_configured_sysroot={default_sysroot.stdout.strip() or '<empty>'}", file=stream)
            if default_sysroot.returncode:
                return_code = 1
            if log_command(stream, "compiler search directories", [str(compiler), "-print-search-dirs"], env=probe_env).returncode:
                return_code = 1
            reported_linker = log_command(stream, "compiler-reported default linker (informational only; not proof of CppLink selection)",
                                          [str(compiler), "-print-prog-name=ld"], env=probe_env)
            print(f"compiler_reported_default_linker={reported_linker.stdout.strip() or '<empty>'}", file=stream)
            if reported_linker.returncode:
                return_code = 1
        stream.flush()
    return return_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
