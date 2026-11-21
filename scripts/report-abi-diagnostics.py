#!/usr/bin/env python3
"""Write a detailed, non-gating ABI trace; verify_elf_abi.py remains the gate."""

import os
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

import verify_elf_abi as abi


VERSION_PREFIXES = ("GLIBC_", "GLIBCXX_", "CXXABI_", "GCC_")


def readelf(*args):
    try:
        result = subprocess.run(["readelf", *map(str, args)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as exc:
        return 127, f"could not execute readelf: {exc}"
    return result.returncode, result.stdout


def sort_version(value):
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"([0-9]+)", value))


def versions(values):
    return sorted((v for v in values if v.startswith(VERSION_PREFIXES)), key=sort_version)


def link_chain(logical, root):
    pieces = []
    root = Path(os.path.abspath(root))
    current = Path(os.path.abspath(logical))
    for _ in range(64):
        try:
            if os.path.commonpath((str(root), str(current))) != str(root):
                pieces.append(f"symlink resolution escaped rootfs at {current}")
                return pieces, None
        except ValueError:
            pieces.append(f"symlink resolution escaped rootfs at {current}")
            return pieces, None
        if not current.is_symlink():
            break
        target = os.readlink(current)
        pieces.append(f"{current} -> {target}")
        current = root / target.lstrip("/\\") if os.path.isabs(target) else current.parent / target
        current = Path(os.path.abspath(current))
    resolved = abi.rootfs_resolve(logical, root)
    return pieces, resolved


def main(argv):
    if len(argv) < 4 or (len(argv[4:]) % 2) or any(argv[i] != "--allow-library" for i in range(4, len(argv), 2)):
        print("usage: report-abi-diagnostics.py TARGET ROOTFS REPORT [--allow-library FILE ...]", file=sys.stderr)
        return 2
    try:
        target = Path(argv[1]).resolve(strict=True)
        root = Path(argv[2]).resolve(strict=True)
        output = Path(argv[3])
        approved = {Path(argv[i + 1]).resolve(strict=True) for i in range(4, len(argv), 2)}
        if not target.is_file() or not root.is_dir():
            raise OSError("target must be a file and rootfs must be a directory")
        with os.scandir(root):
            pass
    except (OSError, RuntimeError) as exc:
        print(f"DIAGNOSTIC COLLECTION FAILURE: cannot inspect input paths: {exc}", file=sys.stderr)
        return 2
    diagnostic_errors = []
    findings = []
    with output.open("w", encoding="utf-8") as report:
        def emit(line=""):
            report.write(str(line) + "\n")

        emit("ABI diagnostic report (informational; strict verifier remains authoritative)")
        emit(f"target={target}")
        emit(f"rootfs={root}")
        emit(f"explicit_allowed_external_files={','.join(map(str, sorted(approved))) or '<none>'}")

        emit("\n=== Target ELF metadata ===")
        for args in (("-h", target), ("-l", target), ("-d", target), ("--version-info", "-W", target)):
            code, data = readelf(*args)
            emit(f"$ readelf {' '.join(map(str,args))} (exit={code})")
            emit(data.rstrip())
            if code:
                diagnostic_errors.append(f"readelf failed for target: {args}")
            elif args[0] == "-h" and not (re.search(r"Class:\s+\S+", data) and re.search(r"Machine:\s+.+", data)):
                diagnostic_errors.append("target ELF header was incomplete or could not be parsed")
            elif args[0] == "--version-info" and not re.search(r"Version (?:needs|definition|symbols) section", data, re.I):
                diagnostic_errors.append("target ELF version information is missing or unreadable")

        emit("\n=== Capsule runtime providers ===")
        for base in abi.default_library_dirs(root):
            physical_base = abi.rootfs_resolve(base, root)
            if physical_base is not None and physical_base.is_dir():
                try:
                    list(physical_base.iterdir())
                except OSError as exc:
                    diagnostic_errors.append(f"rootfs library directory could not be inspected: {physical_base}: {exc}")
        try:
            root_index = abi.index_rootfs(root)
        except (abi.AuditError, OSError, ValueError) as exc:
            root_index = {}
            diagnostic_errors.append(f"Capsule rootfs library metadata could not be indexed: {exc}")
        for soname in ("libc.so.6", "libstdc++.so.6"):
            candidates = root_index.get(soname, [])
            emit(f"\n--- {soname}: {len(candidates)} indexed candidate(s) ---")
            if not candidates:
                emit("ERROR: no provider found in indexed standard Capsule library directories")
                findings.append(f"missing target provider {soname}")
                continue
            try:
                collapsed, reason = abi.collapse_provider_candidates(candidates)
            except abi.AuditError as exc:
                # Record candidate details below even when the fail-closed
                # collapse/proof procedure cannot complete. Never guess a provider.
                collapsed, reason = [], f"FAIL-CLOSED collapse error: {exc}"
            emit(f"provider_selection={reason}")
            for candidate in candidates:
                chain, physical = link_chain(candidate.logical_path, root)
                emit(f"logical_path={candidate.logical_path}")
                emit(f"symlink_chain={' ; '.join(chain) if chain else '<not a symlink>'}")
                emit(f"resolved_path={physical}")
                emit(f"sha256={candidate.sha256}")
                emit(f"elf_class={candidate.elf_class}; machine={candidate.machine}")
                code, header = readelf("-h", "-W", candidate.physical_path)
                emit(f"$ readelf -h -W {candidate.physical_path} (exit={code})")
                emit(header.rstrip())
                if code:
                    diagnostic_errors.append(f"readelf ELF header failed for provider {soname}")
                elif not (re.search(r"Class:\s+\S+", header) and re.search(r"Machine:\s+.+", header)):
                    diagnostic_errors.append(f"ELF header was incomplete for provider candidate {soname} at {candidate.logical_path}")
                code, version_table = readelf("--version-info", "-W", candidate.physical_path)
                emit(f"$ readelf --version-info -W {candidate.physical_path} (exit={code})")
                emit(version_table.rstrip())
                try:
                    definitions = abi.version_definitions(candidate.physical_path)
                except abi.AuditError as exc:
                    definitions = None
                    emit(f"candidate_exported_versions=UNRESOLVED ({exc})")
                    diagnostic_errors.append(f"version definitions unreadable for {soname} at {candidate.logical_path}")
                if definitions is None:
                    emit("candidate_exported_GLIBC_versions=UNRESOLVED")
                    emit("candidate_max_exported_GLIBC=UNRESOLVED")
                    emit("candidate_exported_GLIBCXX_versions=UNRESOLVED")
                    emit("candidate_max_exported_GLIBCXX=UNRESOLVED")
                else:
                    exported_glibc = sorted((v for v in definitions if re.fullmatch(r"GLIBC_\d+(?:\.\d+)*", v)), key=sort_version)
                    exported_glibcxx = sorted((v for v in definitions if re.fullmatch(r"GLIBCXX_\d+(?:\.\d+)*", v)), key=sort_version)
                    emit(f"candidate_exported_GLIBC_versions={','.join(exported_glibc) or '<none>'}")
                    emit(f"candidate_max_exported_GLIBC={max(exported_glibc, key=sort_version) if exported_glibc else '<none>'}")
                    emit(f"candidate_exported_GLIBCXX_versions={','.join(exported_glibcxx) or '<none>'}")
                    emit(f"candidate_max_exported_GLIBCXX={max(exported_glibcxx, key=sort_version) if exported_glibcxx else '<none>'}")
                if code:
                    diagnostic_errors.append(f"readelf version info failed for provider candidate {soname} at {candidate.logical_path}")
                elif not re.search(r"Version definition section", version_table, re.I):
                    diagnostic_errors.append(f"ELF version definitions are missing for provider candidate {soname} at {candidate.logical_path}")
            if len(collapsed) > 1:
                emit("ERROR: provider is ambiguous; no single selected provider is claimed")
                findings.append(f"ambiguous target provider {soname}")
                continue
            if not collapsed:
                emit("ERROR: provider selection is unresolved; no provider is selected")
                findings.append(f"unresolved target provider selection for {soname}")
                continue

        emit("\n=== Dependency graph and version requirements ===")
        try:
            unmodeled = abi.has_unmodeled_loader_dirs(root)
            for config in (root / "etc/ld.so.cache", root / "etc/ld.so.conf", root / "etc/ld.so.preload"):
                resolved = abi.rootfs_resolve(config, root)
                if resolved is not None and resolved.is_file() and resolved.stat().st_size:
                    unmodeled = True
            resolved_conf = abi.rootfs_resolve(root / "etc/ld.so.conf.d", root)
            if resolved_conf is not None and resolved_conf.is_dir():
                for config in resolved_conf.iterdir():
                    if config.name.endswith(".conf"):
                        physical = abi.rootfs_resolve(config, root)
                        if physical is not None and physical.is_file() and physical.stat().st_size:
                            unmodeled = True
        except (abi.AuditError, OSError, ValueError) as exc:
            unmodeled = True
            diagnostic_errors.append(f"rootfs loader metadata could not be inspected: {exc}")
        emit(f"unmodeled_loader_state={unmodeled}")

        loader = None
        code, program_headers = readelf("-l", target)
        if code:
            diagnostic_errors.append("readelf failed while inspecting target program headers")
        match = re.search(r"Requesting program interpreter:\s*(.+?)\]", program_headers)
        if match:
            interp = match.group(1)
            interp_logical = root / interp.lstrip("/")
            interp_physical = abi.rootfs_resolve(interp_logical, root)
            if interp_physical is None:
                emit(f"ERROR: missing PT_INTERP provider {interp}")
                findings.append(f"missing PT_INTERP {interp}")
            else:
                loader = abi.make_provider(interp, interp_logical, interp_physical, "PT_INTERP")

        queue = deque([(abi.make_provider(target.name, target, target, "target"), [], [str(target)])])
        if loader is not None:
            queue.append((loader, [], [f"PT_INTERP {loader.logical_path}"]))
        visited = set()
        while queue:
            obj, inherited, chain = queue.popleft()
            key = (str(obj.physical_path), str(obj.logical_path), tuple(map(str, inherited)))
            if key in visited:
                continue
            visited.add(key)
            try:
                needed, tagged_paths = abi.elf_dynamic(obj.physical_path)
                req_by_soname = abi.version_needs(obj.physical_path)
            except (abi.AuditError, OSError, ValueError) as exc:
                emit(f"DIAGNOSTIC ERROR: cannot read dynamic/version metadata for {obj.logical_path}: {exc}")
                diagnostic_errors.append(f"dependency traversal incomplete at {obj.logical_path}: {exc}")
                continue
            path_tags = {}
            for kind, value in tagged_paths:
                path_tags[kind] = value
            emit(f"\nOBJECT {obj.logical_path} (physical={obj.physical_path}; source={obj.source})")
            for soname in needed:
                detail = []
                try:
                    provider, child_inherited = abi.choose_provider(
                        soname, obj, path_tags, inherited, root_index, root, approved, unmodeled, detail
                    )
                except (abi.AuditError, OSError, ValueError) as exc:
                    emit(f"UNRESOLVED DT_NEEDED {soname} from {obj.logical_path}: {exc}")
                    emit("\n".join(detail))
                    message = f"unresolved {soname} from {obj.logical_path}: {exc}"
                    if isinstance(exc, OSError) or "command failed (readelf" in str(exc) or "cannot inspect library search candidate" in str(exc):
                        diagnostic_errors.append(f"dependency traversal incomplete: {message}")
                    else:
                        findings.append(message)
                    continue
                required = versions(req_by_soname.get(soname, set()))
                try:
                    available = abi.version_definitions(provider.physical_path)
                except (abi.AuditError, OSError, ValueError) as exc:
                    emit(f"DIAGNOSTIC ERROR: cannot read provider version definitions for {provider.logical_path}: {exc}")
                    diagnostic_errors.append(f"dependency traversal incomplete at provider {provider.logical_path}: {exc}")
                    continue
                if not available:
                    diagnostic_errors.append(f"provider version definitions are missing or unreadable: {provider.logical_path}")
                missing = sorted(set(required) - available, key=sort_version)
                dependency_chain = " -> ".join(chain + [f"DT_NEEDED {soname} => {provider.logical_path}"])
                emit(f"EDGE {dependency_chain}")
                emit(f"  provider={provider.physical_path}; sha256={provider.sha256}; source={provider.source}")
                emit(f"  required_versions={','.join(required) or '<none>'}")
                emit(f"  missing_versions={','.join(missing) or '<none>'}")
                emit("\n".join(detail))
                if missing:
                    findings.append(f"{obj.logical_path} requires unavailable {soname} versions: {','.join(missing)}")
                queue.append((provider, child_inherited, chain + [f"DT_NEEDED {soname} => {provider.logical_path}"]))

        emit("\n=== Diagnostic summary ===")
        if findings:
            emit("ABI FINDINGS (informational; strict verifier remains authoritative):")
            for error in findings:
                emit(f"- {error}")
        else:
            emit("No ABI mismatches or provider-selection findings recorded.")
        if diagnostic_errors:
            emit("DIAGNOSTIC COLLECTION/PROCESSING FAILURES:")
            for error in diagnostic_errors:
                emit(f"- {error}")
        else:
            emit("Diagnostic collection and parsing completed without recorded errors.")
    print(f"Wrote ABI diagnostics: {output}")
    # ABI findings remain informational; only an incomplete/failed diagnostic
    # collection returns non-zero. The separate strict ABI step is authoritative.
    return 1 if diagnostic_errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
