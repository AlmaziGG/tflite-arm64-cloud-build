#!/usr/bin/env python3
"""Fail-closed ELF dependency/version audit against an extracted ARM64 rootfs.

This is not a complete glibc dynamic-loader emulator. It models explicit
DT_RPATH/DT_RUNPATH, permits external resolution only to exact caller-approved
shared-object files, checks standard rootfs library trees, rejects conflicting
providers, and fails when unparsed loader state could affect a default choice.
"""

import hashlib
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class AuditError(Exception):
    pass


@dataclass(frozen=True)
class Provider:
    name: str
    logical_path: Path
    physical_path: Path
    sha256: str
    elf_class: str
    machine: str
    source: str


def run(*args):
    try:
        return subprocess.check_output(args, text=True, errors="replace", stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        raise AuditError(f"command failed ({' '.join(map(str, args))}): {exc.output.strip()}") from exc


def rootfs_resolve(path, root):
    """Resolve symlinks as if root were /; never follow absolute links on host."""
    root = Path(os.path.abspath(root))
    current = Path(os.path.abspath(path))
    if os.path.commonpath((str(root), str(current))) != str(root):
        return None
    for _ in range(64):
        rel = current.relative_to(root)
        probe = root
        restart = False
        for part in rel.parts:
            probe = probe / part
            try:
                mode = probe.lstat().st_mode
            except OSError:
                return None
            if stat.S_ISLNK(mode):
                target = os.readlink(probe)
                if os.path.isabs(target):
                    current = root / target.lstrip("/\\")
                else:
                    current = probe.parent / target
                current = Path(os.path.abspath(current))
                if os.path.commonpath((str(root), str(current))) != str(root):
                    return None
                restart = True
                break
        if restart:
            continue
        try:
            mode = current.lstat().st_mode
            if stat.S_ISREG(mode) or stat.S_ISDIR(mode):
                return current
        except OSError:
            return None
        return None
    raise AuditError(f"symlink loop while resolving rootfs path: {path}")


def elf_identity(path):
    header = run("readelf", "-h", str(path))
    cls = re.search(r"Class:\s+(\S+)", header)
    machine = re.search(r"Machine:\s+(.+)", header)
    return (cls.group(1) if cls else "unknown", machine.group(1).strip() if machine else "unknown")


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def elf_dynamic(path):
    output = run("readelf", "-d", str(path))
    needed = re.findall(r"\(NEEDED\).*Shared library: \[(.+?)\]", output)
    paths = []
    for line in output.splitlines():
        m = re.search(r"\((RPATH|RUNPATH)\).*Library (?:rpath|runpath): \[(.*?)\]", line)
        if m:
            paths.append((m.group(1), m.group(2)))
    unsupported = []
    for token in ("AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"):
        if re.search(rf"\({token}\)", output):
            unsupported.append(token)
    if re.search(r"FLAGS_1.*NODEFLIB", output):
        unsupported.append("NODEFLIB")
    if unsupported:
        raise AuditError(f"unsupported loader semantics in {path}: {', '.join(unsupported)}")
    return needed, paths


def elf_soname(path):
    output = run("readelf", "-d", str(path))
    match = re.search(r"\(SONAME\).*Library soname: \[(.+?)\]", output)
    return match.group(1) if match else None


def version_needs(path):
    needs = {}
    current_file = None
    for line in run("readelf", "--version-info", str(path)).splitlines():
        match = re.search(r"\bFile:\s*(\S+)", line)
        if match:
            current_file = match.group(1)
        match = re.search(r"\bName:\s*(\S+)", line)
        if match and current_file:
            needs.setdefault(current_file, set()).add(match.group(1))
    return needs


def version_definitions(path):
    definitions = set()
    in_definitions = False
    for line in run("readelf", "--version-info", str(path)).splitlines():
        if "Version definition section" in line:
            in_definitions = True
        elif "Version needs section" in line:
            in_definitions = False
        if in_definitions:
            match = re.search(r"\bName:\s*(\S+)", line)
            if match:
                definitions.add(match.group(1))
    return definitions


def make_provider(name, logical_path, physical_path, source):
    cls, machine = elf_identity(physical_path)
    return Provider(name, logical_path, physical_path, digest(physical_path), cls, machine, source)


def file_identity(path):
    info = path.stat()
    return info.st_dev, info.st_ino


def provider_description(provider):
    try:
        device, inode = file_identity(provider.physical_path)
        identity = f"device={device}, inode={inode}"
    except OSError:
        identity = "device/inode=unavailable"
    try:
        soname = elf_soname(provider.physical_path) or "<no SONAME>"
    except AuditError:
        soname = "<unreadable SONAME>"
    return (
        f"{provider.logical_path} -> {provider.physical_path} [{identity}; "
        f"{provider.elf_class}/{provider.machine}; SONAME={soname}; SHA256={provider.sha256}]"
    )


def provider_path_sensitivity(provider):
    """Return a conservative reason when copies may resolve dependencies differently."""
    needed, paths = elf_dynamic(provider.physical_path)
    if any("/" in name or "$" in name for name in needed):
        return "DT_NEEDED contains a path or dynamic token"
    for kind, value in paths:
        for entry in value.split(":"):
            if "$" in entry:
                return f"DT_{kind} contains a dynamic path token: {entry!r}"
            if not os.path.isabs(entry):
                return f"DT_{kind} contains a non-absolute path: {entry!r}"
    return None


def explain_provider_equivalence(candidates):
    """Explain whether separate copies may be treated as one ABI provider."""
    if not candidates:
        return False, "no candidates"
    baseline = candidates[0]
    for candidate in candidates[1:]:
        if candidate.sha256 != baseline.sha256:
            return False, "different SHA-256 contents"
        if (candidate.elf_class, candidate.machine) != (baseline.elf_class, baseline.machine):
            return False, "different ELF class or machine"
        if elf_soname(candidate.physical_path) != elf_soname(baseline.physical_path):
            return False, "different ELF SONAME"
        for provider in (baseline, candidate):
            reason = provider_path_sensitivity(provider)
            if reason:
                return False, reason
        if elf_dynamic(candidate.physical_path) != elf_dynamic(baseline.physical_path):
            return False, "different DT_NEEDED/RPATH/RUNPATH metadata"
    return True, "identical SHA-256, ELF class/machine, SONAME and dependency metadata; no path-sensitive records"


def collapse_provider_candidates(candidates):
    """Collapse aliases/inodes and prove equivalence for byte-identical copies."""
    by_inode = {}
    for candidate in candidates:
        by_inode.setdefault(file_identity(candidate.physical_path), []).append(candidate)
    inode_representatives = []
    inode_path_sensitive = []
    for group in by_inode.values():
        paths = {str(item.logical_path) for item in group}
        reason = provider_path_sensitivity(group[0]) if len(paths) > 1 else None
        if reason:
            # Hardlinks share bytes and inode, but the loader may expand
            # $ORIGIN from the logical lookup path, so retain every path.
            inode_representatives.extend(sorted(group, key=lambda item: str(item.logical_path)))
            inode_path_sensitive.append(reason)
        else:
            inode_representatives.append(min(group, key=lambda item: str(item.logical_path)))
    if inode_path_sensitive:
        return inode_representatives, (
            "same device/inode reached through distinct load paths, but path-sensitive "
            f"dynamic metadata prevents merging: {', '.join(sorted(set(inode_path_sensitive)))}"
        )
    if len(inode_representatives) <= 1:
        return inode_representatives, "same physical file (device/inode identity)"
    equivalent, reason = explain_provider_equivalence(inode_representatives)
    if equivalent:
        representative = min(inode_representatives, key=lambda item: str(item.physical_path))
        return [representative], f"ABI-equivalent copies: {reason}; deterministic representative={representative.physical_path}"
    return inode_representatives, reason


def default_library_dirs(root):
    # Loader search roots, plus common multiarch directories below each root.
    return [
        root / "lib",
        root / "usr/lib",
        root / "lib64",
        root / "usr/lib64",
        root / "usr/local/lib",
        root / "usr/local/lib64",
    ]


def has_unmodeled_loader_dirs(root):
    for base in default_library_dirs(root):
        physical_base = rootfs_resolve(base, root)
        if physical_base is None or not physical_base.is_dir():
            continue
        candidates = [physical_base]
        try:
            children = list(physical_base.iterdir())
        except OSError:
            continue
        for child in children:
            if re.search(r"-linux-gnu(?:abi\w+)?$", child.name):
                resolved = rootfs_resolve(child, root)
                if resolved is not None and resolved.is_dir():
                    candidates.append(resolved)
        for directory in candidates:
            for special in ("glibc-hwcaps", "tls", "hwcap"):
                resolved = rootfs_resolve(directory / special, root)
                if resolved is not None and resolved.is_dir():
                    try:
                        if next(resolved.iterdir(), None) is not None:
                            return True
                    except OSError:
                        continue
    return False


def rootfs_files_in(base, root):
    physical_base = rootfs_resolve(base, root)
    if physical_base is None:
        return
    search_dirs = [physical_base]
    try:
        children = list(physical_base.iterdir())
    except OSError:
        return
    # glibc multiarch directories are valid search locations; avoid recursively
    # indexing plugin trees or glibc-hwcaps variants as if they were defaults.
    for child in children:
        if re.search(r"-linux-gnu(?:abi\w+)?$", child.name):
            resolved_child = rootfs_resolve(child, root)
            if resolved_child is not None:
                search_dirs.append(resolved_child)
    for directory in search_dirs:
        try:
            for item in directory.iterdir():
                if item.is_symlink() or stat.S_ISREG(item.lstat().st_mode):
                    yield item
        except OSError:
            continue


def index_rootfs(root):
    by_name = {}
    seen_paths = set()
    for base in default_library_dirs(root):
        for logical_path in rootfs_files_in(base, root) or ():
            if not re.search(r"\.so(?:\.|$)", logical_path.name):
                continue
            resolved = rootfs_resolve(logical_path, root)
            if resolved is None or not resolved.is_file():
                continue
            # Multiple symlink names for the same SONAME and physical object are
            # one provider. Keep distinct physical files separate, even when
            # their bytes happen to be identical.
            seen_key = (str(logical_path), str(resolved))
            if seen_key in seen_paths:
                continue
            seen_paths.add(seen_key)
            try:
                provider = make_provider(logical_path.name, logical_path, resolved, "rootfs")
            except AuditError:
                provider = Provider(logical_path.name, logical_path, resolved, digest(resolved), "invalid", "unknown", "rootfs")
            by_name.setdefault(provider.name, []).append(provider)
    return by_name


def external_provider(path, name):
    if not path.exists():
        return None
    try:
        if not path.is_file():
            raise AuditError(f"library search candidate is not a regular file: {path}")
        provider = make_provider(name, path, path.resolve(strict=True), "LD_LIBRARY_PATH[explicit-file]")
        if provider.elf_class != "ELF64" or provider.machine != "AArch64":
            raise AuditError(f"explicit external provider is not ELF64/AArch64: {path} ({provider.elf_class}/{provider.machine})")
        declared = elf_soname(provider.physical_path)
        if declared != name:
            raise AuditError(f"explicit external provider SONAME mismatch: requested {name}, declared {declared!r} at {path}")
        return provider
    except OSError as exc:
        raise AuditError(f"cannot inspect library search candidate {path}: {exc}") from exc


def mapped_rpath_entries(obj, encoded, root, diagnostics=None):
    entries = []
    # Preserve the path used to find the object: $ORIGIN can differ for two
    # hardlink/symlink aliases even when both resolve to the same inode.
    origin = obj.logical_path.parent
    try:
        origin_is_rootfs = os.path.commonpath((str(root), str(origin))) == str(root)
    except ValueError:
        origin_is_rootfs = False
    for raw in encoded.split(":"):
        if not raw:
            raise AuditError(f"empty RPATH/RUNPATH element in {obj.name}; current-directory lookup is not modeled")
        uses_origin = "$ORIGIN" in raw or "${ORIGIN}" in raw
        entry = raw.replace("${ORIGIN}", str(origin)).replace("$ORIGIN", str(origin))
        if "$" in entry:
            raise AuditError(f"unmodeled dynamic path token {raw!r} in {obj.name}")
        if os.path.isabs(entry):
            if uses_origin:
                # $ORIGIN may legitimately name an explicitly loaded object
                # under artifacts/, so preserve its actual containing path.
                mapped = Path(os.path.abspath(entry))
            else:
                # DT_RPATH/DT_RUNPATH is interpreted in the guest namespace,
                # never as an arbitrary host path on the build runner.
                mapped = root / entry.lstrip("/\\")
        else:
            raise AuditError(f"relative RPATH/RUNPATH {raw!r} in {obj.name} cannot be resolved safely")
        canonical = rootfs_resolve(mapped, root) if (not uses_origin or origin_is_rootfs) else mapped.resolve(strict=False)
        canonical_text = str(canonical) if canonical is not None else "unresolved within Capsule rootfs"
        if diagnostics is not None:
            namespace = "object-relative" if uses_origin else "Capsule-rootfs"
            diagnostics.append(
                f"PATH {obj.physical_path}: DT_RPATH/RUNPATH raw={raw!r}; "
                f"expanded={mapped}; canonical={canonical_text} ({namespace})"
            )
        entries.append(mapped)
    return entries


def rootfs_candidate(directory, soname, root):
    path = directory / soname
    resolved = rootfs_resolve(path, root)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return make_provider(soname, path, resolved, "rootfs-search-path")
    except AuditError:
        return Provider(soname, path, resolved, digest(resolved), "invalid", "unknown", "rootfs-search-path")


def choose_provider(soname, obj, own_paths, inherited_rpath, rootfs_index, root, approved_libraries, unmodeled_loader_state, diagnostics=None):
    tags = dict(own_paths)
    rpath = mapped_rpath_entries(obj, tags["RPATH"], root, diagnostics) if "RPATH" in tags and "RUNPATH" not in tags else []
    runpath = mapped_rpath_entries(obj, tags["RUNPATH"], root, diagnostics) if "RUNPATH" in tags else []
    before_ld_path = rpath + list(inherited_rpath)
    after_ld_path = runpath

    def find_in_directory(directory):
        try:
            is_rootfs_path = os.path.commonpath((str(root), str(directory))) == str(root)
        except ValueError:
            is_rootfs_path = False
        candidate_path = directory / soname
        if diagnostics is not None:
            diagnostics.append(
                f"SEARCH {obj.physical_path}: needed={soname}; directory={directory}; "
                f"canonical={(rootfs_resolve(directory, root) or 'unresolved within Capsule rootfs') if is_rootfs_path else directory.resolve(strict=False)}; "
                f"namespace={'Capsule-rootfs' if is_rootfs_path else 'external'}"
            )
        if is_rootfs_path:
            candidate = rootfs_candidate(directory, soname, root)
            if diagnostics is not None:
                diagnostics.append(f"  {'ACCEPT' if candidate else 'MISS'} rootfs candidate {candidate_path}")
        else:
            # External paths are never trusted as directories. A candidate is
            # accepted only when its final physical file is one of the explicitly
            # approved shared objects (for example, the built TFLite DSO).
            try:
                resolved_candidate = candidate_path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                if candidate_path.exists() or candidate_path.is_symlink():
                    if diagnostics is not None:
                        diagnostics.append(f"  REJECT broken/unresolvable external candidate: {candidate_path}: {exc}")
                    raise AuditError(f"broken or unresolvable external library candidate {candidate_path}: {exc}") from exc
                resolved_candidate = None
            if resolved_candidate is None:
                candidate = None
                if diagnostics is not None:
                    diagnostics.append(f"  SKIP external miss (no physical candidate): {candidate_path}")
            elif resolved_candidate in approved_libraries:
                candidate = external_provider(candidate_path, soname)
                if diagnostics is not None:
                    diagnostics.append(
                        f"  ACCEPT exact approved external file: {candidate_path} -> {resolved_candidate}"
                    )
            else:
                if diagnostics is not None:
                    diagnostics.append(
                        f"  REJECT external candidate not explicitly approved: {candidate_path} -> {resolved_candidate}"
                    )
                raise AuditError(
                    f"external DT_NEEDED candidate is not an explicitly approved file: "
                    f"{candidate_path} -> {resolved_candidate}"
                )
        if candidate is not None:
            return candidate
        return None

    # Dynamic-loader order: DT_RPATH (when RUNPATH is absent), inherited RPATH,
    # LD_LIBRARY_PATH, then DT_RUNPATH. --allow-library models only named files
    # from the configured artifacts LD_LIBRARY_PATH, never an entire directory.
    for directory in before_ld_path:
        candidate = find_in_directory(directory)
        if candidate is not None:
            return candidate, rpath + inherited_rpath if "RUNPATH" not in tags else inherited_rpath

    for approved_path in sorted(approved_libraries, key=str):
        if approved_path.name != soname:
            continue
        if diagnostics is not None:
            diagnostics.append(f"LD_LIBRARY_PATH exact-file lookup: {soname} -> {approved_path}")
        candidate = external_provider(approved_path, soname)
        if diagnostics is not None:
            diagnostics.append(f"  ACCEPT explicit provider: {provider_description(candidate)}")
        return candidate, rpath + inherited_rpath if "RUNPATH" not in tags else inherited_rpath

    for directory in after_ld_path:
        candidate = find_in_directory(directory)
        if candidate is not None:
            return candidate, inherited_rpath

    candidates = rootfs_index.get(soname, [])
    if not candidates:
        raise AuditError(f"unresolved DT_NEEDED {soname!r}, required by {obj.name}")
    if diagnostics is not None and len(candidates) > 1:
        diagnostics.append(f"ROOTFS provider inventory for {soname}:")
        diagnostics.extend(f"  VARIANT {provider_description(item)}" for item in candidates)
    try:
        collapsed, decision = collapse_provider_candidates(candidates)
    except AuditError as exc:
        if diagnostics is not None and len(candidates) > 1:
            diagnostics.append(f"  DECISION: FAIL CLOSED ({exc})")
        raise
    if diagnostics is not None and len(candidates) > 1:
        diagnostics.append(f"  DECISION: {decision}")
    if len(collapsed) != 1:
        locations = "\n".join(f"  {provider_description(item)}" for item in collapsed)
        raise AuditError(f"ambiguous default-path providers for {soname}: {decision}\n{locations}")
    if unmodeled_loader_state:
        raise AuditError(f"cannot certify default-path choice for {soname}: rootfs has unparsed ld.so.cache/config/preload state")
    child_rpath = rpath + inherited_rpath if "RUNPATH" not in tags else inherited_rpath
    provider = collapsed[0]
    if diagnostics is not None and len(candidates) > 1:
        diagnostics.append(f"  ACCEPT provider group: {decision}; selected={provider.physical_path}")
    return provider, child_rpath


def assert_arm64(provider, context):
    if provider.elf_class != "ELF64" or provider.machine != "AArch64":
        raise AuditError(f"wrong ELF architecture for {context}: {provider.logical_path} is {provider.elf_class}/{provider.machine}")


def assert_soname(provider, requested):
    declared = elf_soname(provider.physical_path)
    if declared is not None and declared != requested:
        raise AuditError(f"provider at {provider.logical_path} declares SONAME {declared}, requested {requested}")


def check_versions(obj, soname, provider):
    required = version_needs(obj.physical_path).get(soname, set())
    if not required:
        return []
    available = version_definitions(provider.physical_path)
    missing = sorted(required - available)
    if missing:
        raise AuditError(f"{soname} at {provider.logical_path} lacks required versions: {', '.join(missing)}")
    return sorted(required)


def main(argv):
    if len(argv) < 3:
        print("usage: verify_elf_abi.py TARGET_ELF ROOTFS [--allow-library FILE ...]", file=sys.stderr)
        return 2
    target = Path(argv[1]).resolve(strict=True)
    root = Path(argv[2]).resolve(strict=True)
    try:
        if len(argv[3:]) % 2 or any(argv[index] != "--allow-library" for index in range(3, len(argv), 2)):
            raise AuditError("external objects must be supplied only as repeated --allow-library FILE pairs")
        approved_libraries = {Path(argv[index + 1]).resolve(strict=True) for index in range(3, len(argv), 2)}
        if any(not path.is_file() for path in approved_libraries):
            raise AuditError("every --allow-library path must resolve to a regular file")
        print(f"Target ELF: {target}\nCapsule rootfs: {root}")
        for path in sorted(approved_libraries):
            print(f"Explicit external library allowlist: {path}")
        target_provider = make_provider(target.name, target, target, "target")
        assert_arm64(target_provider, "target ELF")
        header = run("readelf", "-h", str(target))
        if not re.search(r"Class:\s+ELF64", header) or not re.search(r"Machine:\s+AArch64", header):
            raise AuditError("target is not ELF64/AArch64")

        rootfs_index = index_rootfs(root)
        loader_files = [root / "etc/ld.so.cache", root / "etc/ld.so.conf", root / "etc/ld.so.preload"]
        conf_dir = rootfs_resolve(root / "etc/ld.so.conf.d", root)
        if conf_dir is not None and conf_dir.is_dir():
            loader_files.extend(child for child in conf_dir.iterdir() if child.name.endswith(".conf"))
        unmodeled_loader_state = False
        for config in loader_files:
            resolved_config = rootfs_resolve(config, root)
            if resolved_config is not None and resolved_config.stat().st_size > 0:
                unmodeled_loader_state = True
        unmodeled_loader_state = unmodeled_loader_state or has_unmodeled_loader_dirs(root)
        program_headers = run("readelf", "-l", str(target))
        interpreter = re.search(r"Requesting program interpreter:\s*(.+?)\]", program_headers)
        loader = None
        if interpreter:
            interpreter_name = interpreter.group(1)
            interpreter_path = root / interpreter_name.lstrip("/")
            physical = rootfs_resolve(interpreter_path, root)
            if physical is None:
                raise AuditError(f"missing ELF interpreter in rootfs: {interpreter_name}")
            loader = make_provider(interpreter_name, interpreter_path, physical, "PT_INTERP")
            assert_arm64(loader, "PT_INTERP")

        queue = [(target_provider, [])]
        if loader is not None:
            queue.append((loader, []))
        visited = set()
        records = []
        diagnostics = []
        while queue:
            obj, inherited = queue.pop(0)
            key = (str(obj.physical_path), tuple(map(str, inherited)))
            if key in visited:
                continue
            visited.add(key)
            needed, tagged_paths = elf_dynamic(obj.physical_path)
            path_tags = {}
            for kind, value in tagged_paths:
                if kind in path_tags and path_tags[kind] != value:
                    raise AuditError(f"multiple conflicting DT_{kind} values in {obj.name}")
                path_tags[kind] = value
            for soname in needed:
                provider, child_inherited = choose_provider(
                    soname, obj, path_tags, inherited, rootfs_index, root, approved_libraries,
                    unmodeled_loader_state, diagnostics
                )
                assert_arm64(provider, f"provider for {soname}")
                assert_soname(provider, soname)
                required_versions = check_versions(obj, soname, provider)
                records.append(
                    f"OK DT_NEEDED {soname}: {provider.logical_path} ({provider.source}); "
                    f"ELF64/AArch64; SHA256={provider.sha256}; versions={','.join(required_versions) or 'none'}"
                )
                queue.append((provider, child_inherited))

        if loader is not None:
            records.append(f"OK PT_INTERP {loader.name}: ELF64/AArch64 ({loader.physical_path})")
        else:
            records.append("PT_INTERP: absent (shared object or static ELF)")

        print("\n".join(diagnostics + records))
        print("LIMITATION: static dependency audit; it does not fully emulate ld.so, hardware capabilities, loader cache rules, or runtime dlopen().")
        return 0
    except (AuditError, OSError, ValueError) as exc:
        if "diagnostics" in locals() and diagnostics:
            print("\n".join(diagnostics))
        print(f"ABI AUDIT FAILED CLOSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
