#!/usr/bin/env python3
"""Fail-closed ELF dependency/version audit against an extracted ARM64 rootfs.

This is not a complete glibc dynamic-loader emulator. It models explicit
DT_RPATH/DT_RUNPATH and caller-supplied LD_LIBRARY_PATH directories, checks
standard rootfs library trees, rejects conflicting providers, and fails when
an unparsed ld.so.cache could affect a default-path choice.
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
            seen_key = (logical_path.name, str(resolved))
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
        return make_provider(name, path, path.resolve(strict=True), "LD_LIBRARY_PATH")
    except OSError as exc:
        raise AuditError(f"cannot inspect library search candidate {path}: {exc}") from exc


def mapped_rpath_entries(obj, encoded, root):
    entries = []
    # $ORIGIN is relative to the actual loaded object, after safe rootfs
    # symlink resolution. Absolute non-$ORIGIN paths, however, belong to the
    # guest filesystem and must always be rooted at the Capsule rootfs.
    origin = obj.physical_path.parent
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
                entries.append(Path(os.path.abspath(entry)))
            else:
                # DT_RPATH/DT_RUNPATH is interpreted in the guest namespace,
                # never as an arbitrary host path on the build runner.
                entries.append(root / entry.lstrip("/\\"))
        else:
            raise AuditError(f"relative RPATH/RUNPATH {raw!r} in {obj.name} cannot be resolved safely")
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


def choose_provider(soname, obj, own_paths, inherited_rpath, rootfs_index, root, external_dirs, unmodeled_loader_state):
    tags = dict(own_paths)
    rpath = mapped_rpath_entries(obj, tags["RPATH"], root) if "RPATH" in tags and "RUNPATH" not in tags else []
    runpath = mapped_rpath_entries(obj, tags["RUNPATH"], root) if "RUNPATH" in tags else []
    if "RUNPATH" in tags:
        search = list(inherited_rpath) + list(external_dirs) + runpath
    else:
        search = rpath + list(inherited_rpath) + list(external_dirs)
    for directory in search:
        try:
            is_rootfs_path = os.path.commonpath((str(root), str(directory))) == str(root)
        except ValueError:
            is_rootfs_path = False
        if not is_rootfs_path:
            explicitly_external = False
            for external_dir in external_dirs:
                try:
                    if os.path.commonpath((str(external_dir), str(directory))) == str(external_dir):
                        explicitly_external = True
                        break
                except ValueError:
                    continue
            if not explicitly_external:
                raise AuditError(
                    f"library search path {directory} is outside the Capsule rootfs and "
                    "all explicitly supplied LD_LIBRARY_PATH directories"
                )
        candidate = rootfs_candidate(directory, soname, root) if is_rootfs_path else external_provider(directory / soname, soname)
        if candidate is not None:
            child_rpath = rpath + inherited_rpath if "RUNPATH" not in tags else inherited_rpath
            return candidate, child_rpath

    candidates = rootfs_index.get(soname, [])
    if not candidates:
        raise AuditError(f"unresolved DT_NEEDED {soname!r}, required by {obj.name}")
    candidates_by_physical_path = {}
    for candidate in candidates:
        # index_rootfs has already resolved each path inside rootfs. Collapse
        # symlink aliases of one physical file, but never collapse separate
        # files just because their contents or ELF headers match.
        candidates_by_physical_path.setdefault(str(candidate.physical_path), candidate)
    if len(candidates_by_physical_path) != 1:
        locations = ", ".join(f"{p.logical_path} [{p.machine}, sha256={p.sha256}]" for p in candidates)
        raise AuditError(f"ambiguous default-path providers for {soname}: {locations}")
    if unmodeled_loader_state:
        raise AuditError(f"cannot certify default-path choice for {soname}: rootfs has unparsed ld.so.cache/config/preload state")
    child_rpath = rpath + inherited_rpath if "RUNPATH" not in tags else inherited_rpath
    provider = next(iter(candidates_by_physical_path.values()))
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
        print("usage: verify_elf_abi.py TARGET_ELF ROOTFS [LD_LIBRARY_PATH_DIR ...]", file=sys.stderr)
        return 2
    target = Path(argv[1]).resolve(strict=True)
    root = Path(argv[2]).resolve(strict=True)
    external_dirs = [Path(p).resolve(strict=True) for p in argv[3:]]
    try:
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
                    soname, obj, path_tags, inherited, rootfs_index, root, external_dirs, unmodeled_loader_state
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

        print(f"Target: {target}\nRootfs: {root}\n" + "\n".join(records))
        print("LIMITATION: static dependency audit; it does not fully emulate ld.so, hardware capabilities, loader cache rules, or runtime dlopen().")
        return 0
    except (AuditError, OSError, ValueError) as exc:
        print(f"ABI AUDIT FAILED CLOSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
