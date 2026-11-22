#!/usr/bin/env python3
"""Read-only ELF evidence for two baseline binaries. Raw command output stays on the runner."""
import tempfile
import traceback
import importlib.util
import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

import verify_elf_abi as abi

ROOT = Path.cwd()
WORK = ROOT / "work"
PRIVATE = WORK / "private-diagnostics"
ART = ROOT / "artifacts"
TARGETS = {"library": ART / "libtensorflowlite_c.so", "smoke": ART / "tflite_smoke"}
REPORT = "phase2-evidence.json"


def module(filename):
    spec = importlib.util.spec_from_file_location("phase2_support", Path(__file__).with_name(filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def output(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=True, **kwargs).stdout.strip()


def checked(condition, message):
    if not condition:
        raise ValueError(message)


def numeric_max(versions, prefix):
    values = [v for v in versions if re.fullmatch(prefix + r"\d+(?:\.\d+)*", v)]
    return max(values, key=lambda v: tuple(map(int, v[len(prefix):].split("."))), default=None)


@lru_cache(None)
def symbols(path):
    text = output(["readelf", "--dyn-syms", "-W", path])
    checked("Symbol table '.dynsym'" in text, "missing dynamic symbol table")
    return [parts[7] for line in text.splitlines() if len(parts := line.split()) >= 8 and parts[0][:-1].isdigit()]


@lru_cache(None)
def metadata(path):
    header = abi.elf_identity(path)
    checked(header == ("ELF64", "AArch64"), "non-ARM64 ELF in closure")
    dynamic = output(["readelf", "--dynamic", "-W", path])
    version = output(["readelf", "--version-info", "-W", path])
    checked("(NULL)" in dynamic and "Version " in version, "missing ELF metadata")
    needs, tags = abi.elf_dynamic(path)
    definitions = sorted(abi.version_definitions(path))
    symbols(path)
    return dict(sha256=abi.digest(path), bytes=path.stat().st_size, elf_class=header[0], machine=header[1],
                soname=abi.elf_soname(path), needed=needs, path_tags=tags, definitions=definitions,
                version_needs={k: sorted(v) for k, v in abi.version_needs(path).items()},
                max_glibc=numeric_max(definitions, "GLIBC_"), max_glibcxx=numeric_max(definitions, "GLIBCXX_"))


def relative(path, root):
    return str(path.relative_to(root))


def candidate(path, root, relevant):
    physical = abi.rootfs_resolve(path, root)
    checked(physical is not None, "unresolvable provider candidate")
    logical = relative(path, root)
    links = []
    probe = path
    for _ in range(64):
        for parent in [*reversed(probe.relative_to(root).parents), probe.relative_to(root)]:
            part = root / parent
            if part.is_symlink():
                target = Path(os.readlink(part))
                links.append([relative(part, root), str(target)])
                dest = root / str(target).lstrip("/") if target.is_absolute() else part.parent / target
                probe = Path(os.path.normpath(dest / probe.relative_to(part)))
                break
        else:
            break
    checked(probe == physical, "symlink chain unresolved")
    exports = sorted(s for s in symbols(physical) if s.partition("@")[0] in relevant and "@" in s)
    return dict(logical=logical, physical=relative(physical, root), symlinks=links,
                relevant_dynamic_symbols=exports, **metadata(physical))


def development(root):
    names = ("crt1.o", "Scrt1.o", "crti.o", "crtn.o", "features.h", "c++config.h",
             "libc.so", "libstdc++.so", "libstdc++.a", "libc_nonshared.a")
    files = {name: [] for name in names}
    for directory, _, entries in os.walk(root, followlinks=False):
        for name in files.keys() & set(entries):
            files[name].append(relative(Path(directory) / name, root))
    return {k: sorted(v) for k, v in files.items()}


def strict_checks():
    for firmware in ("14", "15"):
        root = WORK / "ota" / f"capsule{firmware}" / "rootfs"
        for target, path in TARGETS.items():
            args = [sys.executable, "scripts/verify_elf_abi.py", path, root]
            if target == "smoke":
                args += ["--allow-library", TARGETS["library"]]
            result = subprocess.run(args, capture_output=True, text=True)
            stem = PRIVATE / f"strict-{firmware}-{target}"
            stem.with_suffix(".out").write_text(result.stdout)
            stem.with_suffix(".err").write_text(result.stderr)
            stem.with_suffix(".rc").write_text(str(result.returncode))
            print(f"Capsule-{firmware} {target} strict ABI: {'FAIL' if result.returncode else 'PASS'} "
                  f"(exit {result.returncode})")


def firmware_report(number):
    root = WORK / "ota" / f"capsule{number}" / "rootfs"
    stage = root.parent
    image, = (stage / "rkaf").rglob("rootfs_dmv.img")
    pairs = {}
    relevant = set()
    sonames = set()
    for target in TARGETS:
        # Each underlying report used the strict resolver independently. It walks on
        # after version mismatches. Extract only structured edges, never raw logs.
        report = (ART / "elf-reports" / f"capsule{number}-{target}-diagnostics.txt").read_text()
        checked("Diagnostic collection and parsing completed without recorded errors." in report
                and "UNRESOLVED DT_NEEDED" not in report, "incomplete closure")
        pattern = r"^EDGE (.+)\n  provider=(.*?); sha256=([0-9a-f]{64}); source=.*\n  required_versions=(\S+)\n  missing_versions=(\S+)"
        edges = []
        for chain, provider, sha, needs, missing in re.findall(pattern, report, re.M):
            hops = chain.split(" -> DT_NEEDED ")
            owner = Path(hops[-2].split(" => ")[-1].removeprefix("PT_INTERP "))
            soname = hops[-1].split(" => ")[0]
            if Path(provider).is_relative_to(root):
                sonames.add(soname)
            else:
                checked(Path(provider) == TARGETS["library"], "unexpected external ELF")
            physical_owner = abi.rootfs_resolve(owner, root) if owner.is_relative_to(root) else owner
            missing_versions = [] if missing == "<none>" else missing.split(",")
            imports = sorted(s for s in symbols(physical_owner) if s.rpartition("@")[2] in missing_versions)
            checked(set(missing_versions) == {s.rpartition("@")[2] for s in imports}, "unattributed version need")
            relevant.update(s.partition("@")[0] for s in imports)
            edges.append(dict(chain=[Path(hops[0]).name] + [h.split(" => ")[0] for h in hops[1:]],
                              owner=owner.name, provider=relative(Path(provider), root) if Path(provider).is_relative_to(root)
                              else "artifacts/libtensorflowlite_c.so", sha256=sha, required=needs.split(",") if needs != "<none>" else [],
                              missing=missing_versions, imports=imports))
        checked(edges, "no edges collected")
        stem = PRIVATE / f"strict-{number}-{target}"
        code = int(stem.with_suffix(".rc").read_text())
        reason = None
        if code:
            reason = re.fullmatch(r"ABI AUDIT FAILED CLOSED: (\S+) at (\S+) lacks required versions: ([A-Za-z0-9_., ]+)",
                                  stem.with_suffix(".err").read_text().strip())
            checked(code == 1 and reason and any(set(reason[3].split(", ")) <= set(e["missing"])
                    and e["chain"][-1] == reason[1] for e in edges), "unexpected strict failure; see private diagnostics")
            reason = dict(soname=reason[1], provider=relative(Path(reason[2]), root), versions=reason[3].split(", "))
        else:
            checked(not any(e["missing"] for e in edges), "strict result disagrees with closure")
        pairs[target] = dict(strict_exit=code, strict_result="FAIL" if code else "PASS", first_failure=reason, edges=edges)
    interp = re.search(r"Requesting program interpreter: ([^]]+)", output(["readelf", "-lW", TARGETS["smoke"]]))[1]
    sonames.add(Path(interp).name)
    found = {n: [] for n in sorted(sonames)}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in found.keys() & set(files):
            found[name].append(candidate(Path(directory) / name, root, relevant))
    checked(all(found.values()), "missing provider inventory")
    loader_state = {}
    for name in ("etc/ld.so.cache", "etc/ld.so.conf", "etc/ld.so.preload", "etc/ld.so.conf.d"):
        path = abi.rootfs_resolve(root / name, root)
        loader_state[name] = (sorted(i.name for i in path.iterdir()) if path and path.is_dir()
                              else path.stat().st_size if path else None)
    return dict(ota_sha256=abi.digest(stage.parent / f"Capsule-{number}-44.90.ota"), rootfs_image_sha256=abi.digest(image),
                loader=interp, loader_config=loader_state, hwcaps=abi.has_unmodeled_loader_dirs(root),
                search_roots=[relative(p, root) for p in abi.default_library_dirs(root)], providers=found,
                development=development(root), audits=pairs)


def check_system_link_input(item, sdk):
    # Called on resolved *opened* files from the private GNU ld -t replay.
    runtime = r"(?:lib(?:c|m|dl|pthread|rt|stdc\+\+|gcc_s|gcc|c_nonshared)(?:-[0-9.]+)?\.(?:so(?:\.[0-9.]+)?|a)|ld-(?:linux-aarch64\.so\.1|[0-9.]+\.so)|(?:[Sgr]?crt1|crt[in]|crtbegin[ST]?|crtendS?)\.o)"
    if re.fullmatch(runtime, item.name) and not item.is_relative_to(sdk):
        raise ValueError("actual system linker input outside pinned ARM SDK")



def toolchain_report(firmwares):
    collector = module("collect-bazel-toolchain.py")
    base = Path((PRIVATE / "bazel-info-output-base.txt").read_text().strip().splitlines()[-1])
    execroot = base / "execroot/org_tensorflow"
    arm = (base / "external/aarch64_linux_toolchain").resolve()
    gcc = arm / "bin/aarch64-none-linux-gnu-gcc"
    sysroot = Path(output([gcc, "-print-sysroot"])).resolve()
    checked(sysroot.is_relative_to(arm), "unexpected sysroot")
    evidence = {}
    relevant = set()
    for target, path in TARGETS.items():
        records = [e for fw in firmwares.values() for e in fw["audits"][target]["edges"] if e["owner"] == path.name]
        names = {s.partition("@")[0] for edge in records for s in edge["imports"]}
        relevant.update(names)
        actions, errors, _ = collector.parse_action_graph((PRIVATE / f"actions-{target}.json").read_text())
        links, _ = collector.select_actions(actions, target)
        checked(not errors and len(links) == 1, "invalid link graph")
        action = links[0]
        argv = action["argv"]
        launcher = collector.resolve_executable(argv[0], WORK / "tensorflow", base, execroot, [arm])
        assignments, clear = collector.launcher_environment(argv, launcher)
        checked(action["env_captured"] and not action["argv_unresolved"], "incomplete link action")
        env = collector.action_environment_for_replay(action["environment"], assignments, captured=True, clear_environment=clear)
        probe = PRIVATE / f"symbol-probe-{target}"
        args, _ = collector.redirect_link_output(argv, probe)
        checked(args is not None, "unsafe replay outputs")
        # -t and -y request ld observations only on a separate private replay output.
        # The baseline artifacts and Bazel actions receive no additional flags.
        result = subprocess.run([launcher, *args[1:], "-Wl,-t", *[f"-Wl,-y,{s}" for s in sorted(names)]],
                                cwd=execroot, env=env, capture_output=True, text=True)
        checked(result.returncode == 0 and sorted(symbols(probe)) == sorted(symbols(path)), "diagnostic link replay mismatch")
        inputs = set()
        references = {name: {"reference": set(), "definition": set()} for name in names}
        for line in (result.stdout + "\n" + result.stderr).splitlines():
            match = re.search(r"(?:^|: )([^:\s]+): (reference to|definition of) (\S+)$", line)
            if match:
                name = match[3].partition("@")[0]
                if name in references:
                    references[name]["reference" if match[2] == "reference to" else "definition"].add(Path(match[1]).name)
            item = (execroot / line).resolve() if line and len(line) < 500 and not re.search(r"\s", line) else None
            if item and item.is_file() and os.environ.get("CAPSULE_ARMGNU103") == "1":
                check_system_link_input(item, arm)
            if item and item.is_relative_to(arm) and item.is_file():
                inputs.add(relative(item, arm))
        checked(inputs, "no toolchain link inputs identified")
        evidence[target] = dict(toolchain_inputs=sorted(inputs), symbol_origins={
            k: {t: sorted(v) for t, v in record.items()} for k, record in references.items()})
    runtime = {}
    for name in ("libc.so.6", "libstdc++.so.6", "libgcc_s.so.1", "ld-linux-aarch64.so.1"):
        path = Path(output([gcc, "-print-file-name=" + name])).resolve()
        checked(path.is_relative_to(arm), "driver did not identify target runtime")
        runtime[name] = candidate(path, arm, relevant)
    includes = subprocess.run([gcc, "-E", "-v", "-x", "c", "-"], input="", text=True, capture_output=True, check=True)
    include_dirs = includes.stderr.split("#include <...> search starts here:")[1].split("End of search list.")[0].split()
    search = output([gcc, "-print-search-dirs"])
    libdirs = re.search(r"^libraries: =(.*)$", search, re.M)[1].split(":")
    def paths(dirs):
        return [relative(p, arm) for raw in dirs if (p := Path(raw).resolve()).is_dir() and p.is_relative_to(arm)]
    checked(all(Path(p).resolve().is_relative_to(arm) for p in include_dirs), "external compiler include search")
    macros = output([gcc, "-dM", "-E", "-include", "features.h", "-x", "c", "-"], input="")
    header = [re.search(rf"^#define {key} (\d+)$", macros, re.M)[1] for key in ("__GLIBC__", "__GLIBC_MINOR__")]
    return dict(triple=output([gcc, "-dumpmachine"]), gcc=output([gcc, "-dumpfullversion"]), sysroot=relative(sysroot, arm),
                glibc_headers=".".join(header), include_dirs=paths(include_dirs), library_dirs=paths(libdirs),
                development=development(sysroot), runtime=runtime, links=evidence)


def validate(path):
    body = path.read_text()
    doc = json.loads(body)
    checked(set(doc) == {"git_sha", "tf_sha", "binaries", "firmware", "toolchain", "acceptance"}, "invalid evidence schema")
    checked(set(doc["firmware"]) == {"14", "15"} and set(doc["binaries"]) == set(TARGETS), "incomplete baseline")
    # Values originate only from ELF fields, guest paths, symbol names and fixed statuses.
    # Reject raw commands, arbitrary strings, host paths, command/environment dumps or credentials.
    def walk(value):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(k)
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str):
            checked(re.fullmatch(r"[A-Za-z0-9_.$@+:/{},()~=-]{1,2048}", value) and
                    not re.search(r"home/runner|/tmp/|/opt/hostedtoolcache|private-diagnostics|execve|github_pat_|gh[pousr]_|Bearer|BEGIN.PRIVATE|https?://", value, re.I),
                    "unsafe public evidence field")
    walk(doc)
    for fw in doc["firmware"].values():
        checked(set(fw["audits"]) == set(TARGETS) and all(a["edges"] for a in fw["audits"].values()), "incomplete ABI matrix")


def main():
    mode = sys.argv[1]
    if mode == "strict":
        strict_checks()
    elif mode == "validate":
        validate(Path(sys.argv[2]))
    elif mode == "verify":
        public = module("verify-public-artifact.py")
        data, digest = public.download(os.environ, name="phase2-abi-evidence")
        with tempfile.TemporaryDirectory() as tmp:
            public.verify_zip(data, digest, Path(tmp), structure=REPORT, validate_structure=validate)
            doc = json.loads((Path(tmp) / REPORT).read_text())
            checked(doc["git_sha"] == os.environ["GITHUB_SHA"], "unexpected build identity")
        summary = f"Independent ZIP verification passed: {digest}. Strict ABI acceptance: {doc['acceptance']}."
        print(summary)
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            print(summary, file=stream)
    elif mode == "collect":
        firmware = {n: firmware_report(n) for n in ("14", "15")}
        doc = dict(git_sha=output(["git", "rev-parse", "HEAD"]), tf_sha=output(["git", "-C", WORK / "tensorflow", "rev-parse", "HEAD"]),
                   binaries={p.name: metadata(p) for p in TARGETS.values()}, firmware=firmware, toolchain=toolchain_report(firmware))
        doc["binaries"] = {k: doc["binaries"][p.name] for k, p in TARGETS.items()}
        doc["acceptance"] = "FAIL" if any(a["strict_exit"] for fw in firmware.values() for a in fw["audits"].values()) else "PASS"
        path = ART / REPORT
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        validate(path)
        print(f"Evidence complete; strict ABI acceptance: {doc['acceptance']}")
    else:
        raise ValueError("unknown mode")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Subprocess exceptions may carry a whole private CppLink command line.
        where = traceback.extract_tb(exc.__traceback__)[-1]
        print(f"Evidence failed: {type(exc).__name__} in {where.name} at line {where.lineno}", file=sys.stderr)
        if type(exc) is ValueError and where.name == "checked":
            print(str(exc), file=sys.stderr)
        sys.exit(1)
