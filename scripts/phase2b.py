#!/usr/bin/env python3
"""Pinned SDK, provenance and acceptance checks for the GNU-A 10.3 experiment."""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import verify_elf_abi as abi


def load(name):
    spec = importlib.util.spec_from_file_location("support", Path(__file__).with_name(name))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


p2 = load("phase2-evidence.py")
public = load("verify-public-artifact.py")
checked = p2.checked
ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "work/armgnu103"
TRIPLE = "aarch64-none-linux-gnu"
GCC = SDK / "bin" / (TRIPLE + "-gcc")
ARCHIVE_SHA = "1e33d53dea59c8de823bbdfe0798280bdcd138636c7060da9d77a97ded095a84"
RUNTIME = ("libc.so.6", "libstdc++.so.6", "libgcc_s.so.1", "crt1.o", "crti.o", "crtn.o")
OLD = {"dlopen", "dlsym", "pthread_create", "pthread_join", "pthread_once", "shm_open", "shm_unlink",
       "_ZSt28__throw_bad_array_new_lengthv", "__libc_start_main"}
EXTRA = ("compatibility.json", "libtensorflowlite_c.so", "tflite_smoke")


def owned(path, directory):
    real = Path(path).resolve(strict=True)
    checked(real.is_relative_to(directory.resolve()), "path outside pinned SDK")
    return str(real.relative_to(directory.resolve()))


def check_identity(version, triple, linker, sysroot):
    checked(version == "10.3.1" and triple == TRIPLE, "wrong compiler version or triple")
    checked(re.search(r"\b2\.36\.1(?:[.\s]|$)", linker), "wrong GNU ld version")
    checked(sysroot == TRIPLE + "/libc", "wrong configured sysroot")


def sdk():
    archive, = (ROOT / "work").glob("gcc-arm-10.3-*.tar.xz")
    checked(abi.digest(archive) == ARCHIVE_SHA, "archive checksum mismatch")
    probe = lambda flag: p2.output([GCC, flag])
    ld = SDK / "bin" / (TRIPLE + "-ld")
    version = probe("-dumpfullversion")
    triple = probe("-dumpmachine")
    sysroot = owned(probe("-print-sysroot"), SDK)
    linker = p2.output([ld, "--version"]).splitlines()[0]
    check_identity(version, triple, linker, sysroot)
    providers = {name: owned(probe("-print-file-name=" + name), SDK) for name in RUNTIME}
    for name, file in providers.items():
        checked(abi.elf_identity(SDK / file) == ("ELF64", "AArch64"), "wrong SDK ELF identity")
    checked(p2.metadata(SDK / providers["libc.so.6"])["max_glibc"] == "GLIBC_2.33", "wrong libc baseline")
    checked(p2.metadata(SDK / providers["libstdc++.so.6"])["max_glibcxx"] == "GLIBCXX_3.4.28", "wrong C++ baseline")
    for lang in ("c", "c++"):
        headers = subprocess.run([GCC, "-E", "-v", "-x", lang, "-"], input="", text=True, capture_output=True, check=True)
        dirs = headers.stderr.split("#include <...> search starts here:")[1].split("End of search list.")[0].split()
        checked(dirs and all(owned(directory, SDK) for directory in dirs), "external SDK include directory")
    print(f"Verified {triple} GCC {version}; {linker}; sysroot {sysroot}; {providers}")


def configure(tf):
    directory = tf / "tensorflow/tools/toolchains/embedded/arm-linux"
    shutil.copyfile(directory / "aarch64-linux-toolchain.BUILD", SDK / "BUILD")
    (SDK / "WORKSPACE").write_text('workspace(name = "aarch64_linux_toolchain")\n')
    template = directory / "cc_config.bzl.tpl"
    src = template.read_text()
    # Only change the AArch64 template blocks. Host tools and armhf retain their own configuration.
    pattern = r'(?ms)(^    if \(ctx.attr.cpu == "aarch64"\):\n)(.*?)(?=^    elif |^    else:)'
    def arm_block(match):
        block = re.sub(r'(?m)^ *"-isystem",\n *"(?:%\{PYTHON_INCLUDE_PATH\}%|/usr/include/)",\n', "", match[2])
        block = re.sub(r'(?m)^ *"/usr/include",\n', "", block)
        return match[1] + block.replace("/11.3.1/", "/10.3.1/")
    updated = re.sub(pattern, arm_block, src)
    checked(updated != src and updated.count("/10.3.1/") == 6, "unexpected upstream AArch64 template")
    template.write_text(updated)
    with (tf / ".bazelrc").open("a") as config:
        print(f"\ncommon --override_repository=aarch64_linux_toolchain={SDK}", file=config)
        print(f"build:elinux_aarch64 --copt=-ffile-prefix-map={ROOT}=.", file=config)


def matrix_ok(rows):
    return set(rows) == {"14-library", "14-smoke", "15-library", "15-smoke"} and all(v == 0 for v in rows.values())


def matrix():
    rows = {f"{n}-{t}": int((p2.PRIVATE / f"strict-{n}-{t}.rc").read_text()) for n in ("14", "15") for t in p2.TARGETS}
    checked(matrix_ok(rows), "strict ABI acceptance failed")


def check_inputs(inputs, expected, smoke):
    required = RUNTIME if smoke else [n for n in RUNTIME if n != "crt1.o"]
    for n in required:
        checked(expected[n] in inputs, "pinned runtime or startup object absent from actual linker inputs")


def compile_info(name, base):
    collector = load("collect-bazel-toolchain.py")
    graph, errors, _ = collector.parse_action_graph((p2.PRIVATE / f"actions-{name}.json").read_text())
    analyzed = len(graph["CppCompile"])
    graph["CppCompile"] = collector.executed_compiles(graph["CppCompile"], p2.PRIVATE / f"build-{name}.jsonl")
    links, _ = collector.select_actions(graph, name)
    checked(not errors and len(links) == 1, "invalid action graph")
    config = links[0]["configuration_id"]
    execroot = base / "execroot/org_tensorflow"
    checked((base / "external/aarch64_linux_toolchain").samefile(SDK), "different Bazel SDK")
    counts = {"analyzed_compiles": analyzed, "executed_compiles": len(graph["CppCompile"]),
              "arm_compile": 0, "host_compile": 0, "root_link": 1}
    system_dirs = set()
    flags = set()
    for action in [*links, *graph["CppCompile"]]:
        if action["configuration_id"] != config:
            checked(Path(action["argv"][0]).name not in (TRIPLE + "-gcc", TRIPLE + "-g++"), "unclassified ARM action")
            counts["host_compile"] += 1
            continue
        argv = action["argv"]
        checked(not action["argv_unresolved"] and (execroot / argv[0]).resolve().samefile(GCC), "mixed target compiler")
        for i, arg in enumerate(argv):
            if arg == "-isystem":
                raw = Path(argv[i + 1])
                if raw.is_absolute():
                    system_dirs.add(owned(raw, SDK))
                else:
                    checked("11.3" not in str(raw) and ".." not in raw.parts, "foreign relative include")
            checked("11.3.1/" not in arg and arg not in ("-I/usr/include", "-L/usr/lib"), "foreign target path")
            if arg.startswith(("-march=", "-mcpu=", "-mabi=", "-std=")) or arg in ("-O2", "-fPIC"):
                flags.add(arg)
        if action is not links[0]:
            counts["arm_compile"] += 1
    checked(counts["arm_compile"] > 0, "no target compiles")
    return dict(counts=counts, target_system_includes=sorted(system_dirs), flags=sorted(flags))


def mapped(path):
    ranges = []
    for row in p2.output(["readelf", "-lW", path]).splitlines():
        cols = row.split()
        if cols and cols[0] == "LOAD":
            start, size = int(cols[2], 16), int(cols[5], 16)
            ranges.extend(range(start // 4096, (start + size + 4095) // 4096))
    return len(set(ranges)) * 4096


def report():
    evidence = json.loads((p2.ART / p2.REPORT).read_text())
    base = Path((p2.PRIVATE / "bazel-info-output-base.txt").read_text().strip().splitlines()[-1])
    expected = {n: owned(p2.output([GCC, "-print-file-name=" + n]), SDK) for n in RUNTIME}
    summaries = {}
    for target, path in p2.TARGETS.items():
        inputs = evidence["toolchain"]["links"][target]["toolchain_inputs"]
        check_inputs(inputs, expected, target == "smoke")
        private = (p2.PRIVATE / f"toolchain-{target}.txt").read_text()
        ld, = re.findall(r"(?m)^  actual_selected_linker=(.+)$", private)
        summary = compile_info(target, base)
        summary["sysroot_comparisons"] = sorted(set(re.findall(r"(?m)^tf2_comparison=(-print-sysroot (?:equal-stderr|same-directory))$", private)))
        summary.update(ld=owned(ld, SDK), ld_version=p2.output([ld, "--version"]).splitlines()[0],
                       old_imports=sorted(s for s in p2.symbols(path) if s.partition("@")[0] in OLD),
                       build_id=re.findall(r"Build ID: ([0-9a-f]+)", p2.output(["readelf", "-nW", path])),
                       load_segment_bytes=mapped(path))
        summaries[target] = summary
    footprints = {}
    for n, fw in evidence["firmware"].items():
        paths = {p for p in p2.TARGETS.values()}
        root = p2.WORK / "ota" / ("capsule" + n) / "rootfs"
        paths.update(root / e["provider"] for e in fw["audits"]["smoke"]["edges"] if not e["provider"].startswith("artifacts/"))
        paths.add(abi.rootfs_resolve(root / fw["loader"].lstrip("/"), root))
        footprints[n] = sum(mapped(p) for p in paths)
    result = dict(archive_sha256=ARCHIVE_SHA, source=(p2.WORK / "sdk-source").read_text().strip(),
                  targets=summaries, closure_load_segment_bytes=footprints)
    (p2.ART / "compatibility.json").write_text(json.dumps(result, indent=2) + "\n")


def verify_guest_opens(trace, expected, root, artifacts):
    """strace -yy resolves successful open results to physical host-visible fd paths."""
    observed = set()
    seen = set()
    for raw in re.findall(r"(?m) = \d+<(/[^<>\n]+)>\s*$", trace):
        path = Path(raw)
        if path in seen or path.parts[1:2] in (("proc",), ("dev",), ("sys",)) or not path.is_file():
            continue
        seen.add(path)
        with path.open("rb") as stream:
            h = stream.read(20)
        if h[:4] != b"\x7fELF" or h[4:6] != b"\x02\x01" or h[18:20] != b"\xb7\0":
            continue
        physical = path.resolve(strict=True)
        checked(physical.is_relative_to(root) or physical in artifacts, "foreign AArch64 runtime in guest trace")
        matches = {p for p in expected if p.samefile(physical)}
        checked(matches and all(abi.digest(physical) == expected[p] for p in matches), "unapproved ARM ELF or guest hash mismatch")
        observed.update(matches)
    missing = {p.name for p in expected.keys() - observed}
    checked(not missing, "missing verified guest opens " + ",".join(sorted(missing)))


def guest():
    """Replay inference under strace and verify actual ARM64 files opened by QEMU."""
    matrix()
    fwdata = json.loads((p2.ART / p2.REPORT).read_text())["firmware"]
    compat = json.loads((p2.ART / "compatibility.json").read_text())
    qlog = (p2.ART / "qemu.log").read_text()
    results = {}
    for n, fw in fwdata.items():
        root = p2.WORK / "ota" / ("capsule" + n) / "rootfs"
        block = qlog.split(f"Running ARM64 TFLite smoke test with Capsule-{n} 44.90 userspace under QEMU\n")[1]
        block = block.split(f"Capsule-{n} QEMU: PASS")[0]
        match = re.search(r"(input type=\d+ bytes=\d+ dims=[0-9x]+)\n(invoke=ok output type=\d+ bytes=\d+)\n(output\[0\]=[-0-9.e+]+)", block)
        checked(match and f"Capsule-{n} QEMU: PASS" in qlog, "missing successful inference")
        expected = {path: abi.digest(path) for path in p2.TARGETS.values()}
        loader = abi.rootfs_resolve(root / fw["loader"].lstrip("/"), root)
        expected[loader] = abi.digest(loader)
        for edge in fw["audits"]["smoke"]["edges"]:
            path = (p2.TARGETS["library"] if edge["provider"] == "artifacts/libtensorflowlite_c.so"
                    else abi.rootfs_resolve(root / edge["provider"], root))
            checked(path and path.is_file(), "strict guest provider missing before replay")
            expected[path] = edge["sha256"]
        trace = p2.PRIVATE / f"qemu-{n}.opens"
        replay = p2.output(["strace", "-f", "-qq", "-yy", "-s", "4096", "-e", "trace=open,openat,openat2",
                            "-o", trace, "qemu-aarch64", "-L", root, "-U", "LD_PRELOAD", "-U", "LD_AUDIT",
                            "-E", "LD_LIBRARY_PATH=" + str(p2.ART), p2.TARGETS["smoke"], p2.WORK / "smoke-model.tflite"])
        checked(all(line in replay.splitlines() for line in match.groups()), "inconsistent traced guest inference")
        verify_guest_opens(trace.read_text(), expected, root, set(p2.TARGETS.values()))
        results[n] = list(match.groups())
    compat["inference"] = results
    (p2.ART / "compatibility.json").write_text(json.dumps(compat, indent=2) + "\n")


def safe(directory):
    p2.validate(directory / p2.REPORT)
    doc = json.loads((directory / p2.REPORT).read_text())
    compat = (directory / "compatibility.json").read_text()
    checked(doc["git_sha"] == os.environ["GITHUB_SHA"] and doc["acceptance"] == "PASS"
            and set(json.loads(compat)["inference"]) == {"14", "15"}, "incomplete acceptance")
    checked(not public.FORBIDDEN.search(compat), "unsafe compatibility report")
    for t, path in p2.TARGETS.items():
        binary = directory / path.name
        checked(abi.digest(binary) == doc["binaries"][t]["sha256"] and abi.elf_identity(binary) == ("ELF64", "AArch64"),
                "unexpected public binary")
        checked(not re.search(rb"/home/runner/|/tmp/[^/\x00 ]+/|github_pat_|gh[pousr]_[A-Za-z0-9]{20,}|BEGIN PRIVATE KEY", binary.read_bytes()),
                "private material in ELF")
    for name in public.TOOLCHAINS:
        public.check_sanitized(directory / name)
        public.check_production(directory / name)


def verify():
    data, digest = public.download(os.environ, name="phase2b-bazel-gnu103")
    with tempfile.TemporaryDirectory() as tmp:
        public.verify_zip(data, digest, Path(tmp), structure=p2.REPORT, extra_files=EXTRA,
                          validate_structure=lambda p: safe(p.parent))
    print("Verified published ZIP " + digest)


if __name__ == "__main__":
    cmd = sys.argv[1]
    try:
        if cmd == "configure":
            configure(Path(sys.argv[2]))
        elif cmd == "safe":
            safe(p2.ART)
        else:
            {"sdk": sdk, "matrix": matrix, "report": report, "guest": guest, "verify": verify}[cmd]()
    except Exception as exc:
        import traceback
        location = traceback.extract_tb(exc.__traceback__)[-1]
        message = str(exc) if location.name == "checked" else type(exc).__name__
        print(f"{cmd} failed at {location.name}:{location.lineno}: {message}", file=sys.stderr)
        sys.exit(1)
