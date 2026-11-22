"""Publish stage outcomes and allowlisted diagnostic evidence, never command lines."""
import os
import re
from pathlib import Path

for key in ("SDK", "LIBRARY", "SMOKE", "LIB_ABI", "EXE_ABI", "DIAGNOSTICS", "QEMU"):
    outcome = os.environ[key]
    if outcome not in ("success", "failure", "skipped", "cancelled"):
        raise ValueError("invalid workflow outcome")
    print(f"{key}={outcome}")
abi = [os.environ["LIB_ABI"], os.environ["EXE_ABI"]]
print("ABI ACCEPTANCE:", "FAIL" if "failure" in abi else "PASS" if abi == ["success"] * 2 else "INCOMPLETE")
for path in Path("work/private-diagnostics").glob("strict-*.rc"):
    if re.fullmatch(r"strict-(14|15)-(library|smoke)\.rc", path.name):
        print(path.stem, int(path.read_text()))
for path in Path(os.environ["RUNNER_TEMP"]).glob("p2b-*"):
    if not path.is_file():
        continue
    for line in path.read_text(errors="replace").splitlines():
        # Explicit compiler diagnostics only. Drop paths, shell arguments and environment values.
        location = re.search(r"([\w.+-]+\.(?:h|cc|cpp|c|S|bzl)):(\d+)(?::\d+)?: (?:fatal )?error:", line)
        if location:
            print("compiler diagnostic", location[1], location[2])
        for pattern in (r"unrecognized command-line option [‘'](-[A-Za-z0-9_+.=-]+)",
                        r"([A-Za-z_][A-Za-z0-9_./-]*\.h): No such file or directory",
                        r"undefined reference to [\x60']([A-Za-z0-9_@.]+)",
                        r"([a-zA-Z_0-9.]+) lacks required versions: ([A-Z0-9_., ]+)",
                        r"(AllocateTensors failed|Invoke failed|Model provided has model identifier|cannot allocate memory in static TLS block)",
                        r"(?:ERROR|STATUS): (Bazel toolchain collector for (?:library|smoke)) \(exit=(\d+)\)",
                        r"(external repository|Unrecognized option|undeclared inclusion|not a known command|Repository mapping|no such package)"):
            found = re.search(pattern, line)
            if found and not any("/home/" in s or "/tmp/" in s for s in found.groups()):
                print("diagnostic", *found.groups())
