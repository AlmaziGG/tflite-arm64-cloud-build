"""Evidence for the immutable Phase 2B ELF pair. Raw traces stay private."""
import collections
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import phase2b as b

work = b.p2.WORK
art = b.p2.ART
lib = art / "libtensorflowlite_c.so"
exe = art / "tflite_smoke"
report = Path("public/isa.json")
pins = {lib.name: "ed0b9bcade45e0714323660d0bdea2e9904f79851726acc90834a34f3ac6691c",
        exe.name: "0351448bdf896fe446951ea980d73e2089c8a7f43f6bd49fcb029e3a22698031"}


def baseline():
    env = dict(os.environ, ARTIFACT_ID="14768499172", GITHUB_RUN_ID="45059762746",
               GITHUB_SHA="e822f52e9c6c55e048eccf5324658255f29b25a4")
    data, digest = b.public.download(env, name="phase2b-bazel-gnu103")
    assert digest == "sha256:ac86980d00be235ad3b1147406f3710d277fe25d998c3d13fd0e1510cd9a30e6"
    b.public.verify_zip(data, digest, art, structure=b.p2.REPORT, extra_files=b.EXTRA,
                        validate_structure=b.p2.validate)
    assert all(b.abi.digest(art / name) == sha for name, sha in pins.items())


def isa(op, args):
    if op in ("sdot","udot"): return "dotprod"
    if op in ("smmla","ummla","usmmla","usdot","sudot"): return "i8mm"
    if op.startswith("f") and re.search(r"(?:\bv\d+\.(?:4h|8h)|\bh\d+\b)", args):
        if op not in ("fcvt","fcvtn","fcvtn2","fcvtl","fcvtl2","fmov"):
            return "fp16"
    if op.startswith(("aes","sha","crc32","ldadd","cas","swp","sqrdml")): return "other-extension"
    return "unclassified"


def inventory():
    tool = b.SDK / "bin/aarch64-none-linux-gnu-objdump"
    text = b.p2.output([tool, "-d", lib])
    special, instructions = {}, {}
    section = symbol = ""
    for line in text.splitlines():
        m = re.match(r"Disassembly of section ([.\w]+):", line)
        if m: section = m[1]
        m = re.match(r"[a-f0-9]+ <([^>]+)>:", line)
        if m: symbol = m[1]
        m = re.match(r"\s*([a-f0-9]+):\s+[0-9a-f]{8}\s+([\w.]+)\s*(.*)", line)
        if not m: continue
        address, op, args = int(m[1],16), m[2], m[3].split("//")[0].strip()
        instructions[address] = symbol
        group = isa(op,args)
        if group != "unclassified":
            special[address] = [section, symbol, group, op, args]
    assert instructions and special
    return special, instructions


def caps(text):
    match = re.search(r"(?m)^caps=([0-9a-f]+),([0-9a-f]+)$",text)
    if not match: raise ValueError("missing guest capabilities")
    a,c = (int(x,16) for x in match.groups())
    if a & 3 != 3 or a & ((1<<9)|(1<<10)|(1<<20)|(1<<22)) or c & ((1<<13)|(1<<14)):
        raise ValueError("unexpected guest capabilities")
    return match.groups()


def validation():
    special, instructions = inventory()
    q = shutil.which("qemu-aarch64")
    listing=subprocess.run([q,"-cpu","help",work/"probe"],capture_output=True,text=True)
    listing_text=listing.stdout+listing.stderr
    assert "cortex-a53" in listing_text.split(), "unrecognized QEMU model list"
    models=listing_text.split()
    results = dict(version=b.p2.output([q,"--version"]).splitlines()[0], executable=Path(q).name,
                   model="cortex-a35", help_exit=listing.returncode, available="cortex-a35" in models, binaries=pins,
                   counts=dict(collections.Counter((r[2]+":"+r[3]) for r in special.values())),
                   inventory=special, firmware={})
    for n in ("14","15"):
        row = results["firmware"][n] = {}
        if not results["available"]: continue
        root = work / "ota" / ("capsule"+n) / "rootfs"
        args=[q,"-cpu","cortex-a35","-L",root,"-U","LD_AUDIT","-U","LD_PRELOAD","-E","LD_LIBRARY_PATH="+str(art)]
        try:
            row["abi"] = [subprocess.run([sys.executable,"scripts/verify_elf_abi.py",path,root,
                           *([] if path==lib else ["--allow-library",lib])],capture_output=True).returncode
                          for path in (lib,exe,work/"probe")]
            if any(row["abi"]): raise ValueError("ABI failure")
            row["caps"]=caps(b.p2.output([*args,work/"probe"],timeout=30))
            smoke=subprocess.run([*args,exe,work/"model"],capture_output=True,text=True,timeout=60)
            row["smoke_exit"]=smoke.returncode
            if smoke.returncode or "invoke=ok output type=3 bytes=1\noutput[0]=100" not in smoke.stdout:
                raise ValueError("immutable smoke failed")
            trace=work/("trace"+n)
            probe=subprocess.run([*args,"-d","in_asm","-D",trace,work/"probe",work/"model"],
                                 capture_output=True,text=True,timeout=120)
            row["probe_exit"]=probe.returncode
            if probe.returncode: raise ValueError("pattern probe failed")
            bias=int(re.search(r"(?m)^base=([0-9a-f]+)$",probe.stdout)[1],16)
            row["patterns"]=re.findall(r"(?m)^result=(\d+),(\d+),(\d+)$",probe.stdout)
            assert [(int(r),int(k)) for r,k,v in row["patterns"]]==[(r,k) for r in range(2) for k in range(6)]
            pcs=set()
            with trace.open() as stream:
                for line in stream:
                    match=re.match(r"0x([0-9a-f]+):",line)
                    if match: pcs.add(int(match[1],16)-bias)
            inside=pcs & instructions.keys()
            assert inside
            (work/("pcs"+n)).write_text(json.dumps(sorted(inside)))
            row["translated_library_pcs"]=len(inside)
            row["translated_special"]=dict(collections.Counter(special[p][2] for p in inside & special.keys()))
            row["translated_symbols"]=sorted({instructions[p] for p in inside})
            row["zero_point"]=int(re.search(r"(?m)^zp=(-?\d+)$",probe.stdout)[1])
            row["delegate_messages"]=sorted(set(re.findall(r"Created TensorFlow Lite (XNNPACK) delegate",probe.stderr)))
        except (ValueError,AssertionError,subprocess.SubprocessError) as exc:
            row["failure"]=type(exc).__name__
    report.parent.mkdir(exist_ok=True)
    report.write_text(json.dumps(results,sort_keys=True)+"\n")
    if not results["available"] or any("failure" in r or r.get("translated_special") for r in results["firmware"].values()):
        sys.exit(1)


def verify():
    data,digest=b.public.download(os.environ,name="phase2c-evidence")
    assert digest=="sha256:"+hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert sorted(z.namelist())==["SHA256SUMS","isa.json"]
        body=z.read("isa.json")
        assert z.read("SHA256SUMS")== (hashlib.sha256(body).hexdigest()+"  isa.json\n").encode()
        assert not re.search(rb"/home/runner|/tmp/|github_pat_|Bearer |PRIVATE KEY|work/private",body)
        assert json.loads(body)["binaries"]==pins
    print("Verified ZIP",digest)


if __name__=="__main__":
    {"baseline":baseline,"validation":validation,"verify":verify}[sys.argv[1]]()
