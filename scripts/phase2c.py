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


def baseline_decode(special, instructions):
    # Cross-check the decoder with actual known extension encodings in this ELF.
    text=b.p2.output(["llvm-objdump","-d","--mcpu=generic",
                      "--mattr=-dotprod,-fullfp16,-i8mm,-lse,-crc,-crypto",lib])
    decoded=set()
    unknown=set()
    for m in re.finditer(r"(?m)^\s*([0-9a-f]+):\s+(?:[0-9a-f]{8}\s+|(?:[0-9a-f]{2}\s+){4})(\S+)",text):
        pc=int(m[1],16)
        if pc in instructions:
            (unknown if m[2] in ("<unknown>",".word",".long",".inst") else decoded).add(pc)
    controls={k:sum(1 for pc,v in special.items() if v[2]==k and pc in unknown)
              for k in ("dotprod","fp16","i8mm")}
    return dict(decoded=len(decoded),unknown=len(unknown),not_compared=len(instructions.keys()-decoded-unknown),
                rejected_controls=controls,version=b.p2.output(["llvm-objdump","--version"]).splitlines()[0])


def runtime_pass(row):
    return (row.get("abi")==[0,0,0] and row.get("smoke_exit")==0 and row.get("probe_exit")==0
            and "failure" not in row and row.get("translated_library_pcs",0)>0 and row.get("translated_special")=={}
            and [(a,b) for a,b,_ in row.get("patterns",[])]==[(str(i),str(k)) for i in range(2) for k in range(6)])


def validation():
    special, instructions = inventory()
    q = shutil.which("qemu-aarch64")
    listing=subprocess.run([q,"-cpu","help",work/"probe"],capture_output=True,text=True)
    listing_text=listing.stdout+listing.stderr
    assert "cortex-a53" in listing_text.split(), "unrecognized QEMU model list"
    models=listing_text.split()
    results = dict(version=b.p2.output([q,"--version"]).splitlines()[0], executable=Path(q).name,
                   model="cortex-a35", executable_path=q, help_exit=listing.returncode, available="cortex-a35" in models, binaries=pins,
                   counts=dict(collections.Counter((r[2]+":"+r[3]) for r in special.values())),
                   inventory=special, decoder=baseline_decode(special,instructions), firmware={})
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
            opens=work/("opens"+n)
            probe=subprocess.run(["strace","-f","-yy","-qq","-e","trace=open,openat,openat2","-o",opens,
                                  *args,"-d","in_asm,exec,nochain","-D",trace,work/"probe",work/"model"],
                                 capture_output=True,text=True,timeout=120)
            row["probe_exit"]=probe.returncode
            if probe.returncode: raise ValueError("pattern probe failed")
            fw=json.loads((art/b.p2.REPORT).read_text())["firmware"][n]
            expected={lib:pins[lib.name],work/"probe":b.abi.digest(work/"probe")}
            for edge in fw["audits"]["smoke"]["edges"]:
                if edge["provider"]!="artifacts/libtensorflowlite_c.so":
                    expected[b.abi.rootfs_resolve(root/edge["provider"],root)]=edge["sha256"]
            loader=b.abi.rootfs_resolve(root/fw["loader"].lstrip("/"),root)
            expected[loader]=b.abi.digest(loader)
            b.verify_guest_opens(opens.read_text(),expected,root,{lib,work/"probe"})
            bias=int(re.search(r"(?m)^base=([0-9a-f]+)$",probe.stdout)[1],16)
            row["patterns"]=re.findall(r"(?m)^result=(\d+),(\d+),(\d+)$",probe.stdout)
            assert [(int(r),int(k)) for r,k,v in row["patterns"]]==[(r,k) for r in range(2) for k in range(6)]
            pcs=set()
            blocks=set()
            with trace.open() as stream:
                for line in stream:
                    match=re.match(r"0x([0-9a-f]+):",line)
                    if match: pcs.add(int(match[1],16)-bias)
                    match=re.match(r"Trace \d+: .*?\[[0-9a-f]+/([0-9a-f]+)/",line)
                    if match: blocks.add(int(match[1],16)-bias)
            inside=pcs & instructions.keys()
            assert inside
            (work/("pcs"+n)).write_text(json.dumps(sorted(inside)))
            assert blocks & instructions.keys(), "missing execution records"
            (work/("blocks"+n)).write_text(json.dumps(sorted(blocks & instructions.keys())))
            row["translated_library_pcs"]=len(inside)
            row["translated_special"]=dict(collections.Counter(special[p][2] for p in inside & special.keys()))
            row["translated_symbols"]=sorted({instructions[p] for p in inside})
            row["zero_point"]=int(re.search(r"(?m)^zp=(-?\d+)$",probe.stdout)[1])
            row["delegate_messages"]=sorted(set(re.findall(r"Created TensorFlow Lite (XNNPACK) delegate",probe.stderr)))
        except (ValueError,AssertionError,subprocess.SubprocessError) as exc:
            row["failure"]=type(exc).__name__
    report.parent.mkdir(exist_ok=True)
    report.write_text(json.dumps(results,sort_keys=True)+"\n")
    if not results["available"] or not all(runtime_pass(r) for r in results["firmware"].values()):
        sys.exit(1)


def check_report(body):
    if re.search(rb"/home/runner|/tmp/|github_pat_|Bearer |PRIVATE KEY|work/private|raw_command=|action_dump=|gh[pousr]_[A-Za-z0-9]{20,}", body):
        raise ValueError("private data in report")
    doc=json.loads(body)
    allowed={"version","executable","executable_path","model","available","help_exit","binaries","counts",
             "inventory","firmware","function_table","decoder"}
    if doc.keys()-allowed or doc["binaries"]!=pins or set(doc["firmware"])!={"14","15"}:
        raise ValueError("unexpected report structure or baseline identity")
    for row in doc["firmware"].values():
        if row.keys()-{"abi","caps","smoke_exit","probe_exit","patterns","translated_library_pcs",
                       "translated_special","translated_symbols","executed_symbols","zero_point","delegate_messages","failure"}:
            raise ValueError("unexpected runtime report field")
    return doc


def verify():
    data,digest=b.public.download(os.environ,name="phase2c-evidence")
    assert digest=="sha256:"+hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert sorted(z.namelist())==["SHA256SUMS","isa.json"]
        body=z.read("isa.json")
        assert z.read("SHA256SUMS")== (hashlib.sha256(body).hexdigest()+"  isa.json\n").encode()
        check_report(body)
    print("Verified ZIP",digest)


if __name__=="__main__":
    {"baseline":baseline,"validation":validation,"verify":verify,
     "public":lambda:check_report(report.read_bytes())}[sys.argv[1]]()
