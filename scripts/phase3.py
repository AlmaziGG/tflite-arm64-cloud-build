"""Separate host oracle, native candidate and strict two-firmware end-to-end comparison."""
import array
import base64
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import wave
import zipfile
import zlib
from pathlib import Path

import phase2d as previous
from phase2d import check, ref

P = Path("work/p3")
PUB = Path("public")
AUDIT = "PHASE-3-REUSE-ASSESSMENT.md"
FILES = (AUDIT, "phase3-report.json", "frontend-equivalence.json", "streaming-results.json",
         "detection-results.json", "resource-summary.json")
CHUNKS = (1, 80, 160, 256, 480, 512, 377)
NAMES = ("silence", "zeros", "tone440", "quiet", "high", "impulse", "step", "noise", "mixed", "boundary", "long")
sha = lambda buf: hashlib.sha256(buf).hexdigest()


def save(name, data):
    PUB.mkdir(exist_ok=True)
    (PUB/name).write_text(json.dumps(data, sort_keys=True, separators=(",", ":"))+"\n")


def fixture(name):
    n = {"long": 480000, "zeros": 479, "boundary": 16321}.get(name, 25743)
    state = 7331
    values = array.array("h")
    for i in range(n):
        state = (1664525*state + 1013904223) & 0xffffffff
        noise = (state >> 16) - 32768
        if name in ("silence", "zeros", "long"):
            v = 0
        elif name in ("tone440", "quiet", "high"):
            v = round((20 if name=="quiet" else 10000)*math.sin(2*math.pi*(3700 if name=="high" else 440)*i/16000))
        elif name=="impulse":
            v = 32767 if i in (479, 4000, 8000) else 0
        elif name=="step":
            v = 17000 if i>=8000 else 0
        elif name=="noise":
            v = noise//2
        elif name=="mixed":
            v = noise//6 + round(11000*math.sin(2*math.pi*510*i/16000))
        elif name=="boundary":
            v = (i*771 % 65536)-32768
        else:
            raise ValueError("unknown fixture")
        values.append(v)
    if sys.byteorder!="little":
        values.byteswap()
    return values.tobytes()


def wav(data):
    b = io.BytesIO()
    with wave.open(b, "wb") as f:
        f.setparams((1,2,16000,0,"NONE","")); f.writeframes(data)
    return b.getvalue()


def command(args, data=None, timeout=90):
    return subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=True)


def candidate(exe, inputs, chunk, data=None, prefix=()):
    path = P/"trace.private"
    path.unlink(missing_ok=True)
    result=command([*prefix,exe,ref.work/"model",path,str(chunk),*inputs],data)
    blob=path.read_bytes()
    check(len(blob)%125==0,"incomplete frame trace")
    frames=[blob[i:i+125] for i in range(0,len(blob),125)]
    metrics=[list(map(int,x.split())) for x in re.findall(rb"(?m)^metrics ([0-9 ]+)$",result.stderr)]
    check(len(metrics)==len(inputs) and all(len(m)==8 for m in metrics),"session metrics")
    events=result.stdout.decode().splitlines()
    check(all(e=="Алиса" for e in events),"stdout protocol")
    return frames,metrics,events


def compare_rows(want, actual, name):
    check(len(want)==len(actual),name+" frame count")
    if want==actual:
        return
    # Unit is a raw uint16 channel or a signed int8 channel, never a byte tolerance.
    diff=[]
    for i,(a,b) in enumerate(zip(want,actual)):
        for k,(x,y) in enumerate(zip(struct.unpack("<40H40b",a),struct.unpack("<40H40b",b))):
            if x!=y:
                diff.append((i,k,x,y))
    raise ValueError(f"{name}: first(frame,channel[raw:0..39,int8:40..79],expected,actual)={diff[0]} "
                     f"count={len(diff)} max_abs={max(abs(x-y) for _,_,x,y in diff)}")


def golden():
    features,streams={},{}
    for name in NAMES:
        pcm=fixture(name); path=P/(name+".wav"); path.write_bytes(wav(pcm))
        reference=command([P/"oracle"],pcm).stdout
        count=max(0,(len(pcm)//2-480)//160+1)
        check(len(reference)==count*120,"reference cadence")
        oracle=[reference[i:i+120] for i in range(0,len(reference),120)]
        (P/(name+".gold")).write_bytes(reference)
        quantized=b"".join(row[80:] for row in oracle)
        features[name]=dict(samples=len(pcm)//2,rate=16000,duration_s=len(pcm)/32000,frames=count,
                            first_end_sample=480 if count else None,step_samples=160,
                            pcm_sha256=sha(pcm),wav_sha256=sha(path.read_bytes()),seed=7331 if name in ("noise","mixed") else None,
                            raw_sha256=sha(b"".join(row[:80] for row in oracle)),int8_sha256=sha(quantized),
                            interleaved_raw_u16le_int8_zlib_b64=base64.b64encode(zlib.compress(reference)).decode())
        streams[name]={}
        for chunk in CHUNKS:
            rows,m,_=candidate(P/"host",[path],chunk)
            compare_rows(oracle,[row[:120] for row in rows],name)
            check(m[0][0]==len(pcm)//2,"sample loss")
            streams[name][str(chunk)]=sha(b"".join(row[80:120] for row in rows))
        raw,_,_=candidate(P/"host",["-"],311,pcm)
        compare_rows(oracle,[row[:120] for row in raw],name+" stdin")
    save("frontend-equivalence.json",features); save("streaming-results.json",streams)


def audit(elf,root):
    args=[sys.executable,"scripts/verify_elf_abi.py",elf,root]
    if elf!=ref.lib:
        args+=["--allow-library",ref.lib]
    result=command(args).stdout.decode()
    return result


def actual_providers(log,root,elf):
    expected={elf.resolve():ref.b.abi.digest(elf)}
    for path,digest in re.findall(r"(?m)^OK DT_NEEDED \S+: (.+?) \([^)]+\); ELF64/AArch64; SHA256=([0-9a-f]{64});",log):
        p=Path(path)
        if p.name==ref.lib.name:
            real=ref.lib
        else:
            # Use firmware's root-confined resolver also for absolute guest symlinks.
            relative=p.relative_to(root) if p.is_relative_to(root) else str(p).lstrip("/")
            real=ref.b.abi.rootfs_resolve(root/relative,root)
        check(real and ref.b.abi.digest(real)==digest,"strict provider identity")
        expected[real]=digest
    loader=re.search(r"OK PT_INTERP [^:]+: ELF64/AArch64 \((.+)\)",log)
    check(loader,"missing dynamic loader")
    ld=Path(loader[1]); check(ld.is_relative_to(root),"foreign loader")
    expected[ld]=ref.b.abi.digest(ld)
    check(ref.lib in expected and any(p.name.startswith("libc") for p in expected),"missing runtime closure")
    return expected


def decision(raw,frames):
    scores=[0]*10; pos=0; grace=74; rows=[]
    for f in range(frames):
        value=raw[f//3] if f%3==2 else -1
        if value>=0:
            scores[pos]=value; pos=(pos+1)%10
        grace=max(0,grace-1)
        total=sum(scores); hit=not grace and total>2295
        rows.append((value,total,hit))
        if hit:
            # A restarted frontend requires new audio context and a new reference session.
            raise ValueError(f"synthetic positive at frame {f+1}; segment and replay before acceptance")
    return rows


def matrix():
    reports={}; resources={}; det={}
    manifest=json.loads((ref.work/"model.json").read_bytes())["micro"]
    check([manifest[k] for k in ("feature_step_size","sliding_window_size","probability_cutoff")]==[10,10,.9],"manifest")
    graph=previous.graph((ref.work/"model").read_bytes())
    runner=(P/"runner").resolve(); replay=(P/"replay").resolve()
    roots={n:ref.work/"ota"/("capsule"+n)/"rootfs" for n in ("14","15")}
    # Global gate: complete all strict audits on both OTAs before the first emulated instruction.
    audits={}; failed=[]
    for n,root in roots.items():
        for elf in (ref.lib,ref.exe,runner,replay):
            try:
                audits[n,elf]=audit(elf,root)
            except subprocess.CalledProcessError as e:
                failed.append((n,elf.name,e.returncode))
                print(n,elf.name,e.stderr.decode()[-1000:],flush=True)
    check(not failed,"ABI failures "+str(failed))
    for n,root in roots.items():
        prefix=["qemu-aarch64","-cpu","cortex-a35","-L",root,"-U","LD_AUDIT","-U","LD_PRELOAD","-E","LD_LIBRARY_PATH="+str(ref.art)]
        trace=P/("opens"+n)
        expected=actual_providers(audits[n,runner],root,runner)
        candidate(runner,[P/"tone440.wav"],160,prefix=["strace","-f","-yy","-qq","-e","trace=open,openat,openat2","-o",trace,*prefix])
        ref.b.verify_guest_opens(trace.read_text(),expected,root,{ref.lib,runner})
        reports[n]={"strict_audits":4,"guest_providers":{p.name:h for p,h in expected.items()}}
        det[n]={}; resources[n]={}
        for name in NAMES:
            gold=(P/(name+".gold")).read_bytes()
            oracle=[gold[i:i+120] for i in range(0,len(gold),120)]
            tensor=b"".join(row[80:] for row in oracle)
            scores=command([*prefix,replay,ref.work/"model"],tensor[:len(tensor)//120*120]).stdout
            check(len(scores)==len(oracle)//3,"invoke cadence")
            rows,metrics,events=candidate(runner,[P/(name+".wav")],377,prefix=prefix)
            compare_rows(oracle,[row[:120] for row in rows],n+" "+name)
            calculated=decision(scores,len(rows))
            actual=[struct.unpack("<hHB",row[120:]) for row in rows]
            check(actual==calculated and len(events)==sum(v[2] for v in calculated),"detector divergence "+name)
            m=metrics[0]
            check(m[:3]==[len(fixture(name))//2,len(rows),len(scores)],"candidate count")
            det[n][name]=dict(invokes=len(scores),raw=list(scores),raw_sha256=sha(scores),
                              sum_by_frame=[x[1] for x in actual],denominator=2550,
                              events_end_sample=[480+160*i for i,x in enumerate(actual) if x[2]])
            resources[n][name]=dict(zip(("samples","frames","invokes","frontend_init_ns","interpreter_init_ns",
                                         "frontend_ns","invoke_ns","total_ns"),m))
        # Fresh interpreter and frontend in the same process versus separate processes.
        path=P/"mixed.wav"
        single,_,_=candidate(runner,[path],80,prefix=prefix)
        double,_,_=candidate(runner,[path,path],512,prefix=prefix)
        check(double==single*2,"session isolation")
        raw,_,_=candidate(runner,["-"],1,fixture("mixed"),prefix)
        check(raw==single,"guest raw chunk invariance")
        rss=P/"rss.private"
        command(["/usr/bin/time","-f","%M","-o",rss,*prefix,runner,ref.work/"model","-","160",P/"long.wav"])
        resources[n]["max_host_qemu_rss_kib"]=int(rss.read_text().strip())
    check(det["14"]==det["15"],"OTA trace divergence")
    save("detection-results.json",det); save("resource-summary.json",resources)
    info=ref.b.p2.metadata(runner)
    info.pop("definitions",None)
    save("phase3-report.json",dict(commit=os.environ["GITHUB_SHA"],model=previous.MODEL,graph=graph,
                                   baseline=ref.pins,elf=info,firmware=reports,real_speech="NOT TESTED",
                                   qemu=ref.b.p2.output(["qemu-aarch64","--version"]).splitlines()[0],
                                   compiler=ref.b.p2.output([ref.b.GCC,"-dumpfullversion"]),
                                   triple=ref.b.TRIPLE,linker=ref.b.p2.output([ref.b.SDK/"bin"/(ref.b.TRIPLE+"-ld"),"--version"]).splitlines()[0]))
    shutil.copyfile(AUDIT,PUB/AUDIT)
    bodies={n:(PUB/n).read_bytes() for n in FILES}
    validate(bodies,os.environ["GITHUB_SHA"])
    (PUB/"SHA256SUMS").write_bytes(sums(bodies))


def sums(bodies):
    return "".join(f"{sha(bodies[n])}  {n}\n" for n in sorted(bodies)).encode()


def validate(bodies,commit):
    check(set(bodies)==set(FILES),"public allowlist")
    check(bodies[AUDIT]==Path(AUDIT).read_bytes(),"reuse assessment identity")
    for body in bodies.values():
        check(not re.search(rb"/home/runner|/tmp/|github_pat_|gh[pousr]_[A-Za-z0-9]{20}|Bearer |PRIVATE KEY|C:\\\\Users",body),"unsafe content")
    doc=json.loads(bodies["phase3-report.json"])
    check(doc["commit"]==commit and doc["baseline"]==ref.pins and doc["model"]==previous.MODEL,"provenance")
    features,streams,detect,resource=[json.loads(bodies[n]) for n in FILES[2:]]
    check(set(doc["firmware"])==set(detect)==set(resource)=={"14","15"},"firmware coverage")
    check(set(features)==set(streams)==set(NAMES) and detect["14"]==detect["15"],"fixture coverage")
    for n in ("14","15"):
        check(doc["firmware"][n]["strict_audits"]==4 and doc["firmware"][n]["guest_providers"][ref.lib.name]==ref.pins[ref.lib.name],"ABI evidence")
        check(set(detect[n])==set(NAMES) and resource[n]["max_host_qemu_rss_kib"]>0,"measurement coverage")
    for name in NAMES:
        f=features[name]; data=fixture(name); frames=max(0,(len(data)//2-480)//160+1)
        raw=zlib.decompress(base64.b64decode(f["interleaved_raw_u16le_int8_zlib_b64"],validate=True))
        check(f["pcm_sha256"]==sha(data) and f["frames"]==frames and len(raw)==frames*120,"golden length")
        quant=b"".join(raw[i+80:i+120] for i in range(0,len(raw),120))
        check(f["int8_sha256"]==sha(quant) and f["raw_sha256"]==sha(b"".join(raw[i:i+80] for i in range(0,len(raw),120))),"golden digest")
        check(streams[name]=={str(c):sha(quant) for c in CHUNKS},"chunk evidence")
        d=detect["14"][name]; scores=bytes(d["raw"])
        check(len(scores)==d["invokes"]==frames//3 and d["raw_sha256"]==sha(scores),"output evidence")
        v=decision(scores,frames)
        check(d["denominator"]==2550 and d["sum_by_frame"]==[x[1] for x in v] and not d["events_end_sample"],"threshold evidence")


def verify_zip(data,digest,commit):
    check("sha256:"+sha(data)==digest,"ZIP checksum")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        check(sorted(archive.namelist())==sorted((*FILES,"SHA256SUMS")),"ZIP allowlist")
        check(all(i.file_size<=8_000_000 for i in archive.infolist()),"oversize report")
        bodies={n:archive.read(n) for n in FILES}
        check(archive.read("SHA256SUMS")==sums(bodies),"manifest mismatch")
        validate(bodies,commit)


if __name__=="__main__":
    if sys.argv[1:]==["golden"]:
        golden()
    elif sys.argv[1:]==["verify"]:
        data,digest=ref.b.public.download(os.environ,name="phase3-wakeword-evidence")
        verify_zip(data,digest,os.environ["GITHUB_SHA"]); print("Verified",digest)
    elif not sys.argv[1:]:
        matrix()
    else:
        raise SystemExit("unknown command")
