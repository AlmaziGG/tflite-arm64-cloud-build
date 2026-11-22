"""Phase 2D. Times in ns, procfs memory in KiB, guest allocator counters in bytes."""
import collections
import concurrent.futures
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics as st
import struct
import subprocess
import sys
import threading
import time
import zipfile

import phase2c as ref

P=Path("public/phase2d-report.json")
MODEL="481cf6c180d3b5cbebfa6af47b4f9544c631d05b73cecf51fb8363ab7d143f38"
MODES=("state","stress","lifecycle","fullcycle")


def check(ok,message):
    if not ok:
        raise ValueError(message)


def graph(data):
    check(hashlib.sha256(data).hexdigest()==MODEL and data[4:8]==b"TFL3","model identity")
    def num(p,fmt="i"): return struct.unpack_from("<"+fmt,data,p)[0]
    def field(p,k):
        vt=p-num(p)
        off=num(vt+4+2*k,"H") if 4+2*k<num(vt,"H") else 0
        return p+off if off else 0
    def val(p,k,fmt,default=0):
        f=field(p,k)
        return num(f,fmt) if f else default
    def vector(p,k,fmt="i",tables=False):
        h=field(p,k)
        if not h: return []
        h+=num(h)
        return [num(q,fmt)+(q if tables else 0) for i in range(num(h))
                for q in [h+4+i*struct.calcsize("<"+fmt)]]
    root=num(0)
    codes=[(val(t,3,"i",val(t,0,"B")),val(t,2,"i",1)) for t in vector(root,1,tables=True)]
    names={0:"ADD",129:"CALL_ONCE",142:"VAR_HANDLE",22:"RESHAPE",143:"READ_VARIABLE",2:"CONCATENATION",
           45:"STRIDED_SLICE",144:"ASSIGN_VARIABLE",3:"CONV_2D",4:"DEPTHWISE_CONV_2D",28:"TANH",
           102:"SPLIT_V",1:"AVERAGE_POOL_2D",9:"FULLY_CONNECTED",14:"LOGISTIC",114:"QUANTIZE"}
    groups=[]
    buffers=vector(root,4,tables=True)
    def buffer_size(idx):
        h=field(buffers[idx],0)
        return num(h+num(h),"I") if h else 0
    for sg in vector(root,2,tables=True):
        tensors=vector(sg,0,tables=True)
        def tensor(i):
            t=tensors[i]; q=field(t,4); q=q+num(q) if q else 0
            return dict(shape=vector(t,0),type=val(t,1,"B"),scale=vector(q,2,"f") if q else [],
                        zero=vector(q,3,"q") if q else [])
        ops=collections.Counter()
        state_shapes=[]
        for op in vector(sg,3,tables=True):
            code,version=codes[val(op,0,"I")]
            ops[f"{names.get(code,code)}.v{version}"]+=1
            if code==143:
                state_shapes.append(tensor(vector(op,2)[0]))
        sizes={0:4,2:4,3:1,4:8,6:1,7:2,9:1}
        logical_bytes=sum(math.prod(vector(t,0))*sizes.get(val(t,1,"B"),0) for t in tensors)
        groups.append(dict(tensors=len(tensors),operators=ops,variables=sum(val(t,5,"B") for t in tensors),
                           resource_reads=state_shapes,logical_tensor_bytes=logical_bytes,
                           constant_payload_bytes=sum(buffer_size(i) for i in {val(t,2,"I") for t in tensors}),
                           inputs=[tensor(i) for i in vector(sg,1)],outputs=[tensor(i) for i in vector(sg,2)]))
    return dict(schema=val(root,0,"I"),bytes=len(data),subgraphs=groups,buffers=len(buffers))


def stats(seq):
    x=sorted(seq)
    check(x and x[0]>=0,"invalid latency")
    return dict(mean=st.mean(x),median=st.median(x),sd=st.pstdev(x),min=x[0],max=x[-1],
                **{f"p{p}":x[math.ceil(len(x)*p/100)-1] for p in (50,90,95,99)})


def snapshot(pid):
    base=Path("/proc")/str(pid)
    s=(base/"status").read_text()+(base/"smaps_rollup").read_text()
    keys=("VmRSS","VmHWM","VmSize","Threads","Pss","Private_Clean","Private_Dirty")
    out={k:int(re.search(r"(?m)^"+k+r":\s+(\d+)",s)[1]) for k in keys}
    fields=(base/"stat").read_text().rsplit(")",1)[1].split()
    out["cpu_s"]=(int(fields[11])+int(fields[12]))/os.sysconf("SC_CLK_TCK")
    return out


def trend(points,stage):
    rows=[p for p in points if p["stage"]==stage]
    check(len(rows)>=6,"insufficient memory samples")
    x=[p["index"] for p in rows]; y=[p["VmRSS"] for p in rows]
    slope=st.linear_regression(x,y).slope
    return dict(initial=y[0],final=y[-1],peak=max(y),delta=y[-1]-y[0],
                early=st.median(y[:5]),late=st.median(y[-5:]),slope_kib_per_step=slope)


def benchmark(root,mode):
    command=["qemu-aarch64","-cpu","cortex-a35","-L",root,"-U","LD_PRELOAD","-U","LD_AUDIT","-E",
             "LD_LIBRARY_PATH="+str(ref.art),ref.work/"probe",ref.work/"model",mode]
    p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    points=[]; seq=collections.defaultdict(list); times={}; result={}
    def consume():
        for line in p.stdout:
            words=line.split()
            if line.startswith("caps="): result["caps"]=ref.caps(line)
            elif words[0]=="point":
                _,stage,index,heap,mapped=words
                points.append(dict(stage=stage,index=int(index),guest_heap=int(heap),guest_mmap=int(mapped),**snapshot(p.pid)))
                p.stdin.write("\n"); p.stdin.flush()
            elif words[0]=="time": times[words[1]]=int(words[2])
            elif words[0]=="sequence": seq[words[1]].append(words[2])
            elif words[0]=="variables": result["variables"]=int(words[1])
            else: raise ValueError("unexpected harness record")
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        f=pool.submit(consume)
        try:
            f.result(timeout=350); check(p.wait(timeout=5)==0,"harness failed")
        finally:
            if p.poll() is None: p.kill()
            p.wait()
    check(points[-1]["stage"]=="end" and "caps" in result,"incomplete lifecycle")
    result.update(points=points,times=times,exit=0,reaped=p.returncode==0)
    if mode=="state":
        check(len(seq["initial"])==5 and len(set(seq["initial"]))==1,"fresh mismatch")
        check(seq["recreate"]==seq["newmodel"]==seq["initial"][:1],"isolation failure")
        result["sequences"]=dict(seq)
    elif mode=="stress":
        rows=[list(map(int,s.split())) for s in (ref.work/"latency-private.txt").read_text().splitlines()]
        check(len(rows)==points[-1]["index"]==10000 and all(len(r)==5 for r in rows),"incomplete stress")
        cols=list(zip(*rows))
        result.update(latency={k:stats(c) for k,c in zip(("copy","invoke","read","total"),cols)},
                      completed=len(rows),failed=0,first_failure=None,restarts=0,output_sha256=hashlib.sha256(bytes(cols[4])).hexdigest(),
                      service_rate=1e9/st.mean(cols[3]),memory=trend(points,"steady"),
                      streaming=simulate(cols[3]),detections=window_count(cols[4]),
                      checksum_windows=[sum(cols[4][i:i+1000]) for i in range(0,10000,1000)])
    elif mode in ("fullcycle","lifecycle"):
        result["memory"]=trend(points,"cycle")
        check(points[-2]["index"]==1000,"incomplete lifecycle")
    return result


def simulate(service):
    # One in service, one pending feature batch. Three new frames per arrival.
    finishes=collections.deque(); dropped=late=peak=0
    for i,ns in enumerate(service):
        arrival=i*30000000
        while finishes and finishes[0]<=arrival: finishes.popleft()
        if len(finishes)==2: dropped+=1; continue
        finish=max(arrival,finishes[-1] if finishes else 0)+ns
        finishes.append(finish); late+=finish>arrival+30000000; peak=max(peak,len(finishes))
    return dict(frames=3*len(service),dropped_batches=dropped,late_batches=late,peak_in_service_and_pending=peak)


def detected(window):
    check(len(window)==10 and all(type(x) is int and 0<=x<=255 for x in window),"invalid probability window")
    return sum(window)>2295


def window_count(samples):
    window=collections.deque([0]*10,maxlen=10)
    count=0
    for sample in samples:
        window.append(sample)
        count+=detected(window)
    return count


def validate(doc):
    check(doc["model_sha"]==MODEL and doc["elf"]==ref.pins and set(doc["firmware"])=={"14","15"},"identity")
    for row in doc["firmware"].values():
        check(row["abi"]==[0,0,0] and all(row[m]["exit"]==0 for m in MODES),"matrix")
        check(row["negative"]=={"missing":1,"corrupt":1,"model":0},"negative suite")
        for mode in MODES:
            ref.caps("caps="+",".join(row[mode]["caps"]))
            check(row[mode]["reaped"] and row[mode]["points"][-1]["stage"]=="end","child lifecycle")
        stress=row["stress"]
        check(stress["completed"]==10000 and re.fullmatch("[0-9a-f]{64}",stress["output_sha256"]) and
              stress["failed"]==stress["restarts"]==0 and stress["first_failure"] is None,"stress")
        check([r["index"] for r in stress["points"] if r["stage"]=="steady"]==list(range(0,10001,250)),"measurement coverage")
        for k in ("copy","invoke","total","read"):
            t=stress["latency"][k]
            check(0<=t["min"]<=t["p50"]<=t["p90"]<=t["p95"]<=t["p99"]<=t["max"] and
                  t["min"]<=t["mean"]<=t["max"],"invalid distribution")
        seq=row["state"]["sequences"]
        check(len(seq["initial"])==5 and len(set(seq["initial"]))==1 and
              seq["newmodel"]==seq["recreate"]==seq["initial"][:1],"fresh state")
        for k in ("persistent","reset","allocate"):
            check(len(seq[k])==1 and re.fullmatch("[0-9a-f]{32}",seq[k][0]),"state sequence")
        for mode in ("lifecycle","fullcycle"):
            check([r["index"] for r in row[mode]["points"] if r["stage"]=="cycle"]==list(range(50,1001,50)),"cycle coverage")
    check(doc["graph"]["subgraphs"][0]["inputs"][0]["shape"]==[1,3,40] and
          doc["graph"]["subgraphs"][0]["outputs"][0]=={"shape":[1,1],"type":3,"scale":[1/256],"zero":[0]},"tensor contract")
    check(doc["firmware"]["14"]["stress"]["output_sha256"]==doc["firmware"]["15"]["stress"]["output_sha256"],"divergent stream")
    check(not re.search(r"/home/runner|/tmp/|github_pat_|Bearer |PRIVATE KEY|raw_command",json.dumps(doc)),"unsafe report")


def main():
    manifest=json.loads((ref.work/"model.json").read_text())
    check(manifest["model"]=="alisa_mww.tflite" and manifest["version"]==2 and
          [manifest["micro"][k] for k in ("feature_step_size","sliding_window_size","probability_cutoff","tensor_arena_size")]==[10,10,.9,32000],"manifest")
    g=graph((ref.work/"model").read_bytes())
    subprocess.run(["qemu-aarch64","--version"],check=True)
    doc=dict(commit=os.environ["GITHUB_SHA"],elf=ref.pins,model_sha=MODEL,graph=g,manifest=manifest,cpu="cortex-a35",
             qemu=ref.b.p2.output(["qemu-aarch64","--version"]).splitlines()[0],kernel=platform.release(),
             host_cpu=re.search(r"model name\s*:\s*(.+)",Path("/proc/cpuinfo").read_text())[1],
             threads=1,warmup=200,logical_host_cpus=os.cpu_count(),
             host_mem_available_kib=int(re.search(r"MemAvailable:\s+(\d+)",Path("/proc/meminfo").read_text())[1]),firmware={})
    errors=[]
    for n in ("14","15"):
        root=ref.work/"ota"/("capsule"+n)/"rootfs"
        row=doc["firmware"][n]={}
        row["abi"]=[subprocess.run([sys.executable,"scripts/verify_elf_abi.py",p,root,
                                    *([] if p==ref.lib else ["--allow-library",ref.lib])],capture_output=True).returncode
                    for p in (ref.lib,ref.exe,ref.work/"probe")]
        if any(row["abi"]): errors.append(n+" ABI"); continue
        cmd=["qemu-aarch64","-cpu","cortex-a35","-L",root,"-U","LD_PRELOAD","-U","LD_AUDIT",
             "-E","LD_LIBRARY_PATH="+str(ref.art),ref.work/"probe"]
        (ref.work/"corrupt").write_bytes(bytes(64))
        row["negative"]={}
        for file,mode,want in (("missing","state",1),("corrupt","state",1),("model","badsize",0)):
            prefix=[]
            if mode=="badsize":
                trace=ref.work/("opens"+n)
                prefix=["strace","-f","-yy","-qq","-e","trace=open,openat,openat2","-o",trace]
            neg=subprocess.run([*prefix,*cmd,ref.work/file,mode],input="\n\n",capture_output=True,text=True,timeout=20)
            row["negative"][file]=neg.returncode
            if neg.returncode!=want: errors.append(n+" negative "+file)
            if mode=="badsize" and neg.returncode==0:
                fw=json.loads((ref.art/ref.b.p2.REPORT).read_text())["firmware"][n]
                expected={ref.lib:ref.pins[ref.lib.name],ref.work/"probe":ref.b.abi.digest(ref.work/"probe")}
                for e in fw["audits"]["smoke"]["edges"]:
                    if e["provider"]!="artifacts/libtensorflowlite_c.so":
                        expected[ref.b.abi.rootfs_resolve(root/e["provider"],root)]=e["sha256"]
                loader=ref.b.abi.rootfs_resolve(root/fw["loader"].lstrip("/"),root)
                expected[loader]=ref.b.abi.digest(loader)
                ref.b.verify_guest_opens(trace.read_text(),expected,root,{ref.lib,ref.work/"probe"})
        for mode in MODES:
            try: row[mode]=benchmark(root,mode)
            except Exception as e:
                errors.append(n+" "+mode+" "+type(e).__name__)
    check(not errors,str(errors))
    validate(doc); P.parent.mkdir(exist_ok=True); P.write_text(json.dumps(doc,sort_keys=True)+"\n")


def verify():
    data,sha=ref.b.public.download(os.environ,name="phase2d-evidence")
    check(sha=="sha256:"+hashlib.sha256(data).hexdigest(),"zip digest")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        check(sorted(z.namelist())==["SHA256SUMS",P.name],"zip members")
        body=z.read(P.name)
        check(z.read("SHA256SUMS")==f"{hashlib.sha256(body).hexdigest()}  {P.name}\n".encode(),"manifest")
        doc=json.loads(body); validate(doc); check(doc["commit"]==os.environ["GITHUB_SHA"],"commit")
    print("Verified",sha)


if __name__=="__main__":
    verify() if sys.argv[1:] == ["verify"] else main()
