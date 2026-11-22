"""Measure speech with the unchanged Phase 3 ELF. Only schema-checked aggregates leave the runner."""
import io
import json
import math
import os
from pathlib import Path
import statistics
import struct
import sys
import wave
import zipfile

import phase3 as p
from phase2d import check
import speech31_samples as s

RUNNER_SHA="242d0d6d0338d1c107ce8dab1279de1b9f95b42aff6b7a71195de378783de320"
PINS={"runner":RUNNER_SHA,"tflite":p.ref.pins[p.ref.lib.name],"model":p.previous.MODEL}
RULE={"cutoff":0.90,"window":10,"sum_exclusive":2295,"grace":74,
      "annotation_allowance_samples":6400,"late_window_samples":16000}
OUT=Path("public31")
FILES=("phase3-1-report.json","speech-test-manifest.json","speech-detection-summary.json",
       "speech-latency-summary.json","speech-session-results.json")
NAME="phase3-1-speech-evidence"


def identity():
    paths=(p.P/"runner",p.ref.lib,p.ref.work/"model")
    check({name:s.sha(path.read_bytes()) for name,path in zip(PINS,paths)}==PINS,"immutable inputs")


def analyze(rows, samples, invokes, stdout_events):
    scores=[]; sums=[]; events=[]; permitted=[]
    window=[0]*10; pos=0; frame=0; next_end=480
    for row in rows:
        check(len(row)==125 and next_end<=samples,"frame extent")
        raw,total,flag=struct.unpack_from("<hHB",row,120)
        frame+=1
        if frame%3==0:
            check(0<=raw<=255,"raw score"); scores.append(raw);window[pos]=raw;pos=(pos+1)%10
        else:
            check(raw==-1,"stride")
        expected=sum(window); hit=frame>=74 and expected>2295
        check(total==expected and flag==int(hit),"decision mismatch")
        sums.append(total)
        if frame==74: permitted.append(next_end)
        if hit:
            events.append(next_end); window=[0]*10;pos=0;frame=0
            next_end+=480  # new frontend needs a complete 30 ms window after a detection
        else:
            next_end+=160
    check(next_end>samples and len(scores)==invokes and len(events)==stdout_events,"incomplete execution")
    return dict(frames=len(rows),invokes=invokes,events=events,permitted=permitted,
                peak_raw=max(scores,default=None),peak_sum=max(sums,default=None),
                features_sha256=s.sha(b"".join(r[80:120] for r in rows)),
                outputs_sha256=s.sha(bytes(scores)),sums_sha256=s.sha(b"".join(struct.pack("<H",v) for v in sums)))


def match(intervals,events):
    # Chronological one-to-one matching; windows registered before any detector run.
    used=set();latencies=[]
    for a,b in intervals:
        for i,t in enumerate(events):
            if i not in used and a-RULE["annotation_allowance_samples"]<=t<=b+RULE["annotation_allowance_samples"]+RULE["late_window_samples"]:
                used.add(i);latencies.append(t-b);break
    return latencies,len(intervals)-len(used),len(events)-len(used)


def summary(manifest,results):
    lat=[]; occurrences=positives=negatives=duration=fa=extra=0
    for item in manifest:
        events=results[item["id"]]["events"]
        if item["label"]=="positive":
            positives+=1;occurrences+=len(item["intervals"])
            delays,_,unmatched=match(item["intervals"],events);lat+=delays;extra+=unmatched
        else:
            negatives+=1;duration+=item["samples"];fa+=len(events)
    return dict(positives=positives,negatives=negatives,occurrences=occurrences,tp=len(lat),fn=occurrences-len(lat),
                miss_rate=(1-len(lat)/occurrences if occurrences else None),extra_positive_events=extra,
                negative_samples=duration,negative_events=fa,false_activations_per_hour=fa*57600000/duration if duration else None,
                latencies_samples=lat,median_latency_ms=statistics.median(lat)/16 if lat else None,
                p95_latency_ms=sorted(lat)[math.ceil(.95*len(lat))-1]/16 if len(lat)>=20 else None)


def diagnose_public_miss(item,path,rows,prefix):
    # The oracle uses independently built ESPMicroSpeechFeatures on the host.
    # The replay ELF takes its INT8 bytes directly, bypassing the guest frontend.
    check(item["id"] in s.RECORDINGS and item["label"]=="positive","public diagnostic scope")
    with wave.open(str(path),"rb") as stream:
        pcm=stream.readframes(stream.getnframes())
    golden=p.command([p.P/"oracle"],pcm).stdout
    check(golden==b"".join(row[:120] for row in rows),"speech oracle RAW/INT8 divergence")
    inputs=b"".join(golden[i+80:i+120] for i in range(0,len(golden),120))
    scores=p.command([*prefix,p.P/"replay",p.ref.work/"model"],inputs[:len(inputs)//120*120]).stdout
    decisions=[struct.unpack_from("<hH",r,120) for r in rows]
    check(scores==bytes(raw for raw,_ in decisions if raw>=0),"independent speech replay divergence")
    padded,metrics,e=p.candidate((p.P/"runner").resolve(),["-"],160,bytes(32000)+pcm,prefix)
    trace=analyze(padded,item["samples"]+16000,metrics[0][2],len(e))
    return dict(oracle_features_sha256=s.sha(inputs),reference_scores_sha256=s.sha(scores),
                public_scores=list(scores),public_sums=[total for _,total in decisions],preroll_1s=trace)


def measure(n,manifest):
    runner=(p.P/"runner").resolve()
    root=p.ref.work/"ota"/("capsule"+n)/"rootfs"
    prefix=["qemu-aarch64","-cpu","cortex-a35","-L",root,"-U","LD_AUDIT","-U","LD_PRELOAD","-E","LD_LIBRARY_PATH="+str(p.ref.art)]
    singles={};results={}
    paths={r["id"]:s.PRIVATE/(r["id"]+".wav") for r in manifest}
    def run(files,chunk=160,pcm=None):
        return p.candidate(runner,files,chunk,pcm,prefix)
    for item in manifest:
        name=item["id"]; path=paths[name]
        rows,metrics,events=run([path])
        check(metrics[0][:2]==[item["samples"],len(rows)],"sample accounting")
        results[name]=analyze(rows,item["samples"],metrics[0][2],len(events))
        singles[name]=(rows,events)
        (s.PRIVATE/f"{n}-{name}.trace").write_bytes(b"".join(rows))
        for chunk in p.CHUNKS:
            again,_,e=run([path],chunk)
            check(again==rows and e==events,"chunk divergence")
        if item["label"]=="positive" and not results[name]["events"]:
            results[name]["miss_diagnostic"]=diagnose_public_miss(item,path,rows,prefix)
        elif item["intervals"] and item["intervals"][0][0]<12160:
            with wave.open(str(path),"rb") as f: pcm=f.readframes(f.getnframes())
            padded=bytes(32000)+pcm
            other,m,e=run(["-"],160,padded)
            results[name]["preroll_1s"]=analyze(other,len(padded)//2,m[0][2],len(e))
    ids=list(paths)
    positives=[r["id"] for r in manifest if r["label"]=="positive"]
    negatives=[r["id"] for r in manifest if r["label"]=="negative"]
    sequences=([ids] if ids else [])+[[i,i] for i in positives]
    if positives and negatives: sequences.append([negatives[0],positives[0]])
    for seq in sequences:
        together,metrics,e=run([paths[i] for i in seq])
        check(together==[row for i in seq for row in singles[i][0]] and
              e==[ev for i in seq for ev in singles[i][1]] and
              [m[1] for m in metrics]==[len(singles[i][0]) for i in seq],"session dependence")
    continuous=None
    if positives and negatives:
        pieces=[];intervals=[];offset=0
        by_id={r["id"]:r for r in manifest}
        for i in (positives[0],negatives[0],positives[0]):
            with wave.open(str(paths[i]),"rb") as f: pieces.append(f.readframes(f.getnframes()))
            intervals.extend([[a+offset,b+offset] for a,b in by_id[i]["intervals"]])
            offset+=len(pieces[-1])//2
        combined=b"".join(pieces)
        rows,m,ev=run(["-"],"vary",combined)
        trace=analyze(rows,offset,m[0][2],len(ev))
        continuous=dict(samples=offset,events=trace["events"],occurrences=intervals,pcm_sha256=s.sha(combined))
    return results,dict(sequences=sequences,chunks=list(p.CHUNKS),continuous=continuous)


def equivalent(left,right):
    check(left==right,"firmware parity")


def produce():
    identity()
    for n in ("14","15"):
        root=p.ref.work/"ota"/("capsule"+n)/"rootfs"
        for elf in [p.ref.lib,(p.P/"runner").resolve(),(p.P/"replay").resolve()]:
            p.audit(elf,root)
    ids=list(s.RECORDINGS)
    if (s.PRIVATE/"q01.wav").exists(): ids.append("q01")
    manifest=[s.info(i) for i in ids]
    det={};sessions={}
    for n in ("14","15"): det[n],sessions[n]=measure(n,manifest)
    equivalent(det["14"],det["15"]); equivalent(sessions["14"],sessions["15"])
    report=dict(commit=os.environ["GITHUB_SHA"],pins=PINS,rule=RULE,cpu="cortex-a35",abi=["14","15"],
                exits={n:{i:0 for i in ids} for n in det})
    docs=dict(zip(FILES,(report,manifest,det,summary(manifest,det["14"]),sessions)))
    validate(docs,os.environ["GITHUB_SHA"])
    OUT.mkdir(exist_ok=True)
    bodies={n:(json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode() for n,v in docs.items()}
    for name,data in bodies.items(): (OUT/name).write_bytes(data)
    (OUT/"SHA256SUMS").write_bytes(p.sums(bodies))


def validate_trace(row,samples):
    fields={"frames","invokes","events","permitted","peak_raw","peak_sum","features_sha256","outputs_sha256","sums_sha256"}
    check(set(row)==fields,"trace schema")
    for k in ("features_sha256","outputs_sha256","sums_sha256"):
        import re
        check(isinstance(row[k],str) and re.fullmatch("[a-f0-9]{64}",row[k]),"trace digest")
    check(all(type(v) is int for v in [row["frames"],row["invokes"]]) and
          0<=row["invokes"]<=row["frames"]//3<=samples//480,"trace counts")
    check((type(row["peak_raw"]) is int and 0<=row["peak_raw"]<=255) if row["invokes"] else row["peak_raw"] is None,"peak raw")
    check((type(row["peak_sum"]) is int and 0<=row["peak_sum"]<=2550) if row["frames"] else row["peak_sum"] is None,"peak sum")
    segments=[0,*row["events"],samples]
    check(all(type(t) is int and 0<t<=samples and t%160==0 for t in row["events"]),"event time")
    check(all(b-a>=12160 for a,b in zip(segments,segments[1:-1])),"event before grace")
    counts=[max(0,(b-a-480)//160+1) for a,b in zip(segments,segments[1:])]
    check(row["frames"]==sum(counts) and row["invokes"]==sum(f//3 for f in counts),"reset accounting")
    check(row["permitted"]==[a+12160 for a,f in zip(segments,counts) if f>=74],"grace timing")
    check(not row["events"] or row["peak_sum"]>2295,"event below cutoff")


def validate(docs,commit):
    check(set(docs)==set(FILES),"report allowlist")
    report,manifest,det,lat,sessions=(docs[k] for k in FILES)
    ids=[r["id"] for r in manifest]
    check(ids==list(s.RECORDINGS) or ids==[*s.RECORDINGS,"q01"],"sample coverage")
    for r in manifest:s.validate_row(r)
    check(report==dict(commit=commit,pins=PINS,rule=RULE,cpu="cortex-a35",abi=["14","15"],
                       exits={n:{i:0 for i in ids} for n in ("14","15")}),"runtime identity")
    check(set(det)==set(sessions)=={"14","15"} and set(det["14"])==set(ids),"OTA coverage")
    equivalent(det["14"],det["15"]);equivalent(sessions["14"],sessions["15"])
    for r in manifest:
        d=det["14"][r["id"]].copy()
        if r["label"]=="positive" and not d["events"]:
            extra=d.pop("miss_diagnostic")
            check(r["id"] in s.RECORDINGS and set(extra)=={"oracle_features_sha256","reference_scores_sha256",
                  "public_scores","public_sums","preroll_1s"},"miss diagnostic schema")
            scores=extra["public_scores"]; totals=extra["public_sums"]
            check(all(type(v) is int and 0<=v<=255 for v in scores) and len(scores)==d["invokes"] and
                  s.sha(bytes(scores))==extra["reference_scores_sha256"]==d["outputs_sha256"] and
                  extra["oracle_features_sha256"]==d["features_sha256"],"reference identity")
            check(totals==[sum(scores[max(0,(i+1)//3-10):(i+1)//3]) for i in range(d["frames"])] and
                  s.sha(b"".join(struct.pack("<H",v) for v in totals))==d["sums_sha256"],"window replay")
            validate_trace(extra["preroll_1s"],r["samples"]+16000)
        elif r["intervals"] and r["intervals"][0][0]<12160:
            validate_trace(d.pop("preroll_1s"),r["samples"]+16000)
        validate_trace(d,r["samples"])
    check(lat==summary(manifest,det["14"]),"metrics")
    run=sessions["14"]; positives=[r["id"] for r in manifest if r["label"]=="positive"]
    negatives=[r["id"] for r in manifest if r["label"]=="negative"]
    check(set(run)=={"sequences","chunks","continuous"} and run["chunks"]==list(p.CHUNKS) and
          run["sequences"]==[ids,*[[i,i] for i in positives],[negatives[0],positives[0]]],"session coverage")
    c=run["continuous"]; by_id={r["id"]:r for r in manifest}
    a,b=by_id[positives[0]],by_id[negatives[0]];delta=a["samples"]+b["samples"]
    import re
    check(set(c)=={"samples","events","occurrences","pcm_sha256"} and c["samples"]==delta+a["samples"] and
          c["occurrences"]==a["intervals"]+[[x+delta,y+delta] for x,y in a["intervals"]] and
          re.fullmatch("[0-9a-f]{64}",c["pcm_sha256"]) and all(type(t) is int and t%160==0 and
          12160<=t<=c["samples"] for t in c["events"]),"continuous schema")


def verify(data,digest,commit):
    check("sha256:"+s.sha(data)==digest,"ZIP digest")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        check(sorted(z.namelist())==sorted((*FILES,"SHA256SUMS")) and
              all(i.file_size<=131072 for i in z.infolist()),"ZIP allowlist")
        bodies={n:z.read(n) for n in FILES}
        check(z.read("SHA256SUMS")==p.sums(bodies),"manifest checksum")
        validate({n:json.loads(v) for n,v in bodies.items()},commit)


if __name__=="__main__":
    os.umask(0o077)
    if sys.argv[1:]==["prepare"]: s.prepare_public()
    elif sys.argv[1:]==["receive"]: s.receive_question()
    elif sys.argv[1:]==["measure"]: produce()
    elif sys.argv[1:]==["verify"]:
        data,digest=p.ref.b.public.download(os.environ,name=NAME)
        verify(data,digest,os.environ["GITHUB_SHA"]);print("Verified",digest)
    else: raise SystemExit("expected prepare, receive, measure or verify")
