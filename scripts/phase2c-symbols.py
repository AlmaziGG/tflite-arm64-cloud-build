"""Recover address ranges only from a replay with identical executable bytes."""
import bisect
import collections
import json
import re
import subprocess
from pathlib import Path

from phase2c import b, lib, work

lab = work / "isa-symbols"
root = Path((lab/"execroot").read_text().strip())
collector = b.load("collect-bazel-toolchain.py")
graph, errors, _ = collector.parse_action_graph((lab/"actions.json").read_text())
assert not errors
links, _ = collector.select_actions(graph,"library")
link, = links
args, _ = collector.redirect_link_output(link["argv"],lab/"symbols.so")
assert args and not link["argv_unresolved"]
args = [x for x in args if x not in ("-s","-Wl,-s","-Wl,--strip-all")]
subprocess.run([*args,"-Wl,-Map,"+str(lab/"sections.map")],cwd=root,env=link["environment"],check=True)
tools = b.SDK / "bin"
for file, tag in ((lib,"ref"),(lab/"symbols.so","sym")):
    subprocess.run([tools/"aarch64-none-linux-gnu-objcopy","--dump-section",f".text={lab}/{tag}.text",file,lab/(tag+".copy")],check=True)
assert b.abi.digest(lab/"ref.text")==b.abi.digest(lab/"sym.text")
def addr(file):
    return re.search(r"(?m)\s\.text\s+PROGBITS\s+([0-9a-f]+)",b.p2.output(["readelf","-SW",file]))[1]
assert addr(lib)==addr(lab/"symbols.so")
names=[]
for line in b.p2.output([tools/"aarch64-none-linux-gnu-nm","-nS",lab/"symbols.so"]).splitlines():
    m=re.fullmatch(r"([0-9a-f]+) ([0-9a-f]+) [tTwW] (\S+)",line)
    if m: names.append([int(m[1],16),int(m[2],16),m[3]])
assert len(names)>300
objects=collections.defaultdict(set)
for a in collector.executed_compiles(graph["CppCompile"],lab/"work/private-diagnostics/build-library.jsonl"):
    v=a["argv"]
    if a["configuration_id"]==link["configuration_id"]:
        obj=Path(v[v.index("-o")+1]).name
        objects[obj].add((v[v.index("-c")+1],tuple(x for x in v if x.startswith(("-march=","-mcpu=")))))
ranges=[]
for m in re.finditer(r"(?m)^ +(?:\.text\S*\s+)?(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+\.o\)?)(?:\s*)$", (lab/"sections.map").read_text()):
    base,size=int(m[1],16),int(m[2],16)
    if size:
        obj=Path(m[3].split("(")[-1].rstrip(")")).name
        if obj in objects: ranges.append((base,size,obj))
ranges.sort()
starts=[r[0] for r in ranges]
for entry in names:
    i=bisect.bisect_right(starts,entry[0])-1
    if i>=0 and entry[0]<starts[i]+ranges[i][1]:
        obj=ranges[i][2]
        if len(objects[obj])==1:
            src,flags=next(iter(objects[obj]))
            entry.extend([obj,flags])
(lab/"functions.json").write_text(json.dumps(sorted(names)))
report=Path("public/isa.json")
doc=json.loads(report.read_text())
names.sort()
starts=[entry[0] for entry in names]
def lookup(pc):
    i=bisect.bisect_right(starts,pc)-1
    return names[i] if i>=0 and pc<names[i][0]+names[i][1] else None
owners={}
for address, item in doc["inventory"].items():
    sym=lookup(int(address))
    item[1]=str(sym[0]) if sym else "unknown"
    if sym: owners[str(sym[0])]=sym[2:]
for n,row in doc["firmware"].items():
    executed={entry[2] for pc in json.loads((work/("pcs"+n)).read_text()) if (entry:=lookup(pc))}
    row["translated_symbols"]=sorted(executed)
    row["executed_symbols"]=sorted({entry[2] for pc in json.loads((work/("blocks"+n)).read_text()) if (entry:=lookup(pc))})
doc["function_table"]=owners
report.write_text(json.dumps(doc,sort_keys=True)+"\n")
