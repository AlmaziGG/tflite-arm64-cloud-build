"""Frozen labels registered independently of wake-word output. All times in PCM samples."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import wave
import zipfile

from phase2d import check

PRIVATE = Path("work/phase31-private")
QUESTION_SHA = "bfb7b8160b0a1b0b2b9d9ebbc1719728f809855f0782f01ca8fc549b25937b73"
DECODER_SHA = "c7e46fcec401dd990405049d2e2f475e2b397779df2519b544b8aab515195282"
DECODER_URL = ("https://files.pythonhosted.org/packages/a0/2d/43c8522a2038e9d0e7dbdf3a61195ecc31ca576fb1527a528c877e87d973/"
               "imageio_ffmpeg-0.6.0-py3-none-manylinux2014_x86_64.whl")
# Sentence ID, audio ID, recording SHA256, credited audio author, pre-registered word interval (ms).
RECORDINGS = {
    "p01": (7545158,678543,"24bc682fbd7e60290c720b4495fd4ce81af25a8b19055f4a660f5f1c086f19d3","fjay69",(1710,2070)),
    "p02": (7467258,668801,"81722ffd7fc5590c4568f7c228e1a3228c61506fa4c77bfb1734ce816e7bd029","fjay69",(910,1260)),
    "n01": (7746778,668836,"6065ce7146d32ab64ec9c3935ba352992f0e5038cbaf10f1277bb3d8be8cf2f5","fjay69",None),
    "n02": (9528403,1270168,"3a025cb53c929259712778ffb4ee2c9fc962c27665f362b538663f0ec471d539","EugeneGS",None),
    "n03": (6933347,651126,"3d0ab0039e57a0d5def3ae438a183e5a3adf987e5dfc77f0cdda7d0eaa778604","fjay69",None),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url):
    import time
    for i in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"Phase31 public-audio validation"}),timeout=30) as stream:
                return stream.read()
        except OSError:
            if i==2: raise
            time.sleep(2**i)


def pinned(data, digest):
    check(sha(data)==digest,"source checksum mismatch")
    return data


def read_wav(path):
    data=path.read_bytes()
    check(len(data)>=44 and data[:4]==b"RIFF" and data[8:12]==b"WAVE" and
          int.from_bytes(data[4:8],"little")==len(data)-8,"RIFF length")
    with wave.open(io.BytesIO(data),"rb") as f:
        check((f.getframerate(),f.getnchannels(),f.getsampwidth(),f.getcomptype())==(16000,1,2,"NONE"),"WAV format")
        n=f.getnframes(); pcm=f.readframes(n)
        check(n>0 and len(pcm)==2*n,"truncated audio")
    return sha(data),sha(pcm),n


def prepare_public():
    PRIVATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    decoder=PRIVATE/"ffmpeg"
    with zipfile.ZipFile(io.BytesIO(pinned(fetch(DECODER_URL),DECODER_SHA))) as z:
        members=[n for n in z.namelist() if re.fullmatch(r"imageio_ffmpeg/binaries/ffmpeg-linux-x86_64-v[\w.]+",n)]
        check(len(members)==1,"decoder member"); decoder.write_bytes(z.read(members[0]))
    decoder.chmod(0o700)
    for name,(sentence,audio,h,author,bounds) in RECORDINGS.items():
        row=json.loads(fetch(f"https://tatoeba.org/en/api_v0/sentence/{sentence}"))
        meta=next(a for a in row["audios"] if a["id"]==audio)
        check(meta["source"]=="tatoeba" and meta["author"]==author and meta["license"]=="CC BY 4.0","audio permission")
        check(row["lang"]=="rus" and len(re.findall(r"\bалиса\b",row["text"].casefold()))==int(bounds is not None),"source label")
        check(meta["download_url"]==f"/en/audio/download/{audio}","media identity")
        mp3=PRIVATE/(name+".mp3"); mp3.write_bytes(pinned(fetch("https://tatoeba.org"+meta["download_url"]),h))
        subprocess.run([decoder,"-nostdin","-y","-v","error","-i",mp3,"-map","0:a:0","-ac","1","-ar","16000",
                        "-c:a","pcm_s16le","-map_metadata","-1","-fflags","+bitexact","-flags:a","+bitexact",
                        PRIVATE/(name+".wav")],check=True,capture_output=True,timeout=30)


def receive_question():
    # Seven independently encrypted, branch-scoped environment secrets. No payload in argv or logs.
    pieces=[os.environ.get(f"P31_{i}","").strip() for i in range(7)]
    if not any(pieces):
        return
    check(all(pieces),"incomplete private delivery")
    data=b"".join(base64.b64decode(s,validate=True) for s in pieces)
    (PRIVATE/"q01.wav").write_bytes(pinned(data,QUESTION_SHA))


def info(name):
    wav_sha,pcm_sha,n=read_wav(PRIVATE/(name+".wav"))
    if name=="q01":
        check(wav_sha==QUESTION_SHA,"owner recording mismatch")
        source="owner-approved"; source_sha=wav_sha; bounds=None
    else:
        _,_,source_sha,_,bounds=RECORDINGS[name]
        source="tatoeba-cc-by-4.0"
    annotations=[] if bounds is None else [[v*16 for v in bounds]]
    row=dict(id=name,source=source,source_sha256=source_sha,wav_sha256=wav_sha,pcm_sha256=pcm_sha,
             samples=n,label="positive" if bounds else "negative",intervals=annotations)
    validate_row(row)
    return row


def validate_row(row):
    check(set(row)=={"id","source","source_sha256","wav_sha256","pcm_sha256","samples","label","intervals"},"manifest schema")
    name=row["id"]; check(name in {*RECORDINGS,"q01"},"unknown sample")
    source_sha=QUESTION_SHA if name=="q01" else RECORDINGS[name][2]
    check(row["source"]==("owner-approved" if name=="q01" else "tatoeba-cc-by-4.0") and row["source_sha256"]==source_sha,"source permission/identity")
    check(all(isinstance(row[k],str) and re.fullmatch("[a-f0-9]{64}",row[k]) for k in ("source_sha256","wav_sha256","pcm_sha256")),"digest")
    check(type(row["samples"]) is int and 0<row["samples"]<=16000*300,"duration")
    bounds=None if name=="q01" else RECORDINGS[name][4]
    check(row["intervals"]==([] if bounds is None else [[v*16 for v in bounds]]) and
          row["label"]==("positive" if bounds else "negative"),"label/annotations")
    check(all(0<=a<b<=row["samples"] for a,b in row["intervals"]),"annotation extent")
    if name=="q01": check(row["wav_sha256"]==QUESTION_SHA,"unexpected conversion")
