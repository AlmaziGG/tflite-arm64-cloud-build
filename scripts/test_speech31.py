import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import zipfile

import phase3 as p
import speech31 as run
import speech31_samples as s


def frame(raw,total,hit=0):
    return bytes(120)+struct.pack("<hHB",raw,total,hit)


class TraceTests(unittest.TestCase):
    def test_detection_at_grace_then_new_window(self):
        rows=[frame(255 if k%3==0 else -1,min(k//3,10)*255,k==74) for k in range(1,75)]
        rows+=[frame(-1,0)]
        row=run.analyze(rows,12640,24,1)
        self.assertEqual(row["events"],[12160])
        self.assertEqual(row["permitted"],[12160])
        run.validate_trace(row,12640)

    def test_no_fake_frame_after_restart(self):
        rows=[frame(255 if k%3==0 else -1,min(k//3,10)*255,k==74) for k in range(1,75)]
        with self.assertRaisesRegex(ValueError,"extent"):run.analyze(rows+[frame(-1,0)],12320,24,1)

    def test_threshold_boundary(self):
        for x in (233,234,235):
            scores=[0]*15+[229]*9+[x]
            rows=[]
            for k in range(1,76):
                n=k//3;total=sum(scores[max(0,n-10):n])
                rows.append(frame(scores[n-1] if not k%3 else -1,total,k==75 and x==235))
            hit=int(x==235)
            result=run.analyze(rows,12320,25,hit)
            self.assertEqual(len(result["events"]),hit)

    def test_stride(self):
        with self.assertRaisesRegex(ValueError,"stride"):run.analyze([frame(0,0)],480,0,0)

    def test_incomplete_trace(self):
        with self.assertRaisesRegex(ValueError,"incomplete"):run.analyze([],480,0,0)

    def test_false_stdout(self):
        with self.assertRaisesRegex(ValueError,"incomplete"):run.analyze([frame(-1,0)],480,0,1)

    def test_unexpected_decision(self):
        with self.assertRaisesRegex(ValueError,"decision"):run.analyze([frame(-1,1)],480,0,0)

    def test_matching_one_to_one(self):
        times=[20000,21000,81000]
        self.assertEqual(run.match([[16000,22000],[76000,80000]],times),([-2000,1000],0,1))

    def test_miss_and_unmatched(self):
        self.assertEqual(run.match([[30000,36000]],[100]),([],1,1))

    def test_empty_metrics(self):
        m=run.summary([],{})
        self.assertEqual(m["tp"],0);self.assertIsNone(m["miss_rate"])
        self.assertIsNone(m["false_activations_per_hour"])

    def test_rate_and_latency(self):
        m=run.summary([dict(id="n",label="negative",samples=32000),dict(id="p",label="positive",intervals=[[16000,23000]])],
                      {"n":{"events":[16000]},"p":{"events":[22000]}})
        self.assertEqual(m["false_activations_per_hour"],1800)
        self.assertEqual(m["median_latency_ms"],-62.5);self.assertIsNone(m["p95_latency_ms"])

    def test_missing_recording(self):
        with self.assertRaises(FileNotFoundError):s.read_wav(Path("work/absent-recording.wav"))

    def test_malformed_and_identity(self):
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"input.wav";file.write_bytes(p.wav(bytes(640)))
            self.assertEqual(s.read_wav(file)[2],320)
            data=bytearray(file.read_bytes());data[24:28]=struct.pack("<I",48000);file.write_bytes(data)
            with self.assertRaisesRegex(ValueError,"WAV format"):s.read_wav(file)
            with self.assertRaisesRegex(ValueError,"source checksum"):s.pinned(data,"0"*64)

    def test_cross_ota_difference(self):
        with self.assertRaisesRegex(ValueError,"parity"):run.equivalent([1],[2])

    def test_partial_private_delivery(self):
        with mock.patch.dict("os.environ",{"P31_2":"YQ=="},clear=True):
            with self.assertRaisesRegex(ValueError,"incomplete"):s.receive_question()


class MeasuredTests(unittest.TestCase):
    def setUp(self):
        self.bodies={n:(run.OUT/n).read_bytes() for n in run.FILES}
        self.docs={n:json.loads(v) for n,v in self.bodies.items()}
        self.commit=self.docs[run.FILES[0]]["commit"]

    def check_invalid(self):
        with self.assertRaises((ValueError,KeyError)):run.validate(self.docs,self.commit)

    def test_pins(self):
        self.docs[run.FILES[0]]["pins"]["model"]="0"*64;self.check_invalid()

    def test_cutoff(self):
        self.docs[run.FILES[0]]["rule"]["cutoff"]=.70;self.check_invalid()

    def test_label(self):
        self.docs[run.FILES[1]][0]["label"]="negative";self.check_invalid()

    def test_annotations(self):
        self.docs[run.FILES[1]][0]["intervals"]=[[0,1]];self.check_invalid()

    def test_private_transcript(self):
        self.docs[run.FILES[1]][0]["transcript"]="private";self.check_invalid()

    def test_duration(self):
        self.docs[run.FILES[1]][0]["samples"]=0;self.check_invalid()

    def test_missing_session(self):
        for row in self.docs[run.FILES[4]].values():row["sequences"].pop()
        self.check_invalid()

    def test_missing_chunk(self):
        for row in self.docs[run.FILES[4]].values():row["chunks"].pop()
        self.check_invalid()

    def test_unlisted_trace(self):
        self.docs["raw.trace"]=[];self.check_invalid()

    def test_reject_scores_for_negative_or_private_sample(self):
        for ota in self.docs[run.FILES[2]].values():
            for name,row in ota.items():
                if name.startswith(("n","q")): row["public_scores"]=[0]
        self.check_invalid()

    def test_real_manifest_verifier(self):
        for kind in ("good","checksum","member","digest"):
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,"w") as z:
                for n,v in self.bodies.items():z.writestr(n,v)
                z.writestr("SHA256SUMS",b"" if kind=="checksum" else p.sums(self.bodies))
                if kind=="member":z.writestr("private.wav",b"")
            data=buf.getvalue();digest="sha256:"+s.sha(data)
            if kind=="good":run.verify(data,digest,self.commit)
            else:
                with self.assertRaises(ValueError):run.verify(data,"bad" if kind=="digest" else digest,self.commit)


if __name__=="__main__":unittest.main(defaultTest="TraceTests")
