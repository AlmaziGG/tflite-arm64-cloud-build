import io
import json
import struct
import subprocess
import sys
import unittest
import zipfile

import phase3 as p


class HostTests(unittest.TestCase):
    def test_uint16_entire_domain(self):
        result=p.command([p.P/"host","--quant-table"]).stdout
        self.assertEqual(result,bytes(min(127,round_fraction(x)-128)&255 for x in range(65536)))

    def test_decision_boundaries_and_reset(self):
        for value in (254,255,256):
            scores=bytes([0]*64+[229]*9+[value-23])
            # 9*229 + [231..233], around the integer threshold; also exercise exact equality below.
            self.check_decisions(scores)
        for last in (233,234,235):
            data=bytes([0]*64+[229]*9+[last])
            sums=self.check_decisions(data)
            self.assertEqual(sums[-1],(2061+last,int(last>234)))
        repeated=self.check_decisions(bytes([255]*150))
        self.assertEqual([i+1 for i,x in enumerate(repeated) if x[1]],[74,148])

    def check_decisions(self,data):
        response=p.command([p.P/"host","--decision-trace"],data)
        got=[tuple(map(int,line.split())) for line in response.stdout.splitlines()]
        start=0
        for k,(s,hit) in enumerate(got):
            want=sum(data[max(start,k-9):k+1])
            self.assertEqual((s,hit),(want,int(k-start+1>=74 and want>2295)))
            if hit: start=k+1
        return got

    def test_bad_wav(self):
        valid=p.wav(bytes(1200))
        bad=[b"",valid[:-1],valid+b"x",b"RIFX"+valid[4:],p.wav(b""),valid[:36]+b"xxxx"+valid[40:]]
        for off,fmt,val in ((20,"H",3),(22,"H",2),(24,"I",44100),(28,"I",123),(32,"H",1),(34,"H",8),(40,"I",2**31)):
            buf=bytearray(valid);struct.pack_into("<"+fmt,buf,off,val);bad.append(bytes(buf))
        path=p.P/"invalid.wav"
        for blob in bad:
            path.write_bytes(blob)
            with self.assertRaises(subprocess.CalledProcessError):
                p.candidate(p.P/"host",[path],160)
        with self.assertRaises(subprocess.CalledProcessError):
            p.candidate(p.P/"host",[p.P/"missing.wav"],160)

    def test_odd_pcm_and_empty(self):
        for pcm in (b"",bytes(321)):
            with self.assertRaises(subprocess.CalledProcessError):
                p.candidate(p.P/"host",["-"],1,pcm)

    def test_first_frame_and_tail(self):
        for n in (1,159,160,479,480,481,639,640,799,800):
            rows,metrics,_=p.candidate(p.P/"host",["-"],33,bytes(n*2))
            self.assertEqual(len(rows),max(0,(n-480)//160+1))
            self.assertEqual(metrics[0][0],n)

    def test_first_mismatch(self):
        with self.assertRaisesRegex(ValueError,"count=1"):
            p.compare_rows([bytes(120)],[bytes(119)+b"\xff"],"sample")

    def test_guest_exit_and_timeout(self):
        with self.assertRaises(subprocess.CalledProcessError):
            p.command([sys.executable,"-c","raise SystemExit(7)"])
        with self.assertRaises(subprocess.TimeoutExpired):
            p.command([sys.executable,"-c","import time; time.sleep(3)"],timeout=.1)

    def test_extra_artifact(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,"w") as z:z.writestr("model.tflite",bytes(10))
        with self.assertRaisesRegex(ValueError,"allowlist"):
            p.verify_zip(b.getvalue(),"sha256:"+p.sha(b.getvalue()),"test")

    def test_wrong_zip_digest(self):
        with self.assertRaisesRegex(ValueError,"checksum"):
            p.verify_zip(b"abc","sha256:invalid","test")


def round_fraction(x):
    whole, remainder=divmod(x*256,666)
    return whole+int(2*remainder>=666)


if __name__=="__main__":
    unittest.main()
