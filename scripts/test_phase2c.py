import unittest
import json
from phase2c import caps, isa, check_report, pins, runtime_pass


class ProfileTests(unittest.TestCase):
    def test_feature_mask(self):
        self.assertEqual(caps("caps=3,0"), ("3","0"))
        for a,b in ((1,0),(3|512,0),(3|1024,0),(3|1<<20,0),(3,1<<13)):
            with self.assertRaises(ValueError):
                caps(f"caps={a:x},{b:x}")

    def test_typed_arithmetic(self):
        self.assertEqual(isa("fmla","v0.8h, v1.8h, v2.h[0]"), "fp16")
        self.assertEqual(isa("fmla","v0.4s, v1.4s, v2.s[0]"), "unclassified")
        self.assertEqual(isa("fcvtl","v0.4s, v1.4h"), "unclassified")

    def test_integer_extensions(self):
        self.assertEqual(isa("sdot","v0.4s"), "dotprod")
        self.assertEqual(isa("smmla","v0.4s"), "i8mm")

    def test_missing_caps_fail_closed(self):
        for raw in ("","caps=garbage","caps=0,0"):
            with self.assertRaises(ValueError):
                caps(raw)

    def test_fail_closed_on_sigill_timeout_incomplete_patterns_or_extension(self):
        row=dict(abi=[0,0,0],smoke_exit=0,probe_exit=0,translated_library_pcs=42,translated_special={},
                 patterns=[(str(i),str(k),"100") for i in range(2) for k in range(6)])
        self.assertTrue(runtime_pass(row))
        for change in ({"abi":[0,1,0]},{"smoke_exit":-4},{"probe_exit":132},{"failure":"TimeoutExpired"},
                       {"patterns":row["patterns"][:-1]},{"translated_special":{"i8mm":1}},{"translated_library_pcs":0}):
            self.assertFalse(runtime_pass(dict(row,**change)))

    def test_only_sanitized_reference_evidence_is_publishable(self):
        doc={"binaries":pins,"firmware":{"14":{},"15":{}}}
        check_report(json.dumps(doc).encode())
        for mutated in (dict(doc,binaries={}), dict(doc,private={"argv":[]}),
                        dict(doc,version="Bearer secret"),dict(doc,firmware={"14":{}}),
                        dict(doc,firmware={"14":{"trace":"anything"},"15":{}})):
            with self.assertRaises(ValueError):
                check_report(json.dumps(mutated).encode())


if __name__ == "__main__":
    unittest.main()
