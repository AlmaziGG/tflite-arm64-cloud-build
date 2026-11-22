import unittest
from phase2c import caps, isa


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


if __name__ == "__main__":
    unittest.main()
