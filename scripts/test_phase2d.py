import unittest
import phase2d as d


class Tests(unittest.TestCase):
    def test_stats(self):
        self.assertEqual(d.stats(list(range(1,101)))["p95"],95)
        with self.assertRaises(ValueError): d.stats([])
    def test_growth(self):
        rows=[dict(stage="steady",index=i,VmRSS=100+i) for i in range(10)]
        self.assertEqual(d.trend(rows,"steady")["slope_kib_per_step"],1)
        with self.assertRaises(ValueError): d.trend([], "steady")
    def test_window(self):
        self.assertFalse(d.detected([255]*9+[0]))
        self.assertTrue(d.detected([255]*9+[1]))
        with self.assertRaises(ValueError): d.detected([255])
    def test_queue(self):
        self.assertEqual(d.simulate([100]*10)["dropped_batches"],0)
        self.assertGreater(d.simulate([90000000]*10)["dropped_batches"],0)
    def test_model_identity(self):
        with self.assertRaises(ValueError): d.graph(b"wrong")
    def test_missing_firmware(self):
        with self.assertRaises(ValueError): d.validate(dict(model_sha=d.MODEL,elf=d.ref.pins,firmware={}))


if __name__=="__main__":
    unittest.main()
