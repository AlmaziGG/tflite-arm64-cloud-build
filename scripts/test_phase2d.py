import unittest
import copy
import json
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

    @unittest.skipUnless(d.P.exists(),"needs completed runner measurements")
    def test_corrupted_runtime_evidence(self):
        original=json.loads(d.P.read_bytes())
        d.validate(original)
        changes=[(("abi",),[0,1,0]),(("stress","completed"),9999),(("stress","failed"),1),
                 (("stress","exit"),-4),(("stress","restarts"),1),(("stress","first_failure"),99),
                 (("stress","caps"),["0","0"]),(("stress","output_sha256"),"0"*64),
                 (("stress","latency","invoke","max"),-1),(("stress","points"),[]),
                 (("state","sequences","recreate"),["ff"]),(("state","sequences","reset"),[]),
                 (("fullcycle","points"),[]),(("lifecycle","reaped"),False)]
        for path,value in changes:
            with self.subTest(path=path):
                doc=copy.deepcopy(original); node=doc["firmware"]["14"]
                for k in path[:-1]: node=node[k]
                node[path[-1]]=value
                with self.assertRaises((ValueError,IndexError)): d.validate(doc)

    def test_reference_window_initialization(self):
        self.assertEqual(d.window_count([255]*9),0)
        self.assertEqual(d.window_count([255]*10),1)


if __name__=="__main__":
    unittest.main()
