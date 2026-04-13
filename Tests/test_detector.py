"""
Tests for Hardware Trojan Detector
Run: python -m pytest tests/ -v
 or: python tests/test_detector.py
"""
import sys, json, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from trojan_detector import VerilogParser, TrojanDetector

NETLISTS = Path(__file__).parent.parent / "netlists"


class TestParser(unittest.TestCase):
    def test_module_name(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        self.assertEqual(p.module_name, "aes_sbox_trojan")

    def test_gates_nonzero(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        self.assertGreater(len(p.gates), 0)

    def test_inputs_outputs(self):
        p = VerilogParser(str(NETLISTS / "clean_circuit.v")).parse()
        self.assertGreater(len(p.inputs), 0)
        self.assertGreater(len(p.outputs), 0)


class TestDetector(unittest.TestCase):
    def test_trojan_circuit_flagged(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        self.assertIn(r.verdict, ("TROJAN_DETECTED", "SUSPICIOUS"))

    def test_anomaly_score_range(self):
        for fname in ["trojan_infected.v", "clean_circuit.v"]:
            p = VerilogParser(str(NETLISTS / fname)).parse()
            r = TrojanDetector(p).analyze()
            self.assertGreaterEqual(r.anomaly_score, 0.0)
            self.assertLessEqual(r.anomaly_score, 1.0)

    def test_suspicious_gates_populated(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        self.assertGreater(len(r.suspicious_gates), 0)

    def test_latch_no_reset_flagged(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        seq_flags = [s for s in r.suspicious_gates
                     if "seq_no_reset" in s.get("flags", [])]
        self.assertGreater(len(seq_flags), 0)

    def test_custom_params(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p, {"fanout_threshold": 5, "score_threshold": 0.3}).analyze()
        self.assertEqual(r.details["params_used"]["fanout_threshold"], 5)

    def test_json_serializable(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        s = json.dumps(r.to_dict())
        self.assertGreater(len(s), 100)

    def test_required_fields(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        for f in ("total_gates", "suspicious_gates", "verdict",
                  "anomaly_score", "triggering_signals", "non_triggering_signals"):
            self.assertTrue(hasattr(r, f))

    def test_module_name_in_details(self):
        p = VerilogParser(str(NETLISTS / "trojan_infected.v")).parse()
        r = TrojanDetector(p).analyze()
        self.assertEqual(r.details["module"], "aes_sbox_trojan")


if __name__ == "__main__":
    unittest.main(verbosity=2)
