import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "eve_analyzer.py"
spec = importlib.util.spec_from_file_location("eve_analyzer", MODULE_PATH)
eve_analyzer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = eve_analyzer
spec.loader.exec_module(eve_analyzer)


class TestEveAnalyzer(unittest.TestCase):
    def test_alert_extraction(self):
        event = {
            "timestamp": "2026-10-11T12:00:00+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.10",
            "src_port": 50000,
            "dest_ip": "10.0.0.20",
            "dest_port": 4444,
            "proto": "TCP",
            "alert": {"signature_id":1000002,"signature":"CODEALPHA LAB TCP SYN to Training Port 4444","severity":2,"category":"Attempted Information Leak","action":"allowed"}
        }
        record = eve_analyzer.extract_alert(event)
        self.assertIsNotNone(record)
        self.assertEqual(record.signature_id, 1000002)
        self.assertEqual(record.proto, "TCP")
        self.assertEqual(record.dest_port, 4444)

    def test_non_alert_is_ignored(self):
        self.assertIsNone(eve_analyzer.extract_alert({"event_type":"dns","proto":"UDP"}))

    def test_load_sample_alerts(self):
        records = eve_analyzer.load_alerts(ROOT / "sample_data" / "eve_sample.json")
        self.assertEqual(len(records), 5)

    def test_severity_labels(self):
        self.assertEqual(eve_analyzer.severity_label(1), "High")
        self.assertEqual(eve_analyzer.severity_label(2), "Medium")
        self.assertEqual(eve_analyzer.severity_label(3), "Low")


if __name__ == "__main__":
    unittest.main()
