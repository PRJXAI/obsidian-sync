"""Release content binding, stale evidence and substitution negative tests."""
import copy
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("verify_release", ROOT / "scripts/verify-release.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.layers = ["sha256:" + "a" * 64]
        self.config = json.dumps({"rootfs": {"diff_ids": self.layers}, "config": {"User": "65532:65532", "Entrypoint": ["/server"]}}).encode()
        digest = "sha256:" + hashlib.sha256(self.config).hexdigest()
        self.report = {"CreatedAt": self.now.isoformat(), "Metadata": {"ImageID": digest, "DiffIDs": self.layers}, "Results": [{"Vulnerabilities": []}]}
        # OCI index and exported configuration identities legitimately differ.
        self.inspected = {"Id": "sha256:" + "b" * 64, "RootFS": {"Layers": self.layers}}

    def test_config_identity_is_not_confused_with_oci_index_identity(self):
        self.assertEqual(module.verify(self.report, self.inspected, self.config, self.now), self.inspected["Id"])

    def test_substitution_missing_scan_and_stale_evidence_fail_closed(self):
        for kind in ["config", "layers", "finding", "unknown", "empty", "stale", "future", "identity"]:
            with self.subTest(kind=kind):
                report = copy.deepcopy(self.report)
                inspected = copy.deepcopy(self.inspected)
                config = self.config
                if kind == "config":
                    config += b" "
                elif kind == "layers":
                    inspected["RootFS"]["Layers"] = ["sha256:" + "c" * 64]
                elif kind in ("finding", "unknown"):
                    report["Results"][0]["Vulnerabilities"] = [{"Severity": "UNKNOWN" if kind == "unknown" else "LOW"}]
                elif kind == "empty":
                    report["Results"] = []
                elif kind in ("stale", "future"):
                    report["CreatedAt"] = (self.now + datetime.timedelta(days=2 if kind == "future" else -2)).isoformat()
                elif kind == "identity":
                    inspected["Id"] = "mutable:tag"
                with self.assertRaises(ValueError):
                    module.verify(report, inspected, config, self.now)


if __name__ == "__main__":
    unittest.main()
