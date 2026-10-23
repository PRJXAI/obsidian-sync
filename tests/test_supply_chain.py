"""Offline negative tests for the supply-chain inventory and scan failure policy."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("supply_chain", ROOT / "scripts/scan-supply-chain.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PIN = "alpine:3.23.7@sha256:" + "a" * 64


class SupplyChainTests(unittest.TestCase):
    def tree(self, root, dockerfile):
        (root / "scripts").mkdir()
        (root / "Dockerfile").write_text(dockerfile)

    def test_inventory_requires_frontend_and_external_base_pins(self):
        for dockerfile in ["FROM alpine:latest\n", "# syntax=docker/dockerfile:1.7\nFROM " + PIN]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.tree(root, dockerfile)
                with self.assertRaises(ValueError):
                    module.inventory(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.tree(root, f"FROM {PIN} AS build\nFROM build AS tests\n")
            self.assertEqual(module.inventory(root), {PIN: ["Dockerfile"]})

    def test_unpinned_compose_image_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.tree(root, f"FROM {PIN}\n")
            compose = root / "docker-compose.test.yml"
            compose.write_text('services:\n  test:\n    image: "alpine:latest"\n')
            with self.assertRaises(ValueError):
                module.inventory(root)
            compose.write_text(f"services:\n  test:\n    image: {PIN}\n")
            self.assertIn("docker-compose.test.yml", module.inventory(root)[PIN])

    def test_repository_images_and_scanner_are_in_inventory(self):
        images = module.inventory(ROOT)
        self.assertIn(module.SCANNER, images)
        self.assertTrue(any(image.startswith("rust:") for image in images))
        self.assertTrue(any(image.startswith("kindest/node:") for image in images))
        self.assertTrue(any(image.startswith("docker/dockerfile:") for image in images))

    def test_findings_and_scanner_errors_fail_without_socket_mount(self):
        for status in [0, 1, 2]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.tree(root, f"FROM {PIN}\n")
                output = root / "reports"
                def fake_run(command, **kwargs):
                    if command[:3] == ["docker", "rm", "--force"]:
                        return subprocess.CompletedProcess(command, 0)
                    self.assertFalse(any("docker.sock" in str(arg) for arg in command))
                    self.assertNotIn("--ignore-unfixed", command)
                    self.assertIn("--cap-drop", command)
                    if "--download-db-only" in command:
                        return subprocess.CompletedProcess(command, 0)
                    self.assertIn("--exit-code", command)
                    (output / "image-00.json").write_text(json.dumps({"Results": []}))
                    return subprocess.CompletedProcess(command, status)
                with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
                    self.assertEqual(module.run_scan(root, output, "linux/arm64"), int(status != 0))
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["images"][0]["exit_code"], status)

    def test_timeout_always_removes_its_own_container(self):
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, 1)
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(subprocess.TimeoutExpired):
                module.scanner_run(["docker", "run", "--rm", "scanner"], ["image"], None, 1)
        name = calls[0][calls[0].index("--name") + 1]
        self.assertEqual(calls[1], ["docker", "rm", "--force", name])


if __name__ == "__main__":
    unittest.main()
