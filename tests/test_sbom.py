"""Offline SBOM source-boundary and immutable image material tests."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("generate_sbom", ROOT / "scripts/generate-sbom.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SbomTests(unittest.TestCase):
    def test_only_explicit_public_dependency_inputs_are_staged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            destination = Path(directory) / "source"
            root.mkdir()
            destination.mkdir()
            for name in module.SOURCE_FILES:
                source = root / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("public manifest")
            (root / ".env").write_text("private fixture, must not be staged")
            materials = module.stage_source(root, destination)
            self.assertEqual({x["path"] for x in materials}, set(module.SOURCE_FILES))
            self.assertFalse((destination / ".env").exists())
            self.assertEqual({str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file()}, set(module.SOURCE_FILES))
            (root / "Cargo.lock").unlink()
            (root / "Cargo.lock").symlink_to(root / ".env")
            with self.assertRaises(ValueError):
                module.stage_source(root, destination)

    def test_export_resolves_mutable_tag_once_and_binds_config_layers(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image.tar"
            image_id = "sha256:" + "a" * 64
            layers = ["sha256:" + "b" * 64]
            config = json.dumps({"rootfs": {"diff_ids": layers}}).encode()
            inspected = {"Id": image_id, "RootFS": {"Layers": layers}, "Os": "linux", "Architecture": "arm64"}
            def save(command, **kwargs):
                self.assertIn(image_id, command)
                self.assertNotIn("mutable:tag", command)
                with tarfile.open(destination, "w") as archive:
                    for name, data in [("manifest.json", json.dumps([{"Config": "config.json"}]).encode()), ("config.json", config)]:
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.object(module, "inspect_image", return_value=inspected), mock.patch.object(module.subprocess, "run", side_effect=save):
                material = module.export_image("mutable:tag", destination)
            self.assertEqual(material["config_digest"], "sha256:" + hashlib.sha256(config).hexdigest())
            self.assertEqual(material["layers"], layers)
            self.assertEqual(material["archive_digest"], module.digest(destination))

    def test_source_completeness_includes_locked_development_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests/compat").mkdir(parents=True)
            (root / "Cargo.lock").write_text('[[package]]\nname = "fixture"\nversion = "1.0.0"\nsource = "registry+fixture"\n')
            (root / "tests/compat/package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/@example/dev": {"version": "2.0.0", "dev": True}}}))
            cargo = {"purl": "pkg:cargo/fixture@1.0.0"}
            npm = {"purl": "pkg:npm/%40example/dev@2.0.0"}
            with self.assertRaises(ValueError):
                module.validate_source_inventory(root, [cargo])
            module.validate_source_inventory(root, [cargo, npm])

    def test_empty_sboms_fail_and_containers_are_always_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            calls = []
            def execute(command, **kwargs):
                calls.append(command)
                if command[1] == "run":
                    self.assertIn("none", command)
                    self.assertNotIn("/var/run/docker.sock", command)
                    (output / "source.cdx.json").write_text('{"components": []}')
                    (output / "source.spdx.json").write_text('{"packages": []}')
                return subprocess.CompletedProcess(command, 0)
            with mock.patch.object(module.subprocess, "run", side_effect=execute):
                with self.assertRaises(ValueError):
                    module.scan("dir:/source", [], output, "source")
            self.assertEqual(calls[1][:3], ["docker", "rm", "--force"])


if __name__ == "__main__":
    unittest.main()
