#!/usr/bin/env python3
"""Create source/runtime/builder CycloneDX + SPDX SBOMs and bound materials.

Uses an offline, digest-pinned Syft container without a Docker socket. Only
public dependency manifests, never configuration/secrets/data, are copied into
the source scanner mount. This is inventory/provenance evidence, not signing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from urllib.parse import unquote
import uuid

ROOT = Path(__file__).resolve().parents[1]
SYFT = "anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9"
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE", "tests/compat/package.json", "tests/compat/package-lock.json")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(65536), b""):
            result.update(block)
    return "sha256:" + result.hexdigest()


def stage_source(root, destination):
    materials = []
    for relative in SOURCE_FILES:
        source = root / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError("Missing or symlinked dependency input")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        materials.append({"path": relative, "digest": digest(target)})
    return materials


def inspect_image(image):
    return json.loads(subprocess.check_output(["docker", "image", "inspect", image], stderr=subprocess.DEVNULL, timeout=30))[0]


def export_image(image, destination):
    inspected = inspect_image(image)
    subprocess.run(["docker", "save", inspected["Id"], "--output", str(destination)], check=True, timeout=180)
    with tarfile.open(destination) as archive:
        manifests = json.load(archive.extractfile("manifest.json"))
        if len(manifests) != 1:
            raise ValueError("Expected exactly one saved image")
        member = archive.getmember(manifests[0]["Config"])
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError("Invalid image configuration")
        config = archive.extractfile(member).read()
        layers = json.loads(config)["rootfs"]["diff_ids"]
        if layers != inspected["RootFS"]["Layers"]:
            raise ValueError("Saved/inspected image layer mismatch")
    return {"image_id": inspected["Id"], "config_digest": "sha256:" + hashlib.sha256(config).hexdigest(), "layers": layers, "os": inspected["Os"], "architecture": inspected["Architecture"], "archive_digest": digest(destination)}


def scan(target, mounts, output, name):
    container = "sync-sbom-" + uuid.uuid4().hex
    command = ["docker", "run", "--rm", "--name", container, "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "3g", "--cpus", "2", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1536m,mode=1777", "-e", "XDG_CACHE_HOME=/tmp/cache", "-e", "HOME=/tmp", "-e", "SYFT_PARALLELISM=4", "-e", "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true", "-e", "SYFT_CHECK_FOR_APP_UPDATE=false", "-v", f"{output}:/reports", *mounts, SYFT, target, "-o", f"cyclonedx-json=/reports/{name}.cdx.json", "-o", f"spdx-json=/reports/{name}.spdx.json"]
    try:
        subprocess.run(command, check=True, timeout=600)
    finally:
        subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
    # Fail on vacuous output or a missing required format instead of uploading an empty SBOM.
    for suffix, key in [("cdx.json", "components"), ("spdx.json", "packages")]:
        if not json.loads((output / f"{name}.{suffix}").read_text()).get(key):
            raise ValueError("Empty SBOM")


def validate_source_inventory(root, components):
    def entries(ecosystem):
        prefix = f"pkg:{ecosystem}/"
        result = set()
        for component in components:
            purl = component.get("purl", "")
            if purl.startswith(prefix) and "@" in purl[len(prefix):]:
                name, version = purl[len(prefix):].rsplit("@", 1)
                result.add((unquote(name), unquote(version.split("?", 1)[0])))
        return result
    cargo = tomllib.loads((root / "Cargo.lock").read_text())
    required_cargo = {(item["name"], item["version"]) for item in cargo["package"] if item.get("source")}
    npm = json.loads((root / "tests/compat/package-lock.json").read_text())
    required_npm = {(item.get("name") or path.rsplit("node_modules/", 1)[-1], item["version"]) for path, item in npm["packages"].items() if path and not item.get("link")}
    if not required_cargo <= entries("cargo") or not required_npm <= entries("npm"):
        raise ValueError("Source SBOM omitted locked Rust or npm dependencies, including test dependencies")


def generate(runtime, builder):
    output = ROOT / ".work/sbom"
    output.mkdir(parents=True, exist_ok=True)
    (output / "materials.json").unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="sbom-", dir=ROOT / ".work") as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        dependencies = stage_source(ROOT, source)
        images = {}
        for name, image in [("runtime", runtime), ("builder", builder)]:
            archive = work / f"{name}.tar"
            images[name] = export_image(image, archive)
            scan(f"docker-archive:/images/{name}.tar", ["-v", f"{archive}:/images/{name}.tar:ro"], output, name)
        scan("dir:/source", ["-v", f"{source}:/source:ro"], output, "source")
        validate_source_inventory(ROOT, json.loads((output / "source.cdx.json").read_text())["components"])
    native = subprocess.check_output(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "/bin/sh", images["builder"]["image_id"], "-c", 'set -eu; rustc --version; p=$(rustc --print target-libdir); sha256sum "$p/self-contained/libc.a"; ar p "$p/self-contained/libc.a" version.lo | strings'], stderr=subprocess.DEVNULL, timeout=30)
    (output / "native-toolchain.txt").write_bytes(native)
    sboms = [{"path": name, "digest": digest(output / name)} for name in ("runtime.cdx.json", "runtime.spdx.json", "builder.cdx.json", "builder.spdx.json", "source.cdx.json", "source.spdx.json", "native-toolchain.txt")]
    # Include a tree fingerprint so a local dirty audit is not mislabeled as a clean commit build.
    tracked = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).split(b"\0")
    sources = []
    for raw in sorted(set(tracked)):
        if raw:
            path = ROOT / os.fsdecode(raw)
            if path.is_symlink() or not path.is_file():
                raise ValueError("Source inventory contains an absent/symlinked file")
            sources.append({"path": os.fsdecode(raw), "digest": digest(path)})
    materials = {"schema_version": 1, "generator_image": SYFT, "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "source_tree_digest": "sha256:" + hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(), "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT)), "dependency_inputs": dependencies, "images": images, "artifacts": sboms, "limitations": ["Unsigned inventory; trust the CI artifact channel, not arbitrary JSON", "Rust toolchain musl and vendored native code require patch-aware review beyond runtime package detection", "Source lockfile inventory includes test/target-specific dependencies, not all are shipped"]}
    (output / "materials.json").write_text(json.dumps(materials, indent=2) + "\n")
    print("Generated source/runtime/builder CycloneDX, SPDX and bound materials in .work/sbom/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-image", default="obsidian-sync:local")
    parser.add_argument("--builder-image", default="obsidian-sync:builder")
    args = parser.parse_args()
    try:
        generate(args.runtime_image, args.builder_image)
        return 0
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print("SBOM generation failed; no complete materials manifest is claimed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
