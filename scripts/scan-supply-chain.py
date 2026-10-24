#!/usr/bin/env python3
"""Scan declared public build/test/scanner images, not just the final runtime.

No Docker socket is exposed to the scanner. Any finding (including UNKNOWN),
missing digest or failed scan fails the gate. Package matches require separate
reachability/platform triage; they are not proof of a runtime exploit.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCANNER = "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
IMAGE = re.compile(r"(?:[a-z0-9.-]+/)*[a-z0-9_-]+:[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}")


def inventory(root):
    files = [root / "Dockerfile", *root.glob("docker-compose*.yml"), *sorted((root / "deploy").rglob("*.yaml")), *sorted((root / ".github").rglob("*.yml")), *sorted((root / "scripts").glob("*.sh")), *sorted((root / "scripts").glob("*.py"))]
    images = {}
    for path in files:
        text = path.read_text()
        for image in IMAGE.findall(text):
            images.setdefault(image, []).append(str(path.relative_to(root)))
        if path.suffix in (".yaml", ".yml"):
            for match in re.finditer(r"^\s*image:\s*['\"]?([^'\"\s#]+)", text, re.MULTILINE):
                image = match.group(1)
                # Built locally and supplied by the verified release handoff, not pulled.
                release_input = path == root / "deploy/compose.release.yml" and image == "${SYNC_RELEASE_IMAGE:?Set"
                if image != "obsidian-sync:local" and not release_input and not IMAGE.fullmatch(image):
                    raise ValueError("External deployment/test image must be digest-pinned")
    # Do not silently accept a newly unpinned Dockerfile frontend or external base.
    stages = set()
    for line in (root / "Dockerfile").read_text().splitlines():
        if line.startswith("# syntax="):
            if not IMAGE.fullmatch(line.split("=", 1)[1]):
                raise ValueError("Dockerfile frontend must be digest-pinned")
        if line.startswith("FROM "):
            parts = line.split()
            if parts[1] not in stages and not IMAGE.fullmatch(parts[1]):
                raise ValueError("External Dockerfile base must be digest-pinned")
            if len(parts) == 4 and parts[2].upper() == "AS":
                stages.add(parts[3])
    if not images:
        raise ValueError("Refusing empty supply-chain inventory")
    return dict(sorted(images.items()))


def scanner_run(command, arguments, log, timeout):
    # A timed-out Docker client does not stop its container; explicitly fence cleanup.
    name = "sync-chain-scan-" + uuid.uuid4().hex
    named = [*command[:3], "--name", name, *command[3:]]
    try:
        return subprocess.run([*named, *arguments], stdout=log, stderr=log, check=False, timeout=timeout)
    finally:
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)


def run_scan(root, output, platform):
    images = inventory(root)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").unlink(missing_ok=True)
    cache = root / ".work/trivy-cache"
    cache.mkdir(parents=True, exist_ok=True)
    # Numeric caller identity works without a passwd entry and preserves host
    # bind-mount ownership on Linux while retaining the capability restrictions.
    command = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "--env", "HOME=/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "2g", "--cpus", "2", "-v", f"{output}:/reports", "-v", f"{cache}:/cache", SCANNER, "--cache-dir", "/cache"]
    with (output / "database.log").open("w") as log:
        result = scanner_run(command, ["image", "--download-db-only", "--quiet"], log, 600)
        if result.returncode:
            raise ValueError("Advisory database update failed")
    summary = []
    for index, (image, sources) in enumerate(images.items()):
        report = f"image-{index:02d}.json"
        (output / report).unlink(missing_ok=True)
        with (output / f"image-{index:02d}.log").open("w") as log:
            try:
                result = scanner_run(command, ["image", "--timeout", "3m", "--skip-db-update", "--image-src", "remote", "--platform", platform, "--scanners", "vuln", "--list-all-pkgs", "--exit-code", "1", "--format", "json", "--output", f"/reports/{report}", image], log, 240)
            except subprocess.TimeoutExpired:
                result = subprocess.CompletedProcess(command, 124)
        entry = {"image": image, "sources": sources, "exit_code": result.returncode, "report": report}
        if (output / report).exists():
            data = json.loads((output / report).read_text())
            findings = [v for item in data.get("Results", []) for v in item.get("Vulnerabilities", [])]
            entry["counts"] = {severity: sum(v["Severity"] == severity for v in findings) for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
            entry["unique_advisories"] = len({v["VulnerabilityID"] for v in findings})
            if findings:
                entry["exit_code"] = entry["exit_code"] or 1
        else:
            entry["exit_code"] = entry["exit_code"] or 1
        summary.append(entry)
        print(f"{'PASS' if entry['exit_code'] == 0 else 'FAIL'} {image}", flush=True)
    (output / "summary.json").write_text(json.dumps({"scanner": SCANNER, "platform": platform, "images": summary}, indent=2) + "\n")
    return int(any(item["exit_code"] != 0 for item in summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), default="linux/amd64")
    args = parser.parse_args()
    try:
        return run_scan(ROOT, ROOT / ".work/security/supply-chain" / args.platform.split("/")[1], args.platform)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Supply-chain scan failed; inspect local reports. No clean result is claimed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
