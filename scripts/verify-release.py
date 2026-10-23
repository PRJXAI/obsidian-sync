#!/usr/bin/env python3
"""Bind an imported local image to a TRUSTED clean Trivy runtime report.

The report must be obtained through an authenticated operator/CI channel. This
is content verification, not a signature or proof that a builder is trustworthy.
Prints the daemon's immutable image ID for use as SYNC_RELEASE_IMAGE.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

DIGEST = re.compile(r"sha256:[a-f0-9]{64}")


def verify(report, inspected, config, now):
    created = datetime.datetime.fromisoformat(report["CreatedAt"].replace("Z", "+00:00"))
    age = (now - created).total_seconds()
    if not -300 <= age <= 86400:
        raise ValueError("Report is stale or future-dated")
    results = report["Results"]
    if not isinstance(results, list) or not results or any(item.get("Vulnerabilities") for item in results):
        raise ValueError("A complete clean runtime scan is required")
    expected = report["Metadata"]
    digest = "sha256:" + hashlib.sha256(config).hexdigest()
    if not DIGEST.fullmatch(expected["ImageID"]) or digest != expected["ImageID"]:
        raise ValueError("Scanned image configuration does not match")
    layers = expected["DiffIDs"]
    if not layers or layers != inspected["RootFS"]["Layers"]:
        raise ValueError("Scanned image layers do not match")
    image_config = json.loads(config)
    if image_config["rootfs"]["diff_ids"] != layers:
        raise ValueError("Saved configuration layers do not match")
    if image_config["config"]["User"] != "65532:65532" or image_config["config"]["Entrypoint"] != ["/server"]:
        raise ValueError("Runtime identity or entrypoint changed")
    if not DIGEST.fullmatch(inspected["Id"]):
        raise ValueError("Daemon did not return an immutable image ID")
    return inspected["Id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--scan-report", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}", args.image):
        parser.error("Invalid local image reference")
    try:
        with args.scan_report.open("rb") as file:
            raw = file.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Oversized report")
        report = json.loads(raw)
        inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image], stderr=subprocess.DEVNULL, timeout=30))[0]
        # Resolve the mutable tag ONCE. Export by immutable ID to fence tag replacement.
        image_id = inspected["Id"]
        if not DIGEST.fullmatch(image_id):
            raise ValueError("Invalid image ID")
        with tempfile.TemporaryFile() as archive:
            subprocess.run(["docker", "save", image_id], stdout=archive, stderr=subprocess.DEVNULL, check=True, timeout=120)
            archive.seek(0)
            with tarfile.open(fileobj=archive) as saved:
                manifest_file = saved.extractfile("manifest.json")
                manifests = json.loads(manifest_file.read(1024 * 1024))
                if len(manifests) != 1:
                    raise ValueError("Expected exactly one image")
                member = saved.getmember(manifests[0]["Config"])
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError("Invalid saved configuration")
                config = saved.extractfile(member).read()
        print(verify(report, inspected, config, datetime.datetime.now(datetime.timezone.utc)))
        return 0
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, tarfile.TarError, subprocess.SubprocessError):
        print("Release verification failed; no verified image reference was produced.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
