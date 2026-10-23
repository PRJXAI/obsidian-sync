#!/usr/bin/env python3
"""Real upstream clients, disposable native service or final distroless image; no real vaults."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
HELPER = "alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63"
parser = argparse.ArgumentParser()
mode = parser.add_mutually_exclusive_group()
mode.add_argument("--storage-config", type=Path, help="Explicit DISPOSABLE loopback-S3 test config")
mode.add_argument("--image", help="Already built local runtime image; filesystem mode")
parser.add_argument("--benchmark", action="store_true", help="Measure real-client logical note/attachment/feed/concurrent workloads")
args = parser.parse_args()
if not args.image:
    subprocess.run(["cargo", "build", *(["--release"] if args.benchmark else []), "--locked"], cwd=ROOT, check=True, timeout=900)
else:
    # Never run this disposable deployment on an SSH/TCP Docker context.
    endpoint = subprocess.check_output(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], text=True).strip()
    if not os.environ.get("DOCKER_HOST", endpoint).startswith("unix://"):
        parser.error("Image fixtures require a local Unix-socket Docker daemon")
subprocess.run(["npm", "ci", "--prefix", "tests/compat", "--ignore-scripts", "--no-fund"], cwd=ROOT, check=True, timeout=180)
(ROOT / ".work").mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="livesync-", dir=ROOT / ".work") as directory:
    work = Path(directory).resolve()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    source = (args.storage_config or ROOT / "config/filesystem.toml").read_text()
    if args.storage_config:
        storage = tomllib.loads(source)["storage"]
        endpoint = urllib.parse.urlparse(storage.get("endpoint", ""))
        if storage["kind"] != "s3" or endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1":
            parser.error("Only explicitly disposable literal-loopback S3 fixtures are accepted")
    source = re.sub(r"^listen\s*=.*$", f'listen = "{("0.0.0.0:8080" if args.image else f"127.0.0.1:{port}")}"', source, flags=re.M)
    data = "/data" if args.image else str(work)
    source = re.sub(r"^metadata_dir\s*=.*$", f'metadata_dir = "{data}/metadata"', source, flags=re.M)
    if not args.storage_config:
        source = re.sub(r"^root\s*=.*$", f'root = "{data}/blobs"', source, flags=re.M)
    # Keep rate limiting enabled; this intense short fixture needs a larger bounded burst.
    if re.search(r"^burst\s*=", source, re.M):
        source = re.sub(r"^burst\s*=.*$", "burst = 1024", source, flags=re.M)
    elif "[http]" in source:
        source = source.replace("[http]", "[http]\nburst = 1024", 1)
    else:
        source = source.replace("[storage]", "[http]\nburst = 1024\n\n[storage]", 1)
    config = work / "config.toml"
    config.write_text(source)
    container = "livesync-fixture-" + secrets.token_hex(6)
    mounts = ["--mount", f"type=bind,source={work}/data,target=/data", "--mount", f"type=bind,source={config},target=/config/test.toml,readonly"]
    restrictions = ["--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if args.image:
        (work / "data").mkdir()
        # Disposable parent only; inaccessible from other host users via private work/.
        # The application creates its own authoritative roots with mode 0700.
        (work / "data").chmod(0o777)
        command = ["docker", "run", "--rm", "--network", "none", "--log-driver", "none", *restrictions, *mounts, args.image, "--config", "/config/test.toml"]
    else:
        command = [str(ROOT / "target" / ("release" if args.benchmark else "debug") / "obsidian-sync-server"), "--config", str(config)]
    process = None
    running = False
    log = (work / "server.log").open("w")

    def admin(*arguments):
        # Issue's deliberate one-shot secret output is captured in RAM, never Docker logs.
        return subprocess.check_output([*command, *arguments], cwd=ROOT, text=True, timeout=60).strip()

    def stop():
        global process, running
        if args.image:
            if not running:
                return
            subprocess.run(["docker", "stop", "--time", "35", container], check=True, stdout=subprocess.DEVNULL, timeout=45)
            state = json.loads(subprocess.check_output(["docker", "inspect", "--format", "{{json .State}}", container], text=True, timeout=15))
            subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL, timeout=15)
            running = False
            if state["Running"] or state["ExitCode"]:
                raise RuntimeError("Disposable container did not shut down cleanly")
        elif process is not None:
            p, process = process, None
            p.send_signal(signal.SIGTERM)
            try:
                status = p.wait(timeout=35)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=10)
                raise RuntimeError("Graceful shutdown timed out") from None
            if status:
                raise RuntimeError(f"Disposable Rust server exited with status {status}")

    def start():
        global process, running
        if args.image:
            subprocess.run(["docker", "run", "-d", "--name", container, "--log-driver", "local", "--memory", "2g", "--cpus", "2", *restrictions, *mounts, "--publish", f"127.0.0.1:{port}:8080", args.image, "--config", "/config/test.toml", "serve"], check=True, stdout=subprocess.DEVNULL, timeout=60)
            running = True
        else:
            process = subprocess.Popen([*command, "serve"], cwd=ROOT, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise RuntimeError("Disposable Rust server exited during startup")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health/ready", timeout=1) as response:
                    if response.status == 204:
                        return
            except (OSError, urllib.error.HTTPError):
                time.sleep(0.1)
        raise RuntimeError("Disposable Rust server did not become ready")

    try:
        vault = admin("create-database", "--name", "vault")
        encrypted = admin("create-database", "--name", "encrypted")
        bootstrap = admin("create-database", "--name", "bootstrap")

        def issue(vault, *flags):
            return dict(line.split("=", 1) for line in admin("issue", "--vault", vault, *flags).splitlines())

        # Separate, independently revocable credentials for devices and encrypted vault.
        issued, peer = issue(vault), issue(vault)
        encrypted_issued = issue(encrypted)
        bootstrap_issued = issue(bootstrap, "--allow-database-reset")
        env = {
            **os.environ, "LS_TEST_URL": f"http://127.0.0.1:{port}",
            "LS_TEST_USER": issued["principal"], "LS_TEST_TOKEN": issued["token"],
            "LS_TEST_PEER_USER": peer["principal"], "LS_TEST_PEER_TOKEN": peer["token"],
            "LS_TEST_ENCRYPTED_USER": encrypted_issued["principal"], "LS_TEST_ENCRYPTED_TOKEN": encrypted_issued["token"],
            "LS_TEST_BOOTSTRAP_USER": bootstrap_issued["principal"], "LS_TEST_BOOTSTRAP_TOKEN": bootstrap_issued["token"],
            "LS_TEST_E2EE_PASSPHRASE": secrets.token_urlsafe(32), "LS_TEST_STATE": str(work / "restart.json"),
        }
        if args.benchmark:
            env["LS_TEST_BENCHMARK_KEYS"] = json.dumps([issue(vault) for _ in range(8)])
        start()
        if args.benchmark:
            samples = []
            finished = threading.Event()

            def monitor():
                while not finished.wait(0.1):
                    try:
                        if args.image:
                            output = subprocess.check_output(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", container], text=True, timeout=5)
                            match = re.match(r"([0-9.]+)(B|KiB|MiB|GiB)", output)
                            if match:
                                samples.append(int(float(match[1]) * {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}[match[2]]))
                        else:
                            output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(process.pid)], text=True, stderr=subprocess.DEVNULL, timeout=5)
                            samples.append(int(output.strip()) * 1024)
                    except (subprocess.SubprocessError, ValueError, OSError):
                        return

            sampler = threading.Thread(target=monitor, daemon=True)
            sampler.start()
            try:
                subprocess.run(["node", "tests/compat/benchmark.mjs"], cwd=ROOT, env=env, check=True, timeout=180)
            finally:
                finished.set()
                sampler.join(timeout=8)
            if not samples:
                raise RuntimeError("No server memory samples collected")
            print(json.dumps({"sampled_peak_container_memory_bytes" if args.image else "sampled_peak_server_rss_bytes": max(samples), "memory_samples": len(samples)}))
        else:
            subprocess.run(["node", "tests/compat/livesync.mjs"], cwd=ROOT, env={**env, "LS_TEST_PHASE": "initial"}, check=True, timeout=180)
            stop()
            start()
            subprocess.run(["node", "tests/compat/livesync.mjs"], cwd=ROOT, env={**env, "LS_TEST_PHASE": "restart"}, check=True, timeout=90)
        stop()
        print("PASS: real-client benchmark" if args.benchmark else "PASS: actual Commonlib 0.1.44/PouchDB 9, isolated devices, conflicts, files, E2EE/compression, live feeds, bootstrap and restart" + (" (final distroless image)" if args.image else ""))
    finally:
        try:
            stop()
        finally:
            log.close()
            if args.image:
                subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                # Test-only helper, not part of the runtime image; no privileges/network.
                subprocess.run(["docker", "run", "--rm", "--network", "none", "--log-driver", "none", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--volume", f"{work}/data:/data", HELPER, "sh", "-c", "rm -rf /data/metadata /data/blobs"], check=True, timeout=60)
