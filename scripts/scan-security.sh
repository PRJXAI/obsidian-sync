#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .work/security .work/trivy-cache
cargo audit --json > .work/security/rustsec.json
cargo deny check
work=$(mktemp -d "$PWD/.work/scan.XXXXXX")
builder="obsidian-sync-audit-builder:scan-$$"
cleanup_builder=true
if [[ -n "${SYNC_SECURITY_BUILDER_IMAGE:-}" ]]; then
  builder=$(docker image inspect "$SYNC_SECURITY_BUILDER_IMAGE" --format '{{.Id}}')
  cleanup_builder=false
fi
trap 'if "$cleanup_builder"; then docker image rm "$builder" >/dev/null 2>&1 || true; fi; rm -rf "$work"' EXIT
# Scan everything eligible for source control, including untracked files, not target/data/secrets.
python3 - "$work" <<'PY'
import pathlib, shutil, subprocess, sys
out=pathlib.Path(sys.argv[1])/'source'
out.mkdir()
files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z']).split(b'\0')
count=0
for raw in files:
    if not raw: continue
    p=pathlib.Path(raw.decode())
    if p.is_symlink(): raise SystemExit(f'Review source symlink before scanning: {p}')
    if p.is_file():
        dst=out/p; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,dst)
        count+=1
if count==0: raise SystemExit('Refusing an empty source scan')
print(f'Staged {count} source files for secret scanning')
PY
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  -v "$work/source:/source:ro" -v "$PWD/.work/security:/reports" \
  ghcr.io/gitleaks/gitleaks:latest@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  dir /source --redact=100 --exit-code 1 --report-format json --report-path /reports/gitleaks.json
# Detect daemon bind-mount misconfiguration instead of accepting a vacuous scan.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "$work/source:/source:ro" alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 \
  test -s /source/Cargo.lock
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
    -v "$PWD:/repo:ro" -v "$PWD/.work/security:/reports" \
    ghcr.io/gitleaks/gitleaks:latest@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
    git /repo --redact=100 --exit-code 1 --report-format json --report-path /reports/gitleaks-history.json
fi
# Scan the exact local runtime image, without giving the scanner a Docker socket.
docker image inspect obsidian-sync:local --format '{{.Id}}' > .work/security/image-id.txt
docker image inspect obsidian-sync:local > .work/security/image-inspect.json
docker save obsidian-sync:local -o "$work/runtime.tar"
docker run --rm --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh \
  -v "$work/runtime.tar:/runtime.tar:ro" -v "$PWD/.work/security:/reports" -v "$PWD/.work/trivy-cache:/cache" \
  aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c \
  -c 'status=0; trivy --cache-dir /cache image --input /runtime.tar --scanners vuln --list-all-pkgs --exit-code 1 --format json --output /reports/trivy.json || status=$?; trivy --cache-dir /cache --version > /reports/trivy-version.txt; exit "$status"'
python3 - <<'PY'
import json
image=json.load(open('.work/security/image-inspect.json'))[0]
scan=json.load(open('.work/security/trivy.json'))
assert image['RootFS']['Layers']==scan['Metadata']['DiffIDs'], 'Scanned layers do not match inspected image'
print('Verified scanned layer digests match the runtime image')
PY
# The static executable also consumes native/toolchain inputs absent from runtime
# OS package metadata. Scan the actual populated builder stage, not just its base.
if "$cleanup_builder"; then docker build --target build -t "$builder" .; fi
docker save "$builder" -o "$work/builder.tar"
docker run --rm --cap-drop ALL --security-opt no-new-privileges \
  -v "$work/builder.tar:/builder.tar:ro" -v "$PWD/.work/security:/reports" -v "$PWD/.work/trivy-cache:/cache" \
  aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c \
  --cache-dir /cache image --input /builder.tar --scanners vuln --list-all-pkgs --exit-code 1 --format json --output /reports/trivy-builder.json
# Rust's self-contained musl is distinct from Alpine's musl-dev. Preserve its
# identity for patch-aware review; package version alone does not reveal backports.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --entrypoint /bin/sh "$builder" -c 'rustc --version; p=$(rustc --print target-libdir); sha256sum "$p/self-contained/libc.a"; ar p "$p/self-contained/libc.a" version.lo | strings' \
  > .work/security/native-toolchain.txt
cargo metadata --locked --format-version 1 > .work/security/cargo-metadata.json
printf 'Runtime and builder scans completed; also run scripts/scan-supply-chain.py and review native-toolchain patches before release.\n'
