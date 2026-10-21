#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .work/security
cargo audit --json > .work/security/rustsec.json
cargo deny check
work=$(mktemp -d "$PWD/.work/scan.XXXXXX")
trap 'rm -rf "$work"' EXIT
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
  -v "$work/source:/source:ro" alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 \
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
  -v "$work/runtime.tar:/runtime.tar:ro" -v "$PWD/.work/security:/reports" \
  aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c \
  -c 'status=0; trivy image --input /runtime.tar --scanners vuln --list-all-pkgs --exit-code 1 --format json --output /reports/trivy.json || status=$?; trivy --version > /reports/trivy-version.txt; exit "$status"'
python3 - <<'PY'
import json
image=json.load(open('.work/security/image-inspect.json'))[0]
scan=json.load(open('.work/security/trivy.json'))
assert image['RootFS']['Layers']==scan['Metadata']['DiffIDs'], 'Scanned layers do not match inspected image'
print('Verified scanned layer digests match the runtime image')
PY
printf 'Security scans completed; inspect advisory timestamps and report scope before accepting a release.\n'
