#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
project="obsidian-sync-test-$$"
cleanup() { docker compose -p "$project" -f docker-compose.test-s3.yml down -v >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
export TEST_S3_ACCESS_KEY TEST_S3_SECRET_KEY
TEST_S3_ACCESS_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(12))')
TEST_S3_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
umask 077
printf '%s' "$TEST_S3_ACCESS_KEY" > "$work/access"
printf '%s' "$TEST_S3_SECRET_KEY" > "$work/secret"
docker compose -p "$project" -f docker-compose.test-s3.yml up -d
port=$(docker compose -p "$project" -f docker-compose.test-s3.yml port object-store 9000 | awk -F: '{print $NF}')
python3 - "$port" <<'PY'
import sys, time, urllib.request, urllib.error
for _ in range(120):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/",timeout=2)
        break
    except urllib.error.HTTPError:
        break
    except (OSError, TimeoutError):
        time.sleep(1)
else:
    raise SystemExit("local S3 service did not start")
PY
python3 - "$work" "$port" <<'PY'
from pathlib import Path
import sys
work=Path(sys.argv[1])
text=Path('config/s3.toml').read_text().replace('/data/metadata',str(work/'metadata')).replace('https://s3.example.internal',f'http://127.0.0.1:{sys.argv[2]}')
text+='\nallow_insecure_loopback = true\n'
(work/'config.toml').write_text(text)
PY
export SYNC_S3_TEST_CONFIG="$work/config.toml" S3_ACCESS_KEY_FILE="$work/access" S3_SECRET_KEY_FILE="$work/secret" SYNC_S3_CREATE_BUCKET=yes
cargo test --locked --test storage_contract s3_contract -- --ignored --exact
python3 scripts/test-livesync.py --storage-config "$SYNC_S3_TEST_CONFIG"
