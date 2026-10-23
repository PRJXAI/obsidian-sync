#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .work
# Keep bind-mount sources inside the checkout (also works with Colima's shared paths).
work=$(mktemp -d "$PWD/.work/compose.XXXXXX")
project="obsidian-sync-smoke-$$"
cleanup() {
  docker compose -p "$project" down -v >/dev/null 2>&1 || true
  # Test-only cleanup runs as the application's UID, without privileges or networking.
  docker run --rm --network none --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
    -v "$work/data:/data" alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 \
    sh -c 'rm -rf /data/metadata /data/blobs' >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/data"
chmod 0777 "$work/data" # Disposable mount parent; service-created roots remain private 0700.
export SYNC_DATA_DIR="$work/data" SYNC_CONFIG_FILE=./config/filesystem.toml SYNC_PORT=18089
docker compose -p "$project" up -d --no-build
for _ in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18089/health/live || true)" = 204 ]; then break; fi
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18089/health/live)" = 204 ]
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18089/health/ready)" = 204 ]
if docker compose -p "$project" exec -T server /server create-vault > "$work/second-writer" 2>&1; then
  printf 'ERROR: second writer acquired metadata\n' >&2; exit 1
fi
grep -q 'another writer owns' "$work/second-writer"
docker compose -p "$project" stop -t 35
docker compose -p "$project" run --rm --no-deps server create-vault
printf 'Compose smoke passed: private probes, lock exclusion, graceful stop, persistent restart. LiveSync adapter readiness 204.\n'
