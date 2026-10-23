#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/sync-generated.py --check
for overlay in filesystem s3 gcs azure; do
  kustomize build "deploy/kustomize/overlays/$overlay" > /dev/null
  printf 'Rendered Kustomize overlay: %s\n' "$overlay"
done
kustomize build deploy/kustomize/base > /dev/null
docker compose config --quiet
SYNC_RELEASE_IMAGE=obsidian-sync:release-validation SYNC_RELEASE_REVISION=validation-only docker compose -f docker-compose.yml -f deploy/compose.release.yml config --quiet
S3_ACCESS_KEY_FILE=/dev/null S3_SECRET_KEY_FILE=/dev/null docker compose -f docker-compose.yml -f docker-compose.s3.yml config --quiet
TEST_S3_ACCESS_KEY=validation-only TEST_S3_SECRET_KEY=validation-only docker compose -f docker-compose.test-s3.yml config --quiet
printf 'All Compose configurations and Kustomize overlays render. API schema checks run only against the disposable smoke cluster.\n'
