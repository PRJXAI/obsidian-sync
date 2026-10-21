#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for features in '' s3 gcs azure s3,gcs s3,azure gcs,azure s3,gcs,azure; do
  printf '\nFEATURES=%s\n' "${features:-filesystem-only}"
  cargo build --locked --no-default-features --features "$features"
  cargo build --release --locked --no-default-features --features "$features"
  cargo clippy --workspace --all-targets --locked --no-default-features --features "$features" -- -D warnings
  cargo test --workspace --locked --no-default-features --features "$features"
done
