#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
cargo deny check
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/sync-generated.py --check
python3 scripts/docs.py check
