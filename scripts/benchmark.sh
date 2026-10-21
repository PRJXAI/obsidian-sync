#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --locked --example benchmark
if [ "$(uname -s)" = Darwin ]; then
  /usr/bin/time -l target/release/examples/benchmark
else
  /usr/bin/time -v target/release/examples/benchmark
fi
