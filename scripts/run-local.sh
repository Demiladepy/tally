#!/usr/bin/env bash
# One command, no Docker: build the bulletin and serve the web app.
#   bash scripts/run-local.sh            -> http://127.0.0.1:8787
# Data and the bulletin's receipt key go to ./bulletin-data (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p tally-bulletin
BIN="${CARGO_TARGET_DIR:-target}/release/tally-bulletin"
mkdir -p bulletin-data
exec "$BIN" --listen 127.0.0.1:8787 --data ./bulletin-data --key ./bulletin-data/bulletin.key --web ./web
