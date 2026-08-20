#!/usr/bin/env bash
set -euo pipefail

# Optional strict warning gates, run locally. Not part of CI:
# nightly-only lints and rustdoc warnings would be noisy for contributors.
# Usage: tools/check-future-compat.sh

echo "==> nightly check with -D warnings (future-incompat awareness)"
cargo +nightly check --workspace --all-features 2>&1 | sed 's/^/  /'

echo "==> nightly build with --future-incompat-report"
cargo +nightly build --workspace --all-features --future-incompat-report 2>&1 | sed 's/^/  /'

echo "==> rustdoc with -D warnings (public API docs gate)"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps 2>&1 | sed 's/^/  /'

echo "All warning gates passed."
