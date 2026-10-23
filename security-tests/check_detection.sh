#!/bin/sh
# Exact detection expectations and CLI/GUI-engine export parity. No app launch.
# TMPDIR must be an existing, non-symlinked scratch directory.
set -eu
umask 077
cd "$(dirname "$0")/.."
: "${TMPDIR:?Set TMPDIR to a real scratch directory}"
# The full runner folds parity into the workspace run. Standalone use still
# checks the debug CLI as well as the engine and release CLI.
case "${1:-}" in
    '') cargo test --locked --test detection_corpus ;;
    --workspace) ;;
    *) echo 'usage: check_detection.sh [--workspace]' >&2; exit 2 ;;
esac
cargo build --locked --release --target-dir target
work=$(mktemp -d "$TMPDIR/loose-keys-detection.XXXXXX")
status=0
if [ "${1:-}" = --workspace ]; then
    set -- cargo test --locked --workspace -- --nocapture
else
    set -- cargo test --manifest-path gui/Cargo.toml --locked --lib \
        tests::shared_detection_corpus_matches_manifest -- --exact --nocapture
fi
LOOSE_KEYS_DETECTION_CLI="$PWD/target/release/loose-keys" \
    "$@" >"$work/engine.log" 2>&1 || status=$?
cat "$work/engine.log"
test "$status" -eq 0 || exit "$status"
# Cargo exits zero when a filter selects no tests. Require the completion
# marker from inside the test, after every comparison has passed.
grep -qx 'PASS: CLI and engine detection parity' "$work/engine.log"
