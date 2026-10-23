#!/bin/sh
# Exact detection expectations and CLI/GUI-engine export parity. No app launch.
# TMPDIR must be an existing, non-symlinked scratch directory.
set -eu
umask 077
cd "$(dirname "$0")/.."
: "${TMPDIR:?Set TMPDIR to a real scratch directory}"
# The CLI half: every corpus case through the debug command. The rest of the
# workspace's tests are `cargo test --locked --workspace`, run on its own.
cargo test --locked --test detection_corpus
cargo build --locked --release --target-dir target
work=$(mktemp -d "$TMPDIR/loose-keys-detection.XXXXXX")
status=0
LOOSE_KEYS_DETECTION_CLI="$PWD/target/release/loose-keys" \
    cargo test --manifest-path gui/Cargo.toml --locked --lib \
    tests::shared_detection_corpus_matches_manifest -- --exact --nocapture \
    >"$work/engine.log" 2>&1 || status=$?
cat "$work/engine.log"
test "$status" -eq 0 || exit "$status"
# Cargo exits zero when a filter selects no tests. Require the completion
# marker from inside the test, after every comparison has passed.
grep -qx 'PASS: CLI and engine detection parity' "$work/engine.log"
