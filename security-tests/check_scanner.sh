#!/bin/sh
# Release gate: run the real scanner through the security harness in both report modes.
# Usage: security-tests/check_scanner.sh [work-dir]
set -eu
cd "$(dirname "$0")/.."
BASE=${1:-${TMPDIR:-/tmp}/loose-keys-check}
mkdir -p "$BASE"
WORK=$(mktemp -d "$BASE/check.XXXXXX")
cargo build --locked --release --quiet
BIN=$PWD/target/release/loose-keys
HARNESS=$(sh security-tests/harness.sh executable)
"$HARNESS" generate --out "$WORK/fresh" >/dev/null
"$HARNESS" generate --out "$WORK/symlink" >/dev/null
echo "== fresh report"
"$HARNESS" check --fixtures "$WORK/fresh" --allowed-exit 0,1 --validate-report \
    -- "$BIN" scan --export {report}
echo "== report path pre-placed as a symlink (export must be refused)"
"$HARNESS" check --fixtures "$WORK/symlink" --report-mode symlink --allowed-exit 2 \
    --validate-report -- "$BIN" scan --export {report}
echo "PASSED"
