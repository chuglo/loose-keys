#!/bin/sh
# Release gate: run the real scanner through the security harness in both report modes.
# Usage: security-tests/check_scanner.sh [work-dir [absolute path of a built loose-keys]]
# Without a path it builds and gates target/release/loose-keys.
set -eu
cd "$(dirname "$0")/.."
BASE=${1:-${TMPDIR:?TMPDIR must name a symlink-free scratch directory}/loose-keys-check}
case "${2:-}" in
    '')
        # Built where BIN points, whatever CARGO_TARGET_DIR or build.target-dir
        # say; the platform check also runs this binary.
        cargo build --locked --release --quiet --target-dir target
        BIN=$PWD/target/release/loose-keys ;;
    /*) BIN=$2 ;;
    *) echo 'the scanner path must be absolute' >&2; exit 2 ;;
esac
mkdir -p "$BASE"
WORK=$(mktemp -d "$BASE/check.XXXXXX")
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
