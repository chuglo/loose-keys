#!/bin/sh
# Compile only the Rust test harness, then execute it with its own exit status.
set -eu
cd "$(dirname "$0")/.."
TMP_BASE=${TMPDIR:?TMPDIR must name a symlink-free scratch directory}
META=$(mktemp "$TMP_BASE/credhyg-harness-build.XXXXXX")
trap 'rm -f "$META"' EXIT HUP INT TERM
cargo test --locked --test security_harness --no-run --message-format=json > "$META"
BIN=$(sed -n '/"name":"security_harness"/s/.*"executable":"\([^"]*\)".*/\1/p' "$META")
case "$BIN" in
    ''|*'
'*) echo 'ERROR: no unique security harness executable' >&2; exit 2 ;;
esac
if [ "${1:-}" = executable ]; then
    printf '%s\n' "$BIN"
    exit 0
fi
"$BIN" "$@"
