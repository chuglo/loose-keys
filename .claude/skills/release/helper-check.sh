#!/bin/sh
# The native helper check (docs/testing/native-helper-tests.md) on a release
# candidate: the suite, then its negative control, each in a new clone of
# lk-sip-base (see docs/testing/guest.md). The harness comes built from the
# candidate, so the guest needs no Rust.
# Usage: sh .claude/skills/release/helper-check.sh <candidate folder>
set -eu
umask 077

CAND=$(cd "${1:?usage: helper-check.sh <candidate folder>}" && pwd -P)
BASE=lk-sip-base
S='/Volumes/My Shared Files/share'
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
. "$(dirname "$0")/guest-lib.sh"

"$TART" list | awk -v vm="$BASE" '$2 == vm && $NF == "stopped" { found = 1 } END { exit !found }' \
    || fail "$BASE is missing or running; see docs/testing/guest.md"
verify_candidate
ZIP="Loose-Keys-$VERSION.zip"
# The digest the runner checks the installed helper against, read from the zip.
DIGEST=$(unzip -p "$CAND/share/$ZIP" 'Loose Keys.app/Contents/MacOS/loose-keys-gui' | shasum -a 256 | cut -d ' ' -f 1)
STAMP=$(date +%m%d-%H%M%S)

# run_suite <name> [--omit-create]: one clone, one run; leaves the exit
# status in $code and results.json in the work folder.
run_suite() {
    name=$1
    shift
    VM="lk-$name-$(printf '%.7s' "$COMMIT")-$STAMP"
    WORK="$CAND/$VM"
    mkdir "$WORK"
    start_guest "$BASE"
    unpack_candidate
    guest sh -c 'cp "$1/security-harness" ~/work/ && mkdir -p ~/verification-scratch' sh "$S"
    step "Helper check ($name), candidate executable $DIGEST"
    guest sh -c 'digest=$1 name=$2 && shift 2 && cd ~/work &&
        TMPDIR="$HOME/verification-scratch" LOOSE_KEYS_HELPER_CHECK=disposable-guest ./security-harness helper-check \
        --bundle "$PWD/target/release/bundle/macos/Loose Keys.app" --sha256 "$digest" \
        --guest-home "$HOME" --work "$HOME/verification-scratch/$name" "$@"' \
        sh "$DIGEST" "$name" "$@" > "$WORK/helper-check.log" 2>&1 && code=0 || code=$?
    guest cat "verification-scratch/$name/results.json" > "$WORK/results.json" 2> /dev/null || true
    printf '%s: exit %s\n' "$name" "$code"
    stop_guest
}

# status <work folder> <case>: that case's status in results.json.
status() {
    python3 -I -c 'import json, sys
try:
    print(json.load(open(sys.argv[1]))["cases"][sys.argv[2]]["status"])
except Exception:
    print("MISSING")' "$1/results.json" "$2"
}

run_suite helper
positive=$code
positive_work=$WORK
run_suite helper-negative --omit-create
negative=$code
negative_work=$WORK

ok=yes
[ "$positive" -eq 0 ] || ok=no
for stage in preflight enable-baseline event-create event-rotate event-delete restart-replay disable cleanup; do
    s=$(status "$positive_work" "$stage")
    printf 'suite            %-16s %s\n' "$stage" "$s"
    [ "$s" = PASS ] || ok=no
done
[ "$negative" -eq 1 ] || ok=no
for stage in preflight enable-baseline; do
    s=$(status "$negative_work" "$stage")
    printf 'negative control %-16s %s\n' "$stage" "$s"
    [ "$s" = PASS ] || ok=no
done
for stage in event-create event-rotate event-delete restart-replay disable cleanup; do
    s=$(status "$negative_work" "$stage")
    printf 'negative control %-16s %s\n' "$stage" "$s"
    case "$stage" in
        event-create) want=FAIL ;;
        cleanup) want=PASS ;;
        *) want='NOT RUN' ;;
    esac
    [ "$s" = "$want" ] || ok=no
done

printf '\nVMs:     %s, %s (stopped)\nLogs:    %s\n' \
    "$(basename "$positive_work")" "$(basename "$negative_work")" "$CAND"
if [ "$ok" = yes ]; then
    printf 'Result:  PASS\n'
else
    printf 'Result:  FAIL (suite exit %s, negative control exit %s)\n' "$positive" "$negative"
    exit 1
fi
