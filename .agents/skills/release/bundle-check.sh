#!/bin/sh
# The shipped-bundle check (docs/testing/guest.md) on a release candidate, in
# a new clone of the base image: the app check, then its negative control.
# Usage: sh .agents/skills/release/bundle-check.sh <candidate folder>
set -eu
umask 077

CAND=$(cd "${1:?usage: bundle-check.sh <candidate folder>}" && pwd -P)
BASE=ghcr.io/cirruslabs/macos-tahoe-base:latest
S='/Volumes/My Shared Files/share'
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
. "$(dirname "$0")/guest-lib.sh"

verify_candidate
VM="lk-bundle-$(printf '%.7s' "$COMMIT")-$(date +%m%d-%H%M%S)"
WORK="$CAND/$VM"
mkdir "$WORK"

start_guest "$BASE"
unpack_candidate

step 'App check'
guest sh -c 'cd ~/work && LOOSE_KEYS_APP_CHECK=synthetic-home sh gui/tests/check-app.sh "$HOME/app-check-1"' \
    > "$WORK/app-check.log" 2>&1 && positive=0 || positive=$?
printf 'app check: exit %s\n' "$positive"

step 'Negative control (must fail on the missing AWS finding)'
guest sh -c 'cd ~/work && LOOSE_KEYS_APP_CHECK=synthetic-home LOOSE_KEYS_APP_CHECK_OMIT_AWS=1 sh gui/tests/check-app.sh "$HOME/app-check-2"' \
    > "$WORK/negative.log" 2>&1 && negative=0 || negative=$?
printf 'negative control: exit %s\n' "$negative"
grep -q 'timeout: specific fixture findings in window' "$WORK/negative.log" && control=ok || control=wrong

stop_guest

printf '\nVM:      %s (stopped)\nCommit:  %s\nLogs:    %s\n' "$VM" "$COMMIT" "$WORK"
if [ "$positive" -eq 0 ] && [ "$negative" -ne 0 ] && [ "$control" = ok ]; then
    printf 'Result:  PASS\n'
else
    printf 'Result:  FAIL (app check exit %s; negative control exit %s, reason %s)\n' \
        "$positive" "$negative" "$control"
    exit 1
fi
