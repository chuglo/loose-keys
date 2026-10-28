#!/bin/sh
# Set up a VM for the release walkthrough: a new clone of lk-sip-base with the
# candidate in /Applications, a decoy home, the app open and nothing scanned.
# A Tart window shows the guest. Announce the window before running this.
# Usage: sh .claude/skills/release/walkthrough.sh <candidate folder>
set -eu
umask 077

CAND=$(cd "${1:?usage: walkthrough.sh <candidate folder>}" && pwd -P)
BASE=lk-sip-base
APP='Loose Keys.app'
S='/Volumes/My Shared Files/share'
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
. "$(dirname "$0")/guest-lib.sh"

"$TART" list | awk -v vm="$BASE" '$2 == vm && $NF == "stopped" { found = 1 } END { exit !found }' \
    || fail "$BASE is missing or running; see docs/testing/guest.md"
verify_candidate
ZIP="Loose-Keys-$VERSION.zip"
VM="lk-walk-$(printf '%.7s' "$COMMIT")-$(date +%m%d-%H%M%S)"
WORK="$CAND/$VM"
mkdir -p "$WORK/share" "$WORK/shots"
cp "$CAND/share/$ZIP" "$WORK/share/"

# The fake login keychain and Notes store would replace the guest's own. With
# SIP on, the guest also refuses tar's change to the Notes group container.
step 'Making a decoy home'
"$CAND/share/security-harness" generate-home "$WORK/decoys" > "$WORK/decoys.log" 2>&1 \
    || fail "decoys; see $WORK/decoys.log"
tar -cf "$WORK/share/decoys.tar" -C "$WORK/decoys/home" \
    --exclude 'login.keychain-db' --exclude 'NoteStore.sqlite*' --exclude 'Group Containers' \
    --exclude './Desktop' --exclude './Documents' --exclude './Downloads' .
if tar -tf "$WORK/share/decoys.tar" | grep -q -e 'login.keychain-db' -e 'NoteStore.sqlite'; then
    fail 'the decoy archive still holds the keychain or the Notes store'
fi

step "Starting a new VM, $VM, from $BASE"
"$TART" clone "$BASE" "$VM" > "$WORK/clone.log" 2>&1 || fail "clone; see $WORK/clone.log"
own_guest
nohup "$TART" run "$VM" --no-clipboard --no-audio --dir="share:$WORK/share:ro" > "$WORK/run.log" 2>&1 &
GUEST_PID=$!
tries=0
until guest test -f "$S/decoys.tar" > /dev/null 2>&1; do
    kill -0 "$GUEST_PID" 2> /dev/null || fail "VM process exited; see $WORK/run.log"
    tries=$((tries + 1))
    [ "$tries" -lt 90 ] || fail "the VM did not answer within three minutes; see $WORK/run.log"
    sleep 2
done

step 'Copying the app and the decoy home in'
for file in "$ZIP" decoys.tar; do
    here=$(shasum -a 256 "$WORK/share/$file" | cut -d ' ' -f 1)
    there=$(guest shasum -a 256 "$S/$file" | cut -d ' ' -f 1)
    [ "$here" = "$there" ] || fail "$file differs in the guest"
done
guest test ! -e "/Applications/$APP" || fail 'the guest already has the app'
guest ditto -x -k "$S/$ZIP" /Applications
guest codesign --verify --deep --strict "/Applications/$APP"
guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$S/decoys.tar"
guest sh -c 'test ! -e "$HOME/Library/Application Support/dev.loosekeys.desktop"' \
    || fail 'the guest already has app state, so it is not a first run'
guest sync
guest open "/Applications/$APP"

# A successful setup hands the running clone to the person doing the checks.
OWNED_VM=

printf '\nVM:      %s (running, app open, nothing scanned yet)\n' "$VM"
printf 'Commit:  %s\n' "$COMMIT"
printf 'Screen:  Tart window (guest only)\n'
printf 'Shots:   %s\n' "$WORK/shots"
