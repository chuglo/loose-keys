#!/bin/sh
# Build one commit of Loose Keys on this Mac, then open it in a new tart VM
# whose home holds synthetic decoys. The app runs only in the guest.
# Usage, from the repository root: sh .claude/skills/vm/open-in-vm.sh [git ref]
set -eu

REF=${1:-main}
BASE=ghcr.io/cirruslabs/macos-tahoe-base:latest
SHARED='/Volumes/My Shared Files/share'
APP='Loose Keys.app'
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")

fail() {
    printf 'FAILED: %s\n' "$*" >&2
    exit 1
}
step() { printf '\n== %s\n' "$*"; }
# Long steps write to a log, so their output stays out of the summary.
logged() {
    name=$1
    shift
    "$@" > "$WORK/$name.log" 2>&1 || fail "$name; see $WORK/$name.log"
}
guest() { "$TART" exec "$VM" "$@"; }

[ -f gui/macos/Info.plist ] || fail 'run this from the repository root'
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
[ -x "$TART" ] || fail "tart not found at $TART"
COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") || fail "not a commit: $REF"
SHORT=$(git rev-parse --short "$COMMIT")
STAMP=$(date +%m%d-%H%M%S)
VM="lk-$SHORT-$STAMP"
WORK="${TMPDIR%/}/vm-$SHORT-$STAMP"
mkdir -p "$WORK/src" "$WORK/share"

# The Apple Development identity when this Mac has one, as for builds a person
# runs; LOOSE_KEYS_SIGN_IDENTITY=- asks for ad hoc.
if [ -z "${LOOSE_KEYS_SIGN_IDENTITY+set}" ] \
    && /usr/bin/security find-identity -v -p codesigning | grep -q 'Apple Development'; then
    LOOSE_KEYS_SIGN_IDENTITY='Apple Development'
fi
LOOSE_KEYS_SIGN_IDENTITY=${LOOSE_KEYS_SIGN_IDENTITY:--}
export LOOSE_KEYS_SIGN_IDENTITY

# An export of the commit alone: no uncommitted change and no old target/.
step "Building $SHORT ($REF)"
git archive --format=tar -o "$WORK/src.tar" "$COMMIT"
tar -xf "$WORK/src.tar" -C "$WORK/src"
rm "$WORK/src.tar"
cd "$WORK/src"
logged build sh gui/build-macos.sh
logged bundle-contract node --test gui/tests/bundle-contract.test.js
ditto -c -k --keepParent "target/release/bundle/macos/$APP" "$WORK/share/app.zip"

# The fake login keychain and Notes store would replace the guest's own.
step 'Making a decoy home'
logged decoys sh security-tests/harness.sh generate-home "$WORK/decoys"
tar -cf "$WORK/share/decoys.tar" -C "$WORK/decoys/home" \
    --exclude 'login.keychain-db' --exclude 'NoteStore.sqlite*' .
if tar -tf "$WORK/share/decoys.tar" | grep -q -e 'login.keychain-db' -e 'NoteStore.sqlite'; then
    fail 'the decoy archive still holds the keychain or the Notes store'
fi
cd "$WORK"
rm -rf "$WORK/src"

step "Starting a new VM, $VM"
logged clone "$TART" clone "$BASE" "$VM"
nohup "$TART" run "$VM" --dir="share:$WORK/share:ro" > "$WORK/run.log" 2>&1 &
tries=0
until guest test -f "$SHARED/decoys.tar" > /dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 90 ] || fail "the VM did not answer within three minutes; see $WORK/run.log"
    sleep 2
done

step 'Copying the app and the decoy home in'
for file in app.zip decoys.tar; do
    here=$(shasum -a 256 "$WORK/share/$file" | cut -d ' ' -f 1)
    there=$(guest shasum -a 256 "$SHARED/$file" | cut -d ' ' -f 1)
    [ "$here" = "$there" ] || fail "$file differs in the guest"
done
guest test ! -e "/Applications/$APP" || fail 'the guest already has the app'
guest ditto -x -k "$SHARED/app.zip" /Applications
guest codesign --verify --deep --strict "/Applications/$APP"
guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$SHARED/decoys.tar"
guest sh -c 'test ! -e "$HOME/Library/Application Support/dev.loosekeys.desktop"' \
    || fail 'the guest already has app state, so it is not a first run'
guest sync

step 'Opening the app'
guest open "/Applications/$APP"

printf '\nVM:      %s (window open, nothing scanned yet)\n' "$VM"
printf 'Commit:  %s (%s)\n' "$COMMIT" "$REF"
printf 'Signed:  %s\n' "$LOOSE_KEYS_SIGN_IDENTITY"
printf 'Decoys:  %s\n' "$WORK/decoys"
printf 'Stop:    tart stop %s   Delete: tart delete %s\n' "$VM" "$VM"
