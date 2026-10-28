#!/bin/sh
# Build one commit of Loose Keys on this Mac, then open it in a new tart VM
# whose home holds synthetic decoys. The app runs only in the guest.
# Usage, from the repository root: sh .agents/skills/vm/open-in-vm.sh [git ref]
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
PROFILE=${LOOSE_KEYS_PROFILE:-}
EXTRA=${LOOSE_KEYS_EXTRA_HOME:-}
if [ -n "$PROFILE" ]; then
    [ -f "$PROFILE" ] || fail "no profile at $PROFILE"
    PROFILE_ID=$(/usr/bin/plutil -extract PayloadIdentifier raw -o - "$PROFILE") \
        || fail "$PROFILE has no PayloadIdentifier"
fi
if [ -n "$EXTRA" ]; then
    EXTRA=$(cd "$EXTRA" && pwd -P) || fail "no folder at $LOOSE_KEYS_EXTRA_HOME"
fi
mkdir -p "$WORK/src" "$WORK/share"

# The profile driver comes from this checkout, like this script; the app from
# the commit.
if [ -n "$PROFILE" ]; then
    MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
    logged profile-driver swiftc -target "$(uname -m)-apple-macosx$MINIMUM" \
        gui/tests/install-profile.swift -o "$WORK/share/install-profile" \
        -framework AppKit -framework ApplicationServices
    cp "$PROFILE" "$WORK/share/profile.mobileconfig"
fi

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
[ -z "$EXTRA" ] || tar -cf "$WORK/share/extra.tar" -C "$EXTRA" .
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
FILES='app.zip decoys.tar'
[ -z "$EXTRA" ] || FILES="$FILES extra.tar"
[ -z "$PROFILE" ] || FILES="$FILES install-profile profile.mobileconfig"
for file in $FILES; do
    here=$(shasum -a 256 "$WORK/share/$file" | cut -d ' ' -f 1)
    there=$(guest shasum -a 256 "$SHARED/$file" | cut -d ' ' -f 1)
    [ "$here" = "$there" ] || fail "$file differs in the guest"
done
guest test ! -e "/Applications/$APP" || fail 'the guest already has the app'
guest ditto -x -k "$SHARED/app.zip" /Applications
guest codesign --verify --deep --strict "/Applications/$APP"
guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$SHARED/decoys.tar"
[ -z "$EXTRA" ] || guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$SHARED/extra.tar"
guest sh -c 'test ! -e "$HOME/Library/Application Support/dev.loosekeys.desktop"' \
    || fail 'the guest already has app state, so it is not a first run'
guest sync

# Installed through System Settings as a person would, before the app's first
# start. The password is the base image's published administrator password.
if [ -n "$PROFILE" ]; then
    step 'Installing the configuration profile'
    guest env LOOSE_KEYS_PROFILE_CHECK=disposable-guest LOOSE_KEYS_GUEST_PASSWORD=admin \
        "$SHARED/install-profile" "$SHARED/profile.mobileconfig" > "$WORK/profile.log" 2>&1 \
        || fail "installing the profile; see $WORK/profile.log"
    grep '^PASS' "$WORK/profile.log"
fi

step 'Opening the app'
guest open "/Applications/$APP"

printf '\nVM:      %s (window open, nothing scanned yet)\n' "$VM"
printf 'Commit:  %s (%s)\n' "$COMMIT" "$REF"
printf 'Signed:  %s\n' "$LOOSE_KEYS_SIGN_IDENTITY"
printf 'Decoys:  %s\n' "$WORK/decoys"
[ -z "$EXTRA" ] || printf 'Extra:   %s\n' "$EXTRA"
[ -z "$PROFILE" ] || printf 'Profile: %s (installed; in the guest, sudo profiles remove -identifier %s removes it)\n' \
    "$PROFILE" "$PROFILE_ID"
printf 'Stop:    tart stop %s   Delete: tart delete %s\n' "$VM" "$VM"
