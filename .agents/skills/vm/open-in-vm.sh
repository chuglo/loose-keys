#!/bin/sh
# Build Loose Keys on this Mac, then open it in a new tart VM whose home holds
# synthetic decoys. The app runs only in the guest.
# Usage, from the repository root:
#   sh .agents/skills/vm/open-in-vm.sh [ref [ref] | .]
#   sh .agents/skills/vm/open-in-vm.sh --into <VM> [ref [ref] | .]
# Two refs are built together, combined as Git would merge them, and `.` is
# this checkout with its uncommitted changes. Neither makes a commit: nothing
# is added to the history for a change that may be dropped. --into puts the
# build into a VM this script opened earlier, keeping the app's saved state.
set -eu

INTO=
if [ "${1:-}" = --into ]; then
    INTO=${2:?usage: open-in-vm.sh --into <VM> [ref [ref] | .]}
    shift 2
fi
REF=${1:-main}
REF2=${2:-}
TAHOE=ghcr.io/cirruslabs/macos-tahoe-base:latest
SIP_BASE=lk-sip-base
SHARED='/Volumes/My Shared Files/share'
APP='Loose Keys.app'
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
# The names this script gives its VMs, and the window check's clones.
OURS='^lk-[0-9a-f]+(-[0-9a-f]+)?(-local)?-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]$'

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
# A run that fails after starting its VM stops it, so it does not hold one of
# the two slots. The VM is kept, with its logs.
STARTED=
stop_on_failure() {
    status=$?
    if [ "$status" -ne 0 ] && [ -n "$STARTED" ]; then
        "$TART" stop "$VM" > /dev/null 2>&1 && printf 'Stopped %s; it is kept for its logs.\n' "$VM" >&2
    fi
}
trap stop_on_failure EXIT
# This Mac runs at most two VMs. Say so before a build, and again just before
# starting a VM, since another session may have started one meanwhile.
slots() {
    running=$("$TART" list | awk '$NF == "running" { print $2 }')
    if [ "$(printf '%s\n' "$running" | grep -c .)" -ge 2 ]; then
        fail "two VMs are running already ($(printf '%s' "$running" | tr '\n' ' ')); one must stop first"
    fi
}
state_of() { "$TART" list | awk -v vm="$1" '$2 == vm { print $NF }'; }

[ -f gui/macos/Info.plist ] || fail 'run this from the repository root'
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
[ -x "$TART" ] || fail "tart not found at $TART"
if [ -n "$INTO" ]; then
    printf '%s\n' "$INTO" | grep -Eq "$OURS" || fail "$INTO is not a VM this script opened"
    [ "$(state_of "$INTO")" = running ] || fail "$INTO is not running"
    INTO_SHARE="${TMPDIR%/}/vm-${INTO#lk-}/share"
    [ -d "$INTO_SHARE" ] || fail "no shared folder for $INTO at $INTO_SHARE; was it opened with this TMPDIR?"
else
    slots
fi

LOCAL=
if [ "$REF" = . ]; then
    # This checkout as it is, uncommitted changes and new files included, as a
    # tree in a scratch index: the checkout's own index is not touched.
    [ -z "$REF2" ] || fail 'a second ref cannot be built with .'
    COMMIT=$(git rev-parse --verify HEAD)
    SHORT="$(git rev-parse --short HEAD)-local"
    index=$(mktemp "${TMPDIR%/}/vm-index.XXXXXX")
    cp "$(git rev-parse --git-path index)" "$index"
    GIT_INDEX_FILE=$index git add -A
    SOURCE=$(GIT_INDEX_FILE=$index git write-tree)
    rm -f "$index"
    LOCAL=1
else
    COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") || fail "not a commit: $REF"
    SHORT=$(git rev-parse --short "$COMMIT")
    SOURCE=$COMMIT
fi
if [ -n "$REF2" ]; then
    COMMIT2=$(git rev-parse --verify --quiet "$REF2^{commit}") || fail "not a commit: $REF2"
    SOURCE=$(git merge-tree --write-tree "$COMMIT" "$COMMIT2") \
        || fail "$REF and $REF2 do not combine without conflicts"
    SHORT="$SHORT-$(git rev-parse --short "$COMMIT2")"
fi
STAMP=$(date +%m%d-%H%M%S)
VM=${INTO:-"lk-$SHORT-$STAMP"}
WORK="${TMPDIR%/}/vm-$SHORT-$STAMP"
PROFILE=${LOOSE_KEYS_PROFILE:-}
EXTRA=${LOOSE_KEYS_EXTRA_HOME:-}
if [ -n "$INTO" ] && { [ -n "$PROFILE" ] || [ -n "$EXTRA" ]; }; then
    fail 'a profile or extra home files need a new VM, not --into'
fi
if [ -n "$PROFILE" ]; then
    [ -f "$PROFILE" ] || fail "no profile at $PROFILE"
    PROFILE_ID=$(/usr/bin/plutil -extract PayloadIdentifier raw -o - "$PROFILE") \
        || fail "$PROFILE has no PayloadIdentifier"
fi
if [ -n "$EXTRA" ]; then
    EXTRA=$(cd "$EXTRA" && pwd -P) || fail "no folder at $LOOSE_KEYS_EXTRA_HOME"
fi
# The clone with SIP on, when this Mac has it, so that macOS asks for folders
# and app data as on a real Mac. The tahoe image boots with SIP off and asks
# for none of them.
BASE=${LOOSE_KEYS_BASE:-}
if [ -z "$BASE" ] && [ -z "$INTO" ]; then
    if [ "$(state_of "$SIP_BASE")" = stopped ]; then BASE=$SIP_BASE; else BASE=$TAHOE; fi
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

# An export of the source alone: no old target/, and no uncommitted change
# unless `.` asked for them.
step "Building $SHORT ($REF${REF2:+ with $REF2}${LOCAL:+, with uncommitted changes})"
git archive --format=tar -o "$WORK/src.tar" "$SOURCE"
tar -xf "$WORK/src.tar" -C "$WORK/src"
rm "$WORK/src.tar"
cd "$WORK/src"
logged build sh gui/build-macos.sh
logged bundle-contract node --test gui/tests/bundle-contract.test.js
ZIP="app-$SHORT-$STAMP.zip"
ditto -c -k --keepParent "target/release/bundle/macos/$APP" "$WORK/share/$ZIP"

if [ -n "$INTO" ]; then
    cd "$WORK"
    rm -rf "$WORK/src"
    step "Putting it into $VM"
    cp "$WORK/share/$ZIP" "$INTO_SHARE/$ZIP"
    here=$(shasum -a 256 "$INTO_SHARE/$ZIP" | cut -d ' ' -f 1)
    there=$(guest shasum -a 256 "$SHARED/$ZIP" | cut -d ' ' -f 1)
    [ "$here" = "$there" ] || fail "$ZIP differs in the guest"
    # The new app beside the old one first, so a failure leaves the old one.
    guest rm -rf "/private/tmp/lk-new-$STAMP"
    guest mkdir -p "/private/tmp/lk-new-$STAMP"
    guest ditto -x -k "$SHARED/$ZIP" "/private/tmp/lk-new-$STAMP"
    guest codesign --verify --deep --strict "/private/tmp/lk-new-$STAMP/$APP"
    # The app's state is saved as it changes, so ending it loses nothing. The
    # helper is restarted from the new app below, if it was loaded.
    guest pkill -f 'MacOS/loose-keys-gui$' || true
    tries=0
    while guest pgrep -f 'MacOS/loose-keys-gui$' > /dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 15 ] || fail 'the app did not quit'
        sleep 1
    done
    guest mv "/Applications/$APP" "/private/tmp/lk-old-$STAMP.app"
    guest mv "/private/tmp/lk-new-$STAMP/$APP" "/Applications/$APP"
    HELPER=$(guest sh -c 'launchctl print "gui/$(id -u)/dev.loosekeys.agent" > /dev/null 2>&1 && echo loaded || echo none')
    if [ "$HELPER" = loaded ]; then
        guest sh -c 'launchctl kickstart -k "gui/$(id -u)/dev.loosekeys.agent"'
    fi
    guest sync
else
    # The fake login keychain and Notes store would replace the guest's own.
    # With SIP on, the guest also refuses tar's change to the Notes group
    # container and to the folders macOS asks about.
    step 'Making a decoy home'
    logged decoys sh security-tests/harness.sh generate-home "$WORK/decoys"
    if [ "$BASE" = "$SIP_BASE" ]; then
        tar -cf "$WORK/share/decoys.tar" -C "$WORK/decoys/home" \
            --exclude 'login.keychain-db' --exclude 'NoteStore.sqlite*' --exclude 'Group Containers' \
            --exclude './Desktop' --exclude './Documents' --exclude './Downloads' .
    else
        tar -cf "$WORK/share/decoys.tar" -C "$WORK/decoys/home" \
            --exclude 'login.keychain-db' --exclude 'NoteStore.sqlite*' .
    fi
    if tar -tf "$WORK/share/decoys.tar" | grep -q -e 'login.keychain-db' -e 'NoteStore.sqlite'; then
        fail 'the decoy archive still holds the keychain or the Notes store'
    fi
    [ -z "$EXTRA" ] || tar -cf "$WORK/share/extra.tar" -C "$EXTRA" .
    cd "$WORK"
    rm -rf "$WORK/src"

    step "Starting a new VM, $VM, from $BASE"
    slots
    logged clone "$TART" clone "$BASE" "$VM"
    nohup "$TART" run "$VM" --dir="share:$WORK/share:ro" > "$WORK/run.log" 2>&1 &
    RUN_PID=$!
    STARTED=1
    tries=0
    until guest test -f "$SHARED/decoys.tar" > /dev/null 2>&1; do
        kill -0 "$RUN_PID" 2> /dev/null \
            || fail "the VM stopped: $(tail -n 1 "$WORK/run.log" 2> /dev/null)"
        tries=$((tries + 1))
        [ "$tries" -lt 90 ] || fail "the VM did not answer within three minutes; see $WORK/run.log"
        sleep 2
    done

    step 'Copying the app and the decoy home in'
    FILES="$ZIP decoys.tar"
    [ -z "$EXTRA" ] || FILES="$FILES extra.tar"
    [ -z "$PROFILE" ] || FILES="$FILES install-profile profile.mobileconfig"
    for file in $FILES; do
        here=$(shasum -a 256 "$WORK/share/$file" | cut -d ' ' -f 1)
        there=$(guest shasum -a 256 "$SHARED/$file" | cut -d ' ' -f 1)
        [ "$here" = "$there" ] || fail "$file differs in the guest"
    done
    guest test ! -e "/Applications/$APP" || fail 'the guest already has the app'
    guest ditto -x -k "$SHARED/$ZIP" /Applications
    guest codesign --verify --deep --strict "/Applications/$APP"
    guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$SHARED/decoys.tar"
    [ -z "$EXTRA" ] || guest sh -c 'tar -xf "$1" -C "$HOME"' sh "$SHARED/extra.tar"
    guest sh -c 'test ! -e "$HOME/Library/Application Support/dev.loosekeys.desktop"' \
        || fail 'the guest already has app state, so it is not a first run'
    guest sync

    # Installed through System Settings as a person would, before the app's
    # first start. The password is the base image's published administrator
    # password.
    if [ -n "$PROFILE" ]; then
        step 'Installing the configuration profile'
        guest env LOOSE_KEYS_PROFILE_CHECK=disposable-guest LOOSE_KEYS_GUEST_PASSWORD=admin \
            "$SHARED/install-profile" "$SHARED/profile.mobileconfig" > "$WORK/profile.log" 2>&1 \
            || fail "installing the profile; see $WORK/profile.log"
        grep '^PASS' "$WORK/profile.log"
    fi
fi

step 'Opening the app'
guest open "/Applications/$APP"
RUNNING_APP='not seen running within 10 seconds'
tries=0
while [ "$tries" -lt 10 ]; do
    if guest pgrep -f 'MacOS/loose-keys-gui$' > /dev/null 2>&1; then
        RUNNING_APP=running
        break
    fi
    tries=$((tries + 1))
    sleep 1
done

if [ -n "$INTO" ]; then
    printf '\nVM:      %s (the new app is open; its saved state and the decoys are kept)\n' "$VM"
else
    printf '\nVM:      %s (window open, nothing scanned yet)\n' "$VM"
    if [ "$BASE" = "$SIP_BASE" ]; then
        printf 'Base:    %s (SIP on: macOS asks for folders and app data as on a real Mac)\n' "$BASE"
    else
        printf 'Base:    %s (SIP off: macOS asks for no folders, and the helper differs from a real Mac)\n' "$BASE"
    fi
fi
printf 'App:     %s\n' "$RUNNING_APP"
printf 'Commit:  %s (%s)%s\n' "$COMMIT" "$REF" "${LOCAL:+, with uncommitted changes (not committed)}"
[ -z "$REF2" ] || printf 'With:    %s (%s), combined without a commit\n' "$COMMIT2" "$REF2"
printf 'Signed:  %s\n' "$LOOSE_KEYS_SIGN_IDENTITY"
if [ -n "$INTO" ]; then
    [ "$HELPER" = loaded ] && printf 'Helper:  restarted from the new app\n'
    [ "$LOOSE_KEYS_SIGN_IDENTITY" = - ] && printf 'Note:    ad hoc signing changes with each build, so macOS may refuse the helper\n'
else
    printf 'Decoys:  %s\n' "$WORK/decoys"
    [ -z "$EXTRA" ] || printf 'Extra:   %s\n' "$EXTRA"
    [ -z "$PROFILE" ] || printf 'Profile: %s (installed; in the guest, sudo profiles remove -identifier %s removes it)\n' \
        "$PROFILE" "$PROFILE_ID"
fi
printf 'Stop:    tart stop %s   Delete: tart delete %s\n' "$VM" "$VM"
# Each run leaves a clone, as each window check does. Only stopped ones of
# those are listed, never a base image or another session's working VM.
OLD=$("$TART" list | awk -v vm="$VM" -v ours="$OURS" \
    '$NF == "stopped" && $2 != vm && ($2 ~ ours || $2 ~ /^lk-window-/) { print $2 }' | tr '\n' ' ')
[ -z "$OLD" ] || printf 'Older:   tart delete %s(stopped clones from earlier runs)\n' "$OLD"
exit 0
