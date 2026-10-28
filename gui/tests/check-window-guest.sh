#!/bin/sh
# Run the sample window check in a fresh, headless disposable macOS guest.
# Uses a cached Tart base and guest command-line tools; never launches host UI.
set -eu
umask 077
[ -f gui/app/Preview.swift ] || { echo 'Run from the repository root.' >&2; exit 1; }
TART=$(command -v tart) || { echo 'Tart is required.' >&2; exit 1; }
# Infrastructure deadlines are separate from the window check's own assertions.
ACTIVE_PID=
bounded() {
    limit=$1
    shift
    "$@" &
    ACTIVE_PID=$!
    command_deadline=$(( $(date +%s) + limit ))
    while kill -0 "$ACTIVE_PID" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$command_deadline" ]; then
            printf 'Infrastructure command exceeded %ss: %s\n' "$limit" "$1" >&2
            kill -KILL "$ACTIVE_PID" 2>/dev/null || true
            wait "$ACTIVE_PID" 2>/dev/null || true
            ACTIVE_PID=
            return 124
        fi
        sleep 1
    done
    if wait "$ACTIVE_PID"; then command_status=0; else command_status=$?; fi
    ACTIVE_PID=
    return "$command_status"
}
BASE=ghcr.io/cirruslabs/macos-tahoe-base:latest
available=$(bounded 15 "$TART" list) || exit 1
printf '%s\n' "$available" | awk -v base="$BASE" '$2 == base { found=1 } END { exit !found }' || {
    echo "Cached Tart image required: $BASE (no image was downloaded)." >&2
    exit 1
}
OUT=${1:-target/window-guest-check}
mkdir -p "$OUT"
WORK=$(mktemp -d "$OUT/run.XXXXXX")
WORK=$(cd "$WORK" && pwd -P)
mkdir "$WORK/share"
VM="lk-window-$(date +%Y%m%d-%H%M%S)-$$"
OWNED=
RUN_PID=
READY_PID=
READY=
cleanup() {
    code=$?
    trap - EXIT HUP INT TERM
    if [ -n "$ACTIVE_PID" ]; then
        kill -KILL "$ACTIVE_PID" 2>/dev/null || true
        wait "$ACTIVE_PID" 2>/dev/null || true
        ACTIVE_PID=
    fi
    if [ -n "$READY_PID" ]; then
        kill -KILL "$READY_PID" 2>/dev/null || true
        wait "$READY_PID" 2>/dev/null || true
    fi
    if [ -n "$OWNED" ]; then
        if [ -n "$READY" ]; then
            bounded 10 "$TART" exec "$VM" sync > "$WORK/sync.log" 2>&1 || true
        fi
        if bounded 30 "$TART" stop "$VM" > "$WORK/stop.log" 2>&1; then
            printf 'VM: %s (stopped)\n' "$VM"
        else
            printf 'FAILED: could not stop %s; see %s/stop.log\n' "$VM" "$WORK" >&2
            code=1
        fi
    fi
    if [ -n "$RUN_PID" ]; then
        kill -KILL "$RUN_PID" 2>/dev/null || true
        wait "$RUN_PID" 2>/dev/null || true
    fi
    printf 'Logs: %s\n' "$WORK"
    exit "$code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# Snapshot exactly the current working-tree inputs, including uncommitted edits.
tar -cf "$WORK/share/source.tar" gui/app gui/macos/Info.plist \
    gui/macos/en.lproj gui/tests/check-window.sh
shasum -a 256 "$WORK/share/source.tar" > "$WORK/source.sha256"
bounded 120 "$TART" clone "$BASE" "$VM" > "$WORK/clone.log" 2>&1
OWNED=$VM
"$TART" run "$VM" --no-graphics --no-audio --no-clipboard \
    --dir="share:$WORK/share:ro" > "$WORK/run.log" 2>&1 &
RUN_PID=$!
deadline=$(( $(date +%s) + 180 ))
while :; do
    "$TART" exec "$VM" test -f '/Volumes/My Shared Files/share/source.tar' \
        >> "$WORK/ready.log" 2>&1 &
    READY_PID=$!
    while kill -0 "$READY_PID" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$deadline" ] || ! kill -0 "$RUN_PID" 2>/dev/null; then
            echo 'Guest startup failed or exceeded three minutes.' >&2
            exit 1
        fi
        sleep 1
    done
    if wait "$READY_PID"; then
        READY_PID=
        break
    fi
    READY_PID=
    if [ "$(date +%s)" -ge "$deadline" ] || ! kill -0 "$RUN_PID" 2>/dev/null; then
        echo 'Guest startup failed or exceeded three minutes.' >&2
        exit 1
    fi
    sleep 1
done
READY=yes
here=$(cut -d ' ' -f 1 "$WORK/source.sha256")
remote_checksum=$(bounded 30 "$TART" exec "$VM" shasum -a 256 '/Volumes/My Shared Files/share/source.tar') || exit 1
there=$(printf '%s\n' "$remote_checksum" | cut -d ' ' -f 1)
[ "$here" = "$there" ] || { echo 'Transferred source checksum differs.' >&2; exit 1; }
bounded 600 "$TART" exec "$VM" sh -c 'mkdir -p ~/window-work &&
    tar -xf "/Volumes/My Shared Files/share/source.tar" -C ~/window-work &&
    cd ~/window-work && caffeinate -d -i sh gui/tests/check-window.sh "$HOME/window-check"' \
    > "$WORK/check.log" 2>&1 && status=0 || status=$?
# Retain both diagnostics even when the check fails before writing its report.
for file in report.txt report.txt.log; do
    bounded 30 "$TART" exec "$VM" sh -c 'cat "$HOME/window-check/$1"' sh "$file" \
        > "$WORK/$file" 2> "$WORK/$file.copy.log" || true
done
cat "$WORK/check.log"
printf 'window check: exit %s\n' "$status"
exit "$status"
