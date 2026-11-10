#!/bin/sh
# Development check of the native bridges: the login, notification and power
# contracts. Each builds against gui/src/notifications.m and runs on its own,
# registering no real service and delivering no notification. Runs all three
# and exits 1 if any failed.
set -u
if [ ! -f gui/src/notifications.m ]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 1
fi
OUT=${1:-target/bridge-check}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)
# Built for the app's minimum macOS, as gui/build.rs builds the bridge.
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist) || exit 1
status=0
for name in login notifications power; do
    if (cd gui && clang -fobjc-arc -fblocks -mmacosx-version-min="$MINIMUM" -Werror=unguarded-availability "tests/${name}_test.m" \
        -framework AppKit -framework UserNotifications -framework ServiceManagement \
        -framework CoreServices -o "$OUT/$name") && "$OUT/$name"; then
        printf 'PASS: %s bridge\n' "$name"
    else
        printf 'FAIL: %s bridge\n' "$name" >&2
        status=1
    fi
done
exit "$status"
