#!/bin/sh
# Run only in an approved synthetic macOS guest; does not change the bundle.
set -eu
if [ "${LOOSE_KEYS_APP_CHECK:-}" != synthetic-home ] ||
   ! /usr/sbin/sysctl -n hw.model | /usr/bin/grep -q '^VirtualMac'; then
    echo 'FAIL: this check requires an approved synthetic macOS guest' >&2
    exit 2
fi
if [ "$#" -ne 1 ]; then
    echo 'Usage: sh gui/tests/check-update-quit.sh <new-workdir>' >&2
    exit 2
fi
umask 077
mkdir "$1"
work=$(cd "$1" && pwd -P)
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
swiftc -target "$(uname -m)-apple-macosx$MINIMUM" gui/tests/update-quit.swift \
    -o "$work/update-quit" -framework AppKit -framework ApplicationServices
exec "$work/update-quit" "$PWD/target/release/bundle/macos/Loose Keys.app" "$work"
