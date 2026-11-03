#!/bin/sh
# Guest only. LOOSE_KEYS_APP_CHECK=synthetic-home is required. Never use a real home.
# Builds a separate AX driver; the shipped bundle is not changed.
set -eu
if [ "${LOOSE_KEYS_APP_CHECK:-}" != synthetic-home ] ||
   ! /usr/sbin/sysctl -n hw.model | /usr/bin/grep -q '^VirtualMac'; then
    echo 'FAIL: set LOOSE_KEYS_APP_CHECK=synthetic-home in an approved test guest' >&2
    exit 2
fi
if [ "$#" -ne 1 ]; then
    echo 'Usage: sh gui/tests/check-app.sh <new-workdir>' >&2
    exit 2
fi
umask 077
mkdir "$1"
work=$(cd "$1" && pwd -P)
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
swiftc -target "$(uname -m)-apple-macosx$MINIMUM" gui/tests/app-check.swift \
    -o "$work/app-check" -framework AppKit -framework ApplicationServices
exec "$work/app-check" "$PWD/target/release/bundle/macos/Loose Keys.app" "$work"
