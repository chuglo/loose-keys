#!/bin/sh
# Guest only. CREDHYG_APP_CHECK=synthetic-home is required. Never use a real home.
# Builds a separate AX driver; the shipped bundle is not changed.
set -eu
if [ "${CREDHYG_APP_CHECK:-}" != synthetic-home ]; then
    echo 'FAIL: set CREDHYG_APP_CHECK=synthetic-home in an approved test guest' >&2
    exit 2
fi
if [ "$#" -ne 1 ]; then
    echo 'Usage: sh gui/tests/check-app.sh <new-workdir>' >&2
    exit 2
fi
umask 077
mkdir "$1"
work=$(cd "$1" && pwd -P)
swiftc gui/tests/app-check.swift -o "$work/app-check" -framework AppKit -framework ApplicationServices
exec "$work/app-check" "$PWD/target/release/bundle/macos/Loose Keys.app" "$work"
