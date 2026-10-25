#!/bin/sh
# Development check of the window's behaviour, on sample data: no engine, no
# scan, and nothing in a home folder is read. It builds the window, then the
# window uses itself through the interface assistive software uses (see Checks
# in gui/app/Preview.swift) and says what did not work. A window appears on
# screen for about a minute. It does not come to the front; leave it alone.
# It needs the screen awake: with the screen locked or its saver on it stops
# with status 2 and one line saying so, having checked nothing.
set -eu
if [ ! -f gui/app/Preview.swift ]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 1
fi
OUT=${1:-target/window-check}
mkdir -p "$OUT"
rm -f "$OUT/report.txt" "$OUT/report.txt.log"
# The bundle's English plural forms, and no other language, next to the
# executable, so the check reads English whatever the Mac's language.
rm -rf "$OUT"/*.lproj
mkdir "$OUT/en.lproj"
cp gui/macos/en.lproj/Localizable.stringsdict "$OUT/en.lproj/Localizable.stringsdict"
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
swiftc -parse-as-library -D PREVIEW -target "$(uname -m)-apple-macosx$MINIMUM" \
    gui/app/*.swift -framework AppKit -framework ApplicationServices -o "$OUT/window-check"
status=0
# OS_ACTIVITY_DT_MODE also sends what AppKit logs to the file the check reads.
OS_ACTIVITY_DT_MODE=YES CHECK_REPORT="$OUT/report.txt" "$OUT/window-check" || status=$?
if [ ! -f "$OUT/report.txt" ]; then
    printf '%s\n' "The window stopped before it finished (status $status), after:" >&2
    grep '^step: ' "$OUT/report.txt.log" | tail -n 3 >&2 || true
    printf '%s\n' "Its output: $OUT/report.txt.log" >&2
    exit 1
fi
cat "$OUT/report.txt"
exit "$status"
