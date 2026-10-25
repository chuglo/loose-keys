#!/bin/sh
# Development check of the window's model, with no window: no engine, no
# scan, and nothing in a home folder is read. It builds the real AppModel with
# a stand-in engine that answers when the test says
# (gui/tests/refresh-order.swift), makes answers arrive out of order, and says
# what the model then showed wrongly. Built as the sample-data window is, with
# PREVIEW, which leaves out the engine's C interface.
set -eu
if [ ! -f gui/tests/refresh-order.swift ]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 1
fi
OUT=${1:-target/model-check}
mkdir -p "$OUT"
# The bundle's English plural forms, and no other language, next to the
# executable, so the check reads English whatever the Mac's language.
rm -rf "$OUT"/*.lproj
mkdir "$OUT/en.lproj"
cp gui/macos/en.lproj/Localizable.stringsdict "$OUT/en.lproj/Localizable.stringsdict"
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
swiftc -parse-as-library -D PREVIEW -target "$(uname -m)-apple-macosx$MINIMUM" \
    gui/app/AppModel.swift gui/app/Models.swift gui/app/Engine.swift \
    gui/tests/refresh-order.swift -framework AppKit -o "$OUT/model-check"
exec "$OUT/model-check"
