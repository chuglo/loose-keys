#!/bin/sh
# Package the already-built app; never launches it or writes to Applications.
set -eu
umask 077
[ "$(uname -s)" = Darwin ] || { echo 'This script requires macOS.' >&2; exit 1; }
APP='target/release/bundle/macos/Loose Keys.app'
[ -d "$APP" ] || { echo 'Run sh gui/build-macos.sh from the repository root first.' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$APP"
VERSION=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$APP/Contents/Info.plist")
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || exit 1
OUT="target/release/bundle/macos/Loose-Keys-$VERSION.dmg"
# hdiutil also refuses an existing destination; do not replace a tested image.
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "Already exists: $OUT" >&2; exit 1; }
STAGE=$(mktemp -d "${TMPDIR:-/private/tmp}/loose-keys-dmg.$$.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
trap 'exit 1' HUP INT TERM
/usr/bin/ditto "$APP" "$STAGE/Loose Keys.app"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/How to install.txt" <<'TEXT'
Drag Loose Keys to Applications.
Then eject this disk and open Loose Keys from Applications.

Arrastra Loose Keys a Aplicaciones.
Después expulsa este disco y abre Loose Keys desde Aplicaciones.
TEXT
/usr/bin/hdiutil create -volname 'Loose Keys' -srcfolder "$STAGE" \
    -fs HFS+ -format UDZO "$OUT"
/usr/bin/hdiutil verify "$OUT"
printf 'Built disk image: %s\n' "$OUT"
