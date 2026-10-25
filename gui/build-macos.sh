#!/bin/sh
# Local app bundle only. No distribution, notarization, or app launch.
set -eu
if [ "$(uname -s)" != Darwin ]; then
    printf '%s\n' 'This build script requires macOS.' >&2
    exit 1
fi
if [ ! -f gui/macos/Info.plist ]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 1
fi
# Signed ad hoc unless LOOSE_KEYS_SIGN_IDENTITY names a code-signing identity,
# such as an Apple Development one.
IDENTITY=${LOOSE_KEYS_SIGN_IDENTITY:--}
# Checked before the old bundle is removed, so a wrong name leaves it in place.
if [ "$IDENTITY" != - ] && ! /usr/bin/security find-identity -v -p codesigning | grep -q -F -- "$IDENTITY"; then
    printf '%s\n' "No valid code-signing identity matches LOOSE_KEYS_SIGN_IDENTITY ($IDENTITY)." \
        'List them with: security find-identity -v -p codesigning' >&2
    exit 1
fi
APP='target/release/bundle/macos/Loose Keys.app'
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
# The engine (the scanner, review store and background agent, as a static
# library) and the `loose-keys` command, built for the macOS that
# .cargo/config.toml sets. Keep the output location fixed, even if the caller
# has CARGO_TARGET_DIR set.
cargo build --workspace --target-dir target --locked --release
# Start from an empty bundle, so nothing left by an earlier build is signed into it.
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
# The keys the window looks up, so the bundle contract test can check each has its Spanish.
STRINGS=target/release/strings
rm -rf "$STRINGS"
mkdir -p "$STRINGS"
# The window, linked with the engine into one executable. Run with --agent it
# is the background agent and starts no app.
swiftc -parse-as-library -O -target "$(uname -m)-apple-macosx$MINIMUM" \
    -import-objc-header gui/app/Bridge.h gui/app/*.swift \
    target/release/libloose_keys_gui.a \
    -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices \
    -Xlinker -dead_strip \
    -emit-localized-strings -emit-localized-strings-path "$STRINGS" \
    -o "$APP/Contents/MacOS/loose-keys-gui"
cp gui/macos/Info.plist "$APP/Contents/Info.plist"
# The command line: the same scanner, run once from a terminal.
cp target/release/loose-keys "$APP/Contents/MacOS/loose-keys"
# The icon at the sizes macOS asks for, with the margin its icon grid expects.
ICONSET=target/release/AppIcon.iconset
rm -rf "$ICONSET"
mkdir -p "$ICONSET" "$APP/Contents/Resources"
icon() {
    /usr/bin/sips -z "$(($1 * 824 / 1024))" "$(($1 * 824 / 1024))" gui/icons/icon.png \
        --padToHeightWidth "$1" "$1" --out "$ICONSET/$2" > /dev/null
}
for size in 16 32 128 256 512; do
    icon "$size" "icon_${size}x${size}.png"
done
# The artwork is 512 pixels, so the largest double-density size is left out.
for size in 16 32 128 256; do
    icon "$((size * 2))" "icon_${size}x${size}@2x.png"
done
/usr/bin/iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
# The window's English plural forms and its Spanish, as binary property lists.
# Each table is named, so nothing else in those folders, such as a .DS_Store,
# reaches the bundle, and a table with a syntax error fails the build.
RESOURCES="$APP/Contents/Resources"
mkdir -p "$RESOURCES/en.lproj" "$RESOURCES/es.lproj" "$RESOURCES/es-419.lproj"
table() {
    /usr/bin/plutil -convert binary1 -o "$RESOURCES/$2" "$1"
}
table gui/macos/en.lproj/Localizable.stringsdict en.lproj/Localizable.stringsdict
for name in Engine.strings InfoPlist.strings Localizable.strings Localizable.stringsdict; do
    table "gui/macos/es.lproj/$name" "es.lproj/$name"
done
# macOS shows English for a key es-419.lproj lacks, without looking in
# es.lproj, so Latin American Spanish is the Spanish of Spain with its own
# entries after it. Of two entries with one key, the later is kept.
for name in Engine.strings Localizable.strings; do
    cat "gui/macos/es.lproj/$name" "gui/macos/es-419.lproj/$name" > target/release/es-419.strings
    table target/release/es-419.strings "es-419.lproj/$name"
done
for name in InfoPlist.strings Localizable.stringsdict; do
    table "gui/macos/es.lproj/$name" "es-419.lproj/$name"
done
# The background agent's launchd job, which the app registers with macOS.
mkdir -p "$APP/Contents/Library/LaunchAgents"
cp gui/macos/dev.loosekeys.agent.plist "$APP/Contents/Library/LaunchAgents/dev.loosekeys.agent.plist"
# Bind the completed bundle to its notification identity, not the linker name.
identifier=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - gui/macos/Info.plist)
# Nested code is signed before the bundle that seals it. No timestamp, so
# signing never contacts Apple's timestamp server.
/usr/bin/codesign --force --sign "$IDENTITY" --timestamp=none --identifier "$identifier.cli" "$APP/Contents/MacOS/loose-keys"
/usr/bin/codesign --force --sign "$IDENTITY" --timestamp=none --identifier "$identifier" "$APP"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP"
# A rebuild changes only what is inside the bundle. Without a new date on the
# bundle itself, the Dock and Finder keep showing the icon they first saw.
touch "$APP"
printf '%s\n' "Built local app bundle: $APP"
printf '%s\n' 'The bundle is not notarized. It has not been launched.'
