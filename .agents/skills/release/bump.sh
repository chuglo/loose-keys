#!/bin/sh
# Set the version everywhere it is written: both Cargo.toml files, Cargo.lock,
# README.md and the bundle's Info.plist.
# Usage, from the root of a worktree: sh .agents/skills/release/bump.sh <new version>
set -eu

NEW=${1:?usage: bump.sh <new version, e.g. 0.4.0>}
printf '%s\n' "$NEW" | grep -Eq '^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
    || { printf 'expected a version of the form 0.y.z\n' >&2; exit 1; }
[ -f gui/macos/Info.plist ] || { printf 'run this from the repository root\n' >&2; exit 1; }
[ -f .git ] || { printf 'run this in a git worktree\n' >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { printf 'commit or preserve existing changes before the bump\n' >&2; exit 1; }
OLD=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
[ "$OLD" != "$NEW" ] || { printf 'already %s\n' "$NEW" >&2; exit 1; }
O=$(printf '%s' "$OLD" | sed 's/\./\\./g')

sed -i '' "s/^version = \"$O\"\$/version = \"$NEW\"/" Cargo.toml gui/Cargo.toml
sed -i '' "s/^Version $O\\([ ,].*\\)\$/Version $NEW\\1/" README.md
sed -i '' "s#<string>$O</string>#<string>$NEW</string>#g" gui/macos/Info.plist
cargo metadata --offline --format-version 1 > /dev/null  # rewrites Cargo.lock

changed=$(git diff --name-only | LC_ALL=C sort | tr '\n' ' ')
want='Cargo.lock Cargo.toml README.md gui/Cargo.toml gui/macos/Info.plist '
[ "$changed" = "$want" ] || { printf 'expected changes in %sgot %s\n' "$want" "$changed" >&2; exit 1; }
if git grep -n -F "$OLD" -- Cargo.toml gui/Cargo.toml README.md gui/macos/Info.plist; then
    printf 'the old version is still written above\n' >&2
    exit 1
fi
printf '%s -> %s in %s\n' "$OLD" "$NEW" "$changed"
