#!/bin/sh
# Build the release candidate for one commit on this Mac: the ad-hoc bundle
# that ships, zipped, plus the source and security harness the guest checks
# use. Every guest check and the GitHub release use this one zip.
# Usage, from the repository root: sh .agents/skills/release/candidate.sh <git ref>
set -eu
umask 077

REF=${1:?usage: candidate.sh <git ref>}
APP='Loose Keys.app'

fail() {
    printf 'FAILED: %s\n' "$*" >&2
    exit 1
}
logged() {
    name=$1
    shift
    "$@" > "$OUT/$name.log" 2>&1 || fail "$name; see $OUT/$name.log"
}

[ -f gui/macos/Info.plist ] || fail 'run this from the repository root'
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
[ "$(cd "$TMPDIR" && pwd -P)" = "${TMPDIR%/}" ] || fail 'TMPDIR must have no symbolic link in its path'
COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") || fail "not a commit: $REF"
SHORT=$(git rev-parse --short "$COMMIT")
VERSION=$(git show "$COMMIT:Cargo.toml" | sed -n 's/^version = "\(.*\)"$/\1/p' | head -n 1)
printf '%s\n' "$VERSION" | grep -Eq '^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'invalid version in Cargo.toml'
OUT=$(mktemp -d "${TMPDIR%/}/release-$VERSION-$SHORT.XXXXXX")
ZIP="Loose-Keys-$VERSION.zip"
DMG="Loose-Keys-$VERSION.dmg"
mkdir -p "$OUT/src" "$OUT/share"

# An export of the commit alone: no uncommitted change and no old target/.
git archive --format=tar -o "$OUT/share/repo.tar" "$COMMIT"
tar -xf "$OUT/share/repo.tar" -C "$OUT/src"
cd "$OUT/src"
export CARGO_TARGET_DIR="$OUT/src/target"

# Releases are signed ad hoc, as 0.1.0 and 0.2.0 were.
LOOSE_KEYS_SIGN_IDENTITY=- logged build sh gui/build-macos.sh
logged bundle-contract node --test gui/tests/bundle-contract.test.js
for file in gui/Cargo.toml gui/macos/Info.plist README.md; do
    grep -q -F "$VERSION" "$file" || fail "$file does not name $VERSION"
done
mkdir "$OUT/version-home"
CLI_VERSION=$(HOME="$OUT/version-home" "target/release/bundle/macos/$APP/Contents/MacOS/loose-keys" --version) \
    || fail 'the bundled version command failed'
[ "$CLI_VERSION" = "loose-keys $VERSION" ] || fail "the bundled command does not report $VERSION"
for key in CFBundleShortVersionString CFBundleVersion; do
    [ "$(/usr/libexec/PlistBuddy -c "Print :$key" "target/release/bundle/macos/$APP/Contents/Info.plist")" = "$VERSION" ] \
        || fail "the bundle's $key is not $VERSION"
done

# The helper check runs this harness in the guest, so the guest needs no Rust.
logged harness-build sh security-tests/harness.sh executable
cp "$(tail -n 1 "$OUT/harness-build.log")" "$OUT/share/security-harness"

logged disk-image sh gui/package-dmg.sh
cp "target/release/bundle/macos/$DMG" "$OUT/share/$DMG"
ditto -c -k --keepParent "target/release/bundle/macos/$APP" "$OUT/share/$ZIP"
(cd "$OUT/share" && shasum -a 256 "$ZIP") > "$OUT/$ZIP.sha256"
(cd "$OUT/share" && shasum -a 256 "$DMG") > "$OUT/$DMG.sha256"
cd "$OUT"
rm -rf "$OUT/src"
printf '%s %s\n' "$COMMIT" "$VERSION" > "$OUT/commit"
shasum -a 256 commit share/repo.tar share/security-harness "share/$ZIP" "share/$DMG" > "$OUT/SHA256SUMS"

printf 'Candidate: %s\n' "$OUT"
printf 'Commit:    %s (%s)\n' "$COMMIT" "$REF"
printf 'Disk image: %s\n' "$OUT/share/$DMG"
printf 'Zip:       %s\n' "$OUT/share/$ZIP"
printf 'SHA-256:   %s\n' "$(cut -d ' ' -f 1 "$OUT/$ZIP.sha256")"
printf 'DMG SHA-256: %s\n' "$(cut -d ' ' -f 1 "$OUT/$DMG.sha256")"
