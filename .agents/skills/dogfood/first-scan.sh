#!/bin/sh
# In a guest the vm skill opened with a synthetic home: press Scan Now,
# answer macOS's folder requests for Loose Keys, read the Overview and the
# places not checked, save every row of Worth Reviewing and Stored Sign-ins
# with its inspector, and compare them with the home's manifest.
# usage: sh first-scan.sh <VM> <the VM's share folder on this Mac> <the home's folder from make_home.py> [<name for the results>]
set -eu
VM=${1:?usage: first-scan.sh <VM> <share folder> <home folder> [<name>]}
SHARE=${2:?usage: first-scan.sh <VM> <share folder> <home folder> [<name>]}
OUT=${3:?usage: first-scan.sh <VM> <share folder> <home folder> [<name>]}
NAME=${4:-first}
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
GUEST='/Volumes/My Shared Files/share'
# A new name for each build: macOS ends a program whose file was replaced.
DRIVE="drive-$(date +%H%M%S)"
MINIMUM=$(/usr/bin/plutil -extract LSMinimumSystemVersion raw -o - "$ROOT/gui/macos/Info.plist")
swiftc -O -target "$(uname -m)-apple-macosx$MINIMUM" "$HERE/drive.swift" -o "$SHARE/$DRIVE" \
    -framework AppKit -framework ApplicationServices
drive() { "$TART" exec "$VM" "$GUEST/$DRIVE" "$@"; }
printf '%s\n' "$DRIVE" > "$OUT/drive-name.txt"

if [ -f "$OUT/decoy-paths.txt" ] && [ "$NAME" = first ]; then
    # This home is not a messy developer's: take the decoys out first.
    cp "$OUT/decoy-paths.txt" "$SHARE/decoy-paths.txt"
    # macOS refuses the removal of a few, such as the Notes store: they stay.
    "$TART" exec "$VM" sh -c 'cd "$HOME" && while IFS= read -r path; do rm -rf "./$path" 2> /dev/null; done < "$1"; true' sh "$GUEST/decoy-paths.txt"
fi
{
    drive scan 300
    drive press "Don't Check" 2> /dev/null || true
    sleep 1
    echo '-- Overview'
    drive page Overview
    drive detail
    if drive press 'Show Places Not Checked' 2> /dev/null; then
        sleep 1
        echo '-- Places not checked'
        drive detail
        drive menu 'Scan Now' > /dev/null 2>&1 || true
    fi
} > "$OUT/$NAME-overview.txt" 2>&1
for page in 'Worth Reviewing' 'Stored Sign-ins'; do
    file=$(printf '%s' "$page" | tr 'A-Z ' 'a-z-')
    drive page "$page"
    sleep 1
    drive dump "/tmp/$file.json" > /dev/null
    "$TART" exec "$VM" cat "/tmp/$file.json" > "$OUT/$NAME-$file.json"
done
python3 "$HERE/compare.py" "$OUT/manifest.json" "$OUT/$NAME-worth-reviewing.json" "$OUT/$NAME-stored-sign-ins.json" \
    > "$OUT/$NAME-compare.txt"
cat "$OUT/$NAME-overview.txt"
grep '^==' "$OUT/$NAME-compare.txt"
tail -n 1 "$OUT/$NAME-compare.txt"
