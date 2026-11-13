#!/bin/sh
# Act out a developer's work in a guest, one step of workday.py at a time,
# and record after each step what Loose Keys listed and whether it sent an
# alert. The app's window must be closed and Scan Automatically on.
# usage: sh workdays.sh <VM> <the VM's share folder on this Mac> [<step> ...]
set -eu
VM=${1:?usage: workdays.sh <VM> <share folder> [<step> ...]}
SHARE=${2:?usage: workdays.sh <VM> <share folder> [<step> ...]}
shift 2
TART=$(command -v tart || printf '%s' "$HOME/.local/share/tart/tart.app/Contents/MacOS/tart")
HERE=$(dirname "$0")
GUEST='/Volumes/My Shared Files/share'
cp "$HERE/workday.py" "$SHARE/workday.py"
cat > "$SHARE/alert-state.py" <<'PY'
import json, os, sys
state = json.load(open(os.path.expanduser("~/Library/Application Support/dev.loosekeys.desktop/state.json")))
after = int(sys.argv[1])
new = [item for item in state["items"] if item["id"] > after]
print(max([after] + [item["id"] for item in state["items"]]), state["notified_revision"])
for item in new:
    print("   listed:", item["rule"], item["severity"], item["path"])
PY
state() { "$TART" exec "$VM" python3 "$GUEST/alert-state.py" "$1"; }
[ "$#" -gt 0 ] || set -- $("$TART" exec "$VM" python3 "$GUEST/workday.py" list | cut -d: -f1)
for step in "$@"; do
    before=$(state 0 | head -n 1)
    last=${before% *}
    sent=${before#* }
    "$TART" exec "$VM" python3 "$GUEST/workday.py" "$step" > /dev/null
    # The helper checks a changed file within seconds and sends an alert
    # within a minute of the window closing.
    sleep 90
    after=$(state "$last")
    now=$(printf '%s\n' "$after" | head -n 1)
    if [ "${now#* }" != "$sent" ]; then alert='ALERT SENT'; else alert='no alert'; fi
    printf '%s: %s\n' "$step" "$alert"
    printf '%s\n' "$after" | tail -n +2
done
