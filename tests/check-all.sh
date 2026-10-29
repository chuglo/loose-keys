#!/bin/sh
# Every check in docs/testing/local-verification.md except the scan by hand.
# The sample window check runs in a headless macOS guest alongside the others,
# which run one at a time. Prints each exit status and elapsed seconds and
# keeps going after a failure; exits 1 if any check failed. Each check's
# output is in its own log. The dependency audit needs the network. Real
# app/helper guest checks do not run.
set -u
if [ ! -f gui/macos/Info.plist ]; then
    printf '%s\n' 'Run this script from the repository root.' >&2
    exit 1
fi
: "${TMPDIR:?Set TMPDIR to a scratch folder with no symbolic link in its path}"
if [ "$(cd "$TMPDIR" && pwd -P)" != "${TMPDIR%/}" ]; then
    printf '%s\n' 'TMPDIR must have no symbolic link in its path.' >&2
    exit 1
fi
RUN=$(mktemp -d "$TMPDIR/check-all.XXXXXX") || exit 1
failed=0
check() {
    name=$1
    shift
    started=$(date +%s)
    "$@" > "$RUN/$name.log" 2>&1
    code=$?
    elapsed=$(( $(date +%s) - started ))
    printf '%s: exit %s (%ss)\n' "$name" "$code" "$elapsed"
    [ "$code" -eq 0 ] || failed=1
}
# The window check copies its own sources into the guest and builds there, so
# it shares nothing with the checks below. A background job ignores Ctrl-C,
# so an interrupt stops it here and waits while it stops its guest.
printf '%s\n' 'window: sample check runs in a headless macOS guest, alongside the others'
window_started=$(date +%s)
sh gui/tests/check-window-guest.sh "$RUN/window" > "$RUN/window.log" 2>&1 &
WINDOW=$!
stop_window() {
    trap - HUP INT TERM
    kill -TERM "$WINDOW" 2>/dev/null
    wait "$WINDOW"
    printf 'Interrupted. Logs: %s\n' "$RUN"
    exit "$1"
}
trap 'stop_window 129' HUP
trap 'stop_window 130' INT
trap 'stop_window 143' TERM
check fmt cargo fmt --all --check
check clippy cargo clippy --locked --workspace --all-targets -- -D warnings
check test-and-detection sh security-tests/check_detection.sh --workspace
check rust-1.88 cargo +1.88.0 build --locked --workspace
check harness-selftest sh security-tests/harness.sh selftest --work "$RUN/selftest"
check scanner-gate sh security-tests/check_scanner.sh "$RUN/gate"
check platform sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$RUN/platform"
check bundle sh gui/build-macos.sh
check bundle-contract node --test gui/tests/bundle-contract.test.js
check model sh gui/tests/check-model.sh "$RUN/model"
check bridges sh gui/tests/check-bridges.sh "$RUN/bridges"
check audit-install cargo install cargo-audit --locked --version 0.22.2 --root "$TMPDIR/cargo-audit"
check audit "$TMPDIR/cargo-audit/bin/cargo-audit" audit --db "$TMPDIR/advisory-db" --file Cargo.lock
wait "$WINDOW"
code=$?
trap - HUP INT TERM
# The guest script writes its last line as it finishes, perhaps well before
# this wait returned.
elapsed=$(( $(stat -f %m "$RUN/window.log") - window_started ))
printf 'window: exit %s (%ss)\n' "$code" "$elapsed"
[ "$code" -eq 0 ] || failed=1
printf 'Logs: %s\n' "$RUN"
exit "$failed"
