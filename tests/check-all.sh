#!/bin/sh
# Every check in docs/testing/local-verification.md except the scan by hand,
# one at a time. Prints one line per check with its exit status and keeps going
# after a failure; exits 1 if any check failed. Each check's output is in its
# own log. The window check puts a window on screen for about a minute, and the
# dependency audit needs the network. No guest check runs.
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
    "$@" > "$RUN/$name.log" 2>&1
    code=$?
    printf '%s: exit %s\n' "$name" "$code"
    [ "$code" -eq 0 ] || failed=1
}
check fmt cargo fmt --all --check
check clippy cargo clippy --locked --workspace --all-targets -- -D warnings
check test cargo test --locked --workspace
check rust-1.88 cargo +1.88.0 build --locked --workspace
check harness-selftest sh security-tests/harness.sh selftest --work "$RUN/selftest"
check scanner-gate sh security-tests/check_scanner.sh "$RUN/gate"
check platform sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$RUN/platform"
check detection sh security-tests/check_detection.sh
check bundle sh gui/build-macos.sh
check bundle-contract node --test gui/tests/bundle-contract.test.js
printf '%s\n' 'window: a window appears for about a minute'
check window sh gui/tests/check-window.sh "$RUN/window"
check model sh gui/tests/check-model.sh "$RUN/model"
check bridges sh gui/tests/check-bridges.sh "$RUN/bridges"
check audit-install cargo install cargo-audit --locked --version 0.22.2 --root "$TMPDIR/cargo-audit"
check audit "$TMPDIR/cargo-audit/bin/cargo-audit" audit --db "$TMPDIR/advisory-db" --file Cargo.lock
printf 'Logs: %s\n' "$RUN"
exit "$failed"
