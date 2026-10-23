# Local checks

[Documentation index](../README.md)

Every check runs locally, one command at a time, and passes only if it exits
0. Run from the repository root on macOS as an ordinary user, with Rust 1.88
or later. The checks that need a virtual machine are in
[the macOS guest](guest.md).

`TMPDIR` must be a folder with no symbolic link in its path, because the
scanner follows none and tests build synthetic homes there. On macOS `/tmp`
and the default under `/var` are links, so:

```sh
mkdir -p /private/tmp/loose-keys-scratch
export TMPDIR="$(cd /private/tmp/loose-keys-scratch && pwd -P)"
```

## Scanner and engine

The whole workspace:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

The oldest Rust the workspace declares. It needs
`rustup toolchain install 1.88.0 --profile minimal` once, and rustup's
`cargo` first on `PATH`:

```sh
cargo +1.88.0 build --locked --workspace
```

## Security harness

This is the check that the security rules hold: run it for any change under
`src/`.

```sh
sh security-tests/harness.sh --self-tests
sh security-tests/harness.sh selftest --work "$TMPDIR/loose-keys-selftest"
security-tests/check_scanner.sh "$TMPDIR/loose-keys-gate"
sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$TMPDIR/loose-keys-platform"
sh security-tests/harness.sh helper-self-tests
```

The helper self-tests need no guest, window or permission; they check the
native helper runner, not the helper ([native helper checks](native-helper-tests.md)).

## Detection correctness

Runs every rule against its cases in `tests/detection-corpus.json`, on
synthetic homes, through both the CLI and the engine. Each case must give
exactly its expected findings, with complete coverage and no gaps, and the two
exported reports must match apart from `generated_at` and finding order. The
engine runs as Cargo's test build, not through the Swift bundle or the C
interface, and no app or helper starts. Run it after changing rules,
scan/report code, the engine's scan/export commands, or the detection corpus.
Never regenerate the expectations from a scan to make a failure pass.

```sh
sh security-tests/check_detection.sh
```

## App bundle

Apple's command-line tools and Node. This builds the app and does not start
it. Run it for a change to `gui/app/`, `gui/macos/`, `gui/build-macos.sh` or
the C interface.

```sh
sh gui/build-macos.sh
node --test gui/tests/bundle-contract.test.js
```

## The window

Run both for a change to `gui/app/`.

The window's behaviour, on sample data with no engine and no home folder read.
A window appears for about a minute and does not come to the front. The screen
must be awake: with it locked or its saver on, macOS shows assistive software
no window, and the check stops with status 2 and says so. A blocked check is
not a pass.

```sh
sh gui/tests/check-window.sh "$TMPDIR/window-check"
```

The window's model, with no window. Nothing appears on screen, and no engine,
scan or home folder is involved:

```sh
sh gui/tests/check-model.sh "$TMPDIR/model-check"
```

## Notifications and power

Run all three for a change to `gui/src/notifications.m`. The worker and scheduler
power tests in `gui/src/agent.rs` and `gui/src/monitor.rs` run in `cargo test`.

The login bridge contract, with a fake service in place of macOS's. It checks
that stopping the helper waits for macOS to finish unregistering it and passes
errors on. It registers no real service and does not check macOS launch
constraints:

```sh
(cd gui && clang -fobjc-arc -fblocks -mmacosx-version-min=10.15 tests/login_test.m -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices -o "$TMPDIR/login-contract" && "$TMPDIR/login-contract")
```

The notification contract. It builds the request and checks its payload, and
delivers nothing:

```sh
(cd gui && clang -fobjc-arc -fblocks -mmacosx-version-min=10.15 tests/notifications_test.m -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices -o "$TMPDIR/notification-contract" && "$TMPDIR/notification-contract")
```

The power bridge: sleep/wake signals posted to the native bridge, safe on the
development Mac. It starts no app or installed helper, changes no power
setting, and does not verify physical sleep or macOS event delivery.
[Power checks](power-tests.md) has its coverage and limits.

```sh
(cd gui && clang -fobjc-arc -fblocks -mmacosx-version-min=10.15 tests/power_test.m -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices -o "$TMPDIR/power-bridge" && "$TMPDIR/power-bridge")
```

## Dependency advisories

Checks the crates in the lock file against the RustSec list. This needs the
network, and the tool is installed outside the repository:

```sh
cargo install cargo-audit --locked --version 0.22.2 --root "$TMPDIR/cargo-audit"
"$TMPDIR/cargo-audit/bin/cargo-audit" audit --db "$TMPDIR/advisory-db" --file Cargo.lock
```

## A scan by hand

On a synthetic home only, in a new output folder. Build the binary first with
`check_scanner.sh` (security harness above). The generated home, from
`security-tests/synthetic_home.rs`, is for looking at by hand; it is not a
detection check:

```sh
sh security-tests/harness.sh generate-home "$TMPDIR/synth"
HOME="$TMPDIR/synth/home" ./target/release/loose-keys scan --feedback -
```

## Before a push to `main`

A push whose commits change only Markdown files or images under `docs/` needs
only the prose review in [AGENTS.md](../../AGENTS.md#commands). For any other
push, run every command above except the scan by hand, on the exact commit,
one at a time, and report each one's exit status. A later pass does not
cancel an earlier failure. The two checks that need the guest, the shipped bundle and the
native helper, are not part of this: run them when asked or when the change
is to what they check, and otherwise list them under "Not verified".
