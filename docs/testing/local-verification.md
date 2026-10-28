# Local checks

[Documentation index](../README.md)

Every check that runs on this Mac. Each passes only if it exits 0, and
[AGENTS.md](../../AGENTS.md#commands) says which ones a change needs. Run from
the repository root as an ordinary user, with `TMPDIR` set to a folder with no
symbolic link in its path:

```sh
mkdir -p /private/tmp/loose-keys-scratch
export TMPDIR="$(cd /private/tmp/loose-keys-scratch && pwd -P)"
```

## Scanner and engine

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

The oldest Rust the workspace declares, after
`rustup toolchain install 1.88.0 --profile minimal` once:

```sh
cargo +1.88.0 build --locked --workspace
```

## Security harness

`cargo test` already runs the harness's own self-tests and the helper
runner's.

```sh
sh security-tests/harness.sh selftest --work "$TMPDIR/loose-keys-selftest"
security-tests/check_scanner.sh "$TMPDIR/loose-keys-gate"
sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$TMPDIR/loose-keys-platform"
```

## Detection

Every rule against its cases in `tests/detection-corpus.json`, through the
CLI and through the engine as a Cargo test, not the bundle or the C
interface:

```sh
sh security-tests/check_detection.sh
```

With `--workspace` it also runs every workspace test, so one run replaces
this and `cargo test --locked --workspace`.

## App bundle

Needs Apple's command-line tools and Node. It builds the app and does not
start it:

```sh
sh gui/build-macos.sh
node --test gui/tests/bundle-contract.test.js
```

The contract test also fails when a key the window looks up has no Spanish,
or a Spanish entry has no key, and lists them ready to paste. `cargo test`
does the same for the engine's text in `gui/macos/es.lproj/Engine.strings`.
Neither shows the Spanish on screen.

## Installer disk image

After building the bundle, run `sh gui/package-dmg.sh`. It verifies the code
signature and the compressed image. Mount the image without opening the app:

```sh
hdiutil attach -readonly -nobrowse target/release/bundle/macos/Loose-Keys-0.4.0.dmg
readlink "/Volumes/Loose Keys/Applications"
codesign --verify --deep --strict "/Volumes/Loose Keys/Loose Keys.app"
diff -qr "target/release/bundle/macos/Loose Keys.app" "/Volumes/Loose Keys/Loose Keys.app"
hdiutil detach "/Volumes/Loose Keys"
```

The shortcut must point to `/Applications`; the bundle must match the source.
Use the version printed by the packaging script. Finder chooses the layout;
there is no custom background or forced icon positioning. Not verified by
these commands: dragging in Finder, installing over an older app, opening
the downloaded image through Gatekeeper, or launching the installed app.
Those checks belong in the disposable guest when requested.

## The window

The window check runs the sample-data build, with no engine and no home
folder. A window appears for about a minute, with a menu bar icon and a
minimized window for a moment, and the screen must be awake and unlocked. Status 2 means it was
blocked, not passed. It reads the icon's label but cannot open its menu. The
model check shows no window, and it uses a fake clock for the window's five-,
two- and thirty-second timers, so it does not check real timing.

```sh
sh gui/tests/check-window.sh "$TMPDIR/window-check"
sh gui/tests/check-model.sh "$TMPDIR/model-check"
```

## Notifications and power

The login, notification and power bridge contracts. The login check covers
the helper's job and the app's own Login Items entry. They register no real
service, deliver no notification and do not check macOS launch constraints:

```sh
sh gui/tests/check-bridges.sh "$TMPDIR/bridge-check"
```

Not verified: real sleep and wake delivery, the installed helper's suspension
and resumption, the real Low Power Mode setting, and battery use. The guest
refuses sleep and has no Low Power Mode, so it cannot check them either.

Guest only, and not yet checked: the app opening at login with no window or
Dock icon, a restored window put away then, whether registering it needs
approval, the icon and its menu in a light and a dark menu bar, closing the
window and quitting, reopening from the Dock, a notification click while no
window is open, and the helper still notifying then.

## Dependency advisories

Needs the network. The tool is installed outside the repository:

```sh
cargo install cargo-audit --locked --version 0.22.2 --root "$TMPDIR/cargo-audit"
"$TMPDIR/cargo-audit/bin/cargo-audit" audit --db "$TMPDIR/advisory-db" --file Cargo.lock
```

## A scan by hand

On a synthetic home only, after `check_scanner.sh` has built the binary:

```sh
sh security-tests/harness.sh generate-home "$TMPDIR/synth"
HOME="$TMPDIR/synth/home" ./target/release/loose-keys scan --feedback -
```

## Before a push to `main`

A push that changes only Markdown and images under `docs/` needs only a review
of the text. For any other push, run this on the exact commit and report the
exit status it prints for each check:

```sh
sh tests/check-all.sh
```

It runs every command above except the scan by hand, one at a time, with the
workspace tests and detection as one `--workspace` run. It keeps going after a
failure, exits 1 if any check failed and prints how long each check took.
Each check's log is in the folder it names at the end. A later pass does not cancel an earlier
failure. The guest checks are not in it.
