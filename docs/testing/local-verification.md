# Local checks

[Documentation index](../README.md)

Checks launched from this Mac. Each passes only if it exits 0, and
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
sh security-tests/harness.sh selftest --work "$TMPDIR/loose-keys-selftest.$$"
security-tests/check_scanner.sh "$TMPDIR/loose-keys-gate"
sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$TMPDIR/loose-keys-platform"
```

The first command runs the harness against its own stand-in scanners, never
the one in `src/`, so it is needed only when `security-tests/`, `schema/`,
the root `Cargo.toml` or `Cargo.lock`, or `gui/tests/helper-control.swift`,
which it compiles in, change. It refuses a work folder it has already filled,
so name a new one each time. The other two check the scanner. They run the
release `loose-keys` command, not the engine or the app, against generated
fixtures. The platform check's folder denial comes from the sandbox, not a
real privacy prompt. Neither covers files kept only in the cloud, security
software, or signing and notarization.

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
signature and the compressed image, and refuses to replace an existing image:
delete the old one first. Mount the image without opening the app:

```sh
DMG="target/release/bundle/macos/Loose-Keys-$(plutil -extract CFBundleShortVersionString raw -o - gui/macos/Info.plist).dmg"
hdiutil attach -readonly -nobrowse "$DMG"
readlink "/Volumes/Loose Keys/Applications"
codesign --verify --deep --strict "/Volumes/Loose Keys/Loose Keys.app"
diff -qr "target/release/bundle/macos/Loose Keys.app" "/Volumes/Loose Keys/Loose Keys.app"
hdiutil detach "/Volumes/Loose Keys"
```

The shortcut must point to `/Applications`; the bundle must match the source.
Finder chooses the layout; there is no custom background or forced icon
positioning. Not verified by these commands: dragging in Finder, installing
over an older app, opening the downloaded image through Gatekeeper, or
launching the installed app. Those checks belong in the disposable guest when
requested.

## The window

```sh
sh gui/tests/check-window-guest.sh "$TMPDIR/window-check"
sh gui/tests/check-model.sh "$TMPDIR/model-check"
```

The window check runs the sample-data build, with no engine and no home
folder. It runs in a fresh headless macOS guest, so it does not put a window
on the host. See [guest prerequisites and retained logs](guest.md#sample-window-check).
The guest screen must be awake and unlocked. Status 2 means it was
blocked, not passed. It reads the icon's label but cannot open its menu, and
it sets filter text in the model, not with keyboard input.

The model check shows no window and answers with a stand-in engine, not the
running bundle. It uses a fake clock, so it does not check real timing. Its
update cases use a stand-in for GitHub; no check here makes a request to
GitHub.

Neither establishes actual typing, restored window sizing, multiple displays
or Spanish layout; those need a guest interaction pass.

## Notifications and power

The login, notification and power bridge contracts. The login check covers
the helper's job and the app's own Login Items entry. They register no real
service, deliver no notification and do not check macOS launch constraints:

```sh
sh gui/tests/check-bridges.sh "$TMPDIR/bridge-check"
```

Not verified: real sleep and wake delivery, the installed helper's suspension
and resumption, the real Low Power Mode setting, and battery use. The guest
refuses sleep and has no Low Power Mode (unverified), so it cannot check them
either.

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

On a synthetic home only, after `check_scanner.sh` has built the binary.
`generate-home` refuses a folder it has already filled, so make a new one
each time:

```sh
synth=$(mktemp -d "$TMPDIR/synth.XXXXXX")
sh security-tests/harness.sh generate-home "$synth"
HOME="$synth/home" ./target/release/loose-keys scan --feedback -
```

## Before a push to `main`

A push that changes only Markdown and images under `docs/`, Markdown under
`.agents/skills/`, or the `AGENTS.md` and `CLAUDE.md` files needs only a
review of the text. For any other push, run this on the exact commit and
report the exit status it prints for each check:

```sh
sh tests/check-all.sh
```

It runs every command above except the installer disk image and the scan by
hand, with the workspace tests and detection as one `--workspace` run. The
sample window check runs in a headless guest at the same time. Ctrl-C stops
it and waits while it stops its guest. It keeps
going after a failure, exits 1 if any check failed and prints how long each
check took. Each check's log is in the folder it names at the end. A window
check that ran leaves a stopped clone, named on the `VM:` line of `window.log`
in that folder; delete it after reporting. The shipped-app and native-helper
guest checks are not in it.

The harness self-test and the window check are skipped when none of the files
they use differ from `origin/main`, which passed this script before it was
pushed. Untracked files count, and both run when git cannot compare. Report a
skipped check as skipped, not passed. A skip trusts that `origin/main` passed;
it does not notice a new Rust toolchain or guest image.
