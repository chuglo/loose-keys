# The macOS guest

[Documentation index](../README.md)

## Setting it up

Build the bundle on this Mac, then copy it into a new clone for each build:

```sh
VM=lk-$(git rev-parse --short HEAD)
N=$(date +%s)   # a new name for each transfer
S="/Volumes/My Shared Files/share"
mkdir -p "$TMPDIR/vm"
ditto -c -k --keepParent "target/release/bundle/macos/Loose Keys.app" "$TMPDIR/vm/app-$N.zip"
git archive --format=tar -o "$TMPDIR/vm/repo-$N.tar" HEAD
tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest "$VM"
tart run "$VM" --no-graphics --dir=share:"$TMPDIR/vm" &
until tart exec "$VM" test -f "$S/repo-$N.tar" 2>/dev/null; do sleep 2; done   # wait for the guest
shasum -a 256 "$TMPDIR/vm/app-$N.zip" "$TMPDIR/vm/repo-$N.tar"
tart exec "$VM" shasum -a 256 "$S/app-$N.zip" "$S/repo-$N.tar"
```

Unpack when the checksums match:

```sh
tart exec "$VM" sh -c "mkdir -p ~/work/target/release/bundle/macos &&
  tar -xf '$S/repo-$N.tar' -C ~/work &&
  ditto -x -k '$S/app-$N.zip' ~/work/target/release/bundle/macos &&
  codesign --verify --deep --strict ~/work/target/release/bundle/macos/'Loose Keys.app'"
```

Transfer checksums detect accidental changes; they do not authenticate a
hostile host. These clones run macOS 26 and boot with SIP off. The
[native helper checks](native-helper-tests.md) need it on, so they clone
`lk-sip-base` instead (below). No check runs the app on macOS 14 or 15.

## Sample window check

Run from the repository root, with `tart` on `PATH`, fewer than two VMs
running (`tart list`: the check starts its own, and macOS runs at most two),
and the `ghcr.io/cirruslabs/macos-tahoe-base:latest` image already cached.
The wrapper does not download it:

```sh
sh gui/tests/check-window-guest.sh "$TMPDIR/window-check"
```

The guest builds the working tree's Swift sources, uncommitted changes
included, and runs `check-window.sh` with sample data and no scanner. No host
window appears and no host privacy grants are needed. This checks sample
window behavior, not the real bundle, helper, or visual appearance.

Each run keeps its logs and report in a new `run.*` folder beneath the output
path. The wrapper never deletes the clone; the session that ran the check
deletes it, by the name on its `VM:` line, after reporting the result.

## The shipped bundle

The test driver needs Accessibility, given in the guest's System Settings to
the process macOS holds responsible for it: Terminal, or the Tart guest agent
under `tart exec` (unverified). Without it the check stops with
`Accessibility is not granted to the driver responsible client`. Whether the
base image already grants it is unverified.

In the guest, from `~/work`, with a new work folder and the screen awake and
unlocked:

```sh
LOOSE_KEYS_APP_CHECK=synthetic-home sh gui/tests/check-app.sh "$HOME/app-check-1"
```

Also run the first-run quit regression against the same bundle:

```sh
LOOSE_KEYS_APP_CHECK=synthetic-home sh gui/tests/check-update-quit.sh "$HOME/update-quit-1"
```

On each launch it scans the empty synthetic home, since the update question
waits for a scan. It leaves update consent unanswered and checks normal
native termination, menu Quit and Command-Q, relaunching against the same
synthetic home between them. It also checks that the window says Loose Keys
can check GitHub once a day and does not mention the IP address. It sends no
update request.

`check-app.sh`'s negative control adds `LOOSE_KEYS_APP_CHECK_OMIT_AWS=1`, with
another new work folder. It must fail with
`timeout: specific fixture findings in window`.

The check does not cover appearance, the helper, or macOS's Desktop,
Documents and Downloads requests, since the app scans a synthetic home, not
the account's own. The guest's language must be English: the driver finds
controls, macOS's save panel included, by their English names.

When done, run `sync` in the guest, then `tart stop "$VM"` on this Mac.

## Pictures and the engine window check

Two development builds, defined in `gui/app/Preview.swift`, save a picture of
each page into `SNAPSHOT_DIR` and quit. The `PREVIEW` build uses sample data
and no engine; it runs on this Mac only when the person explicitly asks,
since its window appears on their screen. The `SNAPSHOTS` build uses the real
engine and needs `sh gui/build-macos.sh` to have run in the guest, which
needs Rust and Apple's command-line tools there. In the guest, from `~/work`,
with `TMPDIR` set as in [local checks](local-verification.md) and a new
synthetic home in `synth`, made as in
[A scan by hand](local-verification.md#a-scan-by-hand):

```sh
MINIMUM=$(plutil -extract LSMinimumSystemVersion raw -o - gui/macos/Info.plist)
swiftc -parse-as-library -D PREVIEW -target "$(uname -m)-apple-macosx$MINIMUM" \
    gui/app/*.swift -framework AppKit -o "$TMPDIR/window-preview"
swiftc -parse-as-library -D SNAPSHOTS -target "$(uname -m)-apple-macosx$MINIMUM" \
    -import-objc-header gui/app/Bridge.h gui/app/*.swift \
    target/release/libloose_keys_gui.a \
    -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices \
    -o "$TMPDIR/window-snapshots"
mkdir -p "$TMPDIR/pictures"
SNAPSHOT_DIR="$TMPDIR/pictures" "$TMPDIR/window-preview"
HOME="$synth/home" SNAPSHOT_DIR="$TMPDIR/pictures" "$TMPDIR/window-snapshots"
```

`SNAPSHOT_LOOK=light` or `dark` picks the appearance. `SNAPSHOT_ACTIONS=1`
also sends the decision and export commands through the engine and writes what
came back to `actions.txt` beside the pictures.

With `CHECK_REPORT=<file>` set instead of `SNAPSHOT_DIR`, either build runs
the window check and writes its result to that file. On the `SNAPSHOTS`
build, with its synthetic `HOME`, that is the check against the real engine.
It needs the screen awake and unlocked, as the sample check does.

For the window in Spanish, copy the built bundle's
`Contents/Resources/*.lproj` beside `window-preview` and add
`-AppleLanguages '(es)'` to its command, or `'(es-MX)'` for Latin American
Spanish. Sample text that no rule has stays English.

Neither build is the shipped bundle, and the `SNAPSHOTS` build checks for no
update. Nothing compares the pictures with earlier ones.

## Managed settings

An organization sets the app's preferences with a configuration profile from
its MDM. To open a build in a new guest with a profile installed, as the
[vm skill](../../.agents/skills/vm/SKILL.md) does:

```sh
LOOSE_KEYS_PROFILE=.agents/skills/vm/managed-settings.mobileconfig \
LOOSE_KEYS_EXTRA_HOME=<folder of extra synthetic files> \
sh .agents/skills/vm/open-in-vm.sh <ref>
```

What macOS reported as managed in a guest is under
[Files](../development/standards.md#files) in the standards.
`sudo profiles remove -identifier <PayloadIdentifier>` in the guest removes
the profile, and its values stop being managed at once.

Not verified: a profile delivered by an MDM server. The payload and where
macOS stores it are the same, but a hand-installed profile shows as not
signed and its user can remove it. A real MDM needs an Apple push
certificate, and Parallels reports that macOS 26 guests enroll but then
receive no profiles (unverified here). A `PayloadScope` `User` profile and a
guest with SIP on are not checked either.

## Repeatable release checks

The [release skill](../../.agents/skills/release/SKILL.md) runs
`check-app.sh` and the native helper checks, each with its negative control,
on a release candidate in fresh clones. It does not run the first-run quit
regression; run that by hand as in [The shipped bundle](#the-shipped-bundle).

The helper's reusable image is named `lk-sip-base`. It must be stopped,
contain synthetic data only, have SIP and Gatekeeper enabled, and have no
Loose Keys installation, app state or registered helper. The helper's
preflight checks these security and first-run prerequisites in each clone.
Keep the base pristine; do not use it for a test or walkthrough.

If that base is absent, preparing it is a separate, supervised setup step:
clone a macOS image, use Tart's Recovery window to enable SIP with
`csrutil enable`, and verify `csrutil status` and `spctl --status` after a
normal boot. Do not disable either protection or answer unrelated security
prompts to get the checks running. Creating a new base from Recovery is
unverified.
