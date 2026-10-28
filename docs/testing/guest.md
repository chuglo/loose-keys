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

## Sample window check

Run from the repository root, with Tart installed and the
`ghcr.io/cirruslabs/macos-tahoe-base:latest` image already cached. The image
must contain synthetic data only, a logged-in desktop, the Tart guest agent
and Apple's command-line tools. The wrapper does not download an image:

```sh
sh gui/tests/check-window-guest.sh "$TMPDIR/window-check"
```

The wrapper snapshots the current working-tree Swift source, English plural
forms, deployment target and window-check script, including uncommitted
changes. It clones the cached image under a new name and starts it with
`--no-graphics --no-audio --no-clipboard`; no host window appears and no host
privacy grants are needed. Only the dedicated source archive directory is
shared, read-only. It waits up to three minutes for readiness and compares
SHA-256 checksums, then the guest builds and runs `check-window.sh` with sample
data and no scanner. `caffeinate` keeps the guest display awake; it does not
unlock an already locked desktop. Host deadlines bound image listing (15
seconds), cloning (120 seconds), checksum and report transfers and stopping
(30 seconds each), and syncing (10 seconds). The guest build plus window
check has a 600-second infrastructure deadline; the window assertions keep
their existing deadlines. A stalled command is terminated and cleanup still
attempts to stop the owned clone; a stop timeout is reported as a failure,
not successful cleanup.

Each invocation keeps its source archive, checksum, command logs, report and
report log in a new `run.*` folder beneath the output path. A failing check
keeps its exit status. Cleanup stops only the clone it created, on success
or failure, and a failed stop makes the wrapper fail. The clone is retained
for inspection, never automatically deleted. Transfer checksums detect
accidental changes; they do not authenticate a hostile host. This checks
sample window behavior, not the real bundle, helper, or visual appearance.
The Rust harness's offline wrapper controls replace Tart with a stand-in and check a stalled
checksum command, successful completion, nonzero check-status propagation,
and stopping only the owned clone. They start no VM or window:

```sh
cargo test --locked --test security_harness
```

Running `check-window.sh` directly on the host requires an explicit request
to show the preview there; normal checks use this wrapper.

## The shipped bundle

In the guest, from `~/work`, with a new work folder and the screen awake and
unlocked:

```sh
LOOSE_KEYS_APP_CHECK=synthetic-home sh gui/tests/check-app.sh "$HOME/app-check-1"
```

The negative control adds `LOOSE_KEYS_APP_CHECK_OMIT_AWS=1`, with another new
work folder. It must fail with `timeout: specific fixture findings in window`.

The check does not cover appearance or the helper. The guest's language
must be English: the driver finds controls, macOS's save panel included,
by their English names.

These clones boot with SIP off, which the
[native helper checks](native-helper-tests.md) need on.

When done, run `sync` in the guest, then `tart stop "$VM"` on this Mac.

## Managed settings

An organization sets the app's preferences with a configuration profile from
its MDM. To open a build in a new guest with a profile installed, as the
[vm skill](../../.agents/skills/vm/SKILL.md) does:

```sh
LOOSE_KEYS_PROFILE=.agents/skills/vm/managed-settings.mobileconfig \
LOOSE_KEYS_EXTRA_HOME=<folder of extra synthetic files> \
sh .agents/skills/vm/open-in-vm.sh <ref>
```

The profile carries one payload whose `PayloadType` is
`dev.loosekeys.desktop`, with the settings as its other keys: the shape MDM
"custom settings" produce. `profiles install` has refused to install
profiles since macOS 11, so `gui/tests/install-profile.swift` opens the file
and installs it through System Settings, typing the base image's
administrator password if asked. It runs only in a `VirtualMac` guest, not as
root, and clicks only where System Settings is the window on top. It passes
when macOS reports every key in the payload as managed.

Checked on 2026-10-28 in a macOS 26.6.2 tahoe-base clone (SIP off), with
`CFPreferencesAppValueIsForced` run as the guest user:

| Where the value came from | Managed |
|---|---|
| `~/Library/Preferences/dev.loosekeys.desktop.plist` | no |
| A profile installed through System Settings | yes |
| A root-owned plist placed in `/Library/Managed Preferences/<user>/` or `/Library/Managed Preferences/` | yes, at once |
| The same plist owned by the user | yes |
| A managed and a home-folder value together | yes; the managed value is returned |

A profile with `PayloadScope` `System` wrote root-owned copies to both
folders. macOS does not check the file's owner: what keeps a person from
setting a managed value is that only root can write in those folders.
`sudo profiles remove -identifier <PayloadIdentifier>` in the guest removes
the profile, and its values stop being managed at once.

Not verified: a profile delivered by an MDM server. The payload and where
macOS stores it are the same, but a hand-installed profile shows as not
signed and its user can remove it. A real MDM needs an Apple push
certificate, and Parallels reports that macOS 26 guests enroll but then
receive no profiles (unverified here). A `PayloadScope` `User` profile and a
guest with SIP on are not checked either.

## Repeatable release checks

The [release skill](../../.agents/skills/release/SKILL.md) builds a candidate
from a committed source archive and runs the checks against that same ZIP.
Its scripts need no Codex Desktop, Computer Use or VNC. They run sequentially
in fresh clones, verify artifact and transfer checksums, retain host logs,
and stop their own guests on failures as well as success. A failed stop is
an error, not successful cleanup. Checksums detect accidental replacement;
they do not authenticate artifacts against someone who can change the
manifest too. The version command runs with a synthetic HOME on the host;
the real app and helper run only in guests.

The helper's reusable image is named `lk-sip-base`. It must be stopped,
contain synthetic data only, have SIP and Gatekeeper enabled, and have no
Loose Keys installation, app state or registered helper. The helper's
preflight checks these security and first-run prerequisites in each clone.
Keep the base pristine; do not use it for a test or walkthrough.

If that base is absent, preparing it is a separate, supervised setup step:
clone a macOS image, use Tart's Recovery window to enable SIP with
`csrutil enable`, and verify `csrutil status` and `spctl --status` after a
normal boot. Do not disable either protection or answer unrelated security
prompts to get the checks running. The earlier experimental VNC bootstrap
is not included: it used fixed screen coordinates and crashed during a
walkthrough. Creating a new base from Recovery remains unverified by the
release scripts; the existing base and per-clone preflight were exercised.

The offline script regressions cover malformed versions without file
changes, a modified candidate being rejected, and a failed guest startup
stopping only its owned clone. Run them from the repository root:

```sh
python3 -I .agents/skills/release/check-scripts.py
```

Checked on 2026-10-27: a candidate built from `1da0303` passed the bundle
contract and version checks, the shipped-app check and its missing-AWS
control, and all eight helper stages plus the omitted-create control.
Both negative controls exited 1 at their intended assertion; the wrappers
exited 0 and stopped their guests. The three offline regressions also passed.

An optional manual walkthrough uses a normal Tart window. It is not a
prerequisite for running the automated checks and must be reported as
unverified when omitted. Its setup excludes protected user folders and
the guest's own keychain and Notes store. No host privacy grants are needed.
