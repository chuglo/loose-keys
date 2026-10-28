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
