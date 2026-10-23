# The macOS guest

[Documentation index](../README.md)

A disposable macOS virtual machine is the only place the app and the helper may
be started. Its home folder is the image's own and holds no real credential.
What an agent may do inside it without asking again is the standing guest-only
authorization in [AGENTS.md](../../AGENTS.md); nothing here extends it.

## Setting it up

This needs `tart` (2.32 or later) and about 80 GB of disk for the image. The
machine is given one scratch folder and nothing else of this Mac.

```sh
VM=guest   # any name
tart clone ghcr.io/cirruslabs/macos-sonoma-xcode:15.4 "$VM"   # once
TAR="repo-$(date +%s).tar"   # a new name for each transfer
mkdir -p "$TMPDIR/vm" && git archive --format=tar -o "$TMPDIR/vm/$TAR" HEAD
tart run "$VM" --no-graphics --dir=share:"$TMPDIR/vm" &
shasum -a 256 "$TMPDIR/vm/$TAR"
tart exec "$VM" shasum -a 256 "/Volumes/My Shared Files/share/$TAR"
tart exec "$VM" sh -c "mkdir -p ~/work && tar -xf '/Volumes/My Shared Files/share/$TAR' -C ~/work"
```

Run commands inside it with `tart exec`, from `~/work`, with Rust installed
there by `rustup` and `/opt/homebrew/bin` first on `PATH`.
`tart run --vnc-experimental` gives a screen to look at and press.
`tart stop "$VM"` when done.

Extract and test only when the two checksums match. Reusing an archive name in
the shared folder can give stale or truncated bytes.

## Accessibility and launch routes

The app check and the helper check each start a separate test driver that needs
Accessibility for the process macOS treats as its responsible client. The route
decides which process that is: where the guest grants Accessibility to
`/usr/libexec/sshd-keygen-wrapper`, a check can run from an SSH session inside
it; a direct `tart exec` launch uses `tart-guest-agent`, which needs its own
grant. Verify `AXIsProcessTrusted` through the driver rather than assuming a
grant carries over. Give a needed grant through the guest's macOS UI, then rerun
the preflight; if that is not possible, record the check as blocked. Never
bypass the driver's permission check or edit TCC databases.

## The shipped bundle

The bundle with its real engine. `gui/tests/check-app.sh` builds
`gui/tests/app-check.swift` as a separate driver and never changes the bundle.
Run `sh gui/build-macos.sh` in the guest first; the check does not build the
bundle. The driver's `PASS` lines say what it checked. It launches the bundle
with a new synthetic `HOME`, never enables the helper, and saves a new report
in the guest's Documents folder through the save panel. The panel must start
in Documents. It removes that export and the synthetic home after the check.
The work folder must not exist. It keeps the driver, app log and a checked
report copy there. Do not run this command on a real home:

```sh
LOOSE_KEYS_APP_CHECK=synthetic-home sh gui/tests/check-app.sh "$TMPDIR/app-check"
```

For the negative control, also set `LOOSE_KEYS_APP_CHECK_OMIT_AWS=1` and use a
different new work folder. That run must fail, which shows that a missing row
fails the check; nothing tests the export assertion's failure path.

The check looks for the three planted values and for the first and last
ten characters of each, not for every fragment. It does not look at
screenshot pixels, other rules, real credentials, the helper, notifications
or signing. It starts the bundle's executable directly, not through
LaunchServices. The guest's screen must be awake and unlocked.

## The native helper

A test-only Rust harness tests the installed helper's registration, filesystem
events, checkpoint replay and shutdown. Run its positive and negative controls
after changing the runner or its Settings driver.
[Native helper checks](native-helper-tests.md) has the command, preflight,
cases and cleanup.

## Folder-access preparation

The app asks for Desktop, Documents and Downloads, in that order, before a
scan or turning on background checks. Model tests cover the order of the
requests and cancelling them. Whether macOS prompts in that order, and whether
the app's grants also cover the helper, is unverified.

To check by hand, use a fresh guest account with synthetic data only and no
earlier folder grants or Full Disk Access for the app. Scan that account's own
home: a folder named `Documents` in a synthetic home is not the protected one.

1. Open the app with `HOME` set to that account's home. Opening alone should
   not ask for folder access.
2. Press **Scan Now**. Check that **Preparing Folder Access** appears and
   macOS asks for Desktop, Documents and Downloads in that order, before the
   scan starts. A folder already granted or absent may not prompt.
3. Deny Documents and allow the others. Confirm the scan continues and lists
   Documents under **Not Checked**.
4. Press **Cancel Preparation** while it is preparing, then answer the open
   prompt: no further prompt or scan should follow.
5. From a fresh permission state, repeat with **Enable Background Checks**.
   Confirm the folder prompts come before the helper is registered,
   notifications are not asked for, and the helper reads the allowed folders
   without asking again. Note any later prompt for another location.
6. Turn background checks off, verify the helper exits, quit the app, remove
   only the test's fixtures and state, and stop the guest.
