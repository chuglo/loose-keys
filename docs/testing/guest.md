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

The check does not cover appearance or the helper.

These clones boot with SIP off, which the
[native helper checks](native-helper-tests.md) need on.

When done, run `sync` in the guest, then `tart stop "$VM"` on this Mac.
