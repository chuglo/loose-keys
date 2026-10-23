# Working with GUI checks

The [root instructions](../../AGENTS.md), [GUI instructions](../AGENTS.md)
and [repository test instructions](../../tests/AGENTS.md) apply here too.
[Local checks](../../docs/testing/local-verification.md) is the command
reference; the [root verification matrix](../../AGENTS.md#commands)
determines which checks a change requires. These checks supplement the
workspace format, lint and test commands; they do not replace them.

## Run checks consistently

Run from the repository root on macOS as an ordinary user. Use Apple's
command-line tools, Node for the bundle contract, and Rust 1.88 or later for
the engine. Set up scratch space in the same shell as the checks:

```sh
mkdir -p /private/tmp/loose-keys-scratch
export TMPDIR="$(cd /private/tmp/loose-keys-scratch && pwd -P)"
```

Run one command at a time and record each exit status. Keep `TMPDIR` free
of symbolic links in every path component. Use the scripts below rather
than assembling alternate Swift builds; the scripts read the deployment
target from `gui/macos/Info.plist`.

| Change | Additional checks |
|---|---|
| `gui/app/`, `gui/macos/`, `gui/build-macos.sh`, C interface | Bundle build, then bundle contract |
| `gui/app/` | Also window and model checks |
| Helper runner or Settings driver | Helper self-tests, then positive and negative guest controls |
| `gui/src/notifications.m` | Login contract, notification contract and power bridge |
| Engine scan/export commands | CLI/engine detection parity via `sh security-tests/check_detection.sh` |

For prose-only changes (Markdown files and images under `docs/`), review the
text and check local paths and commands; no other check is required,
including before a push to `main`. Before any other push to `main`, follow
the full list in the local command reference on the exact commit.

## Checks safe on the host

Build the bundle, then check its contents and signing contracts:

```sh
sh gui/build-macos.sh
node --test gui/tests/bundle-contract.test.js
```

These commands do not open the app or register its helper. The contract
executes the bundled CLI with `--version`, which reads no home files.
The build writes over the executable: quit the app and stop the helper
before rebuilding when either is running in the guest.

For window behaviour, announce first that a window will appear for about a
minute. The screen must be awake, unlocked and without its screen saver:

```sh
sh gui/tests/check-window.sh "$TMPDIR/window-check"
```

This uses sample-data `PREVIEW`, no engine and no home folder. Status 2 means
the screen blocked the check; it is not a pass. Read `report.txt` and
`report.txt.log` in the work folder when it fails.

For the model, with no window, engine or home folder access:

```sh
sh gui/tests/check-model.sh "$TMPDIR/model-check"
```

`refresh-order.swift` compiles with the real model and a stand-in engine
that controls response order. A pass does not verify the running bundle or
the orders macOS produces.

For `notifications.m`, run all three commands verbatim from
[Notifications and power](../../docs/testing/local-verification.md#notifications-and-power):
`login_test.m`, `notifications_test.m` and `power_test.m`. They register no
real service and deliver no notification. The power bridge posts signals
inside its own process; it does not sleep the Mac or change Low Power Mode.
[Power checks](../../docs/testing/power-tests.md) lists what remains unverified.

## Checks only in the disposable guest

The real app, `SNAPSHOTS` build and installed helper must never run on the
host. A substituted `HOME` does not protect the host from a helper launched
by macOS: it scans the account's actual home. Follow
[the guest setup](../../docs/testing/guest.md), using synthetic data only,
and verify transferred archive checksums before extracting or testing.

- **Shipped bundle:** build it in the guest first, then follow
  [The shipped bundle](../../docs/testing/guest.md#the-shipped-bundle) for
  `check-app.sh` and its missing-fixture negative control. Use a new work
  folder for each run. The driver needs an awake, unlocked screen and guest
  Accessibility. It exports through the save panel into guest Documents;
  check cleanup of that export and its synthetic home. A negative control
  must fail for its intended missing assertion, not an unrelated prerequisite.
- **Native helper:** first run `sh security-tests/harness.sh helper-self-tests`
  on the host; this starts no helper and needs no permissions. Then follow
  [Native helper checks](../../docs/testing/native-helper-tests.md) for the
  guest preflight, candidate digest, positive suite and `--omit-create`
  negative control. Use a fresh guest clone for each suite. Build once and
  do not replace the candidate during a run or under a registered helper.
- Grant only the permissions covered by the root standing guest-only
  authorization, through the guest UI, and record grants and outcomes.
  Verify Accessibility through the driver for its actual launch route;
  never bypass its preflight or edit TCC databases. Do not change host
  privacy settings, disable SIP or Gatekeeper, or reset all background items.
- Follow documented cleanup and stop the guest when done. If helper cleanup
  fails, retain the work folder, stop the guest and reset the clone before
  another run; do not claim the helper is off.

## Change tests and report results

Read [Tests](../../docs/development/standards.md#tests) and
[The window and running the app](../../docs/development/standards.md#the-window-and-running-the-app)
before changing these checks.

Add a step in `Checks` in `gui/app/Preview.swift` for a new window control.
The window check cannot type or point; those changes still need interaction
with the built bundle in the guest. Screenshots establish that pages draw,
not that controls work. Keep model ordering tests in `refresh-order.swift`,
including failures and overlapping requests, rather than depending on
accidental timing. Wait for conditions with named deadlines; do not lengthen
timeouts, loosen assertions or bypass permission checks to get a pass.
For a bug, observe the regression test fail with the bug present first.
Use synthetic fixtures, assemble token-shaped values from pieces, and check
new output paths for leaks of the planted values and their pieces.

Use `Checked:` for commands actually run and their exit statuses, and
`Not verified:` for skipped or blocked checks and why. Preserve failed runs
and their work folders even if a later run passes. Expected negative-control
failures must match the documented failure and cleanup outcomes. Report the
native helper's per-case PASS, FAIL, BLOCKED and NOT RUN results; neither
exit 2 nor a successful build is a passing integration check. When guest
checks are neither requested nor required by the change, list them as not
verified. There is no CI to wait for.
