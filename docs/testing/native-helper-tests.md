# Native helper integration checks

[Documentation index](../README.md)

`sh security-tests/harness.sh helper-check` tests the installed bundle's real
helper through ServiceManagement, launchd and FSEvents. It never rebuilds or
changes the bundle.

## Before running

Run only in a disposable guest whose account holds synthetic data and no real
credentials. **The helper scans that account's own home, whatever `HOME` the
window was given.** The runner refuses to start unless it is on a virtual Mac,
as an ordinary console user whose `HOME` is the account's real home, with SIP
and Gatekeeper on and `LOOSE_KEYS_HELPER_CHECK=disposable-guest` set. It
cannot tell whether the guest holds real data: check that yourself.

The guest needs Rust 1.88 or later, Apple's command-line tools, an awake and
unlocked screen, and `TMPDIR` set to a scratch folder with no link in its path
(for example `$HOME/verification-scratch`). Give the Settings driver
Accessibility in the guest's System Settings and, if macOS asks, approve the
Login Items entry.

Use a fresh clone for each suite, set up as in [the macOS guest](guest.md):
the runner refuses existing app state, `.aws`, a running app or helper, or a
registered helper. Do not rebuild or replace the bundle during a run.

## Run

In the guest, from the source tree:

```sh
bundle="$PWD/target/release/bundle/macos/Loose Keys.app"
# Record and approve this digest before the run; the runner checks it again.
candidate_sha256="$(shasum -a 256 "$bundle/Contents/MacOS/loose-keys-gui" | cut -d' ' -f1)"
echo "$candidate_sha256"
LOOSE_KEYS_HELPER_CHECK=disposable-guest sh security-tests/harness.sh helper-check \
  --bundle "$bundle" --sha256 "$candidate_sha256" \
  --guest-home "$HOME" --work "$HOME/verification-scratch/helper-positive"
```

The negative control is the same command with `--omit-create` and a new work
folder. It must exit 1, with event-create FAIL at its missing assertion, later
cases NOT RUN and cleanup PASS.

`results.json` in the work folder records PASS, FAIL, BLOCKED or NOT RUN for
each case, never the review store, its key or fixture values. Exit 0 means
the suite passed, 1 a failure (cleanup included) and 2 a blocked
prerequisite. Keep a failed run's work folder and report it along with any
later pass. If cleanup fails or the run is killed, do not reuse the guest or
say the helper is off: stop the guest, keep the work folder and reset the
clone.

`cargo test` runs the runner's self-tests, which need no guest.

## Limits

The suite covers the helper's start and stop, file creation, rotation and
deletion, and replay after a restart: the runner unloads the helper with
`launchctl bootout`, then presses Restart Helper in Settings. It does not
test whole-home coverage, folder permissions, failed-save recovery, linked
targets, browser sidecars, notifications, login or reboot, sleep and wake,
Low Power Mode, foreground refresh or every consent path. Its leak checks
look for full fixture values and their first and last ten characters, not
every fragment or system log.
