# Native helper integration checks

[Documentation index](../README.md)

`sh security-tests/harness.sh helper-check` runs the Rust runner in
`security-tests/helper.rs`. It tests the installed bundle's real
helper through ServiceManagement, launchd and FSEvents, not injected callbacks.
It never rebuilds or changes the candidate. Build the bundle separately first.

## Safety and prerequisites

Run only in an approved disposable guest whose account holds synthetic data
and no real credentials. **The helper scans that account's own home, whatever
`HOME` the window was given.** The runner refuses to start unless it is on a
virtual Mac (`VirtualMac`), as an ordinary console user whose `HOME` is the
account's real home, with SIP and Gatekeeper on and
`CREDHYG_HELPER_CHECK=disposable-guest` set. That stops an accidental run on a
host, but it cannot tell whether the guest holds real data: check that
yourself first.

Use Rust 1.88 or later and Apple's Swift command-line tools in the guest, with
`TMPDIR` set to an existing scratch folder with no link in its path (for
example `$HOME/verification-scratch`). The screen must be awake and unlocked.
Before running, give the Settings driver Accessibility
([Accessibility and launch routes](guest.md#accessibility-and-launch-routes))
and, if macOS asks, approve the Login Items entry. The runner grants nothing
itself.

Build the bundle once and do not rebuild it during the run. Start from a fresh
clone: the runner refuses existing app state
(`Library/Application Support/dev.loosekeys.desktop` or the older
`.loose-keys-review`), `.aws`, a running app or helper, or a registered
helper. Run one suite per guest, and do not replace an ad-hoc-signed bundle
under a registered helper.

Set up the guest and transfer the source as in [the macOS guest](guest.md).

## Run

In the guest, from the source tree, after building the candidate:

```sh
bundle="$PWD/target/release/bundle/macos/Loose Keys.app"
# Record and approve this digest before the run; the runner checks it again.
candidate_sha256="$(shasum -a 256 "$bundle/Contents/MacOS/loose-keys-gui" | cut -d' ' -f1)"
echo "$candidate_sha256"
```

Supply that digest and a new work folder under an existing guest scratch folder:

```sh
CREDHYG_HELPER_CHECK=disposable-guest sh security-tests/harness.sh helper-check \
  --bundle "$bundle" --sha256 "$candidate_sha256" \
  --guest-home "$HOME" --work "$HOME/verification-scratch/helper-positive"
```

Before enabling, it seeds an empty review store with ordinary skip labels for
the guest's existing folders: toolchains, build trees and protected user
folders. Known sign-in files are read whatever the skips say, so the skips
shorten the run but hide nothing. The new `.aws` fixture stays in scope. The
suite does not test whole-home coverage or folder permissions.

Cases, in fixed order:

1. Preflight: guest, candidate digest, clean product state, driver grant.
2. Enable/baseline: actual Overview consent and registration, completed initial pass;
   the persisted PID must point to this bundle's executable in `--agent` mode.
3. Create: a generated synthetic AWS file becomes exactly one open finding.
4. Rotate: only the fixture values change; the finding's keyed material and
   revision must change.
5. Delete: removing the file leaves no open fixture finding.
6. Restart/replay: Stop Helper unregisters it and its process exits; a file is
   created while it is stopped; Start Helper produces a new PID and replays the
   change from its saved checkpoint without replacing the completed baseline.
7. Disable: withdraw consent, verify unregistration and process exit, then mutate
   the fixture and require unchanged state throughout a 12-second observation.
8. Cleanup: withdraw consent if needed, verify helper exit, stop the test app,
   remove only this run's fixtures/state, and check the app log for planted values.

An event case passes only if the helper's saved event id and its changed-file
count both went up, the full-pass baseline did not change, and the finding
changed as expected, so a full scan cannot pass for a file event. Deadlines
are fixed: 90 seconds
for asynchronous helper outcomes, 20 seconds for lifecycle/UI waits.

## Negative control and self-tests

Run the same command with `--omit-create` and a different new work folder. It must
exit **1**, with preflight and enable/baseline PASS, event-create FAIL at its
missing transition assertion, later cases NOT RUN, and cleanup PASS. A run that
fails for another reason, such as a launch or permission failure, shows
nothing about the control.

Runner self-tests need no guest, window, product process or permission:

```sh
sh security-tests/harness.sh helper-self-tests
```

They also run in `--self-tests` and `cargo test --locked`. They test the
runner, not the helper.

## Results and failure handling

`results.json` records PASS, FAIL, BLOCKED or NOT RUN for every case. It never
copies the review store, HMAC key, credential digests or fixture values. The
owner-only work folder also keeps the embedded runner and driver source, the
compiled driver, compiler diagnostics and the app log. The leak checks on
state and the app log look for full fixture values and their first and last
ten characters, not every possible fragment or system-log destination.

Exit 0 means the named suite passed; 1 means failure (including cleanup failure);
2 means a prerequisite blocked execution. Keep the work folder of a failed run
and report it along with any later pass.

Ctrl-C and SIGTERM request cleanup and record failure. No runner can clean up
after SIGKILL, guest power loss or a broken Accessibility connection. If cleanup
fails, do not reuse the guest or say the helper is off: stop the guest, keep
the work folder, and reset the clone before another run.

## Limits

The fixed suite covers native lifecycle, ordinary known-file events, rotation,
deletion and checkpoint replay. It does not test failed-save recovery, linked
targets, browser sidecars, notifications, login/reboot, sleep/wake, Low Power
Mode, foreground refresh or every consent path. Engine tests cover scheduler
and storage faults with stand-ins for macOS, so they show nothing about how
the installed helper behaves.
