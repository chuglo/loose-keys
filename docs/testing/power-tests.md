# Power checks

[Documentation index](../README.md)

The worker and scheduler tests run in `cargo test`, and the power bridge
command is in [local checks](local-verification.md#notifications-and-power).
None of them installs or launches the helper, opens the app, scans your home,
requests permissions, sleeps the computer, or changes Low Power Mode.

The two worker tests in `gui/src/agent.rs` check that:

- Sleep holds the initial full pass and queued creation without acknowledging
  the event. Wake completes both. A second sleep/wake cycle preserves a queued
  deletion and marks the finding resolved after waking.
- Low Power Mode holds repeated full-pass attempts while changed-file checks
  continue. The event checkpoint cannot pass the held work. Ending the simulated
  mode lets the worker's own retry finish the full pass, without a new file event
  or manual scan.

The scheduler's tests also check cancellation, consent/pause gates, manual
scans, coalesced wake requests, retries and shutdown. `gui/tests/power_test.m`
compiles the real native bridge and posts three sleep/wake cycles to it through
its own process's workspace notification center. It checks that the callbacks
come in order and that each wake rereads notification permission once, then
compares the bridge's read-only Low Power Mode query with the current system
value. Run outside a bundle, the permission read always reports unavailable,
so it sends no notification.

The worker tests inject the Low Power Mode value. They shorten only the retry
delay (`Agent::low_power_pause`); the shipped helper waits ten minutes between
Low Power Mode full-pass attempts.

Not verified: actual macOS delivery of sleep/wake notifications, suspension and
resumption of the installed helper, changes of the real Low Power Mode setting,
or battery/energy use. The disposable guest refuses sleep requests and does not
offer Low Power Mode, so it cannot check them either.
