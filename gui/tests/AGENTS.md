# Working with GUI checks

The [root](../../AGENTS.md), [GUI](../AGENTS.md) and
[test](../../tests/AGENTS.md) instructions apply here too.
[Local checks](../../docs/testing/local-verification.md) has the commands.

## Running

- Use the scripts rather than your own Swift builds; they read the deployment
  target from `gui/macos/Info.plist`.
- When the window check fails, read `report.txt` and `report.txt.log` in its
  work folder.
- `refresh-order.swift` runs the real model against a stand-in engine that
  controls response order. A pass says nothing about the running bundle or
  the orders macOS produces.

## In the guest

- Grant only what the standing guest-only authorization in the root file
  covers, through the guest's UI. Never edit TCC databases or reset all
  background items.
- A negative control must fail at its intended assertion, not at an unrelated
  prerequisite.
- If helper cleanup fails, keep the work folder, stop the guest and reset the
  clone before another run. Do not say the helper is off.
- Report the helper check's PASS, FAIL, BLOCKED and NOT RUN result for each
  case.

## Changing checks

Read [Tests](../../docs/development/standards.md#tests) and
[The window and running the app](../../docs/development/standards.md#the-window-and-running-the-app)
first. Keep model ordering tests, including failures and overlapping
requests, in `refresh-order.swift` rather than relying on timing.
