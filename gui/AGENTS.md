# Working in `gui/`

For coding agents changing the app. The repository's `AGENTS.md` applies here
too, and this file does not repeat it: it adds what is true only of this
folder. The reasons are in `docs/development/standards.md`, under "The C
interface", "Locks, threads and waits" and "The window and running the app".

## Layout

One executable, two modes: the window, and with `--agent` the background
helper. Both link the engine, which links the scanner crate in `src/`.

- `src/lib.rs`: the engine's app side and the C interface (from the comment
  "The C interface"), with every command in `dispatch`.
- `src/agent.rs`: the background helper. launchd starts it at login through
  `macos/dev.loosekeys.agent.plist`.
- `src/monitor.rs`: the helper's schedule, cancellation and the gate for
  manual scans.
- `src/review.rs`: the review store, shared by the app and the helper.
- `src/notifications.m`: the macOS side: notifications, the helper's login
  item, sleep and wake, and file events.
  `build.rs` compiles it with `clang` and archives it with `ar`. Subprocesses
  are confined to build scripts and tests.
- `app/`: the window. `Engine.swift` is its side of `Bridge.h`, `AppModel.swift`
  holds all view state, `Models.swift` decodes the engine's JSON, and
  `Preview.swift` holds the sample engine, its JSON and the window check's
  `Checks`.
- `macos/Info.plist`: its `LSMinimumSystemVersion` (14.0) is the target every
  Swift build uses. `../.cargo/config.toml` sets the same for every Rust
  build, and the bundle contract test fails when they differ. After changing
  it, run `cargo clean --release` once: Cargo does not rebuild for that alone.
- `tests/`: the window, model, bundle, notification and power checks, and the
  guest-only drivers `app-check.swift` and `helper-control.swift`.

## Commands

Before running or changing GUI checks, read [tests/AGENTS.md](tests/AGENTS.md).

Use the [root verification matrix](../AGENTS.md#commands), including its
prose-only exception. Run from the repository root, with `TMPDIR` set as
that file says. Each check passes only if it exits 0.
[Local checks](../docs/testing/local-verification.md) has the commands,
prerequisites and coverage limits. `cargo test` covers the engine, helper
and monitor.

- The window check uses the host-safe sample-data `PREVIEW` build described
  in the root file. It puts a window on screen for about a minute and needs
  the screen awake. Status 2 means it was blocked and checked nothing: not a pass.
- `tests/check-app.sh` and the native-helper integration checks run only in
  the guest ([guest checks](../docs/testing/guest.md)), never on this Mac.
  Helper runner self-tests need no guest or permissions.
- `build-macos.sh` writes over the executable. Quit the app and stop the
  helper first when either runs in the guest.

## The engine

- A new command goes in `dispatch`, with its result type in `app/Models.swift`
  and an answer in `SampleEngine` in `app/Preview.swift`, so the sample-data
  builds still work.
- Changing one of the five functions means changing `Bridge.h`, `src/lib.rs`
  and `app/Engine.swift` together. Ask first.
- Callbacks from macOS arrive on any thread. Return at once when the state
  they need is not set up yet, as they do with `AGENT.get()`.
- A command that acts on a file or link takes a finding's index or id, never a
  path from the window. Copy `item_path`: look the path up, check it again,
  return it. A link is returned only if `rules::known_link` lists it.
- A decision carries the `revision` the row was drawn with, and is checked
  against freshly loaded state inside the store's `update`.
- Keep a closure passed to `Store::update` to the change itself: the app and
  the helper both wait while it runs.
- A new `Mutex` field in `App` goes into `App::recover` only if its value is
  always replaced whole.
- Stopping work is cooperative, through `Monitor::cancel`. A pause or a change
  of consent cancels automatic work only, never a scan the person started.
- Call `prepare_quit` only when the app is really quitting: it closes the scan
  gate for the life of the process.
- The crate type is `staticlib` alone. Adding `rlib` makes Cargo leave `lto`
  off.

## The window

- Engine commands go through `Engine.request` or `send` to keep blocking
  work off the main actor. The exception is `prepare_quit`: it never waits
  for the store and `AppModel.prepareToQuit` calls it synchronously on the
  main actor so the scan gate closes before termination. Keep that call
  synchronous. Engine startup also stays on the main thread, as `Bridge.h`
  requires.
- A change to `Models.swift` changes the sample JSON in `Preview.swift` with
  it. Development-only code stays inside `#if PREVIEW || SNAPSHOTS`.
- Show text from a scan as text, never as markup.
- Keep the Filter field in the toolbar on every page. Removed and put back as
  the page changed, it stopped the app about one run in five.
- An API newer than macOS 14 needs an availability check, or the build fails.
- The `SNAPSHOTS` build uses the real engine, so it runs only in the guest.
