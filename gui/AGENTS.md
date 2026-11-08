# Working in `gui/`

For coding agents changing the app. The repository's `AGENTS.md` applies here
too, and this file does not repeat it: it adds what is true only of this
folder. Before changing code here, read `docs/development/standards.md` under
"The C interface", "Locks, threads and waits" and "The window and running the
app": it has the reasons, and the rules this file leaves to it.

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
- `src/release.rs`: reads GitHub's reply for `check_release` (the window
  fetches it in `app/Updates.swift`), and holds the test that keeps network
  code inside `Updates.swift`.
- `src/notifications.m`: the macOS side: notifications, the helper's and the
  app's login items, sleep and wake, and file events.
  `build.rs` compiles it with `clang` and archives it with `ar`. The file is
  built for macOS 10.15 and Cargo hides clang's warnings, so an API newer
  than macOS 14 needs `@available` here, and the build does not catch a
  missing one.
- `app/`: the window. `Engine.swift` is its side of `Bridge.h`, `AppModel.swift`
  holds all view state, `Models.swift` decodes the engine's JSON,
  `Failure.swift` has the titles of the alerts for failed actions,
  `Commands.swift` the menu bar's commands, and
  `Preview.swift` holds the sample engine, its JSON and the window check's
  `Checks`.
- `macos/Info.plist`: its `LSMinimumSystemVersion` (14.0) is the target every
  Swift build uses. `../.cargo/config.toml` sets the same for every Rust
  build, and the bundle contract test fails when they differ. After changing
  it, run `cargo clean --release` once: Cargo does not rebuild for that alone.
- `macos/*.lproj`: the window's text tables, keyed by the English.
  `es.lproj/InfoPlist.strings` is keyed by the `Info.plist` key instead:
  reword a folder-access reason's Spanish when you reword its English, since
  no check notices. `en.lproj` has only plural forms. `es-419.lproj` has
  only what differs from `es.lproj`; `build-macos.sh` lays it over
  `es.lproj` in the bundle.
- `tests/`: the window, model, bundle, login, notification and power checks,
  and the guest-only drivers `app-check.swift`, `helper-control.swift`,
  `install-profile.swift` and `update-quit.swift`.

## Commands

Before running or changing GUI checks, read [tests/AGENTS.md](tests/AGENTS.md).
`cargo test` covers the engine, helper and monitor. `build-macos.sh` writes
over the executable: quit the app and stop the helper first when either runs
in the guest.

## The engine

- A new command goes in `dispatch`, with its result type in `app/Models.swift`
  and an answer in `SampleEngine` in `app/Preview.swift`, so the sample-data
  builds still work.
- A new `src/*.rs` file whose text reaches the window goes into `SOURCES`
  and `ENGINE` in `src/engine_text_tests.rs`, or its Spanish is not checked.
- Changing one of the five functions means changing `Bridge.h`, `src/lib.rs`
  and `app/Engine.swift` together. Ask first.
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
- An API newer than macOS 14 needs an availability check, or the build fails.
