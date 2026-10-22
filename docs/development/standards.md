# Standards

[Documentation index](../README.md)

The detail behind the rules in `AGENTS.md`: what the code does, why, and
where to look. `AGENTS.md` is the short list to read every session; read the
section here before changing the code it covers.

Each rule describes the code as it is. Where older code does not follow a
rule, the rule says "new code" and names the exception. Do not bring old code
up to a new-code rule on the way to something else. That is a change of its
own. Numbers in brackets refer to the sources at the end.

## Errors and panics

- A failure that can happen in normal use is a value. In the scanner it is a
  gap: `fsutil` returns `Err(Gap)`, a fixed reason that ends up in
  `not_checked`, and `Ok(None)` only for what is skipped by design (absent, a
  link, not a regular file). In the engine it is `Answer<T>`, a `Result` whose
  error is text written for the person. [1]
- A panic is for a broken invariant, never for input. Scanned files, the
  state file, a command's arguments and the environment are all input. [1][8]
- Where a panic goes differs by program, on purpose:
  - Scanner: the process ends. The harness counts a crash as a failed run.
  - App: a panic inside a command is caught in `call` (`catch_unwind`),
    `App::recover` clears the poisoned locks and the command answers with an
    error. The workspace's release profile does not set `panic = "abort"`
    for this reason. With it, `catch_unwind` catches nothing and one bad
    command ends the app. [4]
  - Agent: `run` installs a hook that aborts on a panic in any thread, so
    launchd restarts the agent. A worker that died behind a live process would
    check nothing and still look like monitoring.
- `unwrap()` appears on lock results (see "Locks, threads and waits"), in
  tests, and where failure is impossible by construction. New code in the
  last case says why, with `expect("...")` or a comment, or avoids the
  fallible call: `c"state.json"` instead of `CString::new("state.json")`.
  Older code has bare `unwrap()` there, for example in `src/main.rs` and
  `Store::load`. [1]
- Never unwrap, format or log an error that carries its input when the input
  came from a scanned file. A panic prints the error's `Debug` form, which for
  `FromUtf8Error` and `NulError` includes the bytes, and a `serde_json` type
  error can quote the value it did not expect. Map the error to a fixed
  reason, as `utf8_lines` and `json_hits` in `src/rules/mod.rs` do.

## Unsafe code

- `unsafe` has two uses here: system calls on file descriptors
  (`src/fsutil.rs`, `gui/src/review.rs`) and the C interface to the window and
  the macOS bridge (`gui/src/lib.rs`, `gui/src/agent.rs`). It is not used for
  speed or to get around the borrow checker. [8][9]
- New code: every `unsafe` block has a `// SAFETY:` comment directly above it
  that says why this call's requirements hold here, not what the call does.
  `// SAFETY: openat returned a new owned descriptor.` is the form. Keep one
  operation to a block where you can, so the comment makes one claim. Older
  blocks in `fsutil.rs` and `review.rs` lack comments. Add one when you
  change such a block. [10]
- A `pub unsafe fn` has a `# Safety` section saying what the caller must
  guarantee, as `ch_call` and `ch_free` do. Clippy already requires it.
- Every file descriptor has one owner. Wrap the result of `openat` in
  `File::from_raw_fd` on the next line, before any `?`, so every return path
  closes it once. Lend it to a call with `as_raw_fd`. Use `into_raw_fd` only
  to hand ownership over, as `list_dir` does to `fdopendir`, with a `close` on
  the failure path and a `Drop` type on success. A descriptor closed twice may
  by then belong to another open file. [5]
- Bind a C string to a variable that outlives every use of its pointer.
  `let p = CString::new(x)?.as_ptr();` leaves `p` dangling: the string is
  freed at the end of that statement. [3]
- Call `assume_init` on a `MaybeUninit` only after the call that fills it has
  reported success, as `open_path` does after `fstatat`.
- Release things in `Drop`: `Directory` closes the listing, `Locked` drops the
  file lock, `Guard` in `perform_scan` clears the scanning flag. An early
  return or a caught panic then cannot leave one held. A `Drop` must not
  panic. [8]
- The code is edition 2021 but uses the spellings edition 2024 requires:
  `unsafe extern "C" { }` and `#[unsafe(no_mangle)]`. Keep to them. [7]

## The C interface

`gui/app/Bridge.h` is the whole interface: `ch_app_start`, `ch_call`,
`ch_free`, `ch_set_event_handler`, `ch_agent_main`. The engine's side is under
the comment "The C interface" in `gui/src/lib.rs`; the window's side is
`gui/app/Engine.swift`.

- A new capability is a new command name in `dispatch`, with JSON arguments
  and a JSON result. It is not a new function. The boundary stays small enough
  to review in one sitting, and the window needs no new pointer handling. If
  the functions themselves must change, change `Bridge.h`, `lib.rs` and
  `Engine.swift` together. [8][9]
- Only C types cross: pointers to NUL-terminated UTF-8, `bool`, integers and
  `extern "C"` function pointers. A function pointer that may be null is an
  `Option<extern "C" fn(..)>`, as `ch_set_event_handler` takes. [2][8]
- Each string has one side that frees it, and `Bridge.h` says which:
  - Into the engine: borrowed for the call. The engine checks for null, then
    for UTF-8, and answers a bad one with an error (`text` in `ch_call`).
  - Out of `ch_call`: made with `CString::into_raw` and released only by
    `ch_free`, which rebuilds it with `CString::from_raw`. Never C's `free`,
    never twice. [3]
  - An event's name and payload: valid only during the handler call. The
    handler copies them.
- A panic must not unwind into Swift or Objective-C. Since Rust 1.81 a panic
  that reaches the edge of an `extern "C"` function aborts the process: safe,
  but it ends the app. So commands run inside `catch_unwind` in `call`, and
  the other `extern "C"` functions and callbacks (`ch_app_start`,
  `open_review`, `changed`, `batch`, `delivered` and the rest) stay small and
  do nothing that fails on input. In the agent the abort is the intended
  result. Do not switch to `"C-unwind"`. [2][6]
- Callbacks arrive on other threads. They reach shared state only through
  `OnceLock`, atomics and mutexes, and return at once when the state is not
  set up yet (`AGENT.get()`). [2]
- `emit` copies the event handler out of its mutex before calling it, so the
  handler may call back into the engine.
- The window never supplies a path to act on. It sends a finding's index or
  id. The engine looks the path up, checks it again and returns it
  (`item_path`: a plain printable name, its folder opened without following
  links, never as root). A link is returned only if `rules::known_link` lists
  it. A new file or link action keeps this shape.
- One page is opened without the engine: System Settings at Notifications
  (`AppModel.openNotificationSettings`), a fixed `x-apple.systempreferences:`
  link built from the app's bundle identifier, with nothing from a scan in
  it. It goes through `AppModel.openURL`, which the window check replaces so
  that the check opens nothing on the Mac running it.
- `prepare_quit` closes the scan gate for the life of the process. Call it
  only when the app is really quitting.
- `set_monitoring` does not take an approved helper registration as proof
  that its launchd job is loaded. On new consent it unregisters that
  registration and registers again, with no store or app lock held across
  either native call. The bridge waits for
  [`unregisterWithCompletionHandler:`](https://developer.apple.com/documentation/servicemanagement/smappservice/unregister(completionhandler:)),
  because synchronous unregister does not wait for the old process to exit.
  An error or a ten-second timeout stops the sequence, and a late completion
  cannot start a registration. A registration waiting for approval is not
  retried; withdrawing consent unregisters it too. A native failure becomes a
  fixed error, never system error text. Consent is saved even when
  registration fails, so the status and the manual helper controls stay
  available. A fake native service and engine tests cover the order, the
  failures and pausing without starting a helper. Recovery after
  `launchctl bootout` is unverified, and this sequence did not clear a
  Launch Constraint Violation after a rebuild.
- A decision or reminder about an item's value carries the `revision` the
  row was drawn with. Check it against freshly loaded state inside the store
  transaction: an id can outlive the value the person saw.

## Locks, threads and waits

- `lock().unwrap()` is the convention. A poisoned lock means a thread
  panicked while holding it, and unwrapping passes the panic on instead of
  reading state that may be half changed. The two places that recover say why
  they may: `App::recover` clears the poison because each value it guards is
  only ever replaced whole, and `Store::alone` takes a poisoned guard because
  that mutex holds no data. A new `Mutex` field in `App` goes into `recover`,
  and only if the same is true of it. [4][9]
- New code: do not hold a guard across a call that can block or come back
  in: the scanner, `Store::read` and `update`, `emit`, any `ch_*` function,
  `Monitor`. Copy the value out first, as `work` does with
  `agent.known.lock().unwrap().skip.clone()`. The guard in such an expression
  is dropped at the end of the statement. `Mutex` is not reentrant, so a guard
  held across a call that locks it again waits for ever. One older function in
  `gui/src/lib.rs` breaks this: `defer_review` holds `review` and
  `storage_error` across `Store::update`. [4]
- Where two locks are held, the order is: in the app `review`, then
  `storage_error` or `report`; in the agent `inbox`, then `known`. `Monitor`'s
  lock is taken with no other held (`Agent::remember` drops `known` first).
  Two threads taking two locks in opposite orders can each wait on the other.
- The store has its own pair, taken inside `read` and `update`: a mutex for
  threads and `flock` for the other process. `update` holds both for the whole
  load, change and save, so the closure passed to it delays the app or the
  agent for as long as it runs. Keep a new closure to the change itself. The
  item rechecks inside the existing ones are deliberate: the merge has to be
  one step.
- `Monitor` is the one condition variable. State is changed under its mutex
  and then notified. `wait` checks the state again in a loop, because a wait
  can return with no notification and a notification with no waiter is lost.
  Requests to wake keep the earliest time (`retry_in`). [4]
- Stopping work is cooperative: a shared `AtomicBool` (`Monitor::cancel`) that
  the scanner polls in `Scan::stopped`. A work limit is not a timeout for a
  system call that blocks. `sleep` and `stop` set it for any work.
  `configure` sets it for automatic work only: the monitor remembers which
  kind `arm` last let through, so a pause or a change of consent never ends a
  scan the person started.
- The worker sets its own priority where its thread starts, in `run`, not
  inside the loop, so tests run the worker at ordinary priority. At
  background priority with every core busy, its 5-second slice ends
  unfinished and it waits 30 seconds for the next, which is also the tests'
  deadline.

## Files

The threats are a local user racing a root run with links, and hostile files
(see the file-access rules in `AGENTS.md`).

- Scanned files are opened and read only through `src/fsutil.rs`: `read_head`,
  `read_config`, `open_regular`, `list_dir`, `open_directory`. `open_path`
  walks from `/` one component at a time, each opened relative to the open
  parent with `O_NOFOLLOW`, `O_NONBLOCK` and `O_CLOEXEC`. No component can be a
  link and a FIFO cannot block the scan. The type is checked before the open
  and again on the handle. `std::fs::read`, `File::open` or `read_dir` on a
  scanned path skips all of it. The check before the open is not atomic with
  `openat`, so a file swapped in between can get a device opened before the
  handle check rejects it.
- Check, then use, the same handle. Size, type, owner and cloud flags come
  from the open file, not from the path a second time. `read_config` compares
  the size before and after reading. A path can be swapped between two calls;
  a handle cannot. [5]
- A presence check outside `fsutil` uses `std::fs::symlink_metadata`.
  `Path::exists`, `is_file`, `is_dir` and `fs::metadata` follow links. Treat
  the answer as a hint: whatever is read next still goes through `fsutil`.
- `through_links` is the one deliberate exception to following no links. A
  known sign-in location that is a link is resolved once, used only if the
  real path is inside the home folder, and never as root. Do not add another.
- A cloud-only file (`SF_DATALESS`) is never read, because reading downloads
  it. `fsutil` checks the flag before the open and on the handle.
- The app's `prepare_access` command takes only an index into Desktop,
  Documents and Downloads under the scan home. It lists the folder through
  `fsutil::list_dir` with a budget of zero entries, which is enough for macOS
  to ask for access: it keeps no names, opens no file, follows no link and
  counts as no coverage. No lock is held while a prompt is open. A failed
  probe is not a denial: the scan that follows checks each folder itself and
  reports its own gaps. The window sends these one at a time, before a manual
  scan or turning on the helper; cancelling takes effect once the open call
  returns, and a call that blocks has no timeout. Model tests cover order,
  cancelling and command failures, and an engine test covers the bounded
  probe and a denied folder staying a scan gap. Prompt order on a real Mac,
  and whether the window's grants cover the helper, are unverified
  ([the macOS guest](../testing/guest.md#folder-access-preparation)).
- There are two ways to write, and a new file uses one of them. An export is
  created with `O_CREAT | O_EXCL | O_NOFOLLOW`, mode 0600, relative to the
  parent handle that was checked (`write_export`); as root the folder must be
  root-owned and not writable by others. The app's state is written to a new
  temporary file, synced, renamed over the old one, and the folder synced
  (`Store::save`).
- Everything read back is bounded and checked before use, the app's own state
  included: `Store::open` and `load` require the user's ownership, no access
  for others, one link, a size limit and sane counts. Code running as the user
  can edit that file.
- The app's state folder is `review::STATE_DIR` in the home folder.
  `Store::open` makes and opens each folder on the way without following a
  link, so a link anywhere on that path stops it rather than sending the
  state elsewhere. It moves `state.json` from the older `~/.loose-keys-review`
  once, holding both folders' locks, only when the old file is a private
  regular file of the user's and the new folder holds none; anything else
  there is left as it is. A helper from before the move that is still running
  writes to the removed old folder until it restarts. Review tests in
  `gui/src/review.rs` cover the location, the move, newer state winning, and
  links on the path and at the old folder.

## Secrets

- A value does not leave the function that matched it. A matcher returns
  `Hit`s holding a line, a `span` (a position) and labels. `rules::label`
  accepts only short printable text, and callers pass it names and hosts,
  never a field that stores a secret. `Progress` and events carry counts.
- A type that holds file bytes has no `Debug` or `Display` (`Head` has
  neither), and `Incomplete`'s `Debug` shows only its fixed reason and hit
  count. What goes to the window is rebuilt field by field: `shown` clears
  `fingerprint`, `secret` and `mount` from every item `review_items` sends.
- A fingerprint is keyed: HMAC-SHA-256 under a random key made once per
  install and kept in the owner-only state. An unkeyed hash of a short secret
  can be reversed by guessing. Fingerprints are never exported, and the report
  format forbids hashes outright.
- The agent's log lines are fixed text plus a store error. The scanner's
  progress line is counts. Keep paths and names out of both.
- Bytes read from a file sit in an ordinary `Vec` and are freed, not wiped,
  when the check ends. That is a known limit, not a pattern to extend: do not
  keep file bytes past the check that needs them, and do not cache them. [8]
- Fixtures hold synthetic values only, with words such as `synthetic` and
  `fixture` and hosts under `.invalid`. A token-shaped string is put together
  from pieces (`concat!` in `src/rules/token.rs`, `fake` in its tests) or made
  at run time (`security-tests/synthetic_home.rs`, `security-tests/fixtures.rs`).
  Generated fixture folders are git-ignored. Never commit one.

## Finding text and remediation

Describe what the matcher established: a header, a field, a known location or
an unvalidated token format. Reading enough to match a field is not the same as
validating the credential. Do not say a value was never read when its parser
inspected it, or that a matching file or a browser count guarantees account
access.

Remediation must distinguish preventing future sign-ins from invalidating an
existing credential or session. [Telegram's FAQ](https://telegram.org/faq#q-my-phone-was-stolen-what-do-i-do)
separately requires two-step verification and termination of existing sessions.
[GitHub CLI's login documentation](https://cli.github.com/manual/gh_auth_login)
notes that credential-store failures can fall back to a plain-text file;
`gh auth status` reports its location. The
[BIP-39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed)
allows an additional recovery passphrase, so words alone do not always grant
access.

Rule samples, the detection corpus and the security harness check that finding
text reaches the reports with no credential value in it. They do not check
what third-party products show or how each version stores credentials, and
vendors change their settings.

## The shared scanner crate

- The scanner is the `loose_keys` library (`src/lib.rs`). The `loose-keys`
  command (`src/main.rs`) and the engine (`gui/`) depend on it like any crate,
  and `gui/src/lib.rs` imports its modules by name. Something only one of them
  uses is `pub` in the library, not `#[allow(dead_code)]`.
- Test-only support under `tests/support/` is compiled into each test that
  needs it with `#[path]`, because `#[cfg(test)]` items in the library are not
  built for another crate's tests.
- A rule lives in one file per family under `src/rules/` and is listed in
  `RULES` in `mod.rs`. Its text, targets, matcher and `samples` sit together,
  and a unit test fails a rule that lacks a matching or a non-matching sample.
  Report text is fixed scanner text, never built from file contents.
- Each registered implementation also needs a case in
  `tests/detection-corpus.json`, or the coverage test fails. `Case` in
  `tests/support/detection.rs` documents the fields. Write the expected
  findings from the intended behaviour, never by copying a scan's output.
- Matcher caps: 100 assignments per environment or shell file, 100 MCP
  holders, 100 OpenVPN key blocks, 100 rclone remotes per rule, and 20
  password-note lines. Poetry token entries fill the first 100 findings after
  any INI password findings; warehouse configs list up to 100 embedded keys in
  addition to their password fields. Terraform lists 100 holders and examines
  up to 1,000 instances per resource and 100 named sensitive attributes per
  instance. Service-token matching keeps the first 100 occurrences, then only
  new values until 100 distinct values have been found; later repeats are
  grouped. When another distinct value or capped match is omitted, or
  Terraform's inspection budget leaves entries unchecked, retained findings
  stay listed and a `scan-limit` gap makes the scan partial. Exactly filling a
  match budget is not a gap. An incomplete recheck cannot mark an omitted
  review item fixed. A change to a cap updates this list.

## Tests

- Unit tests are in a `tests` module in the file they test and can reach
  private items. `tests/scan_scope.rs` runs the built scanner as a child
  process and sees what a person would: output, exit status, files. [1]
- A test builds its fixtures in a folder under `TMPDIR` named for the test and
  `std::process::id()`, and removes it at the end or in `Drop`. Tests run in
  parallel, so a shared name collides. `TMPDIR` has to be a real path because
  the scanner refuses a path with a link in it. That is the scanner being
  right, not a check to loosen.
- The environment belongs to the whole process. Give a child its `HOME` with
  `Command::env`. Inside the process pass the home as an argument, as
  `Scan::run`, `App::open` and `Store::open` take it. `std::env::set_var`
  races with tests on other threads, and edition 2024 marks it unsafe for
  that reason. [7]
- Events go to one handler for the whole process. A test that scans through
  the app's side (`start_scan`) holds `one_scan()` in `gui/src/lib.rs`'s tests
  for as long as it scans. One that does not makes the other scanning tests
  fail at random, by seeing or sending their events.
- A test that waits for another thread waits for a condition, with a deadline
  that fails naming what never happened: `Fixture::wait` in `gui/src/agent.rs`,
  `recv_timeout` in `gui/src/monitor.rs`. A stuck worker then fails one test in
  seconds and does not hang the run. A fixed sleep is used only to show that
  nothing happened. A wait the code under test would make is a field the test
  shortens (`Agent::recheck_after`, `low_power_pause`). Do not raise a deadline to
  pass a slow test. Find what is slow.
- A regression test is shown to fail with the bug put back, for example in a
  separate worktree. Assert what a person would notice, not a
  restatement of the code. [9]
- A matcher cap is tested at the cap and one past it, and a test that passes
  the cap asserts both the retained matches and the `scan-limit` gap: a
  truncated result is never a complete one.
- SQLite fixtures are complete databases made by the system `sqlite3`, never
  hand-edited pages: an edited page can be a file SQLite would never write.
- A change to resumable discovery keeps the parity test passing: the union of
  findings from resumed passes, across entry budgets and cancellation, equals
  an uninterrupted pass.
- A new way for text to leave the tool gets a leak check: plant a value,
  search every output for it and for pieces of it, as `tests/scan_scope.rs`
  and the harness's `leak` check do.
- `#[ignore]` is for measurements run by hand, with the reason in the
  attribute (`resident_fixture_measurement`). It is not for a failing test.
- The harness is tested too. `security-tests/reference.rs` runs a deliberately
  careless scanner and expects the harness to catch it. Change the two
  together.
- The harness finds a network attempt only by the denial the kernel logs,
  which it reads with `log show`. Two things seen on macOS 14 shape the
  check. What `log show` returns can trail the kernel by many seconds, and the
  log stamps entries with its own clock, which can run behind the harness's.
  So after a run the harness makes one more denial on purpose, with a marker,
  and asks for the scanner's only once the log returns that one
  (`network::caught_up` in `security-tests/network.rs`), and every query
  starts a minute early (`log_start`). Each run keeps what it saw in
  `network-log/`, with both clocks' times for the marker in
  `caught-up.json`. If you see a miss, read the times there and report it
  with its evidence. Do not rerun until it passes and call that a pass.
- The window check (`sh gui/tests/check-window.sh`;
  [local checks](../testing/local-verification.md)) runs the steps in
  `Checks` in `gui/app/Preview.swift`. It sets the filter in
  code because it cannot type, and does in code what it has no control to
  press for: choosing a reason from the Set Aside… menu, clearing the chosen
  row, putting a list's sort back. Most steps after the two lists need
  `SampleEngine`, which keeps a little state and has switches the check sets
  (a failed store, a refused request, a full list, everything set aside).
  With the screen locked, or its saver on though not
  yet locked, macOS puts a shield over every window and gives a window's
  contents to nobody, so the check asks for its window first and stops with
  status 2 when AppKit logs the shield. Both were made on purpose only in
  the virtual machine. A step that reads what the window drew waits
  for it (`eventually`), because a busy Mac draws late. A step must not
  close an alert in code while the page under it is changing: AppKit stops
  the window doing that, so such a step uses a model that is in no window.
  The picture-taking build only shows that pages draw: it changes pages in
  code, where the check presses the controls.
- The model check (`sh gui/tests/check-model.sh`;
  [local checks](../testing/local-verification.md)) builds
  `gui/tests/refresh-order.swift` with the real `AppModel.swift`,
  `Models.swift` and `Engine.swift` and no window. Its `HeldEngine` holds
  each command until the test answers it and counts simultaneous calls.
  Cases cover coalesced review/status reads, a change or failure during a
  read, latest failures, out-of-order folder answers, concurrent scan/Stop,
  and the id and revision sent with decisions and reminders.
  A call the test never answers fails after ten seconds, naming the command.
  It is a model with a stand-in engine, not the running window or the real
  engine, and it does not show which orders macOS produces.

## Toolchain, lints and dependencies

- `rustfmt` and clippy run with their defaults, and any warning fails the
  check (`-D warnings`). Both manifests have a
  `[lints]` table that denies five more things: an unsafe call inside an
  `unsafe fn` with no block of its own (`unsafe_op_in_unsafe_fn`), and
  clippy's `dbg_macro`, `todo`, `unimplemented` and `mem_forget`. Keep the
  two tables the same. Fix what a lint reports. If it is wrong for this
  code, allow it on the smallest item with the reason in a comment.
- Pass `--locked` to every cargo command that builds. It fails instead of
  rewriting `Cargo.lock`. The workspace has one lock file, at the root.
  `cargo audit --file <lock>` checks one against the RustSec advisory list.
  [Local checks](../testing/local-verification.md) has the commands. [11]
- Both manifests say `rust-version = "1.88"`, and `README.md` tells people
  that version. The checks lint and test with the latest stable and also
  build the workspace with 1.88. Clippy's `incompatible_msrv` lint, on by default,
  reports a standard library item newer than that.
- Edition 2021. Edition 2024 changes when temporaries, lock guards among
  them, are dropped in `if let` and at the end of a block, makes
  `std::env::set_var` unsafe and reformats code. Moving is a change of its
  own, with the lock code reread. [7]
- A version change touches `Cargo.toml`, `gui/Cargo.toml` and `Cargo.lock`.
  The bundle's version keys in `gui/macos/Info.plist` take numbers and dots
  only.

## The window and running the app

### Building and starting

- `sh gui/build-macos.sh` builds the engine with cargo, links the window to
  it with `swiftc`, and signs the bundle ad hoc, or with the identity named
  in `LOOSE_KEYS_SIGN_IDENTITY` ([usage](../usage.md)). It has to work with Apple's
  command-line tools alone, because that is how testers build it
  (`README.md`). `@State` needs a compiler plug-in that comes only with
  Xcode ("plugin for module 'SwiftUIMacros' not found"), which is why view
  state lives in `AppModel`.
- `AppModel` is `@MainActor` and owns all state. Views read it through
  `@EnvironmentObject`. Engine calls block (`start_scan` until the scan ends),
  so they go through `Engine.request` and `send`, which run off the main
  thread. Events may arrive on any thread and are moved to the main actor in
  `AppModel.start`.
- Those calls answer in any order: startup, an event, a click and the window
  coming forward can each ask for the same list while an earlier request is
  still out. `review` and `monitor` each use `ReadTurns`: one read at a time,
  with requests during it sharing the next read. Numbering requests was not
  enough: a later call could read first. The engine renders the snapshot its
  own command read, not a shared copy another call can replace. If a read
  fails while another is already queued, the window keeps what it shows until
  that one answers; otherwise the review list reports the failure and the
  helper status shows as unavailable. Folder answers are applied in the order
  they were requested, not the order the engine ran them, so two folder
  changes that overlap may need another refresh to show the result. Scans and
  cancelling are not ordered with these reads.
- While the window is in front, one task refreshes the review list and helper
  status, waiting five seconds after each pair of reads. Leaving the front or
  quitting cancels it; a read already sent may still finish. A manual scan
  pauses these reads. Show a failure of them without opening an alert every
  five seconds. `gui/tests/refresh-order.swift` checks that a helper finding
  shows up with no scan or injected event, that a failure is shown as one,
  and that cancelling works.
- The engine's JSON is decoded into the types in `Models.swift`, snake case
  to camel case. `Preview.swift` holds sample JSON for the sample-data build,
  which has to change with them. Text from a scan is shown as text, never as
  markup. Development-only code sits inside `#if PREVIEW || SNAPSHOTS`.
- The controls are the system's: `NavigationSplitView`, `Table`, `List`, the
  toolbar, `.inspector`, `Form` in a `Settings` scene, `NSOpenPanel` and
  `NSSavePanel`. Add a feature with one of these before drawing anything.
- Overview shows scan results, background status and folder controls, not
  what a scan covers. That is in [usage](../usage.md), in
  `loose-keys --list-rules` and in every saved report, which keeps the
  scan's exclusions and detection limits.
- The Filter field is in the toolbar on every page, on purpose. Taken out and
  put back as the page changed, it stopped the app about one run in five in
  the window check: AppKit refuses a second search field in a toolbar, and
  the first was not always gone by then. Do not make a toolbar's search field
  depend on the page.
- A row's selection is cleared in the model when the filter hides the row
  (`dropHiddenSelection`), and a stored sign-in's when new results arrive,
  because its id is its place in the results.
- Worth Reviewing and Set Aside show separate portions of the same review
  list. The split is only in the window: scanning, grouping, report counts
  and exports keep set-aside findings. A successful refresh clears a
  selection when a decision moves its row to the other page; a grouped
  credential stays in review while another copy still needs a decision.
  Both pages show read/save failures instead of an empty result. When the
  list cannot be used, Worth Reviewing's badge is the scan's count and Set
  Aside has none, since a scan knows nothing of decisions.
- Decision reasons have fixed names in the app interface and private state.
  `testing` and `no-longer-works` are value decisions with the same scope
  and expiry as the older `test-or-revoked`, which still loads and shows as
  a previous choice and is never guessed into either. An older build,
  including a helper still running from before an update, cannot decode
  the review list once it holds a new reason, so it can neither read nor
  save the list until a build that knows them runs. That is from the
  code; no running app has shown it. Scan and report contracts are
  unchanged.
- Move to Worth Reviewing sends the displayed row's id and revision, so the
  engine can refuse a click after that value has changed. The window
  follows the returned finding only after the command and its ordered
  refresh succeed, and only if the person chose no other row and did not
  change page in the meantime. The model and window checks cover moving
  between pages, filters, failed decisions, reopened findings, a stale click
  and a choice made while the move is saved; they do not cover pointer
  placement, a move with several set-aside rows in the real table, or the
  real engine.
- Two messages in the window's log are known and come from SwiftUI's own
  tables, not from this code: "Publishing changes from within view updates"
  on each selection change, and AppKit's "reentrant operation" warning when
  a table's rows move or return (a sort with a row selected, a filter
  cleared). The window check prints the second as a note.

Starting the app. Run these commands only inside an approved disposable macOS
guest containing synthetic data, when the task needs the app. Generate a new
synthetic home first (`sh security-tests/harness.sh generate-home`, as in
[local checks](../testing/local-verification.md)):

```sh
open --env HOME="$TMPDIR/synth/home" "target/release/bundle/macos/Loose Keys.app"
```

- Confirm the process has that synthetic `HOME`. Do not collect a full process
  environment from the host.
- Quit the app before rebuilding. The build writes over the executable.
- The standing guest-only authorization does not cover host privacy changes
  or `sfltool resetbtm`, which resets background items for every app.
- A registered helper once failed to start after a rebuild, for a reason not
  yet known. Use a fresh guest clone for each helper check.

Looking at the window without a screen. Two development builds, defined in
`gui/app/Preview.swift`, save a picture of each page into `SNAPSHOT_DIR` and
quit. A window appears on the person's screen for a few seconds, so say so
first. The first build uses sample data and no engine; the second uses the
real engine, runs only in the approved guest, and needs
`sh gui/build-macos.sh` to have run there:

```sh
swiftc -parse-as-library -D PREVIEW -target "$(uname -m)-apple-macosx14.0" \
    gui/app/*.swift -framework AppKit -o "$TMPDIR/window-preview"
swiftc -parse-as-library -D SNAPSHOTS -target "$(uname -m)-apple-macosx14.0" \
    -import-objc-header gui/app/Bridge.h gui/app/*.swift \
    target/release/libloose_keys_gui.a \
    -framework AppKit -framework UserNotifications -framework ServiceManagement -framework CoreServices \
    -o "$TMPDIR/window-snapshots"
mkdir -p "$TMPDIR/pictures"
SNAPSHOT_DIR="$TMPDIR/pictures" "$TMPDIR/window-preview"
HOME="$TMPDIR/synth/home" SNAPSHOT_DIR="$TMPDIR/pictures" "$TMPDIR/window-snapshots"
```

`SNAPSHOT_LOOK=light` or `dark` picks the appearance. `SNAPSHOT_ACTIONS=1`
also sends the decision and export commands through the engine. With
`CHECK_REPORT=<file>` set instead of `SNAPSHOT_DIR`, either build runs the
window check and writes its result to that file; on the second build that is
the check against the real engine.

## Sources

Recheck a source before leaning on a detail: these change.

1. The Rust Programming Language, "To panic! or Not to panic!" and "Test
   Organization". https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html
   and https://doc.rust-lang.org/book/ch11-03-test-organization.html
2. The Rustonomicon, "Foreign Function Interface": unwinding, callbacks from
   other threads, nullable function pointers. https://doc.rust-lang.org/nomicon/ffi.html
   The Reference has the table of what a panic does at each ABI boundary:
   https://doc.rust-lang.org/reference/items/functions.html
3. `std::ffi::CString`: `into_raw` and `from_raw`, and the dangling `as_ptr`.
   https://doc.rust-lang.org/std/ffi/struct.CString.html
4. `std::sync::Mutex` (poisoning, relocking), `std::sync::Condvar` (waits that
   return early, notifications that are not kept) and
   `std::panic::catch_unwind`. https://doc.rust-lang.org/std/sync/struct.Mutex.html,
   https://doc.rust-lang.org/std/sync/struct.Condvar.html,
   https://doc.rust-lang.org/std/panic/fn.catch_unwind.html
5. `std::fs`, "Time of Check to Time of Use", and `std::io`, "I/O Safety".
   https://doc.rust-lang.org/std/fs/index.html and
   https://doc.rust-lang.org/std/io/index.html
6. Rust 1.81 release notes: a panic leaving an `extern "C"` function aborts.
   https://blog.rust-lang.org/2024/09/05/Rust-1.81.0/
7. Rust 1.82 release notes (`unsafe extern`, unsafe attributes) and the 2024
   edition guide (`if let` temporaries, `set_var`).
   https://blog.rust-lang.org/2024/10/17/Rust-1.82.0/ and
   https://doc.rust-lang.org/edition-guide/rust-2024/
8. ANSSI, Secure Rust Guidelines: unsafe, FFI, panics, `Drop`, tooling.
   https://anssi-fr.github.io/rust-guide/
9. Microsoft, Pragmatic Rust Guidelines: unsafe, panics, FFI, tests.
   https://microsoft.github.io/rust-guidelines/
10. Clippy's lint list and configuration (`undocumented_unsafe_blocks`,
    `missing_safety_doc`, `incompatible_msrv`).
    https://rust-lang.github.io/rust-clippy/master/ and
    https://doc.rust-lang.org/clippy/lint_configuration.html
11. Cargo, `--locked` and the `[lints]` table; RustSec and `cargo audit`.
    https://doc.rust-lang.org/cargo/commands/cargo-build.html,
    https://doc.rust-lang.org/cargo/reference/manifest.html and https://rustsec.org/
