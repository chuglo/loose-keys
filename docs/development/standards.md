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
  registration fails, so the status and Restart Helper stay available.
  Settings shows Restart Helper only while the helper is not running; it
  unregisters a registered helper and registers it again, as new consent
  does. Recovery after `launchctl bootout` is unverified; the guest helper
  check's restart stage tests it.
- The app adds itself to Login Items (`SMAppService.mainAppService`,
  through `ch_app_login_status` and `ch_app_login_set` in `notifications.m`,
  declared only in `lib.rs`, not in `Bridge.h`) only while Show in Menu Bar
  and background checks are both on. Show in Menu Bar is on until the person
  turns it off, stored as `menu_bar_off` so state without it reads as on. `set_menu_bar` and `set_monitoring`
  each save their setting, then `reconcile_app_login` registers or
  unregisters only when the item differs, waiting for unregister as for the
  helper, and never repeats a request waiting for approval. Both hold
  `app_login` from the save to the change, so the later of two changes at
  once decides the item. When the engine first reads the state, it removes
  an item the state does not want, as after a state reset, and adds none
  back; unreadable state changes nothing. A helper failure is reported before
  a Login Items failure. Quitting leaves the item, so it opens the app at the
  next login. The menu bar menu changes nothing: its text is a fixed phrase
  and a count (`menuBarLine`) and the status Settings shows. Remaining risks:
  an older build saving the state drops `menu_bar_off`, which turns the
  icon back on; checks already on from before this setting add no item
  until either setting changes; the person removing the item in System
  Settings, which the window shows as not in Login Items; whether
  registering needs the person's approval, unverified.
- A decision about an item's value carries the `revision` the row was drawn
  with. Check it against freshly loaded state inside the store
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
  held across a call that locks it again waits for ever. [4]
- Where two locks are held, the order is: in the app `app_login` first, then
  `review`, then `storage_error` or `report`; in the agent `inbox`, then
  `known`. `app_login` holds no data and is the one guard held across the
  store and `ch_*` calls, because it orders whole Login Items changes;
  nothing it calls takes it, and it is dropped before `emit`. `Monitor`'s
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
  inside the loop, so tests run the worker at ordinary priority.

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
  returns, and a call that blocks has no timeout. Prompt order on a real Mac,
  and whether the window's grants cover the helper, are unverified.
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
- The organization's expected-findings list enters only through the
  window's `set_expected`, from a preference macOS reports as forced
  (`CFPreferencesAppValueIsForced`): a configuration profile or a file under
  `/Library/Managed Preferences/`, where only root can create or replace a
  file (macOS checks the folder, not the file's owner). The merged defaults
  are never read: they include
  `~/Library/Preferences/dev.loosekeys.desktop.plist`, which anyone who can
  write to the home folder can write. The engine checks each entry again
  (`review::accepted`: a rule the scanner has, a plain `~/` path below the
  home, 32 at most) and keeps it in `state.json` beside the person's
  decisions, with the same standing as a Kept decision. The CLI reads none
  of it. A file planted at a listed path is still listed, under Set Aside
  with its rule and details, counted and exported.
- The app's state folder is `review::STATE_DIR` in the home folder.
  `Store::open` makes and opens each folder on the way without following a
  link, so a link anywhere on that path stops it rather than sending the
  state elsewhere. It moves `state.json` from the older `~/.loose-keys-review`
  once, holding both folders' locks, only when the old file is a private
  regular file of the user's and the new folder holds none; anything else
  there is left as it is. A helper from before the move that is still running
  writes to the removed old folder until it restarts.

### Saved automatic coverage

The helper keeps the last completed automatic pass's unread paths and reasons
in `Agent.unread_places`, alongside its count and completion time in the same
owner-only store transaction. A pass in progress does not replace that snapshot;
a failed save retries the slice. Snapshots contain no file contents or credential
values. `UnreadPlaces` deduplicates path/reason pairs and limits them to 4096
entries and 512 KiB serialized, within the store's existing 8 MiB limit. Reaching
either limit marks the snapshot truncated, and the UI describes the count as a
lower bound. The store validates these bounds on save and load.

`automatic_coverage` reads this snapshot on demand without scanning or probing
file access. It returns all retained paths escaped through `report::escape`;
there are no file actions on these display paths. Frequent status polls keep
only the count, truncation flag and completion time. The model orders detail
reads with `ReadTurns`, retains a usable snapshot after failures, and refreshes
it when a newly completed pass is observed while Not Checked is open. Automatic
and manual details are labeled separately because their scopes differ; their
counts are not added. Exports still contain only the manual report.

Older state has no snapshot and is shown as count-only until the next automatic
full pass. An older app/helper saving state can discard the new optional field.
The retained result is historical: file changes do not rewrite its paths, and
the helper still excludes `scan-limit` gaps from its completed-pass count because
slice boundaries are resumable. This does not claim complete coverage of limits
that no slice gets past. Guest behavior and actual macOS permissions remain
subject to the guest checks, not the preview or Rust tests.

Verification: the helper's multi-slice test checks persistence and replacement;
store tests cover entry/byte caps and old state; the helper check searches saved state and detail output for planted file values;
the engine check exercises path escaping; model checks cover overlapping
reads and failures; the sample window check opens the list from Settings and
asserts that no scan was requested.

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
  read with `log show`, which can trail the kernel and stamps entries with
  its own clock. So it waits for a marker denial of its own before reading
  (`network::caught_up` in `security-tests/network.rs`). If you see a miss,
  report it with `network-log/caught-up.json` from that run. Do not rerun
  until it passes and call that a pass.
- The window check runs the steps in `Checks` in `gui/app/Preview.swift`. It
  cannot type, so it sets the filter in code, and does in code what it has
  no control to press for. With the screen locked or its saver on, macOS
  shows assistive software no window, so the check stops with status 2. A
  step that reads what the window drew waits for it (`eventually`), because
  a busy Mac draws late. A step must not close an alert in code while the
  page under it is changing: AppKit stops the window doing that, so such a
  step uses a model that is in no window.

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

### Disk image packaging

`gui/package-dmg.sh` copies the signed build into a compressed, read-only
HFS+ disk image with an `/Applications` shortcut and English/Spanish install
instructions. It uses macOS tools, adds no dependency, starts no app, and
never writes to Applications. A private temporary staging directory is
removed on exit; an existing output image is refused. The release candidate
includes both this image and the existing ZIP in its checksum manifest.
Candidate verification requires both packages at fixed paths and rejects
a missing or modified one; candidates from the ZIP-only workflow must be
rebuilt. The offline script regression checks each package independently.
The ZIP remains the input to the guest scripts; that does not verify the
Finder installation flow. See [disk image checks](../testing/local-verification.md#installer-disk-image)
for verification and remaining unverified behavior. Packaging does not add
notarization or change signing.

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
  status, waiting five seconds after each pair of reads. Leaving the front
  cancels it, unless Show in Menu Bar is on: it then waits thirty seconds
  instead (App Nap may stretch that, unverified). Quitting cancels it; a read
  already sent may still finish. A manual scan pauses these reads. Show a
  failure of them without opening an alert every five seconds.
- Opened at login (`keyAELaunchedAsLogInItem`, checked in both launch
  calls), the app gives way to a copy already running, has no Dock icon, and
  orders out each window it makes or restores until the person opens a menu
  or a window: macOS 14 has no way to start a scene without its window. A
  failed status read never removes the icon. Turned off with no window open,
  the app quits; a minimized window counts as open. With the option on,
  closing the last window removes the Dock icon and hides the app, so the
  helper does not take it for one in front. The window is opened through an
  `openWindow` taken from the icon, which outlives it, and a Dock reopen also
  runs the system's own. All of this is unverified on a real login.
- The engine's JSON is decoded into the types in `Models.swift`, snake case
  to camel case. `Preview.swift` holds sample JSON for the sample-data build,
  which has to change with them. Text from a scan is shown as text, never as
  markup. Development-only code sits inside `#if PREVIEW || SNAPSHOTS`.
- The window, its alerts, the menu bar menu, the folder-access prompts and
  the notification are in English and Spanish; the saved reports, the copied
  summary and the command line stay English. The tables are in
  `gui/macos/<lang>.lproj`, keyed by the English, and the build writes them
  into the bundle as binary property lists, which also fails it on a syntax
  error. A literal in a SwiftUI control is looked up already;
  `Text(verbatim:)` and `Text(someString)` are not, so other text comes from
  `String(localized:)`.
  A path, name or error is only ever an interpolated value, never part of a
  key or a format, and reaches `Text` as a String, never inside a literal,
  so Markdown in it is not read. Words for states the logic compares, such
  as the state of automatic scanning, are enum cases with a text, not the
  text itself.
- Engine text is translated when the window shows it, through `EngineText`
  in `Models.swift` and `Engine.strings`. The engine and the review list keep
  English: the helper writes the list too, `report::escape` turns accented
  letters into `\u{..}`, and `rules::label` drops a subject or detail that
  has one. A key is the exact English, or has one `%@` (any text) or `%lld`
  (digits) for the part that varies, which is never used as a format. A
  subject or detail keeps that part as it came; in prose and errors it is
  looked up in turn, two levels deep, because the engine nests its own words,
  as in "Could not save: export directory: permission-denied.". An item saved
  before a rewording keeps the old English, shown untranslated, until a scan
  finds it again; a fixed item that is not found again keeps it. The Filter
  ignores case and accents and matches both the shown and the English text.
- Latin American macOS words some names and buttons differently
  (Configuración del Sistema, Elementos de inicio, basurero, Agregar, OK).
  macOS gives a key missing from
  `es-419.lproj` in English rather than looking in `es.lproj`, so
  `es-419.lproj` holds only what differs and the build lays it over
  `es.lproj`. Mexico, the US and the rest of Latin America resolve to
  `es-419`; Spain to `es`. Both were checked on macOS 27 with a sample
  executable, not with the bundle. Unverified: whether the folder-access
  prompt and the notification follow a per-app language choice, and the
  notification's language after a change, since the helper keeps the
  language it started with.
- `gui/tests/bundle-contract.test.js` checks that the window's keys, as the
  compiler lists them in `target/release/strings`, and the notification's
  match the Spanish tables exactly, with the same placeholders and no
  Markdown, and that every count has plural rules in both
  `Localizable.stringsdict` files. `engine_text_tests` in `gui/src` checks
  `Engine.strings` the same way, Markdown aside (engine text is shown as
  it is), against the fixed text the engine and scanner give the window,
  read from the rules and the engine's source. An error worded by macOS,
  such as a failed save or an unreadable review store, has no key: it shows
  in English, alone or inside a translated sentence. The model check looks
  engine text up in a made-up table: exact keys, templates, the lookup's
  depth, the order of languages, and the Filter and sort. The host window
  and model checks copy only `en.lproj` beside their executables, so they
  run in English whatever the Mac's language.
- The controls are the system's: `NavigationSplitView`, `Table`, `List`, the
  toolbar, `.inspector`, `Form` in a `Settings` scene, `MenuBarExtra`,
  `NSOpenPanel` and `NSSavePanel`. Add a feature with one of these before
  drawing anything. The one drawing is the menu bar's key with a dot for
  open items or a full list (`MenuBarIcon`), because SF Symbols has no key
  with a badge.
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
  save the list until a build that knows them runs (from the code,
  unverified).
- There is no snooze. Private state still has each item's `deferred` field,
  always written false, because older builds cannot read the list without
  it. What they saved there is not read: an item they snoozed is open and
  may be notified once more (from the code, unverified).
- Move to Worth Reviewing sends the displayed row's id and revision, so the
  engine can refuse a click after that value has changed. The window
  follows the returned finding only after the command and its ordered
  refresh succeed, and only if the person chose no other row and did not
  change page in the meantime. The checks do not cover pointer placement, a
  move with several set-aside rows in the real table, or the real engine.
- Review tables keep a set of selected ids. Filtering intersects it with
  visible rows, and refresh maps each grouped finding to its current entry
  before removing hidden selections. The inspector shows a single finding
  only for one selection; file actions likewise require exactly one id.
  Multiple decisions capture the displayed ids and revisions, send existing
  commands sequentially, stop on the first failure and refresh even then.
  Earlier successful saves are not rolled back. Repeated batch presses are
  disabled until that refresh ends. The model check covers captured targets,
  filtering, fixed rows, repeated presses and failure; the window check sets
  multiple table rows through accessibility, checks the inspector and returns
  several sample findings with its button.
  Unverified: modifier-key selection with a pointer and batch decisions
  through the real engine in the guest.
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

Confirm the process has that synthetic `HOME`. Do not collect a full process
environment from the host.

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

For the window in Spanish, copy the built bundle's
`Contents/Resources/*.lproj` beside `window-preview` and add
`-AppleLanguages '(es)'` to its command, or `'(es-MX)'` for Latin American
Spanish. Sample text that no rule has stays English.

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
