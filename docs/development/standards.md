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
  link, not a regular file). A place is listed there once for each reason,
  however many roots or reads reach it, but for the `~/` row that ends a full
  list (`Scan::gap`; tests:
  `a_place_reached_from_two_roots_is_listed_once_as_not_checked`,
  `a_full_list_ends_with_its_row_though_the_home_was_listed_before`). In the
  engine it is `Answer<T>`, a `Result` whose error is text written for the
  person. [1]
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
  Older code has bare `unwrap()` there, for example in `src/main.rs`. [1]
- Never unwrap, format or log an error that carries its input when the input
  came from a scanned file. A panic prints the error's `Debug` form, which for
  `FromUtf8Error` and `NulError` includes the bytes, and a `serde_json` type
  error can quote the value it did not expect. Map the error to a fixed
  reason, as `utf8_text` and `json_hits` in `src/rules/mod.rs` do.
- `std::process::exit` runs no `Drop`, on any thread. The command returns
  an `ExitCode` from `main` instead. The agent calls `exit` in `run`, only
  at startup failures, when the event stream cannot be opened again, and at
  the end. New code that ends the agent saves
  what must be kept through the store first and leaves nothing to a
  `Drop`. [14]
- The agent exits 0 where starting again would not help (run as root,
  `HOME` not absolute) and 1 where it may: the review list's folder or file
  cannot be used, as before the home volume is mounted, the home cannot be
  watched, or the worker cannot start. Its launchd job restarts it only
  after a failure, a minute later at the soonest (`ThrottleInterval`), so a
  failure that lasts costs one start a minute. Not verified: launchd
  restarting a real helper after such a failure.

## Unsafe code

- `unsafe` has two uses here: system calls, mostly on file descriptors
  (`src/fsutil.rs`, `gui/src/review.rs`), and the C interface to the window and
  the macOS bridge (`gui/src/lib.rs`, `gui/src/agent.rs`). It is not used for
  speed or to get around the borrow checker. [8][9]
- New code: every `unsafe` block has a `// SAFETY:` comment directly above it
  that says why this call's requirements hold here, not what the call does.
  `// SAFETY: openat returned a new owned descriptor.` is the form. Keep one
  operation to a block where you can, so the comment makes one claim. Older
  blocks in `fsutil.rs`, `review.rs`, `agent.rs` and `gui/src/lib.rs` lack
  comments. Add one when you change such a block. [10]
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
  `unsafe extern "C" { }` and `#[unsafe(no_mangle)]`. Keep to them. The one
  exception is the plain `extern "C"` block of access-list functions in
  `src/fsutil.rs`. [7]

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
  do nothing that fails on input. `notification_permission` catches a
  panic itself and hands the save that wakes the helper to a thread of its
  own, which waits for the store and saves nothing while the state cannot
  be read. In the agent the abort is the intended
  result. Do not switch to `"C-unwind"`. [2][6]
- Callbacks arrive on other threads. They reach shared state only through
  `OnceLock`, atomics and mutexes, and return at once when the state is not
  set up yet (`AGENT.get()`). [2]
- `emit` copies the event handler out of its mutex before calling it, so the
  handler may call back into the engine.
- The window never supplies a path to act on. It sends a finding's id.
  The engine looks the path up, checks it again and returns it
  (`item_path`: a plain printable name, its folder opened without following
  links, never as root). An issuer's page goes through `open_link`, which
  returns the URL only if `rules::known_link` lists it; `AppModel.openLink`
  then opens it with `NSWorkspace`. A new file or link action keeps this
  shape.
- Fixed pages open without the engine: System Settings at Notifications,
  Files & Folders and Login Items, and GitHub's page for the latest release.
  None has anything from a scan in it. Login Items opens through
  `AppModel.openLoginItems`, the others through `AppModel.openURL`; the
  window check replaces both, so that it opens nothing on the Mac running it.
  It does not replace `openLink` and presses no button that opens an
  issuer's page.
- `set_monitoring` does not take an approved helper registration as proof
  that its launchd job is loaded. On new consent it unregisters that
  registration and registers again, with no store lock held across either
  native call; only `app_login` is, as "Locks, threads and waits" says. The
  bridge waits for
  [`unregisterWithCompletionHandler:`](https://developer.apple.com/documentation/servicemanagement/smappservice/unregister(completionhandler:)),
  because synchronous unregister does not wait for the old process to exit
  (unverified).
  An error or a ten-second timeout stops the sequence, and a late completion
  cannot start a registration. A registration waiting for approval is not
  retried; withdrawing consent unregisters it too. A native failure becomes a
  fixed error, never system error text. Consent is saved even when
  registration fails, so the status and Restart Helper stay available.
  Settings shows Restart Helper only while the helper is not running; it
  unregisters a registered helper and registers it again, as new consent
  does. It holds `app_login` and checks Scan Automatically under it, so
  checks turned off meanwhile are not followed by a new registration
  (`restart_helper_does_not_register_the_helper_once_checks_are_off`).
  Recovery after `launchctl bootout` is unverified; the guest helper
  check's restart stage tests it. The helper counts as running only while a
  process of the person's, other than the one asking, has the number the
  helper saved when it started and runs the app's program: the file
  `proc_pidpath` gives for it is the asking process's own, by device and
  inode (`helper_running`). Nothing clears that number when the helper ends,
  so otherwise any process later given it would read as the helper. Test:
  `only_this_program_at_the_saved_number_is_the_helper_running`, with an
  unrelated process and a suspended copy of the test program. Not covered:
  another process of the app's program given the number reads as the
  helper, and a helper started from another copy of the app does not. The
  real helper's status is checked only in the guest.
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
  one step. Their deadline is asked between items and between the 1 MiB
  pieces of a file read through, which a recheck reads as the scan does
  (`a_recheck_of_a_large_record_stops_when_the_rechecks_run_out_of_time`).
  Not bounded: a read the system blocks, as on a network share that stopped
  answering, holds the store until it returns. A change that fails saves
  nothing: an engine command that can refuse goes through
  `try_update_state`, which leaves the saved state and the app's copy as
  they were and does not count the refusal as a storage failure.
- While `storage_error` is set, the commands that change settings,
  decisions or folders refuse first, and a scan saves nothing. A later
  read that works clears an error from reading. An error from a change
  that could not be saved (`storage_unsaved`) stays until the app opens
  again: what the change would have saved, such as a scan's findings, is
  lost, and the list is not what was found
  (`a_failed_read_is_cleared_by_a_later_one_and_a_failed_save_is_not`). A
  scan whose save was skipped counts as such a change, unless it was
  cancelled with nothing to list
  (`a_scan_not_saved_keeps_the_error_after_the_state_reads_again`,
  `a_stopped_scan_keeps_the_error_only_when_it_found_something`).
- `Monitor` is the one condition variable. State is changed under its mutex
  and then notified. `wait` checks the state again in a loop, because a wait
  can return with no notification and a notification with no waiter is lost.
  Requests to wake keep the earliest time (`retry_in`). [4]
- Sleep holds the agent's checks until macOS reports the wake (`sleep`). If
  none comes within an hour of `Instant` time, which does not advance while
  the Mac sleeps, `wait` takes the wake as missed and checks again. Test:
  `a_wake_that_never_comes_does_not_stop_the_checks_for_good`. Not verified:
  a real missed wake, and whether dark wakes add up to an hour while the Mac
  is asleep.
- The agent takes in the state on the worker, the event stream's queue and
  the notification completion, each read at its own moment. A read takes a
  number first (`Agent::ticket`), an update takes one inside the store's
  lock, and `remember` ignores a state numbered below the one it took in
  last, so a pause read before monitoring was resumed is not applied after
  it. Test: `a_state_read_earlier_does_not_replace_one_read_later`.
- Stopping work is cooperative: a shared `AtomicBool` (`Monitor::cancel`) that
  the scanner polls in `Scan::stopped`. A work limit is not a timeout for a
  system call that blocks. `sleep` and `stop` set it for any work.
  `configure` sets it for automatic work only: the monitor remembers which
  kind `arm` last let through, so a pause or a change of consent never ends a
  scan the person started.
- The atomics are `AtomicBool` flags, such as `cancel` and the scanning
  flag, and two values that stand alone (`PERMISSION`, an `AtomicU8`, and
  `Agent.unsaved`, an `AtomicU32`). None hands over other data, and all use
  `SeqCst`. Keep to that. Data
  another thread reads goes through a `Mutex`, `Condvar` or channel, never a
  flag set after writing it. A weaker ordering is a change of its own, with
  the reasoning in a comment. [15]
- Limits and deadlines use `Instant` (`Scan::started`, the monitor's `due`).
  `SystemTime` is only for a timestamp written down (`report::utc_now`,
  `now` in `gui/src/lib.rs`). It can go backwards, so both handle
  `duration_since` failing. A time stored while the clock was ahead stays in
  the future after it is put right: the helper counts a last full pass
  stamped more than a day ahead as long ago (`pass_due`), or the weekly pass
  would wait until the clock was a week past the stamp. Test:
  `a_pass_stamped_in_the_future_does_not_hold_off_the_next`. Other stored
  times (`decided_at`, `retry_at`) are not checked this way.
  `Instant + Duration` panics on overflow. That is
  fine for a constant such as `CADENCE`, but a duration from input or state
  uses `checked_add`. [14]
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
- Discovery opens the files of the folder it is visiting from the handle
  `list_dir` listed them from (`Listing.handle`, `read_head_in`,
  `read_config_in`), with the same checks for the file itself, instead of
  walking from `/` again for each.
  A folder whose path is swapped for a link after it was listed is still read
  as listed, never behind the link. Tests:
  `entries_read_from_a_listed_folder_are_checked_as_paths_are` in
  `src/fsutil.rs`, and `special_files_links_and_large_headers_do_not_break_discovery`
  through the CLI. Where a listing gives no entry type, the entry is looked
  at without following a link; one removed since it was listed is passed by,
  and any other error ends the listing with a gap. Test:
  `unknown_entry_types_use_nofollow_metadata`, which asks of one entry with
  no type. Not covered: a scan of a volume that gives no types.
- Discovery opens each folder it lists the same way from the folders above
  it that it opened for the last one (`fsutil::Folders`), not from `/`. Each
  folder
  is still opened relative to its open parent with the checks above, so no
  link is followed. A folder kept open is used as it was opened, as
  `Listing.handle` is: if its path is swapped for a link or another folder
  afterwards, what is listed below it is in the folder that was opened, never
  behind the link. At most 32 names of a path are kept open; a deeper folder
  is walked to from `/`. Test: `folders_listed_in_turn_are_listed_as_paths_are`
  in `src/fsutil.rs`; the scanner's discovery tests run through it. These
  synthetic checks do not
  verify macOS privacy prompts, real cloud placeholders, root behavior or a
  simultaneous cross-process rename race. Paths can still change after a
  handle is opened; the reported spelling identifies the path as listed.
- Check, then use, the same handle. Size, type, owner and cloud flags come
  from the open file, not from the path a second time. `read_config` compares
  the size before and after reading. A path can be swapped between two calls;
  a handle cannot. [5]
- Each read and each loop over scanned data is bounded, so one huge or
  endless file, or an enormous tree, cannot stall a scan or exhaust its
  memory. `fsutil` bounds each read by the size it is given (`HEADER` and
  `CONFIG_MAX` in `src/scan.rs`), and agent records have `STREAM_MAX`,
  `TREE_ENTRIES` and `TREE_DEPTH`. Discovery has a depth limit and entry
  budgets per folder and per root (`src/scan/discovery.rs`,
  `run_budgeted`), and a scan in the app caps its findings and
  `not_checked` rows (`Scan::halted`, `Scan::gap`). A traversal limit
  that is reached is a `scan-limit` gap, so a cut-short scan is never shown
  as complete. The matcher caps are under
  [The shared scanner crate](#the-shared-scanner-crate), and the numbers a
  person relies on in [usage](../usage.md#supported-checks).
- A presence check outside `fsutil` uses `std::fs::symlink_metadata`.
  `Path::exists`, `is_file`, `is_dir` and `fs::metadata` follow links. Treat
  the answer as a hint: whatever is read next still goes through `fsutil`.
  Where presence is all that is asked of a known location (a place whose
  presence is the finding, a wallet extension's storage, a sweep's tree of
  records), it goes through `fsutil::presence` and `Scan::there`: not there,
  or below a file, is absence, and any other error is a gap, as a read of
  that place would give, never absence. `through_links` gives None past a
  folder it cannot look in, so the path is then read or asked about as it
  is named, which reports it. Test:
  `a_known_location_whose_presence_cannot_be_told_is_a_gap`. Not covered: a
  macOS privacy denial, which the test stands in for with a folder of mode
  000 (unverified).
- `through_links` is the one deliberate exception to following no links in
  what is scanned. A known sign-in location that is a link is resolved once,
  used only if the real path is inside the home folder, and never as root. Do
  not add another.
  A wallet extension's storage in a browser profile is a known location too:
  the scan, a check of changes and a recheck resolve it this way before the
  `symlink_metadata` that tells it is there; that call alone would follow a
  linked `Local Extension Settings` wherever it led, also as root, and
  report a wallet in the home with no gap. A profile that is a link is
  looked in as for its sign-ins, and a check of changes finds the storage
  at the real place a link in the browser's folder leads to, as
  `linked_targets` finds a file in a profile; otherwise a linked profile
  would be passed over with no gap. An entry of the browser's folder that is
  not a folder is looked in only if it is a link that leads to one: it is
  resolved once with `through_links`, and of a link out of the home folder
  only whether it leads to a folder is asked, by one `fs::metadata`, for
  `targeted` to give the gap below it. A link to a file, as Chrome's
  `SingletonSocket` is, is passed by with one look and no gap. Tests:
  `a_wallet_store_behind_a_link_out_of_the_home_is_not_followed`,
  `a_wallet_store_in_a_linked_profile_is_found_where_it_is`,
  `an_entry_that_leads_to_no_folder_is_no_profile`. Not covered: a run as
  root, a link changed between the resolution and the presence check, and
  a change at the real place a storage folder that is itself a link leads
  to, which a scan finds and a check of changes does not.
  The gap says why a link was not followed: `symlink` when it leads outside
  the home folder or the scan runs as root, where the text report and the
  window say that no link is followed; `permission-denied` or `unreadable`
  when it cannot be resolved, as when it loops or passes through a folder
  that cannot be opened. A place below a link to a file is not there and is
  no gap. Tests: `links_resolve_only_to_places_inside_home`,
  `a_link_that_cannot_be_resolved_is_not_said_to_leave_the_home`,
  `a_known_location_below_a_link_to_a_file_is_not_a_gap`, and
  `a_link_not_followed_as_root_is_not_said_to_leave_the_home` in
  `src/report.rs` and `gui/src/lib.rs`. Not covered: a scan run as root.
- `scan::home` resolves `HOME` once, as a relocated home is reached through a
  link. A folder given to `--select` or `--exclude` that begins with `HOME`
  as set, as the shell writes `~/notes`, has that prefix replaced by the
  resolved home (`named_folder`). Nothing else in the path is resolved, so a
  link after the prefix is still not followed. Without the replacement, a
  folder excluded this way would still be read though the report listed it
  as left out, a selected one would be an `unreadable` gap, and the whole
  home could be excluded. Test:
  `folders_named_through_a_linked_home_are_the_ones_in_it`. Not covered: a
  folder named through another link to the home, and places added in the app
  (`add_place`), which are taken as given.
- Discovery passes over folders only, so `--exclude` refuses a path that is
  a file or a link (`symlink_metadata` in `excluded_folder`, `src/main.rs`):
  either would be read while the report said it was left out. The path is
  looked up and kept without a trailing slash: with one, the lookup fails on
  a file and follows a link. A path whose lookup fails, such as one with
  nothing there or in a folder that cannot be opened, is taken, as nothing at
  it can be read. Test:
  `an_excluded_path_that_is_not_a_folder_is_refused`.
- The walk compares paths byte for byte and reaches no folder through a
  link, but a disk that ignores case and Unicode normalisation takes
  `~/documents` for `~/Documents`. So `scan::on_disk` looks up each folder
  on the way with `symlink_metadata`: `--exclude` refuses a path with a link
  in it, such as `~/docs-link/notes`, and both `--exclude` and `--select`
  keep the part that can be looked up as `fs::canonicalize` spells it, which
  with no link in it changes only the spelling. `realpath` keeps a path
  under `/System/Volumes/Data`, which reaches the same folders with no link
  on the way, so the longest part that is the home folder or a folder above
  it, compared by device and inode, is then spelled as the home is, and the
  home-folder guard sees it. `/System/Volumes/Data` and the folders above it
  are none of the home's folders by inode, yet a walk from one reaches the
  home, so `skipped_folder` also refuses a folder that the home's spelling
  under `/System/Volumes/Data` begins with, when that spelling has the
  home's device and inode. Without this, an excluded folder would be read
  while the report listed it as left out, and a selected one would be walked
  a second time. Tests: `an_excluded_folder_is_the_one_the_scan_would_read`,
  `a_folder_selected_in_another_spelling_is_scanned_once`,
  `a_folder_named_through_the_data_volume_is_the_one_the_scan_reads`. Not
  covered: a link put on the way after the lookup, another name for a folder
  that the home folder's own path does not pass through, and places added or
  folders skipped in the app, which come from the folder panel or the scan's
  own report. `--select` takes `/System/Volumes/Data` or a folder above it,
  as it takes `/`, and the walk from there can reach the home again under
  `/System/Volumes/Data`, where a folder excluded by its usual path is read.
  `--exclude` also takes macOS's lookup prefixes themselves, such as
  `/.nofollow/` or `/.resolve/1/`, which name `/`, and lists them as left
  out while the home is read.
- An export's folder is not a scanned file. Run as the person, `write_export`
  resolves it with `fs::canonicalize`, through links and `..` as any program
  writing to that path would, and opens the real folder without following
  links. The file's own name is still created relative to that handle with
  `O_EXCL | O_NOFOLLOW`, so a link at the name is refused and nothing is
  overwritten. A link someone else put on the way can only lead the export
  into a folder the person can write to, as a new file of theirs. So
  `--export /tmp/r.json` (on macOS `/tmp` is a link), a path through a linked
  home and `../r.json` all work. A path as given that does not end in its
  file name, as `out/r.json/` and `out/r.json/.` do not, is refused rather
  than created as `r.json`. As root the folder is still walked to from `/`
  without following links, and a link or `..` on its path is refused by
  name. Tests:
  `export_reaches_its_folder_through_links_but_never_follows_its_name` and
  `an_export_path_ending_in_a_slash_is_refused` in
  `tests/scan_scope.rs` and
  `as_root_a_link_or_dot_dot_before_the_export_folder_is_refused_by_name` in
  `src/fsutil.rs`, which passes `root` to `write_export`: no test runs as
  root.
- A cloud-only file (`SF_DATALESS`) is never read, because reading downloads
  it. `fsutil` checks the flag before the open and on the handle.
- Discovery does not enter the folders in `EXCLUDED` and does not open the
  settings files in `ASKS` (`src/scan.rs`), for the reason
  [usage](../usage.md) gives; from the helper the prompt would come with
  nobody at the window. The report lists the folders as excluded. Tests:
  `other_apps_data_and_media_stores_are_not_entered`, which also checks that
  a change there reads nothing, and
  `exclusions_and_detection_boundaries_are_visible` in `tests/scan_scope.rs`.
  Not verified: that the prompts are gone in a guest with SIP on, and that
  `Music/Music` is guarded as the TV library is.
- The blocks of `EXCLUDED` from `Library/Mail` on are app data macOS refuses to
  a program
  without Full Disk Access, which Loose Keys never asks for: Mail, Messages,
  Safari, call history, iPhone backups and the like. Listing one was a
  `permission-denied` gap after every scan, so **Show Places Not Checked**
  carried no signal. Discovery, record trees and change checks leave these
  folders out, and the limitations say so. Known locations are still read
  wherever they are, a refused one is still a gap, and so is a protected
  folder the list leaves out. Messages' and Home's settings files, refused
  the same way, are passed by as `ASKS` passes the Contacts and TV ones. A
  folder or file is listed only when logs of refusals from 2022 to macOS 14.5
  or a macOS 26 guest with SIP on show it, no rule names a location in it and it is
  not where the person keeps or edits their own files, so
  `Library/Mobile Documents`, `Library/CloudStorage`, Desktop, Documents and
  Downloads stay gaps when refused. `~/.Trash` and `Library/Autosave
  Information` are the exception, chosen by the person: refused on nearly
  every Mac, they kept Show Places Not Checked showing after every scan, so
  they are left out and the limitations name them. Tests: `app_data_macos_protects_is_neither_read_nor_a_gap`, which
  locks each listed folder and an unlisted one and checks that a scan and a
  sweep report only the unlisted one, that a change in a listed folder
  reports nothing while a change of the unlisted one is its gap, and that no
  rule target or Chromium browser folder is inside the list,
  `messages_and_home_settings_macos_protects_are_not_a_gap`, and
  `exclusions_and_detection_boundaries_are_visible`. The helper's saved
  refusals of a listed folder or file itself, which an older build's pass
  kept until the next weekly one, are neither shown nor counted
  (`scan::not_tried`, `still_unread` in `gui/src/lib.rs`), while a refused
  known location inside a listed folder still is; tests
  `places_this_build_does_not_try_are_known` and
  `saved_refusals_of_places_no_longer_tried_are_left_out`.
  Remaining risks:
  - The list is checked against a macOS 26 guest with SIP on, not against
    macOS 15 or 27. A folder
    macOS starts guarding is a gap until listed, and one it stops guarding
    stays unread while listed.
  - A key file deleted to the Trash but not emptied, or one in an unsaved
    document's autosave, is not found, even with Full Disk Access.
  - Mail and Messages attachments, shortcuts and iPhone and iPad backups
    are not read, even when the terminal has Full Disk Access, so a key or
    password export sent as an attachment is missed.
  - Entries match path endings, so a folder such as `x/Library/Mail` inside
    a scanned folder is left out too.
  - Fewer gaps mean more scans end `complete`, with exit status 0, though
    these folders were not read.
  - On macOS 27, known locations in the folders XProtect guards (several
    browsers' and wallets', unverified) are still gaps when refused.

  Not verified: whether looking up a known location inside a listed folder
  makes macOS ask.
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
  root-owned and not writable by others, and its access list must have no
  allow entry that lets anyone add, delete or rename names in it or change
  its access list or owner (`lets_others_change`). Deny entries are
  accepted; a list that cannot be read refuses the export. A new file takes
  the access-list entries its folder marks for inheriting, and macOS checks
  those before the mode, so a 0600 export in a shared folder could still be
  read by others.
  Before any byte is written, `write_export` asks for the new file's access
  list (`acl_get_fd_np`). If it has any entry, or cannot be asked for, the
  export is refused and the empty file removed as a failed write's is,
  below. A folder whose inherited entries only deny is refused too. Someone
  the folder lets read could open the empty file before it is removed, and
  finds it empty. Not covered: entries that also let others change the new
  file's access list. Someone could then open the file, clear its list
  before `write_export` asks for it, and read the report through what they
  opened: a race, unverified. A write that fails partway, as on a
  full disk, removes the name again, but only while `fstatat` on it shows the
  file just created (same device and inode), so that no part of a report is
  left and the name can be tried again. A file put in its place since is left
  as it is. The check and the removal are two steps: something able to write
  to that folder (as root, only root) could swap the name between them. Tests:
  `an_export_that_cannot_be_written_in_full_leaves_no_file` in
  `tests/scan_scope.rs`, with a file-size limit on the CLI, and
  `an_export_into_a_folder_that_shares_new_files_is_refused`, with an
  inheritable `group:everyone` read entry added by `chmod +a`.
  `a_folder_access_list_that_lets_others_change_it_is_seen` in
  `src/fsutil.rs` gives folders entries with `chmod +a` and asks
  `lets_others_change` about each; no test runs as root, so its use in the
  root check is not run. The app's state, and the copy of the update
  answer beside it, are written to a new temporary file, synced, renamed
  over the old one, and the folder synced (`Store::replace`).
- Everything read back is bounded and checked before use, the app's own state
  included: `Store::open` and `load` require the user's ownership, no access
  for others, one link, a size limit and sane counts; the update answer's
  copy is opened with the same checks (`Store::open_private`). Code running
  as the user can edit those files.
- The organization's expected-findings list enters only through the
  window's `set_expected`, from a preference macOS reports as forced
  (`CFPreferencesAppValueIsForced`). The merged defaults are never read:
  they include `~/Library/Preferences/dev.loosekeys.desktop.plist`, which
  anyone who can write to the home folder can write. Checked in a guest on
  2026-10-28 (macOS 26): a plist in that home-folder location is not
  forced; a root-owned plist under `/Library/Managed Preferences/` and a
  configuration profile installed through System Settings are, and a file
  there is still forced after a change of owner, so the protection is that
  the folder is writable by root alone. Delivery by an MDM server is
  unverified. The engine drops each entry of another shape on its own and
  checks the rest again (`review::accepted`: a rule the scanner has, a plain
  `~/` path below the home, 32 at most), then keeps them in `state.json`
  beside the person's decisions, with the same standing as a Kept decision;
  the helper reads them there and so applies the list the app last saved
  ([usage](../usage.md#expected-findings-set-by-mdm)). The CLI
  reads none of it. A file planted at a listed path is still listed, under
  Set Aside with its rule and details, counted and exported. Tests:
  `an_expected_place_is_set_aside_and_does_not_alert`,
  `returning_an_expected_item_keeps_it_open_until_the_list_drops_it` and
  `an_expected_list_is_checked_capped_and_deduplicated` in
  `gui/src/review.rs`; `the_expected_list_is_compared_with_the_store` and
  `an_expected_entry_sets_the_row_aside_until_the_person_returns_it` in
  `gui/src/lib.rs`.
- The app's state folder is `review::STATE_DIR` in the home folder.
  `Store::open` makes and opens each folder on the way without following a
  link, so a link anywhere on that path stops it rather than sending the
  state elsewhere. It moves `state.json` from the older `~/.loose-keys-review`
  once, holding both folders' locks, only when the old file is a private
  regular file of the user's and the new folder holds none; anything else
  there is left as it is. It looks first without the locks, so a start with
  nothing to move does not wait for the store, as when the old folder stays
  because something else is in it.
- The window names an item by its id, so the ids in `state.json` are input
  like any other number in a file. `Store::load` refuses a list in which two
  items share an id, an id is above `next_id`, or `next_id` has no room left
  to number a whole list and then a full list of new findings
  (`Review::ids_hold`). `Store::save` refuses the same, so a counter that
  runs out, which `saturating_add` keeps from wrapping to zero, is never
  saved. A refused list is shown as unavailable, never as empty. Id 0 is an
  item from before ids, numbered on the next update. Tests:
  `saved_ids_are_checked_before_the_list_is_used`,
  `a_counter_without_room_for_a_full_list_is_not_saved` and
  `ids_left_by_older_lists_and_by_removed_items_are_kept`.
- The person's decisions are capped at `MAX_ITEMS`. A decision stays when
  what it was about leaves the list, where it can no longer be moved back,
  so at the cap `Review::make_room` drops from those no listed item uses,
  matched as `forget` matches them (by value where there is one, else by
  place): every Kept past `RECONFIRM` first, then the oldest. Such a
  decision only sets aside a credential found again, so dropping it can make
  that ask for attention again, never hide it. One a listed item uses stays,
  even a Kept that has run out, because `ingest` reads it to tell whether a
  copy is news; only when every decision is in use is a new one refused.
  Test: `a_full_list_of_decisions_makes_room_from_ones_nothing_listed_uses`.
  They are also limited to `DECISION_BYTES`, an eighth of the store, as
  items are to three quarters: a decision copies its item's path, and a
  state past `STORE_BYTES` would refuse every later save. Test:
  `decisions_about_long_paths_leave_room_to_save_the_state`.
- A scan's digests are made with the key the list had when it began
  (`perform_scan`, `Agent::fingerprint`). A list replaced while it ran, as
  when its file is deleted or put back from a copy, has another key, and
  what the scan found would be taken there for other values: marked fixed
  by the next scan and listed again as news. So the save compares the two
  keys and, where they differ, saves nothing the scan found. The app says
  so (`LIST_REPLACED`) and keeps no report; the helper saves the list
  unchanged, takes its key and makes the check again, as after any save
  that failed. Tests: `a_scan_whose_list_was_replaced_saves_nothing`,
  `a_check_made_with_the_key_of_a_list_since_replaced_is_made_again`. Not
  covered: a full pass under way when the list is replaced saved its
  earlier slices into the old list, so it ends without their findings, which
  return at the next pass or when their files change.
- A decision in the app is a label. Set Aside changes what asks for
  attention, never what a scan finds, counts or exports; a skipped folder is
  left out of discovery and reported as left out (below). Whoever can write
  inside a scanned folder could otherwise hide a credential, so nothing read
  from one can set a finding aside: the organization's list enters only as a
  forced preference (above). The CLI reads none of the app's state, so it
  gives the same result whatever the app saved (`src/main.rs` matches
  `--fail-on-open` against every finding worth reviewing).
- In a folder the person stopped checking, a scan still reads the known
  locations: a rule's own file, a file directly in a folder a rule covers or
  at the top of a tree of records, and a place whose presence is the
  finding. `scan::read_when_skipped` names those from the rules' targets, by
  rule and place, and `Review::resolve` looks again at an item in a skipped
  folder only where it says so, at every check as for any other item. Any
  other item there is not read and stays as it is. So a folder added to the
  scan inside a skipped one, or that is one, is left out with it
  (`run_budgeted`), as is one given to `--select` inside an `--exclude`.
  Without this, every item in a skipped folder would stay open after its
  credential was removed. Tests:
  `a_known_file_in_a_skipped_folder_is_still_marked_fixed` in
  `gui/src/lib.rs`,
  `what_a_scan_reads_in_a_skipped_folder_is_what_read_when_skipped_names`,
  which compares it with what a scan given the skip finds, and
  `a_folder_selected_inside_a_skipped_one_is_left_out_with_it` in
  `tests/scan_scope.rs`. Not covered: a known location that is a link into a
  skipped folder is listed where the link leads, which the function does not
  follow, so that item stays open until the folder is included again.

### Saved manual roots and grouped file actions

The app stores the folders a person added in `Review.selected_places`, in
the owner-only state. The list has at most eight distinct absolute UTF-8
paths, each at most 4096 bytes, with no NUL or parent component. Load and
save both validate it; invalid state is unavailable, not an empty scope.
State without the field has no added folders. Adding and removing one uses
the store transaction, so a failed save leaves the prior list and another
writer's changes intact. A scan takes the latest usable list and reads it
with the scanner's no-follow, bounded access; an unavailable folder stays
listed and produces a gap. The helper keeps this field when saving but does
not watch these folders. An older app or helper can drop the field when it
saves: downgrade persistence is not promised. Tests:
`old_state_has_no_added_folders_and_maximum_valid_roots_round_trip` and
`saved_added_folders_are_bounded_before_they_can_be_scanned` in
`gui/src/review.rs`; `added_folders_and_their_removal_survive_reopening_the_app`,
`saved_added_folders_are_scanned_without_following_links`,
`invalid_added_folder_input_does_not_poison_the_saved_list` and
`added_folder_changes_are_shared_and_failed_saves_keep_the_previous_list` in
`gui/src/lib.rs`.

Each grouped `PlaceView` includes `actionable`, computed from its original
name before escaping. The window offers the file actions for an actionable
secondary copy and sends only its id to `item_path`, which resolves that id
afresh and validates the path and parent. Test:
`every_grouped_copy_has_its_own_validated_file_action`; the window check
presses the secondary copy's control. Permission-denial wording names both
file permissions and macOS privacy, not an assumed cause.

### Saved automatic coverage

The helper keeps the last completed automatic pass's unread paths and reasons
in `Agent.unread_places`, alongside its count and completion time in the same
owner-only store transaction. A pass in progress does not replace that snapshot;
a failed save retries the slice. Snapshots contain no file contents or credential
values. `UnreadPlaces` deduplicates path/reason pairs and limits them to 4096
entries and 512 KiB serialized, within the store's 8 MiB limit. Reaching
either limit marks the snapshot truncated, and the window says the list is
full. The store validates these bounds on save and load.

`automatic_coverage` reads this snapshot on demand without scanning or probing
file access. It returns all retained paths escaped through `report::escape`;
there are no file actions on these display paths. Frequent status polls keep
only the count, truncation flag and completion time. The model orders detail
reads with `ReadTurns`, retains a usable snapshot after failures, and refreshes
it when a newly completed pass is observed while the places not checked are
open. The window merges them with the last manual scan's places into one
list ("The window and running the app"). Exports contain only the manual
report.

State without a snapshot is shown as count-only until the next automatic
full pass, and an older app or helper saving state can discard the field.
The retained result is historical: file changes do not rewrite its paths, and
the helper leaves `scan-limit` gaps out of its completed-pass count because
slice boundaries are resumable. This does not claim complete coverage of limits
that no slice gets past. Guest behavior and actual macOS permissions remain
subject to the guest checks, not the preview or Rust tests.

Tests: `a_full_pass_says_how_many_places_it_did_not_read` in
`gui/src/agent.rs`; `unread_snapshot_is_bounded_and_marks_omissions` and
`old_unread_count_has_no_invented_details` in `gui/src/review.rs`;
`automatic_coverage_needs_readable_state` in `gui/src/lib.rs`. The sample
window check opens the list from the Overview, asserts that no scan was
requested and that a failed read keeps the saved paths, and checks that
Settings neither counts nor links to the list.

### Saved stored sign-ins

Stored sign-ins are kept in their own part of the state, `Review.stored`
(`gui/src/review/stored.rs`), not as a kind of item beside the findings
worth reviewing. Builds before it ignore that field and drop it when they
save. A generation number that made them refuse the file would instead stop
a helper still running from before an update from saving Worth Reviewing at
all, and nothing in the app restarts a running helper. So an older build
costs the stored sign-ins and the choices about them until the next scan,
never the findings that alert.

Both kinds share `next_id`, and `Store::load` and `Store::save` refuse an id
held in both lists, more than `MAX_STORED` (512) stored sign-ins, or more
than `MAX_ITEMS` items in all. Stored sign-ins take at most an eighth of
`ITEM_BYTES` (768 KiB), and their decisions 512 entries and a quarter of
`DECISION_BYTES`, inside the existing limits, so the whole state stays
within what older builds load. One that does not fit sets `stored.full`,
never Worth Reviewing's `full`. Worth Reviewing first drops resolved
stored sign-ins when it needs room; they are never shown.

Nothing about a stored sign-in alerts. `ingest_stored` has its own revision
counter, `stored.revision`, which a notification never reads, and does not
touch `pending`, `attempts` or `retry_at`. A whole-file fingerprint that
changes alone, as at a token refresh, keeps the revision, so a press drawn
before it still names the item. Worth Reviewing is resolved and ingested
first, and its check for another copy reads only its own items, so a stored
copy never makes a finding worth reviewing look old. When a file becomes
readable by others, the stored item is marked gone and the finding worth
reviewing is new and alerts; when it is made private again, the finding is
marked fixed and the stored sign-in opens quietly.

Decisions are kept apart. A stored sign-in takes only Kept, which covers
its file and lasts `RECONFIRM` as for a finding; `decision_stored` honours
only Kept and the organization's list, and the engine refuses another
reason. A reason about the
value would also have covered a copy of it in a file worth reviewing. The
organization's list and the record of entries moved back are shared, so
moving one kind back at a file also stops the list setting aside the other
kind there. Setting one kind aside keeps that record while the other kind is
at the file, so the other kind, once moved back, stays open.

A recheck asks for one kind (`Want`): `Want::Stored` keeps a test-format
hit, or an inventory rule's hit in a file others can't read, which is what a
scan lists as a stored sign-in, and skips presence-only rules.
`stored.checked_at` is set by a manual scan that wasn't stopped and by the
helper's last slice of a full pass; until then the window says no sign-ins
yet rather than none. `pending_review` also counts the saved ones no longer
found (`stored_gone`). When a scan this session counted more sign-ins than
that and none is listed, the window says the list doesn't hold them, ahead
of no sign-ins yet, so a list an older helper emptied never reads as not
looked at. The window gets both kinds in `pending_review`'s one
list, told apart by `kind`; a stored sign-in no longer found is left out,
and `item_path` finds an id in either list.

Verification: `gui/src/review/stored.rs` tests the saving without alerts,
the share of the room and the room fixed findings hold, a slice that leaves a stored sign-in out, the order
of the merge, files made readable or private, the one reason, a token
refresh, decisions that don't cross kinds, an older build's save and the
load limits. `a_recheck_for_stored_sign_ins_keeps_what_a_scan_would_list_as_one`
in `src/scan/tests.rs` covers `Want`. `gui/src/stored_tests.rs` covers the
counts, `decide_review` and `item_path`, a manual scan and `stored_full`,
and plants a stored value to search every output for it and its pieces.
The helper tests `a_batch_with_only_a_stored_sign_in_is_saved`,
`a_stored_sign_in_found_in_the_background_never_notifies` and
`removing_a_sign_in_file_marks_it_gone` cover background passes. The model
check covers the window's lists, counts, empty states, a failed read and
moving back; the
sample window check sets a sign-in aside and back.

Remaining risks: a helper from before the update that is still running
empties the stored part each time it saves, until it restarts; whether an
app update restarts it is macOS behaviour and unverified. Each token refresh
saves the state once, within `RECHECK_AFTER`. The 10-second recheck budget
is shared, with Worth Reviewing first, so a stored sign-in not reached stays
listed until a later check. A Discovery key under a skipped folder stays
listed, since that folder is not read again.

### Changes in folders discovery passes over

A change inside a folder in `EXCLUDED` (`target`, `.git`, `node_modules` and
the rest) reaches the helper's inbox as one change of the outermost such folder
(`scan::change_at`). Where that folder holds a known location the change is
not in, as `Library/Caches` holds the Claude CLI's records, the change goes no
further up than a folder holding none, and a change at or in the location is
checked as it is. Checking the folder reads the same known locations and
`.git` files the change itself would, and no more. Without this, every file a
build or `git` writes would be a change of its own, and builds would start
walks of the whole home back to back. Tests:
`a_change_where_discovery_does_not_go_is_one_of_the_folder_it_passes_over` in
`src/scan/tests.rs`, and `a_password_added_to_a_repositorys_settings_is_found`
in `gui/src/agent.rs`. Not verified: the event volume of a real build against
the installed helper.

The helper's limits, each of which turns changes into a full pass or holds
one off. Keep them when changing `gui/src/agent.rs`:

- More than 5,000 changes held at once become one full pass
  (`more_changes_than_can_be_held_become_one_full_pass`); changes folded as
  above do not (`a_flood_of_changes_where_scans_do_not_read_is_not_a_full_pass`,
  `many_batches_of_changes_where_scans_do_not_read_are_not_a_full_pass`).
- The worker remembers when each path was last checked, to space out the
  checks of a file that keeps changing. Past 20,000 such paths it forgets
  those whose wait is over, which loses no change, and asks for a full pass
  only if that many are still waiting
  (`many_paths_checked_once_are_not_a_full_pass`).
- A path a change check leaves unfinished asks for a full pass only when it
  was the first the check began; otherwise it is checked again in a later
  round, ahead of paths that changed since
  (`a_folder_one_check_cannot_finish_is_finished_by_a_full_pass`,
  `a_changed_folder_the_check_did_not_begin_is_checked_in_the_next_round`,
  `a_folder_too_large_for_a_check_is_finished_while_other_changes_keep_coming`).
- A slice of a full pass whose entries run out partway through a folder's
  listing passes on no subfolder twice
  (`a_listing_cut_by_the_budget_passes_on_no_subfolder_twice`), and a pass
  made in slices finds what an uninterrupted one finds
  (`resumed_sweeps_agree_with_an_uninterrupted_pass`, both in
  `src/scan/tests.rs`).
- When FSEvents drops events because the helper fell behind (`UserDropped`),
  the helper opens its stream again (`ch_watch_resume`) from the last batch it
  handled, up to 10 times in 10 minutes; after that, and for events the
  kernel dropped or ids that wrapped, a full pass makes up for them. If the
  stream cannot be opened again the helper exits with failure, and launchd
  starts it again from its saved place
  (`events_dropped_for_falling_behind_are_read_again_not_walked`,
  `events_dropped_again_and_again_become_a_full_pass`,
  `the_event_stream_opened_again_replays_what_came_after`,
  `a_drop_while_the_stream_is_opened_again_is_replayed`). That dropped events
  are still in the volume's change history is unverified beyond the
  synthetic folder that test uses.
- Neither the place a batch ends at nor the saved place is ever set to 0,
  the number FSEvents gives some events, which would make the next start read
  from now (`an_event_numbered_zero_moves_no_place`).
- A full pass under way, or one that ends with another owed, is saved, so a
  helper started again begins a full pass (`pass_at_start`). A pass given up
  after three slices that got nowhere is begun again by the next start too. A
  pass asked for that has made no slice yet, as one Low Power Mode holds, is
  not saved: a restart leaves it to the weekly pass
  (`a_full_pass_under_way_is_made_after_a_restart`,
  `a_pass_that_ends_with_another_owed_leaves_it_saved`).

Not verified: how long a real start's replay takes, and how often a real
helper is dropped or its replays fall behind again.

**Set Up Notifications…** asks with macOS's prompt, which appears in a
corner of the screen and can be missed or taken for a confirmation; macOS
then answers no. A no to the person's own request keeps the Overview's
Notifications row, as "Off in System Settings" with **Open System Settings**
(`notificationsTurnedDown`), until macOS says anything else; notifications
turned off later in System Settings are not raised there again. The button
is not titled Allow, since it leads to macOS's own prompt. A provisional
request needs no prompt, but macOS delivered
those notifications to Notification Center only, without a banner, in a
macOS 26 guest. Verification: the window check's lines for **Set Up
Notifications…**. Not verified: macOS versions other than 26.

While notifications are not allowed and something waits to be sent, the
helper asks macOS again at most once a quarter-hour, and at once after the app
changes the shared state, which it does when notifications are allowed there.
A notification handed to macOS holds off the next until its completion comes
back, or for two minutes if it never does. The last check before sending
(`allowed`) reads the review list on a background queue, not the main one,
which a save holding the store could otherwise block.
Verification: `notification_permission_is_asked_again_once_in_a_while_not_at_every_wake`
and `a_delivery_that_never_hears_back_stops_holding_up_the_next`. Not
verified: a completion that never comes, or permission given in System
Settings, with a real helper.

## Numbers, offsets and text from a file

A length, count or offset decoded from a scanned file is input like the rest
of the file. Arithmetic and indexing on it can wrap or panic, and the type
checker does not catch either. [8]

- Arithmetic on a decoded number uses `checked_add`, `checked_sub` and
  `checked_mul`, and gives up on `None`, as `src/rules/sqlite.rs` does with
  a cell's length. Release builds wrap on overflow silently, so a wrapped sum
  passes a bounds check it should fail. Plain `+` is fine where both sides are
  already bounded, such as a position in a buffer `fsutil` capped at 1 MiB
  plus a small constant (`u16_at`). Do not set `overflow-checks` in a profile
  to change this. [12][13]
- Narrow a number with `try_from`, not `as`:
  `usize::try_from(varint(page, &mut at)?).ok()?`. `as` truncates and changes
  sign silently, and clippy refuses a narrowing one. Widening (`u32` to
  `usize`) is fine. A reinterpretation the format defines uses
  `cast_signed()` with a comment, as the SQLite rowid does. Taking the low
  byte of a `u32` on purpose masks it first, as `base64_decode` in
  `private_key.rs` does. [12]
- Index with `.get(..)` and give up on `None` (`bytes.get(at..at + 2)?`).
  Index directly only after a length check in the same function, as
  `blob.len() < 19` comes before `blob[15]` in `private_key.rs`. A panic
  there is a crash on input. [8]
- Slice a `str` only at a byte offset that `find`, `split_once`,
  `char_indices` or a match on an ASCII character returned. An offset made
  by arithmetic or a byte limit can land inside a character, and slicing
  there panics. To cut text at a byte limit, step back to
  `is_char_boundary`. `floor_char_boundary` needs Rust 1.91, newer than the
  supported 1.88. [14]
- Size an allocation from a file only after capping it.
  `Vec::with_capacity(cells)` is safe because `cells` is a `u16`. A count a
  header claims can be anything: `with_capacity` panics above `isize::MAX`
  bytes, and a smaller huge count still exhausts memory. Cap it at the
  matcher's budget or use `try_reserve`. [14]
- No recursion over nested data from a file. The SQLite reader keeps the
  pages it still has to visit in a list, and a new parser does the same with
  an entry limit. Running out of stack is not a panic `catch_unwind` can
  catch, and a spawned thread has 2 MiB of it. `serde_json` stops at 128
  levels. Keep its `unbounded_depth` feature off. [14][16]
- Keep a file name as `Path` or `OsStr` until it is shown. A name that is not
  UTF-8 is shown through `to_string_lossy` and `report::escape`
  (`Scan::rel`), so its bad bytes read as `\u{fffd}`. Two such names can look
  the same, and in the app a decision about the place then covers both
  files. APFS refuses such names (checked 2026-10-30), so only another kind
  of volume can hold them. Repaired text names some other file, so nothing
  reopens or acts on a file through it: `full_path` takes only printable
  ASCII, and `recheck_path` refuses text holding U+FFFD. `Path::display`
  escapes nothing and is no substitute for `report::escape`. [14]

## Secrets

- A value does not leave the function that matched it. A matcher returns
  `Hit`s holding a line, a `span` (a position) and labels. `rules::label`
  accepts only short printable text, and callers pass it names and hosts,
  never a field that stores a secret. `Progress` and events carry counts.
- Registry URL subjects are display labels, never review identities. npm,
  RubyGems and Bundler keep only the authority's host and optional port; an
  at-sign after `/`, `?` or `#`, or a backslash, makes the label ambiguous and
  omits it without omitting the finding. An encoded slash in userinfo still
  permits a host label. This conservative extraction is not URL or credential
  validation and makes no network request.
- Those registry entries carry a separate private scope identity: `Hit::scope`
  holds only a byte range for the original key, which can itself contain
  credentials. The scanner computes a domain-separated keyed digest with the
  install's existing HMAC key, discards the bytes and keeps the digest only in
  private review state. Ingest, decisions, pruning and fresh rechecks compare
  this identity, not the host label or line number. It never enters reports,
  events, summaries or window responses. Changing a key's spelling or embedded
  userinfo can create a new item; this errs toward asking for attention.
- `registry_labels` marks the private state's label generation. Missing/zero
  means legacy: loading clears npm, RubyGems and Bundler subjects, including
  resolved history, and removes their personal decisions, including orphaned
  ones. Organization expectations still concern the rule/file and retain that
  scope, with their subjects cleared. IDs, timestamps and resolution flags
  stay intact. New safe labels and scope identities survive later loads; an
  older build saving state drops the marker and causes migration again.
  Reads alone do not rewrite disk: the next successful update persists it.
  Old unresolved items have unknown scopes, so they remain alongside fresh
  scoped findings until a complete recheck finds no credential of that rule
  at the file. Never infer their removal from redaction or a host collision.
  This cannot erase earlier exports, logs, backups or copies, or prevent an
  older running app/helper from writing unsafe labels again.
  Real window/clipboard behavior and older concurrent
  app/helper behavior remain unverified.
- A known file's own rule records where its one value is (`Hit::at`, a
  position), as the service-token rule does, so a token both find in one
  file gets the same keyed `secret` digest under both and is one review item
  with two places. `review_items` shows that item as the file's own rule's
  copy, with its title and steps (`gh auth logout` for GitHub CLI's hosts
  file), not the token rule's: among the copies it may show (one needing a
  decision, else one set aside, a fixed one only when all are), one found
  by a rule whose id does not start with `secret.` comes first. Those
  rules (service-token, agent-record, env-assignment) look for a kind of
  value in any file they read. The entry's `severity`, which the window's
  Risk column shows and sorts by, is the highest (`review::rank`) among the
  copies in the shown copy's group (needing a decision, else set aside,
  else fixed), not the shown copy's own: GitHub CLI's and Vault's rules
  rate a token medium that the token rule rates high, and nothing may look
  safer than it is. A copy set aside or fixed while another needs a
  decision does not raise it. Only the entry built for display changes;
  stored items, and the severity each Kept decision records and is matched
  against, do not.
  Kept chosen in the window covers the value in one file whichever rules
  found it there: `decide_review` records a Kept for the item the window
  named and for each other copy of its value at that path
  (`copies_in_its_file`), each with that copy's own rule, subject, scope,
  fingerprint, kind, sharing and severity, and none at another path. Move
  to Worth Reviewing undoes each of those copies the same way, so the
  entry is never left half set aside. A reason about the value already
  covers every copy and still records one decision. The revision check
  (`as_shown`) is still on the item the window named; its copies are those
  holding that item's value as the store has it now. All copies are
  decided in one store update, and a refusal saves nothing: with room for
  fewer decisions than copies, after `make_room` (which drops only
  decisions no listed item uses), the press fails as a whole with the
  usual "Too many findings are set aside" error. npm, Yarn and pnpm,
  RubyGems, PyPI and Poetry, GitHub
  CLI, Vault, kubeconfig, Cargo, MySQL, the warehouse configs' named fields
  and Continue's YAML record the literal as the line holds it, without its
  quotes. An MCP config records a server's value only when that server has
  one value, its name is shown as no other server's is, and the value is in
  the file as JSON decodes it. Only a header named Authorization or
  Proxy-Authorization (case-insensitive) omits a `Bearer`-style scheme.
  Environment values, even a variable named Authorization, other headers,
  arguments and apiKey fields keep their whole literal: stripping a scheme
  from them would make distinct passwords share decisions and hide
  prefix-only rotations from review. Several distinct values, colliding display
  names or a
  decoded value absent from the original text still leave a finding without
  a value identity. This is not a full authorization parser: unsupported
  scheme syntax and escaped values may not group with a token found by
  another rule. Identities are refreshed by a scan, not by loading state
  alone. Rules whose one finding can stand for several values in a file or
  on a line (netrc,
  Maven, Composer, Docker, Terraform state, Codex's TOML headers), whose
  values are rebuilt rather than read as they are (pgpass), or whose value
  the token rule does not match whole (Bundler's user:password, AWS's
  secret key, Terraform's token file) record none, so a token the
  service-token rule also finds there is still a second item.
  Items saved without a digest take one on the next scan without becoming
  news (ingest compares fingerprints when one side has none). A decision
  saved on such an item, kept or about the value, still covers it by place
  and fingerprint; a decision about the value made on the token's copy
  covers the known file's copy too. If only the known file's copy was set
  aside, the grouped entry is open in Worth Reviewing until the other copy
  is decided; Kept chosen for the entry then covers both. One item that
  stood for several values of a rule at one
  place, such as a kubeconfig's tokens, which have no subject, splits into
  one item per value, and each value not already listed is news once.
  Tests: `a_token_in_a_known_file_has_one_identity_under_every_rule_that_finds_it`,
  `a_server_with_one_value_says_where_it_is`,
  `a_token_two_rules_find_in_one_file_is_one_item`,
  `a_token_in_a_known_file_is_shown_with_that_file_s_advice`,
  `an_entry_speaks_for_the_file_s_own_rule_within_what_needs_attention`,
  `a_known_file_entry_shows_the_highest_risk_of_its_copies`,
  `an_entry_s_risk_is_the_highest_of_the_copies_its_state_comes_from`,
  `keeping_an_entry_covers_each_copy_of_its_value_in_that_file`,
  `moving_an_entry_back_returns_each_copy_of_its_value_in_that_file`,
  `keeping_an_entry_without_room_for_each_copy_keeps_none`,
  `a_known_file_item_saved_without_its_value_takes_it_quietly`,
  `a_known_file_item_that_stood_for_two_values_splits_and_is_news_once` and
  `a_known_file_item_saved_without_its_value_joins_the_token_s_entry`.
  Not verified: the running app's list and notifications after an update.
- A type that holds file bytes has no `Debug` or `Display` (`Head` has
  neither), and `Incomplete`'s `Debug` shows only its fixed reason and hit
  count. What goes to the window is rebuilt field by field: `shown` clears
  `fingerprint`, `secret`, `mount` and `scope` from every item `review_items`
  sends.
- A finding's `subject` (a profile, host or variable name) and `detail` are
  `#[serde(skip)]` in `report::Finding`: the window and the text summary
  show them (each a short printable name, as `rules::label` allows; the text
  summary escapes them, and `shown` does for the window, as other programs
  can edit the state file), and the JSON report, the output people pass
  on, leaves them out, as they can name the person's accounts and hosts.
  `token_type` is a `&'static str` from the scanner's fixed list
  (`PROVIDERS` in `src/rules/token.rs`), so it carries nothing from a file
  and is exported. Test:
  `a_finding_in_the_json_report_has_only_the_fields_of_the_schema` in
  `src/report.rs`, which sets every field and checks that none of the
  private ones reaches the report, and
  `stored_subjects_reach_the_window_escaped` in `gui/src/lib.rs`.
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

## Read-only, offline, runs nothing

The scanner reads the most sensitive files a person has, so the ways out of
the process stay closed or in one place.

- No network code except the update check ([Update check](#update-check)):
  a connection is a way for a secret to leave the Mac. The scanner gate
  watches the `loose-keys` command for network attempts, and
  `network_code_lives_only_in_updates_swift` fails when a known network
  call appears elsewhere in `src/`, `gui/src/` or `gui/app/`.
- No process started: files the scanner reads name programs to run, and
  whoever can write such a file would choose what a scanner that ran it
  starts. [Tests](#tests) has what the scanner gate checks and what it
  misses.
- No write into a scanned folder: Loose Keys never changes the files it
  scans (`README.md`). The scanner gate fails when a scanned or outside tree
  changed during a run. Loose Keys writes only a requested export and its
  own state, as [Files](#files) says.

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

Rule text is window text, so the rules under "The window and running the app"
apply to it. Hedge once per finding. The reason says why the exposure matters,
the next step names the first action, and each step is one action, or a few in
one place, with its condition or place first ("If the key may have been
copied, …", "In HCP Terraform, …"). Use one verb per act: revoke at the
issuer, delete the local file, sign out of a session; name a vendor's control
by its label. A command that ends a step follows a colon with nothing after
it; one inside a sentence goes in single quotes. Rules that share an id are
one entry in the command's report, and a rule that copies another's fields
copies its text, so that text must fit every file each covers. The
[Apple Style Guide](https://support.apple.com/guide/applestyleguide/welcome/web)
and [Google's guide to procedures](https://developers.google.com/style/procedures)
have the general rules.

Rule samples, the detection corpus and the security harness check that finding
text reaches the reports with no credential value in it. They do not check
what third-party products show or how each version stores credentials, and
vendors change their settings.

A scan sees only the places and formats it knows, so nothing it outputs says
a Mac is clean or gives it a score. For the same reason the command's exit
code describes the run, not the findings, so a script cannot read success as
"no credentials" or miss a partial scan. `--fail-on-open` is the one
exception, for device-management checks that ask for it. The usage text in
`src/main.rs` has the codes.

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
  Report text is fixed scanner text, never built from file contents. A hit
  can carry a `Wording` in place of its rule's text, as temporary AWS keys
  do, under the same id, kind and severity; list it in `wordings()` so the
  Spanish check sees it.
- Each registered implementation also needs a case in
  `tests/detection-corpus.json`, or the coverage test fails. `Case` in
  `tests/support/detection.rs` documents the fields. Write the expected
  findings from the intended behaviour, never by copying a scan's output.
- A recheck says an item is gone only when this build has its rule and, for a
  rule found by a file being there, a target that names the item's place.
  Otherwise `recheck_values` knows nothing (`None`), so an item saved by
  another build, or under a target list that has changed since, is never
  marked fixed with its file unread. Test:
  `a_recheck_this_build_cannot_make_is_not_a_fix` in `src/scan/tests.rs`.
- A shipped rule id is stored in saved choices, organizations'
  `ExpectedFindings` lists and reports, and nothing migrates it. Renaming one
  drops the organization's entries for it without notice, asks again about
  findings set aside under it, and leaves items saved under the old id open.
- Inline environment tables retain each literal secret separately and skip a
  service-token assignment only when its whole value matches the token rule. Quoted
  commas do not separate pairs. The existing scalar parser accepts a limited
  subset of TOML, not every escaped or multiline value; secrets it cannot parse
  can be missed. The token rule reads those known settings files whole as well,
  so suppressing a duplicate assignment does not hide a token beyond the head;
  the existing 1 MiB config limit and its gap still apply. A key bundle is
  checked block by block within its 4 KiB head:
  any unprotected key found there takes precedence over protected or unknown
  keys. Keys past the head and key validity remain unverified. Rule tests cover
  the matching and limits; the detection corpus checks the findings and that
  fixture values and fragments do not enter CLI or engine exports.
- A file named only by a pattern that starts with `*` (`names_loosely`) is
  passed over with no gap when it is over 1 MiB and its rule's `candidate`
  rejects its 4 KiB head (`check_head` in `src/scan/read.rs`). Such names are
  common, and large logs under them would fill `not_checked` and make nearly
  every scan partial. In practice this is `*.txt`, `*.rtf`, `*.conf` and
  `*_tokens.json`: the other patterns read whole (`*.env`, `*.tfvars`,
  `*.ovpn`, `*.tfstate`) are also named by a rule that accepts any head, which
  reads the file and reports `too-large`. Only `*.conf` is tested:
  `a_conf_file_over_1_mib_is_a_gap_only_with_an_interface_head` in
  `tests/scan_scope.rs`. A change updates the reads limit in `docs/usage.md`.
- Text configs read through `utf8_text` drop a leading byte order mark, and
  the value positions they give stay ones in the file. Maven and FileZilla
  XML that stops inside a tag, comment or declaration is an `unreadable` gap
  that keeps what was found before that point. Tests:
  `a_byte_order_mark_is_not_part_of_the_first_line` and
  `xml_that_stops_inside_a_tag_is_a_gap` in `src/rules/mod.rs`.
- Codex's MCP servers in `~/.codex/config.toml` are read line by line for
  literal HTTP headers under `http_headers`, inline or as a table of their
  own, and judged as the JSON MCP configs' headers are. `env_http_headers`
  and `bearer_token_env_var` name variables and are not read. This is a
  limited subset of TOML: a multiline string, array or table, or a server
  written as one inline table, can hide a header. The field names were not
  checked against Codex's current documentation or code (unverified).
- The WireGuard, 1PIF and old Azure CLI `accessTokens.json` rules were
  written from the formats as remembered, not from real files or the tools'
  code (unverified): how WireGuard parses a config, that a 1PIF export's
  `uuid`, and its `secureContents` or `typeName`, fall in its first 4 KiB, the field names in
  `accessTokens.json`, and that Azure CLI 2.30 stopped using it. A `.conf`
  file's text must be UTF-8 only when it has an `[Interface]` section, so
  another program's config in another encoding is not a gap.
  Test: `wireguard_keys_are_found_in_conf_files_only` in
  `tests/scan_scope.rs`.
- Matcher caps: 100 matches per file for the line-based configs that go
  through `utf8_lines` and for Maven, FileZilla, AWS and `.netrc`, 100
  assignments per environment or shell file, 100 MCP holders, 100 Codex MCP
  header lines, 100 OpenVPN key blocks, 100 rclone remotes per rule, and 20
  password-note lines. PyPI passwords and Poetry tokens share one 100, as do a
  warehouse config's password fields and embedded keys. Composer and
  Terraform's token file, one finding per host, have no cap of their own.
  Terraform lists 100 holders and examines
  up to 1,000 instances per resource and 100 named sensitive attributes per
  instance; in a version 3 state (Terraform 0.11 and earlier) a resource's
  instances are its `primary` and its `deposed` copies, searched under the
  same limits. Service-token matching keeps the first 100 occurrences, then only
  new values until 100 distinct values have been found; later repeats are
  grouped. When another distinct value or capped match is omitted, or
  Terraform's inspection budget leaves entries unchecked, retained findings
  stay listed and a `scan-limit` gap makes the scan partial. Exactly filling a
  match budget is not a gap. An incomplete recheck cannot mark an omitted
  review item fixed. A change to a cap updates this list.
- A service-token format (`PROVIDERS` in `src/rules/token.rs`) is matched with
  no context, so its prefix and shape alone must say who issued it. A prefix
  the Gitleaks, Betterleaks or TruffleHog rule sets match only next to the
  service's name is left out, as Mem0's, Dropbox's and ElevenLabs' are
  (`prefixes_that_need_the_services_name_are_not_tokens`). A format
  made of parts is checked part by part (`Part`), not as one character class
  and a total length, so text of the right length with a separator out of
  place is not reported. A token ends where its parts do. What follows may be
  a separator, but not a word character or a character one of the format's
  parts can hold: that makes a longer string, which is not reported. So "/"
  ends a Slack or Discord webhook URL but continues an AWS Bedrock key, whose
  base64 holds "/" and "+". A comma ends every token but Fly.io's, which
  joins its macaroons with commas
  (`a_comma_ends_a_token_whose_format_has_none`). So a token after a Fly.io
  token and a comma is taken into it, and when the two together are longer
  than 2,000 characters the Fly.io token is not reported.
  Mapbox secret tokens follow Betterleaks' pattern
  without its offline filter, which decodes the middle part and drops one that
  is not a `{"u":...,"a":...}` object; a string of the right shape with another
  middle part is reported. `formats_are_strict` has a body of the
  right length with one part wrong for each such format, and
  `the_parts_of_a_format_fit_how_it_is_counted` checks that the parts can be
  matched one after the other. Not verified: tokens vendors issue today
  beyond the published formats, and how often ordinary text matches one.

### Docker registry token coverage

The Docker rule checks literal string values in `auth`, `identitytoken` and
`registrytoken` inside each `auths` entry at its Docker, Podman and Helm
paths. Docker's [AuthConfig definition](https://github.com/docker/cli/blob/fb2fe0eac78bb48b63905b31d95f3950dcb1b588/cli/config/types/authconfig.go)
names the token fields, and [SaveToWriter](https://github.com/docker/cli/blob/fb2fe0eac78bb48b63905b31d95f3950dcb1b588/cli/config/configfile/file.go)
preserves them while encoding username/password auth. This is source-level
format evidence, not a live Docker login check. Tokens are not decoded or
validated. Empty values, nonstrings, whitespace and reference/masking forms
are skipped; JSON token values otherwise retain literal shell characters.

The rule emits one finding per file, with no registry subject or value. It
runs no helpers and reads the config without following links, up to 1 MiB.
Detection and private fingerprint material use the same field selection.
Token material includes its field name, so field changes and token rotation
cannot reuse another field's fingerprint. Kept and managed decisions have
rule and file scope.

Tests: `rules::docker::tests`, the detection corpus at the three paths, and
`docker_token_fingerprints_follow_tokens_not_config_layout`. Real Docker,
Podman and Helm login flows, helper-backed secrets and app alerts remain
unverified.

## Tests

- Unit tests are in a `tests` module in the file they test and can reach
  private items. The scanner's are all in `src/scan/tests.rs`, and reach a
  private item of another file in `src/scan/` only if it is `pub(super)`.
  The engine's `background_tests.rs`, `engine_text_tests.rs` and
  `stored_tests.rs` are files of their own in `gui/src`, declared in `lib.rs`.
  `tests/scan_scope.rs` runs
  the built scanner as a child process and sees what a person would: output,
  exit status, files. [1]
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
- The leak check for a new output is made as `tests/scan_scope.rs` and the
  harness's `leak` check make theirs.
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
- Only `build.rs` and tests start a process. The scanner gate checks the
  `loose-keys` command for it with probes that record whether they ran:
  stand-ins for `git`, `aws`, `security` and other tools first on its
  `PATH`, and the commands a hostile `.git/config`, AWS `credential_process`
  and kubeconfig `exec` name. Nothing catches a program by another name or
  full path, or a process started by the engine, the helper or the window:
  review is the only guard there.
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
  `[lints]` table that denies eight more things: an unsafe call inside an
  `unsafe fn` with no block of its own (`unsafe_op_in_unsafe_fn`), clippy's
  `dbg_macro`, `todo`, `unimplemented` and `mem_forget`, and a cast that
  can truncate, wrap or lose a sign
  (`cast_possible_truncation`, `cast_possible_wrap`, `cast_sign_loss`).
  Keep the two tables the same. Fix what a lint reports. If it is wrong for this
  code, override it on the smallest item with
  `#[expect(lint, reason = "...")]`, not `#[allow]`: clippy fails once the
  lint no longer fires there, so the override cannot outlive its reason. [6]
- Clippy does not check arithmetic or indexing here. Its lints for them
  (`arithmetic_side_effects`, `indexing_slicing`, `string_slice`) are
  restriction lints, and the places they report here are nearly all bounded
  already. "Numbers, offsets and text from a file" is the rule for
  them. Turning one on is a lint setting to ask about first. [10]
- Pass `--locked` to every cargo command that builds. It fails instead of
  rewriting `Cargo.lock`. The workspace has one lock file, at the root.
  `cargo audit --file <lock>` checks one against the RustSec advisory list.
  [Local checks](../testing/local-verification.md) has the commands. [11]
- The test-only `jsonschema` and `zip` are set in the root manifest's
  `[dev-dependencies]` with default features off, so schema resolution
  never fetches a URL or reads a file and `zip` builds only the deflate
  codec the harness's fixture uses.
- Both manifests say `rust-version = "1.88"`, and `README.md` tells people
  that version. The checks lint and test with the latest stable and also
  build the workspace with 1.88. Clippy's `incompatible_msrv` lint, on by default,
  reports a standard library item newer than that.
- Edition 2021. Edition 2024 changes when temporaries, lock guards among
  them, are dropped in `if let` and at the end of a block, makes
  `std::env::set_var` unsafe and reformats code. Moving is a change of its
  own, with the lock code reread. [7]
- A version change touches both `Cargo.toml` files, `Cargo.lock`,
  `README.md` and `gui/macos/Info.plist`; the release skill's `bump.sh` sets
  all five. The bundle's version keys in `Info.plist` take numbers and dots
  only.
- A component and its tests keep the language and toolchain they have.
  Building the app needs only Rust and Apple's command-line tools
  ([README](../../README.md#build-the-app)), and testers build it that way.
  Another language or runtime in a component is one more toolchain for
  everyone who builds or checks it, and in what ships, more code running
  beside a person's credentials, as an added crate is.
- macOS only. The file access relies on macOS calls and flags
  (`SF_DATALESS`, `acl_get_fd_np`), and every check runs on macOS, so a branch
  for another system would be code no check runs, and a claim for one would
  be unverified.

## The window and running the app

### Disk image packaging

`gui/package-dmg.sh` copies the signed build into a compressed, read-only
HFS+ disk image with an `/Applications` shortcut and English/Spanish install
instructions. It uses macOS tools, adds no dependency, starts no app, and
never writes to Applications. A private temporary staging directory is
removed on exit; an existing output image is refused.
See [disk image checks](../testing/local-verification.md#installer-disk-image)
for verification and remaining unverified behavior. Packaging does not add
notarization or change signing.

### Update check

The app's only network request. `gui/app/Updates.swift` sends one GET to
`api.github.com/repos/chuglo/loose-keys/releases/latest` with an ephemeral
session: no cookies, cache or saved credentials, a fixed User-Agent, a
30-second timeout, and no redirect followed. It accepts only a 200 reply
from that host over HTTPS and reads at most 1 MiB. The `check_release` command
(`check` in
`gui/src/release.rs`) caps the reply again, reads only `tag_name`, `draft`
and `prerelease`, accepts only `vX.Y.Z` with 1 to 9 digits a part, and
answers with fixed text that never contains the reply. The app's own
version may go on past `x.y.z`, as a test build's does: a `-` suffix comes
before that release and a `+` suffix changes nothing (test:
`a_prerelease_of_this_app_is_offered_its_release`). The window shows
only the version numbers the engine returns, and Download opens a fixed
URL. The automatic checks look every hour and check once a day has passed
by the wall clock, because a timer stops while the Mac sleeps. The person's answer is `update_check` in the app's private state. The
sample and model-check builds compile no fetcher, and the picture build
uses none.

The answer is also kept as `true` or `false` in `update-check.json` beside
the state, because a helper of an older build still running after an update
saves the state without the field, which it does not know. Older builds
never touch that file. `set_update_check` writes it first, inside the store's
update, so a copy that cannot be written saves no answer. `Store::load`
takes the copy's answer only when the state has none, and the next save
puts it back in the state. A copy that is missing, not a private file of the
user's, over 16 bytes or anything but `true` or `false` is no answer: the
question is asked again and nothing is checked. Test:
`the_update_choice_outlasts_a_save_by_an_older_build`.

Checked by: `release.rs` tests (parsing, caps, errors, and
`network_code_lives_only_in_updates_swift`, which fails if a network name
on its lists appears in any other window, engine, bridge or scanner source;
build scripts are not read. The lists include readers that take a URL,
`Data(contentsOf:)`, `String(contentsOf:)`, `XMLParser(contentsOf:)`, their
Objective-C forms and `WKWebView`, apart from the exact local-file reads in
`LOCAL_READS`; a reader not listed, such as `NSDictionary(contentsOf:)`,
would not be caught), the model check's `updates:`
cases, and the window check's update steps.

The question whether to check automatically is a row at the bottom of the
Overview, with Don't Check and Check Automatically, not an alert: it is not
urgent, and as an alert it came over what the first scan had just found
[27, 28]. It stays until answered there or in Settings. The model keeps
what the last status read that worked said, so a read that fails for a
moment neither asks nor takes the row away (the model check's `updates:`
cases). Quit leaves consent unanswered. The IP address GitHub sees is a
caveat, so it is in [usage](../usage.md), not the question's line
([the shipped bundle](../testing/guest.md#the-shipped-bundle) has the check).

What Check for Updates… found uses a native `NSAlert` sheet with
`preventsApplicationTerminationWhenModal` disabled on that alert alone.
SwiftUI's multi-button alert otherwise blocks termination before the app
delegate (unverified). Only explicit button responses open the fixed download
page;
system dismissal and Quit do not. No other modal or global termination
policy is changed. Runtime behavior on macOS 14 and simultaneous unrelated
sheets remains unverified.

Remaining risks: a compromised GitHub account or API can announce a fake
newer version, though Download still opens the real release page; TLS trust
is the system's, with no pinning; GitHub sees the IP address and that the
app checked. An older build saving the state still drops the other fields it
does not know, `menu_bar_off` among them; only the update answer has a copy.
Not verified by any check: a live request from the built app, that a
refused redirect reaches the app as a non-200 reply (unverified URLSession
behaviour), and that a helper of an older build keeps running after the app
is replaced (macOS behaviour).

### Building and starting

- `sh gui/build-macos.sh` builds the engine with cargo, links the window to
  it with `swiftc`, and signs the bundle ad hoc, or with the identity named
  in `LOOSE_KEYS_SIGN_IDENTITY` ([README](../../README.md#build-the-app)). It
  has to work with Apple's command-line tools alone, because that is how
  testers build it (`README.md`). `@State` needs a compiler plug-in that
  comes only with Xcode ("plugin for module 'SwiftUIMacros' not found"),
  which is why view state lives in `AppModel`.
- `AppModel` is `@MainActor` and owns all state. Views read it through
  `@EnvironmentObject`. Engine calls block (`start_scan` until the scan ends),
  so they go through `Engine.request` and `send`, which run off the main
  thread. The one exception is `prepare_quit`, which `prepareToQuit` calls
  on the main actor from `applicationWillTerminate`: a call sent off the
  main thread could still be waiting when the process ends, and the monitor
  has to be stopped first, so that no scan starts and a running one is
  cancelled. It takes only the monitor's lock and skips `App::ready`, so it
  does not wait for the store. Events may arrive on any thread and are moved
  to the main actor in `AppModel.start`.
- Those calls answer in any order: startup, an event, a click and the window
  coming forward can each ask for the same list while an earlier request is
  still out. `review` and `monitor` each use `ReadTurns`: one read at a time,
  with requests during it sharing the next read. Numbering requests was not
  enough: a later call could read first. The engine renders the snapshot its
  own command read, not a shared copy another call can replace. If a read
  fails while another is already queued, the window keeps what it shows until
  that one answers; otherwise the review list reports the failure and the
  helper status shows as unavailable, each with the reason. A read answers
  for every request it shares, so its failure opens an alert when any of
  them asked for one (every read but the timed ones does), including a
  request whose own read failed and left its answer to this one. Folder
  answers go through `RequestOrder`, which numbers each request and uses an
  answer only when no later request's answer has been used, so neither an
  older list nor an older failure replaces what a newer answer showed. Two
  folder changes that overlap may need another refresh to show the result.
  The folders are read at launch, each time Settings opens, and when Scan
  Now is pressed before any list was read. A list the window couldn't get
  is said on the Overview and in Settings, and one the engine couldn't read
  from its saved state in Settings, never as no added folders. Scans and
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
- A failed action is shown in the window it was taken in, and in no other.
  The alert's title says what failed ("Couldn't Save the Report", from
  `FailureTitle`) and its message why; the app's name is no title, since
  macOS already shows its icon [27].
  Settings has its own alert (`settingsFailure`) for its switches and
  buttons; the main window's is `failure`. Settings reports whether it is
  open (`onAppear`, `onDisappear`). A failure that comes after it has closed,
  or from taking the icon out of the menu bar, goes to the main window,
  which comes up for it. Checked by the model check's `failures:` case and
  the window check's refused Show in Menu Bar. Remaining risks: a failure
  of a main-window action, a File menu command chosen with only Settings
  open, or a review read after a helper event still waits for the main
  window if it is closed.
- The engine's JSON is decoded into the types in `Models.swift`, snake case
  to camel case. `Preview.swift` holds sample JSON for the sample-data build,
  which has to change with them. Text from a scan is shown as text, never as
  markup. Development-only code sits inside `#if PREVIEW || SNAPSHOTS`.
- The window, its alerts, the menu bar menu, the folder-access prompts and
  the notification are in English and Spanish; the saved reports, the copied
  summary and the command line stay English. The tables are in
  `gui/macos/<lang>.lproj`, keyed by the English (`InfoPlist.strings` by
  its `Info.plist` key), and the build writes them into the bundle as binary
  property lists, which also fails it on a syntax error. A literal in a
  SwiftUI control is looked up already;
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
  depth, the order of languages, and the Filter and sort. The window and
  model checks copy only `en.lproj` beside their executables, so they run in
  English whatever the Mac's language.
- Every toolbar button, and what the inspector and a row's context menu do
  to the chosen item, is also a command in the menu bar (`Commands.swift`),
  since the toolbar can be hidden. The Item menu acts as the inspector does:
  Show in Finder and Copy Path need exactly one chosen row, never an
  arbitrary one of several (`chosenFile`), and Set Aside and the two
  moves back act on every chosen item.
- The controls are the system's: `NavigationSplitView`, `Table`, `List`, the
  toolbar, `.inspector`, `Form` in a `Settings` scene, `MenuBarExtra`,
  `NSOpenPanel` and `NSSavePanel`. Add a feature with one of these before
  drawing anything. The one drawing is the menu bar's key with a dot for
  open items or a full list (`MenuBarIcon`), because SF Symbols has no key
  with a badge.
- Layout and wording follow Apple's Human Interface Guidelines, and the
  Nielsen Norman Group's research where Apple says nothing [17–25]. How
  prominent something is matches how much it matters [17, 22]: the Overview
  leads with what needs a decision, and what a person rarely needs is one
  labeled step away, in Settings or the saved report [23]. A problem the
  person can fix is shown where it has its effect, says in plain words what
  to do, and offers the control that does it, as Restart Helper does in
  Settings [18, 24]. Where macOS waits for the person to let the helper or
  the app start, Open System Settings beside the line calls
  `SMAppService.openSystemSettingsLoginItems()`; the window check records
  the press instead. Unverified: that it opens Login Items on macOS 26 and
  later, and that the list there is still named Allow in the Background.
  A count or badge appears only where a person acts on
  it or would miss it [21, 25], so places not checked have none: nearly
  every Mac has places macOS keeps private. A sheet is for a short task,
  with Cancel or Close beside any Done; a little information goes in a
  popover [19, 20]. Each state has at most one prominent button, so the next
  step is plain. An explanation sits directly under the control it explains,
  not in a footer the person has to match back to it. The Scan Automatically
  switch has the same name and line on the Overview and in Settings, and
  turns on the same way in both, with no confirmation: the line says what it
  does, and an alert is not for an action that can be undone [22, 27].
- Window text is as short as it can be. Apple's writing guidance says to
  check that each word needs to be there [18]: a note that repeats its
  heading is cut, not reworded. A test that pins long text is suspect.
  Limits, ordering, timing and caveats are in [usage](../usage.md).
  The same guidance gives the rest: verbs on buttons and links, no "we",
  which leaves unclear who is meant, a setting described by what it does
  when on, a button that opens a setting rather than only
  its location, and an empty page that offers the next step [18]. Apple's style
  guide recommends contractions and rules out idioms, which translate badly
  [26]; here the Spanish is keyed on the exact English, so a reworded
  sentence needs its Spanish again. New text says "your files" or names what
  is left out, not "your home folder", because the places to check will not
  stay fixed.
- Overview answers first: a heading with what needs a decision and at most
  one button, then the Scan Automatically switch. A newer version comes last,
  with a plain Download, so the page keeps one prominent button. A scan or
  its preparation is said once, in the heading: the window's subtitle stays
  empty on the Overview. Under the heading is only what the person can act
  on: a folder macOS kept from the last scan, with Open System Settings. The sidebar's names and counts are
  not repeated on the page [22]. The first page offers Scan Now alone, with
  the toolbar hidden as the sidebar is, so the page's own button is the one
  control. View > Show Sidebar opens the sidebar there; it sets the model
  directly, because the system's `SidebarCommands` did not open it against
  the first page's hiding in the window check.
  Scan Automatically is offered on the Overview after an answer [17]. The heading never says "nothing" for
  a list that was not read, nor before anything was checked. Under "Nothing
  Worth Reviewing", Show Places Not Checked says that some places couldn't be
  checked when any were, so the heading's line does not say it again; Worth
  Reviewing's empty states, which have no such link, say it in words [22]. While the helper makes
  its first full pass and this window has not scanned, the heading says
  Checking Your Files… or, once items turn up, Still checking your files…;
  after it, the line is when the helper last checked. "From earlier scans."
  is only for a list nothing has checked in this launch. For 15 seconds
  after the person turns automatic scanning on, a helper that is not yet
  running is Starting…, not Helper Not Running (`helperStarting`, timed by
  the model's clock). The update question, a row at the bottom, waits
  until a scan or the helper's first full pass has an answer, and none is
  running, so the first page and a scan's progress come without it [17].
  Folder controls, skipped
  folders, check timing and Pause are in Settings. The
  Overview does not show what a scan covers. That is in
  [usage](../usage.md), in `loose-keys --list-rules` and in every saved
  report, which keeps the scan's exclusions and detection limits.
- What the last manual scan and the helper's last full pass could not read
  is in one popover, opened only by Show Places Not Checked under the
  Overview's answer [23]. The link shows only when something went unread.
  It is one list: each place once under its reason, from either scan, as
  which scan missed it changes nothing a person does; long paths are cut in
  the middle. Checked by the window check's line for places both scans
  missed.
  The engine's `blocked` names which of Desktop, Documents and Downloads
  the scan was denied, as those fixed words matched against its
  `permission-denied` gaps, never a path; the window shows Finder's name
  for each. Open System Settings opens Privacy & Security, Files & Folders
  (`openFilesAndFoldersSettings`). Checked by the engine test
  `access_preparation_is_bounded_and_does_not_claim_coverage` and the window
  check, which records the link instead of opening it. Unverified: that
  macOS 26 and later still open that pane from the link.
- The Filter field is on the three lists and not on the Overview, which has
  nothing to filter. It is AppKit's search field in an ordinary toolbar item
  (`FilterField`), which comes and goes with the page as the Inspector button
  does. Do not use `.searchable` for it: taken out and put back as the page
  changed, its toolbar item stopped the app about one run in five in the
  window check, as AppKit refuses a second one and the first was not always
  gone by then. The window check switches pages and checks
  that the field is on each list and not on the Overview. Not verified:
  focusing the field with Command-F, which the window check cannot press.
- Filtering a review group checks every listed path, including fixed and
  set-aside copies. Matching secondary paths are display-only context below
  the representative path; the row's id, revision, sort key and file-action
  target do not change. Copy hints count all listed places, not only active
  ones. Filtered counts compare visible rows with this page's usable list,
  including fixed rows, never the scan's finding count. No Matches and Clear
  Filter do not replace read/save errors or a genuinely empty source list.
- The inspector starts hidden. A changed selection opens it, clearing that
  selection closes it, and the toolbar can explicitly show an empty
  inspector. An unchanged selection does not undo a manual hide. Selection
  changes use the same delayed-close guard as toolbar presses.
  The initial content size is capped against the main screen's visible
  frame with room for the title bar and toolbar; restored window sizes are
  not changed. Screens smaller than the 760 by 480 content minimum plus
  window chrome remain unsupported by this sizing rule.
- Full manual reports and manual gaps live only in this app session;
  `docs/usage.md` says so and no page does. Stored sign-ins are saved (see
  "Saved stored sign-ins"). The Overview counts from saved findings until a
  scan, and says nothing of saving: the answer is in the saved list.
  An empty, never-scanned review list keeps its onboarding rather than
  claiming that saved findings exist.
- A row's selection is cleared in the model when the filter hides the row,
  or when the page changes to another list (`dropHiddenSelection`). A row is
  named by its item id on every list.
- Worth Reviewing, Stored Sign-ins and Set Aside show separate portions of
  the same review list; Set Aside lists both kinds. Stored sign-ins never
  count toward the menu bar, the Overview or Worth Reviewing's subtitle, and
  Stored Sign-ins has its own sort, since it has no Risk or First Seen
  column. The split is only in the window: scanning, grouping, report counts
  and exports keep set-aside findings. A successful refresh clears a
  selection when a decision moves its row to another page; a grouped
  credential stays in review while another copy still needs a decision.
  Each page shows read/save failures instead of an empty result. When the
  list cannot be used, the badges of Worth Reviewing and Stored Sign-ins are
  the scan's counts and Set Aside has none, since a scan knows nothing of
  decisions.
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
synthetic home first (`sh security-tests/harness.sh generate-home "$synth"`,
as in [local checks](../testing/local-verification.md#a-scan-by-hand)):

```sh
open --env HOME="$synth/home" "target/release/bundle/macos/Loose Keys.app"
```

Confirm the process has that synthetic `HOME`. Do not collect a full process
environment from the host.

Pictures of each page, and the window check against the real engine, come
from two development builds in `gui/app/Preview.swift`:
[the macOS guest](../testing/guest.md#pictures-and-the-engine-window-check)
has how to run them.

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
6. Rust 1.81 release notes: a panic leaving an `extern "C"` function aborts,
   and `#[expect]` with lint reasons is stable.
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
12. The Reference, "Overflow" and "Numeric cast" under operator
    expressions: overflow wraps when checks are off, and `as` truncates.
    https://doc.rust-lang.org/reference/expressions/operator-expr.html
13. Cargo profiles, `overflow-checks`: on in dev, off in release.
    https://doc.rust-lang.org/cargo/reference/profiles.html
14. The standard library: `str` slicing and `is_char_boundary`,
    `Vec::with_capacity` and `try_reserve`, `Path::to_string_lossy` and
    `display`, `Instant` and `SystemTime`, `std::thread` ("Stack size") and
    `std::process::exit`. https://doc.rust-lang.org/std/
15. Mara Bos, Rust Atomics and Locks, chapters 2 and 3: stop flags, Relaxed,
    Release and Acquire ordering. https://mara.nl/atomics/
16. `serde_json::Deserializer::disable_recursion_limit` and the
    `unbounded_depth` feature.
    https://docs.rs/serde_json/latest/serde_json/struct.Deserializer.html
17. Apple, Human Interface Guidelines, "Feedback": deliver information in a
    way that matches its significance; show status passively; keep alerts
    for critical, ideally actionable information.
    https://developer.apple.com/design/human-interface-guidelines/feedback
18. Apple, Human Interface Guidelines, "Writing": an error close to the
    problem, without blame, saying what fixes it; plain words.
    https://developer.apple.com/design/human-interface-guidelines/writing
19. Apple, Human Interface Guidelines, "Sheets": a scoped task or a request
    for information; Done always paired with Cancel or Back.
    https://developer.apple.com/design/human-interface-guidelines/sheets
20. Apple, Human Interface Guidelines, "Popovers": a small amount of
    information or functionality; not for warnings.
    https://developer.apple.com/design/human-interface-guidelines/popovers
21. SwiftUI `badge(_:)`: optional, supplementary information, as short as
    possible. Apple's rule that a badge counts only unread notifications is
    for the app icon (Human Interface Guidelines, "Notifications").
    https://developer.apple.com/documentation/swiftui/view/badge(_:) and
    https://developer.apple.com/design/human-interface-guidelines/notifications
22. Jakob Nielsen, "10 Usability Heuristics for User Interface Design",
    Nielsen Norman Group, reviewed 2024: 1, visibility of system status; 4,
    consistency and standards; 8,
    aesthetic and minimalist design; 9, help users recognize, diagnose and
    recover from errors. https://www.nngroup.com/articles/ten-usability-heuristics/
23. Jakob Nielsen, "Progressive Disclosure", Nielsen Norman Group, 2006:
    rarely needed options on a secondary screen, reached by an obvious,
    clearly labeled control. https://www.nngroup.com/articles/progressive-disclosure/
24. Tim Neusesser and Evan Sunwall, "Error-Message Guidelines", Nielsen
    Norman Group, 2023: plain words, near the source, with a remedy.
    https://www.nngroup.com/articles/error-message-guidelines/
25. Kim Flaherty, "Indicators, Validations, and Notifications", Nielsen
    Norman Group, 2024: indicators add clutter, so show one only if it would
    be missed; a passive notice is easily missed.
    https://www.nngroup.com/articles/indicators-validations-notifications/
26. Apple Style Guide, "contractions" and "Intro to international style":
    use common contractions; don't use idiomatic or colloquial expressions.
    https://support.apple.com/guide/applestyleguide/welcome/web
27. Apple, Human Interface Guidelines, "Alerts": a title that describes the
    situation; no alert for common actions that can be undone, nor merely to
    inform. https://developer.apple.com/design/human-interface-guidelines/alerts
28. Therese Fessenden, "Modal & Nonmodal Dialogs: When (& When Not) to Use
    Them", Nielsen Norman Group, 2017: no modal dialog for nonessential
    information unrelated to the current task; a nonmodal one lets people
    continue. https://www.nngroup.com/articles/modal-nonmodal-dialog/
