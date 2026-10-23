# Working in this repository

For coding agents. `CLAUDE.md` only imports this file, so edit this one.
`docs/development/standards.md` has the reasons, examples and sources. Read its
section before changing the code a rule covers.

loose-keys scans a person's home folder for stored credentials and
says how to remove the exposure. It reads the most sensitive files a person
has, so a mistake here leaks a secret or reports a result people wrongly
trust. Review the file-access and output rules below before changing what the
tool reads, writes or shows.

## Layout

One Cargo workspace, one `Cargo.lock`, one `target/`. The product is the
app; the `loose-keys` command ships inside its bundle.

- `src/`: the scanner, a library crate (`lib.rs`), and the `loose-keys`
  command on top of it (`main.rs`). `rules/` has one file per rule family,
  `fsutil.rs` is the only code that opens scanned files, `scan.rs` sets what
  is visited and the work limits, `report.rs` builds every output.
- `gui/`: the app's engine, a static library that depends on the scanner
  crate, so a change under `src/` changes the app too.
- `gui/app/`: the macOS window, in Swift. `gui/app/Bridge.h` is its whole
  interface to the engine: five C functions, JSON in and out.
- `security-tests/`: a Rust test harness that runs the built scanner against
  hostile fixtures.

## Commands

Before running or changing tests, read [tests/AGENTS.md](tests/AGENTS.md).

Run from the repository root as an ordinary user, with Rust 1.88 or later.
`TMPDIR` must be a folder with no symbolic link in its path, because scanned
files are opened without following links and tests build synthetic homes
there. On macOS `/tmp` and the default under `/var` are links, so:

```sh
mkdir -p /private/tmp/credhyg-scratch
export TMPDIR="$(cd /private/tmp/credhyg-scratch && pwd -P)"
```

For changes to code, tests, build scripts, dependencies or configuration:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

For prose-only changes, meaning Markdown files and images under `docs/`,
review the edited text and check referenced local paths and commands against
their definitions. No build or test reads them, so no other check is required,
before a push to `main` either.

The Rust 1.88 build runs in the list before a push, not for every change.

The table below is the verification matrix for the whole repository,
including `gui/`. [Local checks](docs/testing/local-verification.md) has each
command, what it needs and what it does not cover:

| Change | Also run |
|---|---|
| anything under `src/` | the security harness |
| rules, scan/report code, the engine's scan/export commands, the detection corpus | `sh security-tests/check_detection.sh` |
| `gui/app/`, `gui/macos/`, `gui/build-macos.sh`, the C interface | the bundle build and its contract test |
| `gui/app/` | also the window check and the model check |
| the helper runner or its Settings driver | helper self-tests, then the guest controls |
| `gui/src/notifications.m` | the login bridge and notification contracts, and the power bridge |

The shipped-bundle and native-helper checks run only in the disposable macOS
guest; `docs/testing/guest.md` has its setup and both checks.

There is no CI: no workflow runs these checks, so none exists to wait for or
to cite. Before a push to `main` that is not prose-only, follow "Before a
push to `main`" in `docs/testing/local-verification.md`: every check there on
the exact commit, one command at a time, with each one's exit status
reported. Run the guest checks when the person directing the session asks or
when the change is to what they check; otherwise list them under "Not
verified".

## Keep the machine you work on safe

- Never run the scanner, the app or the background helper
  (`gui/src/agent.rs`) on a real home folder. Set `HOME` to a synthetic home
  for every run. Started without it, the app opens on the real home and
  creates `~/Library/Application Support/dev.loosekeys.desktop` there, and
  real paths land in your
  session's record. macOS starts the helper on the account's actual home
  whatever `HOME` says, so the app and the helper are started only inside
  the guest, whose home is not a real one.
- The sample-data `PREVIEW` build and `gui/tests/check-window.sh` are the
  exception: they use no engine and read no home folder, so they may run on
  the host without substituting `HOME`. Say first that a window will appear.
  The real app, helper and `SNAPSHOTS` build remain guest-only.
- Never write a complete token-shaped string into source, tests, docs, a
  commit message or your own output. Build it from pieces, as
  `src/rules/token.rs` does with `concat!`, or generate it at run time. Secret
  scanners, this one included, read repositories and agent session records
  and will report it.
- Start the app only when the task needs it, and only as "The window and
  running the app" in `docs/development/standards.md` says.
- **Standing guest-only authorization (2026-10-14).** In an approved
  disposable macOS guest containing synthetic data only, enable background
  checks and answer the macOS prompts the requested verification needs
  without asking again: the test driver's Accessibility, helper/Login Items
  consent, notifications and Documents access for export checks. Record
  grants and outcomes, do the documented cleanup and stop the guest when
  done. This does not authorize host Accessibility, host screen sharing or
  any other host privacy or security change, scans of a real home,
  unrelated prompts, or disabling SIP or Gatekeeper.
- Push, merge, tag or release only when the person directing the session
  asked for that action. A tag also needs the list in "Before a push to
  `main`" to pass on the exact commit, and that person's word on what that
  leaves unchecked (the guest checks).

## What the product must keep doing

- **Read-only, offline, runs nothing.** No network code, no
  `std::process::Command` outside `build.rs` and tests, no write into a
  scanned folder. The only writes are an export the person asked for (a new
  file, never an overwrite) and the app's own state, both owner-only.
- **No secret value in any output,** nor a fragment or unkeyed hash of one:
  reports, events, logs, error text. A `Hit` holds a position, never the
  value. A `subject` (profile, host, variable name) is
  shown on the Mac but not written to the JSON report; `token_type` is from
  the scanner's fixed list, so it may be.
- **File names are hostile.** Show one only through `report::escape`. The
  window names a finding by index or id, never by path, and the engine hands
  back a path to act on only when `full_path` accepts it. Reading a listed
  file again is not acting on it: `recheck_path` takes any name that could
  be listed as it is.
- **Say what was not checked.** A file in scope that could not be read is a
  `not_checked` gap, never silence. Exit codes describe the run, not the
  findings. No scores, no "clean".
- **Finding text says what the matcher established,** no more: a matched
  format is not a validated credential. Remediation tells preventing future
  sign-ins apart from ending an existing credential or session.
- **A decision is a label, never a filter.** Setting an item aside or
  skipping a folder changes what asks for attention, never what is found. The
  CLI never reads the app's state, and nothing inside a scanned folder can
  silence a finding: whoever can write there could hide a credential.
- **Every read and loop over scanned data has a limit** (4 KiB heads, 1 MiB
  configs, entry and depth budgets), so one endless or huge file cannot stall
  the scan. A traversal limit that is reached is reported as a `scan-limit`
  gap.
- **Three dependencies, by choice:** `libc`, `serde`, `serde_json`. Each added
  crate is more code running next to a person's credentials. Ask before
  adding one, or anything needing a paid service or a signing identity.
  Test-only `jsonschema` and `zip`, with their transitive dependencies, were
  approved on 2026-10-13, and `zip` 9, which adds `nix` and `typed-path`, on
  2026-10-21. They belong only in dev-dependencies; schema
  HTTP/file resolution and unnecessary ZIP codecs stay disabled.
  Optional signing of local builds with an Apple Development identity
  (`LOOSE_KEYS_SIGN_IDENTITY` in `gui/build-macos.sh`) was approved on
  2026-10-15. The ad-hoc default must keep working without one.
- **macOS only:** the code has no branch for
  another system, and nothing is built, checked or claimed for
  one. The engine still has no window, dialog or clipboard code.
- **Standard macOS controls only** in the window, with system fonts, colours
  and symbols.

## How to work

- **Work in a worktree.** Make every change, code or prose, in a git
  worktree under `.claude/worktrees/`, never in the main checkout. Reading
  and investigating in the main checkout is fine.
- **Judge by exit status and report what you checked.** A command passed if
  it exited 0, not if the end of its output looks right. In reports and
  commits write "Checked:" for what you ran and "Not verified:" for what you
  did not, such as the running app. Do not call verified what you
  only read, and label an API or macOS behaviour you could not confirm
  "unverified", as the docs do.
- **Do not make a check pass by weakening it:** no deleted or ignored test,
  loosened assertion or longer timeout. A lint that is wrong for this code
  is allowed on the smallest item, with the reason in a comment; one that
  found a real problem is fixed. If a test is wrong, say why in the commit
  that changes it. If it fails only sometimes, report what
  you saw.
- **For a bug, write the test first and watch it fail** with the bug present.
- **Stay inside the task.** No refactor, rename, reformat or new abstraction
  on the way, and no `dbg!`, stray print, commented-out code or scratch file
  left behind: the diff shows the change and nothing else.
- **Review boundary changes.** When changing inputs, outputs, file access,
  limits, processes, dependencies or privileges, document the mitigation and
  its verification in the development or testing guide, with remaining risks
  and unverified behavior. `README.md` and `docs/usage.md` carry a limit only
  when it changes what a person does or relies on. Do not remove a limitation
  without evidence.
- **Commits:** one change each, with its docs (`README.md`, `docs/`, the
  usage text in `src/main.rs`). Subject in plain words, body says why, then
  the Checked and Not verified paragraphs. `git log` shows the form.
- **Ask first** before changing a report field, flag or exit code (contracts,
  kept in `schema/report-1.schema.json` and the usage text in `src/main.rs`),
  CI, lint settings, `edition` (2021) or `rust-version` (1.88), or removing
  a test.

## Rust

- **Errors.** An expected failure is a value: a `Result`, or a gap in the
  report. A panic is for a broken invariant. Never unwrap or print an error
  that embeds bytes from a scanned file, such as `FromUtf8Error`.
- **Unsafe** is only for system calls and the C interface. A block you add or
  change gets a `// SAFETY:` comment saying why the call's requirements hold
  (older blocks lack one). Wrap a new file descriptor in `File` at once, so
  it is closed exactly once.
- **The C interface** stays at five functions: add a command to `dispatch` in
  `gui/src/lib.rs`, not a function. Only `ch_free` releases what `ch_call`
  returned. A panic in a command is caught in `call`; in any other
  `extern "C"` function it ends the process, so keep those small.
- **Locks.** In new code, copy what you need out of a `Mutex` and drop the
  guard before calling the scanner, the store, the event handler, `Monitor`
  or a `ch_*` function. Where two locks are held, take `review` before
  `storage_error` or `report` in the app, and `inbox` before `known` in the
  agent; take `Monitor`'s with no other held.
- **Files.** Open and read scanned files only through `src/fsutil.rs`, which
  opens without following links and bounds every read. The one deliberate
  resolution exception is `through_links`: a known sign-in location may
  resolve to a path inside the home folder, never as root. That resolved
  path is then opened without following links. Do not add another exception.
  For a presence check use `symlink_metadata`, never `Path::exists` or
  `fs::metadata`, which follow links.
- **Tests.** Synthetic data only, in a folder under `TMPDIR` named for the
  process and the test. Give a child its `HOME` with `Command::env`, never
  `std::env::set_var`. Wait for another thread with a deadline that fails
  with a message. A test that scans through the app's side holds
  `one_scan()` for the whole scan. A new way for text to leave the tool gets
  a leak check: plant a value and search every output for it and its
  pieces. A new rule needs matching and non-matching `samples`, and
  a case in `tests/detection-corpus.json`.

## The window (Swift)

- View state lives in `AppModel` as `@Published`, not in `@State`: the app
  must build with Apple's command-line tools alone, where `@State` does not
  compile.
- A page that draws is not a page that works. `gui/tests/check-window.sh` chooses
  rows and presses headings and buttons the way assistive software does; add
  a line to `Checks` in `gui/app/Preview.swift` for a control you add. It
  cannot type or point, so a change to either still needs a person, or a
  session that can use the screen, to click through the built bundle.
- Engine calls answer in any order. Review and monitor reads go through
  `ReadTurns` in `AppModel`, which coalesces requests and allows one read of
  each list at a time. Folder responses use `RequestOrder`. Keep failures
  under the same ordering rules as successful responses. A failed request
  must not replace a usable list with an empty one.
- Never say "nothing found" for a list that could not be read, saved or
  filled. A count beside a heading comes from what the scan found when the
  list cannot be used.
