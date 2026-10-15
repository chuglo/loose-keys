# Working with tests

The [root instructions](../AGENTS.md) apply here too. Read this file before
running tests anywhere in the repository, not only when editing `tests/`.
[Local checks](../docs/testing/local-verification.md) is the command reference;
the [root verification matrix](../AGENTS.md#commands) determines which checks
the change requires. Follow those instructions rather than inventing a
different test sequence.

## Run checks consistently

Run from the repository root on macOS, as an ordinary user, with Rust 1.88
or later. First set up scratch space in the same shell as the checks:

```sh
mkdir -p /private/tmp/credhyg-scratch
export TMPDIR="$(cd /private/tmp/credhyg-scratch && pwd -P)"
```

Every component of `TMPDIR` must be free of symbolic links. Do not use `/tmp`
or the default macOS path under `/var`, or relax the scanner's link checks
to accommodate them. Preserve the real `HOME` for build tools; scanner
children receive their synthetic `HOME` through the fixtures.

For code, tests, build scripts, dependencies or configuration, run these
checks in order, one command at a time, and record each exit status:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Keep `--locked` on Cargo commands that build. A focused test is useful while
developing, but does not replace the workspace checks or the additional
checks below. Confirm a test filter actually selected the intended test:
Cargo can exit 0 when it ran no tests. Do not force single-threaded tests to
hide a race; fixtures must work with the normal parallel test runner.

For any change under `src/`, also run the security harness commands, in this
order:

```sh
sh security-tests/harness.sh --self-tests
sh security-tests/harness.sh selftest --work "$TMPDIR/credhyg-selftest"
security-tests/check_scanner.sh "$TMPDIR/credhyg-gate"
sh security-tests/harness.sh platform --binary target/release/loose-keys --work "$TMPDIR/credhyg-platform"
sh security-tests/harness.sh helper-self-tests
```

For rules, scan/report code, the engine's scan/export commands or the
detection corpus, also run:

```sh
sh security-tests/check_detection.sh
```

Use that script for CLI/engine detection parity: it builds the release CLI,
passes its path to the engine test and requires the test's completion marker.
The Cargo workspace run alone does not replace it.

For app, C interface, helper runner, Settings driver or notification bridge
changes, use the additional checks in the root matrix and local command
reference. A bundle build does not start the app or verify its behaviour.
The real app, `SNAPSHOTS` build and installed helper run only in the
[disposable macOS guest](../docs/testing/guest.md), with synthetic data.
The host-safe sample-data window check needs an awake screen; announce that
a window will appear before running it. Its status 2 is blocked, not passed.

For prose-only changes (Markdown files and images under `docs/`), review the
text and check referenced local paths and commands; no other check is
required, including before a push to `main`. Before any other push to `main`,
follow the full list in the local command reference on the exact commit,
including the Rust 1.88 build and dependency audit. There is no CI to wait
for.

## Keep fixtures safe and assertions meaningful

Read [Tests](../docs/development/standards.md#tests) before changing tests.

- `scan_scope.rs` tests the built CLI's output, exit status and file effects.
  `detection_corpus.rs` runs the shared detection cases through the CLI;
  `support/` supplies fixtures shared with engine tests through `#[path]`.
- Use synthetic data only. Create fixtures under `TMPDIR` with names unique
  to the process and test, and remove them at the end or in `Drop`. Never run
  the scanner against a real home, including for debugging.
- Give a child its synthetic `HOME` with `Command::env`; pass homes explicitly
  to in-process APIs. Never use `std::env::set_var` in tests. Engine scanning
  tests hold `one_scan()` for the whole scan because events are process-wide.
- Never put a complete token-shaped string in fixtures, source or output.
  Assemble it from pieces or generate it at runtime. A new output channel
  needs a leak check for both the planted value and its pieces.
- For a bug, write the regression test first and observe it fail with the
  bug present. Do not delete or ignore tests, loosen assertions, increase
  timeouts or rerun until green to claim success. Report intermittent failures.
- A new rule needs matching and non-matching `samples` and a case in
  `detection-corpus.json`. Derive expected findings from intended behaviour,
  never regenerate expectations from scanner output to make a test pass.
- Test matcher limits at the cap and one past it; assert retained findings
  and the `scan-limit` gap. Build SQLite fixtures using the system `sqlite3`,
  not hand-edited database pages. Wait for conditions with a deadline that
  fails naming what did not happen.

## Report what ran

Use `Checked:` for commands actually run and their exit statuses, and
`Not verified:` for omitted or blocked checks and their reasons. A command
passes only when it exits 0; reading code or seeing a success-looking last
line is not a test result. Preserve failures even if a later run passes.
List guest checks as not verified when neither requested nor required by
the change; do not imply Cargo tests cover the running app or native helper.
