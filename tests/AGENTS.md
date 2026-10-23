# Working with tests

The [root instructions](../AGENTS.md) apply here too, and this file does not
repeat them. [Local checks](../docs/testing/local-verification.md) has the
commands; the [root matrix](../AGENTS.md#commands) says which a change needs.

## Running

- Keep `--locked` on Cargo commands that build.
- A focused test helps while developing but replaces no check. Cargo exits 0
  when a filter selects no test, so confirm it ran.
- Do not force single-threaded tests to hide a race.
- Keep the real `HOME` for build tools; scanner children get their synthetic
  `HOME` from the fixtures. Do not relax the scanner's link checks to suit
  `/tmp` or `/var`.
- Cargo tests do not cover the running app or the native helper.

## Fixtures and assertions

Read [Tests](../docs/development/standards.md#tests) before changing tests.

- `scan_scope.rs` tests the built CLI's output, exit status and file effects.
  `detection_corpus.rs` runs the shared detection cases through the CLI;
  `support/` holds fixtures shared with engine tests through `#[path]`.
- Remove fixtures at the end or in `Drop`. Pass homes explicitly to
  in-process APIs.
- Derive a corpus case's expected findings from intended behaviour; never
  regenerate them from scanner output.
- Test a matcher limit at the cap and one past it, asserting the retained
  findings and the `scan-limit` gap.
- Build SQLite fixtures with the system `sqlite3`, not hand-edited pages.
