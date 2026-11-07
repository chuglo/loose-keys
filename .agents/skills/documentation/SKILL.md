---
name: documentation
description: Audit Loose Keys' documentation (README.md, docs/, the AGENTS.md files, skill files) for drift from the code and for slop, and fix what the person picks. Finds broken links and anchors; paths, flags and code names that no longer exist; versions, limits, commands and window labels that disagree with the code; and prose that breaks the docs' rules, such as filler, repeats, run records, history and internals nobody acts on. Use when asked to check, audit, review, tidy, trim, clean up or fact-check the docs or their code references, or whether the docs are up to date; before any push and before committing a docs change; and after a change that renames or removes files, flags, settings or window labels the docs mention.
---

Read `AGENTS.md` first. The audit only reads, so it may run in the main
checkout. Change nothing until the person has seen the findings and said
which to fix.

The docs are every tracked Markdown file: `README.md`, `docs/`, the
`AGENTS.md` files (each nested one is relative to its own folder) and the
`SKILL.md` files under `.agents/skills/`. Audit the pages the person named,
or all of them. Window text in `gui/app/` and finding text in `src/rules/`
are not docs; AGENTS.md has their rules.

## 1. Start from the change

When the request is about a change (a diff, a branch, a push, "I
renamed…"), list the old names and values from `git diff` or `git log -p`
and `git grep` the docs for each. This finds more than the scripts do.
Before a push, the change is what the remote lacks, such as
`git log -p origin/main..HEAD`.

## 2. Run the checks

From the repository or worktree root, with the pages to audit or none for
all of them:

```sh
python3 -I .agents/skills/documentation/check_refs.py [page.md ...]
python3 -I .agents/skills/documentation/check_prose.py [page.md ...]
```

Each prints `path:line: kind: detail` and exits 0 when it found nothing, 1
when it found something and 2 when it could not run. The docstring at the
top of each script lists its kinds. A finding is a line to read, not a
verdict: confirm each before reporting it.

`check_refs.py` finds links, anchors, repository paths, options and code
names that no longer hold. A missing file says whether its deletion is not
yet committed, or names the commit that last had it; a missing name names
the commit that removed it. Read that commit to see where the thing went.
It skips a name the code never had, such as a standard library item, a lint
or an Apple constant, so it misses a typo too.

`check_prose.py` finds filler words, "the owner", emoji, dated run results,
phrases about past drafts and worktrees, a page named like a spec or plan,
and passages of ten or more words said twice. It compares the named pages
against every page, but only word for word and outside code blocks. For a
repeat in other words, `git grep` the page's distinctive terms (script
names, variables, unusual words) across `*.md`.

## 3. Facts

Read each statement of fact against its source. When the change is known,
check the facts it touches; on a full audit, check the rows below on every
page and read the named pages in full. A passage you will recommend cutting
needs no claim-by-claim check.

| The docs say | Source |
|---|---|
| The app version, and versions in example commands and file names | `version` in `Cargo.toml` |
| The minimum Rust | `rust-version` in both `Cargo.toml` files |
| The minimum macOS | `LSMinimumSystemVersion` in `gui/macos/Info.plist`, `MACOSX_DEPLOYMENT_TARGET` in `.cargo/config.toml` |
| Command options, defaults and exit codes | the usage text in `src/main.rs` |
| Report fields | `schema/report-1.schema.json` |
| The dependencies | `[dependencies]` in both `Cargo.toml` files |
| The C functions and engine commands | `gui/app/Bridge.h`, `dispatch` in `gui/src/lib.rs` |
| Read sizes, entry and depth budgets, timers | the constants in `src/fsutil.rs`, `src/scan.rs`, `src/scan/` and `gui/src/` |
| Rules and supported formats | `src/rules/`, `tests/detection-corpus.json` |
| App labels in bold, such as **Scan Now** | the `Button`, `Text` or menu item label in `gui/app/` |
| Which checks exist and what a run includes | `tests/check-all.sh` and the scripts it names |
| What a check tests | the check's script or test |
| A skill's steps | the scripts beside its `SKILL.md` |

Find the source with `git grep`. When two sources disagree, report the
split rather than picking one. A label macOS shows, such as **Open
Anyway**, is Apple's, not the app's. Never run the app, the helper or the
scanner on a real home folder to confirm a fact; read the code.

## 4. Prose

The docs keep only what a reader acts on, what could be misread, and what a
check or scan does not cover. Beyond what `check_prose.py` reports, flag:

- Lines nobody acts on: internal mechanism, timings, how a test works
  inside, what-if steps the documented setup never hits.
- A caveat, limit, rule or step already stated on another page, especially
  in AGENTS.md or a skill. Keep it on the page that owns it (below) and
  link there. Before calling a repeat a mistake, check with `git log -S`
  whether a commit put it there on purpose, and say so in the finding.
- Run records and history: a dated result of a build, candidate or run,
  what a past draft, worktree or tool did. Recommend deleting them,
  never moving them to a page of their own. A dated note that confirms a
  macOS behaviour is evidence for a limit, not a run record; keep it unless
  another page already holds it.
- A note about an earlier version of the app that a person updating from it
  no longer needs.
- Notes about systems or deployments the project does not support. It is
  macOS only.
- A claim of verification the page does not back, or an unconfirmed Apple
  behaviour not labelled "unverified".
- Marketing tone, and headings or bullets that plain sentences would carry.

Keep each "does not cover" or "Not verified" statement unless it is stale. A
limit documented nowhere else moves to the right page; it is never just
deleted. Docs may name the home folder when describing what the app does
today; the rule against it is for window text.

A fact belongs on one page:

- `README.md`: installing, building and the command line, for a person
  using the app.
- `docs/usage.md`: the app's controls, and the numbers, limits, timing and
  caveats the window leaves out.
- `AGENTS.md` files: short rules for agents. A nested one does not repeat
  the root.
- `docs/development/standards.md`: the reasons, examples and sources behind
  each AGENTS.md rule.
- `docs/testing/`: how to run each check, what it needs and what it does
  not cover.
- A skill's `SKILL.md`: its steps. A docs page keeps only what the skill
  sends readers there for.
- `docs/README.md`: a row for every page under `docs/`, each of which opens
  with a link back to it.

## 5. Report

Give the findings in the terminal, each with its `path:line`, a few quoted
words, why it is wrong, the evidence (`file:line` in the code, or the
commit), and a proposed fix. Use these headings, leaving out empty ones:

```
Wrong or stale
- docs/<page>.md:97 - "Loose-Keys-0.4.0.dmg": the version is 0.9.0 (Cargo.toml:3). Fix: write <version>.
Broken references
Cuts and rewrites
- docs/<page>.md:63-69 - "Both were preserved from": history of a past worktree. Fix: cut the paragraph.
Could not confirm
Outside the docs
```

Put the most misleading first, and order cuts by how much they remove.
"Could not confirm" holds claims you could not check against a source.
"Outside the docs" holds what the docs fix depends on: code, comments or
sources that disagree with each other, or a change the code only half made.
Present each cut as a recommendation, and say when a page had nothing to
report.

End with one line each for Checked (the scripts and their exit status, and
the pages and sources you read) and Not verified (what you did not read).

## Fixing

Only after the person picks the findings to fix:

1. Work in a worktree, as AGENTS.md says. Make the agreed changes and no
   others.
2. Run both scripts on the edited pages and reread the changed text. A
   Markdown-only change needs no build or test. A change to code, such as
   the usage text in `src/main.rs` or a script's comment, follows the
   AGENTS.md matrix.
3. Show the diff. Commit on the branch in the form `git log main` shows,
   keeping the configured commit signing. Push or merge only when asked.

## Checking this skill

```sh
mkdir -p /private/tmp/loose-keys-scratch
export TMPDIR="$(cd /private/tmp/loose-keys-scratch && pwd -P)"
python3 -I .agents/skills/documentation/check_refs_test.py
python3 -I .agents/skills/documentation/check_prose_test.py
```

Each builds a small repository with one planted finding of each kind and
checks that exactly those are reported. `mdpages.py` holds the Markdown
reading both scripts share.
