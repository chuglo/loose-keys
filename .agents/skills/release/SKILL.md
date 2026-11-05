---
name: release
description: Build, check, and publish a Loose Keys release. Use when asked to prepare a release, check whether one is ready, or tag and publish it. An explicit request to publish or cut a release authorizes publication; preparation or review alone does not.
---

Read `AGENTS.md`, `tests/AGENTS.md`, and `docs/testing/local-verification.md`.
Run scripts from a worktree root with `TMPDIR=/private/tmp/loose-keys-scratch`;
create that directory first. Tests run from a terminal, without an
interactive desktop agent or VNC.

## Build

1. Read the commits since the last release tag, including their Not verified
   paragraphs. Check existing worktrees and reuse an unfinished version bump
   if it matches the release.
2. Use a minor version for features or contract changes (`schema/`, CLI flags
   or exit codes, `gui/app/Bridge.h`), a patch for fixes only. Releases are 0.x.
   In a clean worktree, run `sh .agents/skills/release/bump.sh 0.y.z`.
   It changes five version files. Stage those files by name.
3. Commit the bump, keeping the configured commit signing. Announce the
   sample-data window check, then run `sh .agents/skills/release/prepare.sh`
   with Tart on `PATH`. It runs `tests/check-all.sh` on the exact commit,
   then `candidate.sh` from it, prints every exit status and the candidate,
   and stops at a failed check or a changed tree. They do not run side by
   side: the release build's load made a timed check fail. Record the
   commit, each exit status, and any failed runs. `check-all.sh` skips the
   window check when its files match `origin/main`.
4. `candidate.sh` builds an ad-hoc bundle and harness from the commit, checks
   the bundle and versions, mounts the disk image read-only at a folder of
   its own, checks its signature and Applications shortcut, and compares its
   app with the unzipped ZIP. Keep the candidate directory: the guest checks
   use this ZIP, and publication uses both tested packages. A new build needs
   new checks.

## Guest checks

Run these only when requested. Check `tart list` first, then run them one at
a time: macOS allows two running VMs. Leave other people's VMs alone.

```sh
sh .agents/skills/release/bundle-check.sh "<candidate directory>"
sh .agents/skills/release/helper-check.sh "<candidate directory>"
```

The helper check needs a stopped, pristine `lk-sip-base` with SIP and
Gatekeeper on. Setup and permission rules are in `docs/testing/guest.md`.

The scripts reject changed candidate files, check transfers and stop their
clones. Logs and helper `results.json` files stay in the candidate directory.
Report each helper case and exit status. A negative control must fail at its
intended assertion. Failed cleanup leaves the helper's state unknown: stop
that guest and use a fresh clone. Keep failed logs. Delete test VMs when
requested, preserving the reusable bases.

## Optional walkthrough

When requested, announce the Tart window and run
`sh .agents/skills/release/walkthrough.sh "<candidate directory>"`.
It opens the tested ZIP in a fresh guest with decoys. Setup excludes protected
folders, the login keychain and Notes; clipboard and audio sharing are off.

Check results and inspectors, Settings, the menu bar, closing and reopening,
login after a reboot, and Spanish (`es` and `es-419`). Record what was checked.
Sync and stop the guest afterward. List an omitted walkthrough as Not verified.

## Publish

Report the commit, ZIP and DMG SHA-256, exit statuses, logs and remaining checks
in the session's release report. Include untested items from the commit history,
appearance, login, updating from the prior release, a physical Mac and
notarization. Keep verification details in that report and commit messages.

Public release notes are concise: user-visible changes in the window's words,
installation instructions, and download checksums. Include limitations only
when they affect what a person must do or can rely on, such as the beta's
notarization notice or a known bug. Omit internal test inventories, VM details,
process history and lists of unverified scenarios.

An explicit request to publish or cut this release authorizes its merge,
push, tag and publication. Do not ask again solely because optional checks
were omitted: report them under "Not verified". Preparation or review alone
requires publication approval after the candidate and release notes are ready.
A failed or blocked required check still prevents release; run guest checks
only when requested.

Releases are published immutable. Once published, the release's tag and
packages cannot be changed or deleted, and the tag name cannot be reused even
after the release is deleted, so a wrong package needs a new patch version.
A changed release commit needs new checks and a new candidate.

Write the notes to a file, with both packages' checksums as
`Loose-Keys-0.y.z.zip: <SHA-256>` lines, then run:

```sh
sh .agents/skills/release/publish.sh "<candidate directory>" "<notes file>"
```

In this order, stopping at the first failure, it rechecks the candidate's
`SHA256SUMS` and the notes' checksums; requires immutable releases (if they
are off, stop and ask the person directing the session, and leave repository
settings to them); requires that the tested commit fast-forwards main and
that no `v0.y.z` tag names another commit; pushes main; creates and pushes
the signed tag; publishes both tested packages; checks that the release is
immutable, that its attestation covers both packages, and that GitHub
verifies the commit and tag signatures; and downloads both packages to
compare them with the tested copies. A step already done for the same commit
is checked and skipped, so a stopped run can be repeated. `gh release create`
publishes only after every upload succeeds; a failed upload deletes its
draft.

It pushes from the worktree, so the main checkout's `main` stays behind until
`git pull --ff-only` runs there.

## Checking these scripts

Run `python3 -I .agents/skills/release/check-scripts.py` for the offline
regressions and `sh -n` on each shell script. Check that this skill has valid
`name` and `description` frontmatter and that its referenced files exist.
The regressions start no VM and reach no remote: `publish.sh` runs against
stand-ins for `git` and `gh`. Candidate, guest and publish runs check the real
tools.
