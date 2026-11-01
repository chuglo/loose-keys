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
3. Commit after the required checks. Before a push or tag, run
   `sh tests/check-all.sh` on the exact commit. Announce the sample-data
   window check first; the script skips it when its files match
   `origin/main`. Record the commit, each exit status, and any failed runs.
   Check that the tree stayed clean. Keep the configured commit signing.
4. Run `sh .agents/skills/release/candidate.sh <commit>`. It builds an ad-hoc
   bundle and harness from that commit, checks the bundle and versions, and
   prints the candidate directory and ZIP and DMG checksums. Both packages
   contain the same app. Keep the directory: the guest checks use this ZIP,
   and publication uses both tested packages. Run the disk image checks in
   `docs/testing/local-verification.md`: mount read-only, verify the signature
   and Applications shortcut, and compare its app with the unzipped ZIP.
   A new build needs new checks.

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

Fetch the remote and check that the tested commit can fast-forward main or
is already on main. A changed release commit needs new checks and a new
candidate. Recheck the candidate's `SHA256SUMS` against its files.

Releases are published immutable.
`gh api 'repos/{owner}/{repo}/immutable-releases' --jq .enabled` must print
`true`; otherwise stop and ask the person directing the session, and leave
repository settings to them. Once published, the release's tag and packages
cannot be changed or deleted, and the tag name cannot be reused even after
the release is deleted, so a wrong package needs a new patch version.

Merge the tested commit, push main, create and push its signed `v0.y.z` tag,
then publish both tested packages:

```sh
gh release create v0.y.z "<candidate directory>/share/Loose-Keys-0.y.z.zip" \
  "<candidate directory>/share/Loose-Keys-0.y.z.dmg" \
  --verify-tag --title "Loose Keys 0.y.z (beta)" --notes-file "<notes file>"
```

With packages, `gh release create` uploads them to a draft and publishes only
after every upload succeeds; a failed upload deletes that draft. If it fails,
check `gh release view v0.y.z` before retrying: a draft is not locked yet.

Verify the remote commit and tag signatures. Check that the release is
immutable and that its attestation covers both tested packages. The first
command must print `true`, and each must exit 0:

```sh
gh release view v0.y.z --json isImmutable --jq .isImmutable
gh release verify v0.y.z
gh release verify-asset v0.y.z "<candidate directory>/share/Loose-Keys-0.y.z.zip"
gh release verify-asset v0.y.z "<candidate directory>/share/Loose-Keys-0.y.z.dmg"
```

Download both published packages into a fresh directory and compare their
SHA-256 values with the tested copies.

## Checking these scripts

Run `python3 -I .agents/skills/release/check-scripts.py` for the offline
regressions and `sh -n` on each shell script. Check that this skill has valid
`name` and `description` frontmatter and that its referenced files exist.
The regressions start no VM; candidate and guest runs check the real tools.
