---
name: release
description: Build, check, and publish a Loose Keys release. Use when asked to prepare a release, check whether one is ready, or tag and publish it. Publishing requires explicit approval.
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
   window first. Record the commit, each exit status, and any failed runs.
   Check that the tree stayed clean. Keep the configured commit signing.
4. Run `sh .agents/skills/release/candidate.sh <commit>`. It builds an ad-hoc
   bundle and harness from that commit, checks the bundle and versions, and
   prints the candidate directory and ZIP checksum. Keep the directory:
   the guest checks and upload must use this ZIP. A new build needs new checks.

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

Report the commit, ZIP SHA-256, exit statuses, logs and remaining checks.
Include untested items from the commit history, appearance, login, updating
from the prior release, a physical Mac and notarization. Draft release notes
in the window's words, with installation instructions.

Get approval to merge, push, tag and publish this release, including acceptance
of what remains unverified. Fetch the remote and check that the tested commit
can fast-forward main. A changed release commit needs new checks and a new
candidate. Recheck the candidate's `SHA256SUMS` against its files.

Merge the tested commit, push main, create and push its signed `v0.y.z` tag,
then publish the tested ZIP:

```sh
gh release create v0.y.z "<candidate directory>/share/Loose-Keys-0.y.z.zip" \
  --verify-tag --title "Loose Keys 0.y.z (beta)" --notes-file "<notes file>"
```

Verify the remote commit and tag signatures. Download the published ZIP into
a fresh directory and compare its SHA-256 with the tested copy.

## Checking these scripts

Run `python3 -I .agents/skills/release/check-scripts.py` for the offline
regressions and `sh -n` on each shell script. Check that this skill has valid
`name` and `description` frontmatter and that its referenced files exist.
The regressions start no VM; candidate and guest runs check the real tools.
