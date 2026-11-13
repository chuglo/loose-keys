---
name: dogfood
description: Use the Loose Keys app the way a person would, on synthetic home folders in disposable macOS guests, and compare what the window lists with what was planted. Use when asked to dogfood the app, to measure noise, misses or triage effort, or to see whether a rule, scope or window change made the lists better or worse.
---

Read `AGENTS.md` and the [vm skill](../vm/SKILL.md) first. The app runs only
in a guest. The homes, manifests and results stay under `$TMPDIR`: they hold
token-shaped values, made at run time, and never go into the repository or a
message. Refer to a finding by its rule and its path.

Run everything from the repository or worktree root, with `TMPDIR` set as
`AGENTS.md` says.

## 1. Build a home

```sh
sh security-tests/harness.sh generate-home "$TMPDIR/dogfood/decoys"
python3 .agents/skills/dogfood/make_home.py backend "$TMPDIR/dogfood/backend" "$TMPDIR/dogfood/decoys/manifest.json"
```

The homes are `backend`, `javascript`, `ai`, `careful` and `web3`
(developers), and `crypto_user`, `executive` and `freelancer` (people the Mac
infostealers of 2025 and 2026 robbed). Each is in `homes/`, with what it
plants and where a person would expect it: Worth Reviewing, Stored Sign-ins,
not shown, or debatable. `manifest.json` beside the home lists that, and the
decoys every guest also gets. It is written before the app sees the home;
change an expectation in `homes/`, never to match a result.

## 2. Open it in a guest

Use the vm skill with `LOOSE_KEYS_EXTRA_HOME="$TMPDIR/dogfood/backend/home"`.
For `crypto_user`, `executive` and `freelancer`, also set
`LOOSE_KEYS_BASE=ghcr.io/cirruslabs/macos-tahoe-base:latest`: their files
are in Desktop, Documents and Downloads, which a clone of `lk-sip-base`
refuses to have written. That guest has SIP off, so macOS asks for no folders
there.

## 3. First scan

```sh
sh .agents/skills/dogfood/first-scan.sh <VM> "$TMPDIR/vm-<name>/share" "$TMPDIR/dogfood/backend"
```

`<name>` is the VM's name without `lk-`. The script builds `drive.swift`,
presses Scan Now, answers macOS's folder requests for Loose Keys with Allow,
and saves into the home's folder the Overview's text
(`first-overview.txt`), every row of both lists with its inspector, and
`first-compare.txt`: misses, noise, wrong placement, duplicates and rows the
manifest does not list. For a home that is not a messy developer's it first
removes the decoys. If the scan does not finish, look for a macOS request
with `drive prompts` and answer it as a person would.

Before calling a difference a bug, read the rule or window code behind it and
`docs/usage.md`: it may be a documented limit or a choice.

## 4. Triage and daily use

`drive` is in the guest's share under the name in `drive-name.txt`. Run it
with `tart exec <VM> "/Volumes/My Shared Files/share/<name>" <command>`; with
no command it lists them. Count each filter, selection, menu and reason as
one action.

For daily use, turn on Scan Automatically (`toggle "Scan Automatically"`),
press Set Up Notifications… and answer macOS (`prompts Allow`), close the
window (`menu Close`), then:

```sh
sh .agents/skills/dogfood/workdays.sh <VM> "$TMPDIR/vm-<name>/share" [<step> ...]
```

It does one step of `workday.py` at a time in the guest and prints what was
listed and whether an alert was sent. `python3 workday.py list` says what
each step is and whether an alert for it is worth the interruption.

## 5. After a change

Put the build into the same guest with the vm skill's `--into`, then run
`first-scan.sh` again with a fourth argument, such as `fixed`, to name the
new results. An item an earlier build listed stays until its file no longer
matches, so judge a scope change on a new guest or by the rows that are new.

Stop and delete each guest you opened when you have its results.

## Checks for these scripts

```sh
sh -n .agents/skills/dogfood/first-scan.sh && sh -n .agents/skills/dogfood/workdays.sh
python3 -m py_compile .agents/skills/dogfood/*.py .agents/skills/dogfood/homes/*.py
swiftc -typecheck .agents/skills/dogfood/drive.swift
```

Not covered: appearance, which the driver cannot see, and typing or pointing.
