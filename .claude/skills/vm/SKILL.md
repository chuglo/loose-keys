---
name: vm
description: Build a commit of Loose Keys on this Mac and open it in a new macOS VM whose home holds synthetic decoys, ready for the person to press Scan Now. Use when the person asks to open, try or test a build in a VM. Takes an optional git ref; the default is the local main.
argument-hint: "[branch, tag or commit; default main]"
---

Open a build in a new VM. Ref asked for: "$ARGUMENTS" (none means `main`).

1. If the ref is `main` and it differs from `origin/main`, say in one line
   which commit is being built. Uncommitted changes are never in the build.
2. Say that a VM window will open, then run this from the repository root,
   in the background and with the sandbox disabled (tart needs it). It takes
   a few minutes:

   ```sh
   mkdir -p /private/tmp/loose-keys-scratch
   TMPDIR=/private/tmp/loose-keys-scratch sh .claude/skills/vm/open-in-vm.sh <ref>
   ```

3. Report the summary it prints: the VM, the commit and how it was signed.
   The person presses Scan Now. Do not drive the app or scan for them.
4. If it fails, report the step and the log it names. Every build gets a new
   clone: never fall back to a VM from an earlier run.

What the script does: it builds from a `git archive` export of the commit in
`$TMPDIR`, runs the bundle contract test, makes a decoy home with
`security-tests/harness.sh generate-home` (leaving out its fake login keychain
and Notes store, which would replace the guest's own), clones
`macos-tahoe-base`, checks both copies by SHA-256, installs the app in the
guest's `/Applications`, checks its signature and that the guest has no app
state yet, then opens it. It signs with the Apple Development identity when
this Mac has one; `LOOSE_KEYS_SIGN_IDENTITY=-` asks for ad hoc.

The app runs only in the guest. Never open it on this Mac. These clones boot
with SIP off, so the helper there does not behave as on a real Mac. Stopping
and deleting VMs (`tart stop`, `tart delete`) are the person's call; old
`lk-*` VMs stay until they remove them.
