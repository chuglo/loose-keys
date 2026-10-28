---
name: vm
description: Build a commit of Loose Keys on this Mac and open it in a new macOS VM whose home holds synthetic decoys, ready for the person to press Scan Now. Use when the person asks to open, try or test a build in a VM. Takes an optional git ref; the default is the local main.
---

Open a build in a new VM. Use the branch, tag or commit requested in the
conversation; when none is specified, use local `main`.

1. If the ref is `main` and it differs from `origin/main`, say in one line
   which commit is being built. Uncommitted changes are never in the build.
2. Say that a VM window will open, then run this from the repository root,
   in the background. The environment needs permission to build locally and
   run Tart virtualization; use its supported execution mechanism. It takes
   a few minutes:

   ```sh
   mkdir -p /private/tmp/loose-keys-scratch
   TMPDIR=/private/tmp/loose-keys-scratch sh .agents/skills/vm/open-in-vm.sh <ref>
   ```

   To open it as a Mac whose organization manages the app, add
   `LOOSE_KEYS_PROFILE=<file.mobileconfig>`: the profile is installed
   through System Settings before the app's first start, and the step fails
   unless macOS reports each of its `dev.loosekeys.desktop` keys as managed.
   `managed-settings.mobileconfig` beside this file is an example to copy.
   `LOOSE_KEYS_EXTRA_HOME=<folder>` adds that folder's files to the decoy
   home, such as a synthetic file at a path the profile names.

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
