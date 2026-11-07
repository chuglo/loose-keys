---
name: vm
description: Build Loose Keys on this Mac and open it in a new macOS VM whose home holds synthetic decoys, ready for the person to press Scan Now, or put a new build into a VM it opened earlier. Use when the person asks to open, try or test a build in a VM. Takes an optional git ref, two refs, or `.` for this checkout's uncommitted changes; the default is the local main.
---

Open a build in a new VM. Use what the conversation asks for; when nothing is
specified, use local `main`.

- A branch, tag or commit: pass it.
- Two unmerged branches together: pass both refs. The script combines them
  without a commit.
- Uncommitted changes in a worktree: pass `.` from that worktree's root.
  A change the person hasn't approved yet is built this way, also with
  `--into`, and committed only after they approve it.
- Never make a commit, merge or branch only so that a build has something:
  no work-in-progress or unsigned commit either.

1. If the ref is `main` and it differs from `origin/main`, say in one line
   which commit is being built.
2. Say that a VM window will open, then run this from the repository (or
   worktree) root, in the background. The environment needs permission to
   build locally and run Tart virtualization; use its supported execution
   mechanism. It takes a few minutes:

   ```sh
   mkdir -p /private/tmp/loose-keys-scratch
   TMPDIR=/private/tmp/loose-keys-scratch sh .agents/skills/vm/open-in-vm.sh <ref> [<second ref>]
   ```

   This Mac runs at most two VMs. With two running, the script stops at
   once and names them: ask the person which to stop, rather than stopping
   one yourself. A `lk-window-*` VM is a window check that ends on its own
   within minutes, so offering to wait for it is reasonable.

   Only when the person asks for the build in a VM that is already open,
   add `--into <VM>` before the ref or `.`: it replaces the app in that VM,
   keeps the app's saved state and the decoys, and restarts the helper if it
   was loaded. It works only for a running VM this script opened with the same
   `TMPDIR`. Never choose it yourself instead of a new VM.

   To open it as a Mac whose organization manages the app, add
   `LOOSE_KEYS_PROFILE=<file.mobileconfig>`: the profile is installed
   through System Settings before the app's first start, and the step fails
   unless macOS reports each of its `dev.loosekeys.desktop` keys as managed.
   `managed-settings.mobileconfig` beside this file is an example to copy.
   `LOOSE_KEYS_EXTRA_HOME=<folder>` adds that folder's files to the decoy
   home, such as a synthetic file at a path the profile names. Neither works
   with `--into`.

3. Report the summary it prints: the VM, its base, whether the app is
   running, the commit and how it was signed, and the `tart delete` line for
   older stopped clones, which the person may run. The person presses Scan
   Now. Do not drive the app or scan for them.
4. If it fails, report the step and the log it names. A run that fails after
   starting its VM stops that VM and keeps it. Without `--into`, every build
   gets a new clone: never fall back to a VM from an earlier run.
5. Once the person approves what the VM showed or says they're done, stop
   and delete it without asking: `tart stop`, then `tart delete`. This is
   only the VM named on the `VM:` line of a run in this conversation without
   `--into`, never one it only put a build into. After they turn it down or
   change topic, ask once, since they may want the next build in it. A VM a
   failed run kept goes too, once the failure is reported and no one is
   looking into it. Of window-check clones, delete only the one named on the
   `VM:` line of a check you ran (in `window.log` for a `tests/check-all.sh`
   run), never one picked by name or time.

What the script does: it checks that fewer than two VMs are running, then
builds from a `git archive` export of the commit (of two commits combined
with `git merge-tree`, which fails on a conflict, or of the checkout's files
staged in a scratch index for `.`) in `$TMPDIR`, runs the bundle contract
test, makes a decoy home with `security-tests/harness.sh generate-home`
(leaving out its fake login keychain and Notes store, which would replace the
guest's own), checks the slots again, clones the base, checks both copies by
SHA-256, installs the app in the guest's `/Applications`, checks its
signature and that the guest has no app state yet, opens it and checks that
it runs. It signs with the Apple Development identity when this Mac has one;
`LOOSE_KEYS_SIGN_IDENTITY=-` asks for ad hoc, which can make macOS refuse the
helper after `--into`.

The base is `lk-sip-base` when this Mac has it, stopped: SIP is on, so macOS
asks for folders and other apps' data as on a real Mac, and the decoys leave
out Desktop, Documents, Downloads and Group Containers, which the guest
refuses to have written. Otherwise it is `macos-tahoe-base`, which boots with
SIP off: macOS asks for no folders and the helper does not behave as on a real
Mac. `LOOSE_KEYS_BASE=<image>` picks another.

The app runs only in the guest. Never open it on this Mac. Any other VM,
such as an older `lk-*` clone or one another session opened, is the
person's to stop or delete; it stays until they remove it. Never delete
`lk-sip-base` or a `ghcr.io` base image.
