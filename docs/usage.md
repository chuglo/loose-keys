# Using the app

[Project README](../README.md) · [Documentation index](README.md)

This guide covers the Loose Keys window. It explains how to run a scan, what
the three lists hold, how to decide what to do with a finding, and how
automatic scanning works. For what the scanner looks for and what it can miss,
see [Detection and limits](detection.md).

## Scanning

1. On the first page, click **Scan Now**. When the scan finishes, the
   Overview tells you what it found.
2. Turn on **Scan Automatically** to have a helper check your home folder on
   its own. What it finds shows up without you running a scan. If macOS needs
   your approval, the Overview offers **Open System Settings** so you can give
   it.
3. To get alerts while the app is closed, click **Set Up Notifications…**. You
   can find it on the Overview or in Settings. macOS then asks in a corner of
   the screen. Choose Allow. If you say no, the Overview tells you notifications
   are off and offers **Open System Settings** to turn them on there. Once
   you've answered macOS, Settings shows the same **Open System Settings**
   button.

Opening the app doesn't turn on automatic scanning or notifications.

Before a scan or before you turn on automatic scanning, the app asks
macOS for access to Desktop, Documents and Downloads. It asks for one folder at
a time.

- If you deny one, Loose Keys still checks the rest. After the scan, the
  Overview names the folder it couldn't read. It offers **Open System
  Settings** so you can allow it under Privacy & Security, Files & Folders.
  Scan again after you allow it.
- **Stop Scan** waits until you answer the prompt that's open. So does
  **Cancel Preparation**, which you see while turning on automatic scanning.
- Other protected folders may still prompt you later. If macOS refuses one,
  it appears under **Show Places Not Checked**.

Loose Keys never needs Full Disk Access. It doesn't check the app data that
macOS protects, such as Mail, Messages and Safari.
[Where the scanner looks](detection.md#where-the-scanner-looks) lists those places.

## What each list holds

The sidebar has three lists. Select a finding to see what it is, why it
matters and what to do. When Loose Keys' rules name the issuer's page, **Open
the Page to Revoke It** or **Open the Page to Manage It** opens it in your
browser. These buttons only open pages listed in those rules.

- **Worth Reviewing** holds findings that need a decision. For example, a
  password or token, a private key with no passphrase, or a password export.
  Automatic scanning alerts you to new ones.
- **Stored Sign-ins** holds what the scanner lists without asking you to
  decide anything:
  - sign-ins an app or command-line tool keeps so you stay signed in, such as
    the AWS CLI's session cache or an AI tool's login file
  - private keys protected by a passphrase, and keys held on a security key
  - low-risk matches, such as a Stripe test-mode key
  - KeePass password databases

  Loose Keys never alerts you about these. If a file becomes readable by other users, its sign-in
  moves to Worth Reviewing as a new finding. A low-risk match doesn't move.
- **Set Aside** holds findings you chose to put off with **Set Aside…**, along
  with your reason. See [Reviewing findings](#reviewing-findings).

Both **Scan Now** and automatic scanning fill all three lists. Loose Keys
saves them, so they keep their items and your choices after you quit. Two
things last only until you quit: the full report and the places a manual scan
couldn't read. Use **Export** to save the report before you quit. After a new
launch, the Overview's Worth Reviewing count comes from the saved findings.

Worth Reviewing has one item for each password or token the app can pick out,
however many files it's in. Loose Keys doesn't match other findings, such as a
private key file, across files. The same key in two key files is two items. The saved
report and the copied summary list every finding, so their count can be
higher. Within one file, it works like this:

- Sometimes a sign-in file's own check and the general token check both find
  the same token. In `~/.npmrc` or `~/.aws/credentials`, that's one item. In
  some files, such as `~/.netrc`, Loose Keys lists it twice.
- If an app keeps its own sign-in in a file, Loose Keys lists that file once,
  in Stored Sign-ins. Examples are the AWS CLI's session cache and
  `~/.config/github-copilot/apps.json`.
- If a file holds several credentials of one kind, Loose Keys lists each one.
  For example, it lists each token in a Kubernetes config that has several.

An item shows the highest risk among its findings that still need a decision.
If none do, it shows the highest risk among the ones you set aside.

The three lists together hold up to 4096 items. They hold fewer when their
saved details get close to 6 MiB. Stored sign-ins take at most 512 of those items and
768 KiB.

- When Worth Reviewing is full, the Overview says so. Save the report to see
  the rest, up to the [findings limit](detection.md#limits).
- When Stored Sign-ins is full, the subtitle under its title says so.

**Filter** matches each row's name, what it concerns (such as a profile or
host) and the path of every listed copy. That includes fixed and set-aside
copies. A filtered list tells you how many rows match out of this page's
total, or says **No Matches**. **Clear Filter** brings all rows back. The
inspector starts hidden and opens when you select an item. To show or hide it,
use its toolbar button or **View > Show Inspector**.

## Reviewing findings

If a finding doesn't need fixing, you can set it aside with **Set Aside…**. The
item moves out of Worth Reviewing into **Set Aside**, under Findings in the
sidebar. The window keeps showing Worth Reviewing. When you select a set-aside
finding, the inspector shows your reason under **Set Aside**. **Move to Worth
Reviewing** there undoes it. **Show Details** says when the finding needs
review again.

| Reason | Covers | Ends when |
|---|---|---|
| **Not a Password or Key**, **Used Only for Testing**, **No Longer Works** | For a password or token the app picks out, every copy, wherever it's stored. For other findings, such as a private key, a password export or a password in `~/.netrc`, only that finding in its file | For a password or token the app picks out, the choice doesn't end when a file changes. If you replace the password or key, the new value appears in Worth Reviewing as a new finding. For other findings, it ends when the file changes or becomes readable by others. With **Not a Password or Key**, changed text appears in Worth Reviewing if Loose Keys flags it again |
| **Keeping It Here on Purpose** | One file. Loose Keys still reports the same credential elsewhere | The file becomes readable by others, a different kind of credential appears there, or six months pass. It still applies if you change the value |
| **Keeping It Here on Purpose**, on a stored sign-in (the only reason a stored sign-in can have) | That file. It still applies when the app that keeps the sign-in refreshes it. **Move to Stored Sign-ins** undoes it | A different kind of sign-in appears in the file, or six months pass. Then the sign-in comes back to Stored Sign-ins without an alert. If the file becomes readable by others, the sign-in leaves Stored Sign-ins and shows up in Worth Reviewing as a new finding |

**Keeping It Here on Purpose** covers the credential in that file, whichever
checks found it there. In `~/.config/gh/hosts.yml`, for example, both GitHub
CLI's check and the general token check find it. **Move to Worth Reviewing**
brings it back for both checks. For npm, RubyGems and Bundler registry entries, the
choice covers that entry's scope. It doesn't cover a new scope in the same
file.

If you choose **Keeping It Here on Purpose** for just one copy of a credential,
the other copies stay in Worth Reviewing. In the inspector, **Set Aside…** applies the reason you chose to
every selected finding. In Set Aside, you can select several findings and
choose **Move to Worth Reviewing**. If you select both set-aside findings and
set-aside stored sign-ins, the inspector offers both moves, and each one moves
only its own kind. If saving fails partway, the list shows the error. Choices
it saved before the failure are kept.

**Expected by your organization** appears when a managed setting from your
organization lists the finding's rule and file. See
[Expected findings set by MDM](managed.md#expected-findings-set-by-mdm). It
covers only that file. Loose Keys still reports a different kind of credential
there. **Move to Worth Reviewing** puts the finding back in Worth Reviewing
anyway. It stays there until your organization's list changes. That list can
set stored sign-ins aside too, and **Move to Stored Sign-ins** puts one back
anyway.

Setting an item aside doesn't stop Loose Keys finding it. Scan results, saved
reports and copied summaries list and count it like any other finding. They
leave out your reason. The counts under the window's title include it too ("3 to review, 5 set aside").

The app keeps up to 4096 choices. It keeps fewer once they fill 1 MiB. A
few thousand ordinary choices do that. When the app needs room for another choice, it
forgets the oldest choices about findings that are no longer on its list. If
a scan finds one of those credentials again, it appears in Worth Reviewing.

## When an item is fixed

Each scan checks every open item's file again. So does each automatic full
pass, when it ends. If the file is gone or no longer holds the credential, the
item is fixed and leaves its list. This happens even when the scan couldn't
read everything else. It doesn't happen when you stop the scan with **Stop
Scan**. A stored sign-in that's no longer found leaves its list the same way.

The app stops rechecking after 10 seconds. Any item it hasn't reached stays
open until a later scan.

If you've stopped checking a folder, the app rechecks an item there only if a
scan still reads that item's file. Other items in the folder stay
open, even after you remove the credential. They stay open until you choose
**Include Again** and scan.

Sometimes a file is on a drive, network share or disk image that isn't
connected. The file isn't gone. Its item stays open until the volume is back
and the app can look at the file. The app can't tell one volume from another
mounted at the same place. If a second drive is mounted under the first one's
name, the app treats the file as gone.

When an item leaves the list, that doesn't mean other copies are gone. It
doesn't mean the credential was revoked either.

## Automatic scanning and notifications

A separate helper does the automatic scanning. It has no window or Dock icon.
When you consent, Loose Keys registers the helper with macOS as a background
item (a launchd job). macOS starts it at login and restarts it if it stops
unexpectedly.

The helper:

- checks a file when it changes
- works through the whole home folder in short slices at low priority. This is
  the full pass, and it repeats weekly
- drops an item from its list when its file no longer matches

Busy files, work limits, sleep, Low Power Mode and macOS permission prompts
can delay detection.

Closing the window quits the app, unless the app is in the menu bar. Quitting
the app doesn't stop the helper. **Pause Scanning** in Settings stops the
helper's checks and alerts. If you turn **Scan Automatically** off, on the
Overview or in Settings, that also removes the background item.

Settings shows when the helper last checked a file and when it last finished a
full pass. If registering the helper fails, the app shows an error but
remembers that you agreed. The status still says whether the helper is running. While it
isn't running, Settings offers **Restart Helper** so you can try again.

Alerts work like this:

- A new finding worth reviewing can produce one grouped alert. So can a
  finding whose credential changed or whose file became readable by others.
  The alert says only that something was found, never which file or
  credential.
- Stored sign-ins and places not checked never alert. An item you haven't
  resolved doesn't alert again, even after more scans or a restart.
- While the app is in front, Loose Keys holds the alert. Within a minute after
  you switch away, it sends the alert for the items that are still open and
  that you haven't set aside. That includes items you already saw in the
  window.
- If **Scan Now** found an item while **Scan Automatically** was off, that item
  can also alert once after you turn automatic scanning on.

The alert, or its **Review** button, opens Worth Reviewing. If macOS doesn't
accept the alert, Loose Keys tries again after a minute, then after five.
Settings lists an alert that hasn't been sent yet under **Pending
Notification**. After three failed tries, it adds **Try Again**.

## Menu bar

**Show in Menu Bar**, in Settings, is on until you turn it off. The key in the
menu bar shows one of three things:

- A dot: items are open in Worth Reviewing, or the list is full.
- No dot: nothing is open in the places checked, or the app is still reading the
  list. This doesn't mean nothing is exposed.
- A warning triangle: the app can't read the list.

The key's menu shows the count. It also shows the state of automatic scanning,
unless the helper is running. From the menu you can open the window or Settings.
The menu itself doesn't change anything. Before any check, while the list is empty, the menu
says **No scan this session** instead of a count. While automatic scanning
makes its first pass, it says **Checking your files…**.

While **Show in Menu Bar** is on, closing the window leaves the app in the menu
bar. It has no Dock icon until a window opens. If automatic scanning is also
on, the app is in Login Items and opens at login in the menu bar. Turning
either one off removes it from Login Items. If you quit, the app stays closed
until you next log in.

## Places not checked

**Show Places Not Checked**, on the Overview, lists what the last manual scan
and the last automatic full pass couldn't read. Each place appears once under
its reason, whichever scan missed it. Opening the list doesn't start a scan. The reasons
include **No Access**, **Couldn't Be Read** and **Only Partly Checked**.
[Places not checked: reasons](detection.md#places-not-checked-reasons)
explains them.

- The list shows up to 20 places under each reason, then says how many more there are. A
  saved report has them all, but only from the manual scan.
- A scan in the app keeps up to 4096 places not checked. If there are more,
  the list ends with `~/` under **Only Partly Checked**.
- Places from automatic scanning date from the last completed full pass. Later
  file or permission changes don't update them. That part keeps up to 4096
  paths with their reasons, within 512 KiB. It says when it's incomplete.
- The automatic part doesn't list places where a work limit was reached
  (**Only Partly Checked**). So if
  every automatic pass stops short of a place, that place isn't listed there.
  **Scan Now** lists the work limits it reaches.

## Choosing folders

You can add folders with **Add Folder or Drive…** in Settings, or by dropping
them on the Settings window. Loose Keys keeps them for later launches and
manual scans until you remove them. You can save up to eight. Loose Keys
includes them in one-time scans, but the helper doesn't watch them. If a drive
is disconnected, it stays listed. Its unavailable paths appear under **Show
Places Not Checked** instead of quietly disappearing from the list.

To leave a folder out, select an open finding directly in that folder. In the
inspector, under Folder, choose **Stop Checking** followed by the folder's
name.

- The app offers this only for a folder inside your home folder. The folder's
  path can have only unaccented letters, digits, spaces and common
  punctuation. To leave out part of an added folder or drive, remove it and
  add a narrower one.
- You can skip up to 32 folders. After that, the app asks you to remove one
  first.
- Settings lists the skipped folders under **Skipped Folders**. **Include
  Again** brings one back.
- If you add a folder that's inside a skipped one, or the skipped folder itself, Loose
  Keys leaves it out too.

Saved reports and the copied summary say that you left a skipped folder out.
That doesn't make the scan incomplete. A scan and the weekly pass still read
known sign-in files in the folder, and the files directly in an AI tool's own
folder. But Loose Keys doesn't check those files when they change. Nothing inside a scanned folder
can silence the scanner. There's no ignore file or inline comment, by design.

## Saving and copying

The **Export** menu has **Save Report…** for the full report, **Save Counts
Only…**, and **Copy Summary** for the text summary.

The app never writes over a file. If you choose to replace a file when saving,
the app writes the new file beside it. Then it moves the old one to the Trash.
Some shared folders give new files extra permissions. The app, `--export` and `--feedback` won't save in such a folder. Save the file
somewhere only you can read.

If a path has any character other than unaccented letters, digits, spaces and
common punctuation, the app shows it escaped. **Copy Path** and **Show in
Finder** don't work on it. **Copy Path** puts a path in single quotes if it has
spaces or other characters a shell acts on. That way you can paste it into
Terminal. A copied path or summary stays on this Mac's clipboard.

## Menus and shortcuts

Every toolbar button is also in the menu bar.

| Command | Menu | Shortcut |
|---|---|---|
| **Scan Now** | File | Command-R |
| **Stop Scan** | File | Command-period |
| **Save Report…** | File | Command-S |
| **Show Sidebar** | View | Control-Command-S |
| **Show Inspector** | View | Option-Command-I |
| **Copy Path** | Item | Option-Command-C |
| **Show in Finder**, **Set Aside**, **Move to Worth Reviewing**, **Move to Stored Sign-ins** | Item | |

The Item menu acts on the items you've selected in the list. Command-click
selects several findings, and Shift-click selects a range. While the list is active,
Command-A selects every visible finding. File actions work on one item at a
time. Double-click a row in any of the three lists to show its file in
Finder. Or Control-click it for **Show in Finder** and **Copy Path**.

## Updates

After your first scan, or after automatic scanning's first full pass, Loose
Keys asks whether it may check for updates. The question is at the bottom of
the Overview. If you choose **Check Automatically**, the app asks
GitHub for the latest release when it starts and once a day while it's open.
The other choice is **Don't Check**. GitHub sees your IP address and that Loose
Keys checked. Loose Keys sends nothing about your files or findings.

When there's a newer version, the bottom of the Overview says so, and **Download** opens its
release page. Loose Keys never installs anything, so you download the new
version and replace the app yourself. With **Scan Automatically** on, the old
version's helper can keep running after that (unverified). To start the new
one, turn **Scan Automatically** off and on again in Settings.

**Check for Updates…**, in the Loose Keys menu, checks once, whatever the
setting. It shows the answer in the main window, and opens the window if it's
closed. You can turn **Check for Updates Automatically** on or off in Settings.
The `loose-keys` command and the background helper never go online.

## Language

The app follows the language macOS uses for it, English or Spanish. If macOS
uses Latin American Spanish, the app uses the words that Latin American macOS
uses, such as Configuración del Sistema. Saved reports, the copied summary and
the `loose-keys` command are always in English.

## Where the app keeps its data

The app keeps the lists in a file only your account can read, at
`~/Library/Application Support/dev.loosekeys.desktop/state.json`. It stores
these things, but no credential values:

- file paths
- added scan folders
- rule identifiers
- fingerprints of the credentials it found, and the key stored beside them
- the names of profiles, hosts and variables that findings concern
- your consent and review choices

Don't share this file. With the key beside the fingerprints, anyone can check
a guessed password against them. The app also keeps your answer about update
checks in `update-check.json` beside it. The directory uses mode `0700`, and
the files use `0600`.

If the app can't open Worth Reviewing, it can't save anything that a scan or
the helper finds. You also can't change choices or settings. First, check
whether other users can read the folder or a file in it. If so, set the modes above,
then quit Loose Keys and open it again. If a newer version saved the list, open
that version again. Otherwise, quit Loose Keys and move `state.json` out of the
folder. The app then starts a new list and forgets what that file held,
including your choices and folders.

If you run an older version of the app or helper after a newer one, the older
version:

- drops stored sign-ins and your choices about them when it saves its list.
  The next scan lists the sign-ins again, without those choices.
- can forget the folders you added when it writes its state. After updating or
  downgrading, check the folder list.

## Removing Loose Keys

1. In Settings, turn off **Show in Menu Bar** and **Scan Automatically**.
   This removes the app from Login Items, stops the helper and removes its
   background item.
2. Quit the app and move it to the Trash. If you linked the `loose-keys`
   command, remove the link: `sudo rm /usr/local/bin/loose-keys`.
3. Delete `~/Library/Application Support/dev.loosekeys.desktop`.
4. Optionally, remove the window sizes macOS saved and the folder access you
   granted: `defaults delete dev.loosekeys.desktop` and
   `tccutil reset All dev.loosekeys.desktop`.

After step 1, macOS keeps its own record of the helper. There's no command that removes
just this app's record. Whether deleting the app removes it is unverified. While it
remains, macOS can refuse the helper of a later build with a different
signature (unverified).
