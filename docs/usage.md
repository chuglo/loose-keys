# Usage and detection limits

[Project README](../README.md) · [Documentation index](README.md)

## The app

On the first page, click **Scan Now**. When the scan finishes, the Overview
says what it found and offers **Scan Automatically**: turned on, a helper
checks your home folder on its own, and its findings appear without a manual
scan. If macOS requires approval, Overview offers **Open System Settings**
to give it. For alerts while the app is closed, click **Set Up
Notifications…**, on the Overview or in Settings, and choose Allow in the
request macOS shows in a corner of the screen. If macOS answers no, the
Overview says notifications are off, with **Open System Settings** to turn
them on there. Settings offers the same once macOS has an answer.

**Scan Now** gives a detailed point-in-time report. The sidebar lists
what is worth reviewing and the sign-ins that are stored. When a scan could
not read some places, **Show Places Not Checked** on the Overview lists them
with the reasons. Select a finding to see what it is, why it matters and
what to do. Where the rules name the issuer's page, **Open the Page to Revoke
It** or **Open the Page to Manage It** opens it in your browser; these buttons
open only pages the rules list. The **Export** menu has **Save Report…** for
the full report, **Save Counts Only…**, and **Copy Summary** for the text
summary. Opening the app does not turn on automatic scanning or notifications.

Worth Reviewing, Stored Sign-ins and Set Aside are saved, and both **Scan
Now** and automatic scanning fill them, so they keep their items and your
choices after you quit. Only the full report and the places a manual scan
could not read last until you quit the app: use **Export** to save the report
before quitting. After a new launch, the Overview counts Worth Reviewing from
saved findings.

The app follows the language macOS uses for it: English or Spanish, with
the words Latin American macOS uses, such as Configuración del Sistema, in
Latin American Spanish. Saved reports, the copied summary and the
`loose-keys` command are always in English.

Before a scan or turning on automatic scanning, the app asks macOS for
Desktop, Documents and Downloads, one at a time. The rest are still checked
when you deny one. After the scan, the Overview names the folder it could not
read, with **Open System Settings** to allow it under Privacy & Security, Files
& Folders; scan again after allowing it. **Stop Scan**, or
**Cancel Preparation** when turning on automatic scanning, stops once the
open prompt is answered. The app data macOS protects, such as
Mail, Messages and Safari, isn't checked, nor are the Trash and unsaved
document autosaves, which macOS protects too, and Full Disk Access is never
needed; [Supported checks](#supported-checks) lists those folders. Other
protected folders may still prompt later, and one that macOS refuses appears
under **Show Places Not Checked**.

The app never writes over a file. If you choose to replace one when saving,
the app writes the new file beside it and then moves the old one to the Trash.
The app and `--export`/`--feedback` refuse a folder that gives its new files
an access list, as some shared folders do; save the file somewhere only you
can read.
A path with any character outside plain ASCII, such as an accented letter, is
shown escaped, and **Copy Path** and **Show in Finder** do not work on it.
**Copy Path** puts a path with spaces or other characters a shell acts on in
single quotes, so it can be pasted into Terminal. A copied path or summary
stays on this Mac's clipboard.

Worth Reviewing has one item for a password or token the app can pick out,
however many files it is in. Other findings, such as a private key file, are
not matched across files: the same key in two key files is two items. The saved report
and the copied summary list each finding, so their count can be higher.
Worth Reviewing, Stored Sign-ins and Set Aside together hold up to 4096
items, fewer when their saved details near 6 MiB. Stored sign-ins
take at most 512 of those items and 768 KiB. When Worth Reviewing is full,
the Overview says so; save the report to see the rest, up to the findings
limit below. When Stored Sign-ins is full, the subtitle under its title says
so.

**Filter** matches each row's name, what it concerns (such as a profile or
host) and every listed copy's path, including fixed and set-aside copies.
Matching secondary paths appear under the row's representative path;
the row still identifies the same grouped finding. A copy-count hint counts
the files it is listed in, including fixed and set-aside copies; two rules
matching the same text in one file are one copy. Filtered lists say how many
rows match out of this page's total, or **No Matches**; **Clear Filter**
brings all rows back. The inspector starts hidden to leave space for the list
and opens when you select an item. Its toolbar button, or **View > Show
Inspector** (Option-Command-I), can show or hide it at any time.

Every toolbar button is also in the menu bar. The File menu's **Scan Now** is
Command-R, **Stop Scan** Command-period and **Save Report…** Command-S;
**View > Show Sidebar** is Control-Command-S. The **Item** menu has **Show
in Finder**, **Copy Path** (Option-Command-C), **Set Aside**, **Move to
Worth Reviewing** and **Move to Stored Sign-ins** for the items selected in
the list. Double-click a row in any of the three lists to show its file in
Finder, or Control-click it for **Show in Finder** and **Copy Path**.

### Reviewing findings

Findings that do not need fixing can be set aside (**Set Aside…**), for one of
four reasons:

- **Not a Password or Key**
- **Used Only for Testing**
- **No Longer Works**
- **Keeping It Here on Purpose**

Use Command-click to select several findings, Shift-click to select a range,
or Command-A while the table has focus to select all visible findings.
The inspector's **Set Aside…** applies the chosen reason to every selected
finding. In Set Aside, you can also select several findings
and choose **Move to Worth Reviewing**. File actions need a single selection.
Each choice is saved in turn. If one fails, the ones before it stay saved, the
list refreshes and shows the error, and the rest are left as they were.

When the app can pick out a password or token, the first three cover every
copy it picks out, wherever it is stored. For other findings, such as a private
key, a password export or a password in `~/.netrc`, they cover that finding in
its file until the file changes or becomes readable by others. If a password
or key is replaced, the new one appears in Worth Reviewing. For **Not a Password
or Key**, changed text appears there if it is flagged again. A finding set
aside under the earlier combined reason, for testing or no longer working,
stays set aside and is shown as a previous choice. The app keeps up to 4096
choices, and fewer once they fill 1 MiB, as a few thousand ordinary ones do. When it needs
room for another, it forgets the oldest choices about findings no longer on
its list, so such a credential found again appears in Worth Reviewing.

**Keeping It Here on Purpose** covers one file. The same credential turning
up elsewhere is still reported. It covers the credential in that file
whichever checks found it there, as GitHub CLI's check and the general token
check both do in `~/.config/gh/hosts.yml`, and **Move to Worth Reviewing**
returns it for each. It still applies if you change the value in
that file, and ends if the file becomes readable by others, if a different kind
of credential appears there, or after six months. For npm, RubyGems and Bundler
registry entries, it covers that entry's scope, not a new scope in the same file.

An update that removes unsafe registry labels clears earlier personal choices
for npm, RubyGems and Bundler, so those findings may need review again.

A token that a sign-in file's own check and the general token check both find
in that file, as in `~/.npmrc`, is one item, which shows the file's own
check's steps unless only that copy has been set aside. In some files, such
as `~/.netrc`, it is listed twice. A token in `~/.config/gh/hosts.yml` shows
GitHub CLI's steps at High, the general token check's risk, though GitHub
CLI's check rates it Medium. Any item shows the
highest risk among its findings that still need a decision, or, when none
does, among those set aside. A file holding several
credentials of one kind, such as a Kubernetes config with several tokens,
lists each.

**Expected by your organization** appears when a managed setting from your
organization lists the finding's rule and file. It covers only that file; a
different kind of credential there is still reported. **Move to Worth
Reviewing** reviews it anyway, and it stays in Worth Reviewing until your
organization's list changes. The list sets stored sign-ins aside too, and
**Move to Stored Sign-ins** lists one anyway.

A stored sign-in can be set aside only as **Keeping It Here on Purpose**. It
covers that file and still applies when the app that keeps the sign-in
refreshes it. It ends if a different kind of sign-in appears in the file, or
after six months, when the sign-in comes back to Stored Sign-ins without an
alert. **Move to Stored Sign-ins** undoes it. With items of both kinds
selected in Set Aside, the inspector offers both moves, and each moves only
its own kind. If the file becomes readable by others, the sign-in leaves
Stored Sign-ins and shows up in Worth Reviewing as a new finding. A stored
sign-in that is no longer found leaves the list. An
older version of the app drops stored sign-ins and your choices about them
when it saves its list; the next scan lists the sign-ins again, without those
choices.

Setting an item aside moves it out of Worth Reviewing into **Set Aside**, under
Findings in the sidebar. You stay in Worth Reviewing. The inspector of a
set-aside finding shows your reason under **Set Aside**, with **Move to Worth
Reviewing** to undo it later. **Show Details** says when the finding needs review
again. If you keep just one copy of a credential, the other copies remain in
Worth Reviewing.

Setting an item aside never stops it being found or counted in scan results,
saved reports or copied summaries, which list it like any other finding,
without your reason. The counts under the window's title still include it ("3
to review, 5 set aside"). To leave a folder out, select an open finding
directly in it and choose **Stop Checking** followed by the folder's name,
under Folder in the inspector. It is offered only for a folder inside your
home folder with a plain ASCII path; to leave out part of an added folder or
drive, remove it and add a narrower one. Up to 32 folders can be skipped; past
that, the app asks you to remove one first. Saved reports and the copied
summary name a skipped folder as left out by you, which does not make the
scan incomplete, and Settings lists it under Skipped Folders, where
**Include Again** brings it back. Known sign-in
files in it, and
the files directly in an AI tool's own folder, are still read by a scan and by
the weekly pass, though not when they change. Nothing inside a scanned folder
can silence the scanner: there is no ignore file or inline comment, by design.

A scan in the app, and each automatic full pass as it ends, look at each
pending item's own file again. When the file is gone or no longer matches, the
item is fixed and leaves its list, even if the scan could not read everything
else, but not by a scan you stop with **Stop Scan**. These rechecks stop after
10 seconds; an item not reached stays open until a later scan. In a folder you stopped
checking, an item is looked at again only when a scan still checks its file
for it, so other items there stay open, even after you remove the credential,
until you choose **Include Again** and scan. A file on a drive, network share
or disk image that is not connected is not gone: its item stays open until the
volume is back and the file can be looked at. The app cannot tell one volume
from another mounted at the same place, so a second drive mounted under the
first one's name reads as the file being gone. An item leaving the list does
not mean other copies are gone or that the credential was revoked.

The app keeps pending review in owner-only local storage at
`~/Library/Application Support/dev.loosekeys.desktop/state.json`. It stores
file paths, added scan folders, rule identifiers, keyed fingerprints and their
key, the names of profiles, hosts and variables that findings concern,
consent, and review choices, not credential values. Do not share it: with the
key, anyone can check a guessed password against it. Your answer about update
checks is also kept in `update-check.json` beside it. The directory uses mode
`0700`; the files use `0600`. The CLI does not use this review state.

If Worth Reviewing cannot be opened, nothing a scan or the helper finds is
saved, and choices and settings cannot be changed. If the folder or a file in
it is not private, set the modes above, then quit Loose Keys and open it
again. If a newer version saved the list, open that version again. Otherwise, quit Loose Keys and move `state.json` out
of the folder: the app then starts a new list and forgets what that file held,
including your choices and folders.

#### Expected findings set by MDM

An organization can list findings its own tools create on purpose, so they
start out in Set Aside instead of Worth Reviewing. Deliver a configuration
profile with a payload of type `dev.loosekeys.desktop` holding the key
`ExpectedFindings`: an array of dictionaries, each with `rule` (an id from
`loose-keys --list-rules`) and `path` (`~/` and the file's path inside the
home folder, plain ASCII, one file per entry). The first 32 entries in that
form are used; an entry with a rule this version doesn't have, or a path of
another form, is ignored without notice. The app reads the key only from a
managed value; a plist in `~/Library/Preferences` is ignored. Only a profile
installed by hand, on a test Mac with SIP off, has been checked; delivery from
an MDM server and a user-scope profile are unverified
([managed settings](testing/guest.md#managed-settings)).

```xml
<key>ExpectedFindings</key>
<array>
  <dict>
    <key>rule</key><string>key.ssh.private</string>
    <key>path</key><string>~/.safe-chain/certs/ca-key.pem</string>
  </dict>
</array>
```

An entry covers only the rule it names. Where two checks find one credential
in a file, list an entry for each, or the item stays in Worth Reviewing and
can alert. For a token in `~/.config/gh/hosts.yml`, that is
`dev.gh.inline-token` and `secret.service-token`.

Expected findings are still found and counted, and stay in saved reports and
copied summaries. The background helper follows the list the app last read, so
a changed or removed profile takes effect when the app next opens or comes to
the front. The `loose-keys` command does not read the list, so `--fail-on-open`
and counts files count expected findings as open. To honour the list, a script
reads the full report (`--export`) and matches each finding's rule and path.

### Background helper and notifications

Checks react to filesystem events. Busy files, work limits, sleep, Low Power
Mode and macOS permission prompts can delay detection. Added folders and
drives are included in one-time scans, not watched by the helper.

Folders added with **Add Folder or Drive…** in Settings, or dropped on the
Settings window, are kept for later launches and manual scans until you remove
them. Up to eight are saved. An added folder inside a folder you stopped
checking, or the same folder, is left out with it until you choose **Include
Again**. Disconnected drives
stay listed; their unavailable paths are listed under **Show Places Not
Checked** rather than silently removed. An older app or helper can forget these saved folders
when it writes its state, so check the folder list after updating or
downgrading.

Automatic scanning is done by a separate helper with no window or Dock icon.
Giving consent registers it with macOS as a launchd job, which starts it at
login and restarts it if it stops unexpectedly. It checks a file when it
changes, works through the whole home folder in short slices at low priority,
repeats that pass weekly, and drops an item from its list when its file no
longer matches. Closing the window quits the app, unless it is in the menu bar, and
quitting the app does not stop the helper. **Pause Scanning** in Settings
stops its checks and alerts; turning **Scan Automatically** off, on the
Overview or in Settings, also removes the launchd job. Settings shows when
the helper last checked a file and last finished a full pass.

For places automatic scanning could not read, **Show Places Not Checked**
lists what it saved and does not run another scan. That list is dated to the
last completed automatic full pass; later file or permission changes do not
rewrite that result. It is one list with the last manual scan's places: each
place once under its reason, whichever scan missed it. Saved reports still
contain only the manual scan. The automatic list keeps up to
4096 paths with their reasons, within 512 KiB, and says when it is incomplete.
It leaves out work limits (`scan-limit`), so a place every automatic pass
stops short of is not listed there; **Scan Now** lists the work limits it
reaches. Older versions saved only the count; their details become available
after the next automatic full pass. A scan in the app keeps up to 4096 places
not checked; when there are more, the last of them is `~/` with the reason
`scan-limit`. **Show Places Not Checked** lists up to 20 of them under each
reason, then how many more (the larger of the two scans' counts when both
missed places under it); a saved report has them all.

If registering the helper fails, the app shows an error and keeps your
consent, and the status still says whether the helper is running. While it
is not running, Settings offers **Restart Helper** to try again.

A new finding worth reviewing, or one whose credential changed or whose file
became readable by others, can produce one grouped alert. It says only that
something was found, never which file or credential. Stored sign-ins and
scan gaps do not alert, and an unresolved item does not alert again across
scans or restarts. While the app is in front, the alert is held; within a
minute after you switch away, it is sent for the items still open that you
have not set aside, including ones you already saw in the window. An item
**Scan Now** found while **Scan Automatically** was off can also alert once
after you turn it on.

The alert, or its **Review** button, opens Worth Reviewing. If macOS does not
take it, it is tried again after a minute, then after five. Settings lists an
alert not sent yet under **Pending Notification**, with **Try Again** after
three failed tries.

### Menu bar

**Show in Menu Bar**, in Settings, is on until you turn it off. The key in the menu bar
has a dot while items are open in Worth Reviewing or the list is full, and is
a warning triangle when the list cannot be read. A key with no dot means
nothing is open in what was checked, or the list is still being read, not
that nothing is exposed. Its menu shows the count, and the state of automatic
scanning unless it is running, and opens the window or Settings; it changes
nothing. Before any check, with nothing on the list, the menu says **No scan
this session**, or **Checking your files…** while automatic scanning
makes its first pass, instead of a count.

While it is on, closing the window leaves the app in the menu bar, with no Dock icon
until a window opens. With automatic scanning also on, the app is in Login
Items and opens at login in the menu bar; turning either off removes it.
Quit lasts until the next login.

### Updates

After your first scan, or automatic scanning's first full pass, Loose Keys
asks, at the bottom of the Overview, whether it may check for updates. If you
choose **Check Automatically** rather than **Don't Check**, the app asks
GitHub for the latest release when it starts and once a day while it is open.
GitHub sees your IP address and that Loose Keys checked; nothing about your
files or findings is sent. A newer version appears at the bottom of Overview,
and **Download** opens its release page. Loose Keys never installs anything:
download and replace the app yourself. With **Scan Automatically** on, the old
version's helper can keep running after that (unverified); to start the new
one, turn **Scan Automatically** off and on again in Settings.

**Check for Updates…**, in the Loose Keys menu, checks once whatever the
setting and shows the answer in the main window, opening it if it is closed.
Turn **Check for Updates Automatically** on or off in Settings. The
`loose-keys` command and the background helper never go online.

### Removing Loose Keys

1. In Settings, turn off **Show in Menu Bar** and **Scan Automatically**.
   This removes the app from Login Items, stops the helper and removes its
   launchd job.
2. Quit the app and move it to the Trash. If you linked the `loose-keys`
   command, remove the link: `sudo rm /usr/local/bin/loose-keys`.
3. Delete `~/Library/Application Support/dev.loosekeys.desktop`.
4. Optionally, remove the window sizes macOS saved and the folder access you
   granted: `defaults delete dev.loosekeys.desktop` and
   `tccutil reset All dev.loosekeys.desktop`.

macOS keeps its own record of the helper after step 1, and no command removes
one app's record. Whether deleting the app removes it is unverified. While it
remains, a later install of a build with a different signature can have its
helper refused.

## Supported checks

- possible password-export CSV and private-key headers recursively across your
  home directory, regardless of extension (including renamed files). A CSV
  export is found only when its header is the file's first line. This check
  finds a PEM or OpenSSH private key only near the start of a file, within
  its first 4 KiB and after nothing but blank lines, certificates or
  openssl's attributes, and a PuTTY `.ppk` key only by its first line; one
  pasted under other text in a note, or written into code, is not. A key with
  a passphrase, and a PGP private-key block, whose armor doesn't show whether
  it has one, are listed, not flagged;
- unencrypted Bitwarden JSON exports of a personal vault or an organization
  that hold login passwords, and 1Password export files (`.1pux`, and the
  `.1pif` of 1Password 7 and earlier, by its first item);
- Docker registry passwords and tokens stored in `~/.docker/config.json`
  (`auth`, `identitytoken` and `registrytoken` fields); the same fields in
  `~/.config/containers/auth.json` and
  `~/Library/Preferences/helm/registry/config.json` are also checked;
- AWS access keys in `~/.aws/credentials` and `~/.aws/config`;
- HTTP(S) username/password URLs in `~/.git-credentials` and
  `~/.config/git/credentials`;
- `user:password` pairs inside URLs, a token written alone where a URL's
  user name goes (a known issuer format, or 32 or more letters and digits
  with both in it, so never a name such as `git`), and tokens in a known
  issuer format anywhere, in each repository's `.git/config` (nothing else
  in a `.git` folder is read);
- GitHub CLI `oauth_token` fields in `~/.config/gh/hosts.yml`;
- npm auth, token and password fields in `~/.npmrc`;
- service tokens in about 140 known issuer formats (AWS, GitHub, GitLab, OpenAI,
  Anthropic, Google Gemini, Stripe, Slack, npm, PyPI, Cloudflare, Vercel and
  more) and Slack and Discord webhook URLs, in the first 4 KiB of any file up
  to 1 MiB, and anywhere in `.env*`, `*.env`, `.envrc`, `.dev.vars*`, `secrets.toml`,
  `*.tfvars`, shell startup and history files, the history files of psql,
  MySQL, redis-cli, Python, Node.js and irb, Aider's `.aider.chat.history.md`
  and `.aider.input.history`, `~/.cache/huggingface/token`,
  `~/.gradle/gradle.properties`, `~/.codex/config.toml` and
  `~/.config/goose/secrets.yaml`. Stripe test-mode keys are listed
  at low risk. Keys whose prefix does not name the service, such as Google API
  keys starting `AIza` (including Gemini keys in that form), Notion keys
  starting `secret_`, and Twilio, Dropbox and ElevenLabs keys, are found only
  under a variable or setting named like a secret, in the `.env*`, shell, MCP
  and AI tool settings files below;
- AI agent records: the folders where Claude Code, Codex, Gemini, Cursor,
  Continue, Copilot, Cline, Roo Code, Windsurf, OpenCode and Goose keep session
  transcripts and logs, and VS Code's workspace storage, are read in full for
  tokens, up to 256 MiB per file (`--list-rules` has each folder). Folders in
  them that hold programs or caches (`extensions`, `plugins`, `packages`, `bin`,
  `Cache`, `Code Cache`, `GPUCache`) are not: their files are checked like any
  other file;
- variables named like secrets and set to a value, and variables of any name
  set to a private key or a URL with a password in it, in `.env*`, `*.env`,
  `.envrc`, `.dev.vars*`, `secrets.toml`, `*.tfvars`, shell files,
  `~/.gradle/gradle.properties`, `~/.codex/config.toml` and
  `~/.config/goose/secrets.yaml`;
- cloud and infrastructure: Google service-account key files anywhere, kubeconfig
  credentials in `~/.kube` and in a kubeconfig saved anywhere else, secrets in
  Terraform state files (`*.tfstate`, `terraform.tfstate*`), passwords in dbt
  and Snowflake client configs, rclone's saved passwords and keys, Terraform
  and Vault tokens, Azure service principal secrets, and the stored sign-ins
  of rclone, gcloud, the Azure CLI (including the `~/.azure/accessTokens.json`
  of older versions) and the AWS CLI (listed, not flagged);
- package registries and build tools: project and home `.npmrc`, Yarn, pnpm,
  `.pypirc`, Poetry, Cargo, RubyGems, Bundler, Composer, Maven, Gradle, and
  passwords inside URLs in Git and pip config and `~/.curlrc`;
- other developer files: `.netrc`, `.pgpass`, `.my.cnf`, GnuPG private keys
  (one with a passphrase is listed, not flagged), FileZilla and DBeaver saved
  passwords, OpenVPN profiles (`.ovpn`) with a private key inside, WireGuard
  configs (`.conf`) with a private key in their `[Interface]` section, and the
  stored sign-ins of about thirty deploy and AI command-line tools (listed,
  not flagged);
- literal secrets in MCP server configs and AI tool settings files, including
  ones written with comments (Zed, VS Code, opencode), and OAuth token files
  such as mcp-remote keeps in `~/.mcp-auth` (listed, not flagged);
- browsers: whether profiles of Chrome (and Chrome Beta and Canary), Brave,
  Edge, Arc, Chromium, Vivaldi, Opera, Opera GX and Yandex hold saved passwords
  or payment cards, and whether Firefox, Waterfox, LibreWolf and Zen profiles
  hold saved passwords. Other browsers and channels are not checked. Only a
  count is read from the database file, and nothing is decrypted; a table
  longer than one page is counted as "many". A database the scanner cannot
  read (truncated, UTF-16, WITHOUT ROWID tables or overflow pages) is listed as
  not checked, as is one with pending changes in its `-wal` or `-journal` file,
  which an open browser may have. A leftover journal can keep it that way after
  the browser closes. A crafted file, or damage in a part the reader skips, can
  still give a wrong count;
- crypto wallets: listed wallet extensions in those Chromium browsers' profiles
  and desktop wallet folders (reported by presence, without reading their
  contents), and recovery phrases from the English BIP-39 word list written
  into the first 4 KiB of a file. The phrase heuristic skips sorted word
  lists, repetitive phrases and two common public 12-word BIP-39 test
  vectors; it does not validate checksums or wallet use;
- Telegram Desktop's session folder, KeePass 2 databases (listed, not
  flagged; KeePass 1 `.kdb` files are not recognised), and password-looking
  lines in `.txt` and `.rtf` notes.

`loose-keys --list-rules` prints every rule and where it looks.

Each finding has a risk level and numbered steps for dealing with it. High
means the credential works from any computer until it is revoked or expires,
medium that it needs more to use or unlocks less, and low that it is protected
or for testing only. `--fail-on-open` counts only what is worth reviewing: a
stored sign-in counts once its file's permissions let other users read it, and
a test-mode key never counts. The summary also says what a finding concerns,
such as the AWS profile or registry host; the JSON report leaves that out and
names only the kind of token. Not covered: browser cookies and sessions,
Safari, Notes, Mail, Messages and other app data macOS protects, iPhone and
iPad backups, the Trash, unsaved document autosaves, the Keychain, images and password-manager vaults. The rules for
known files read simple literal fields at the listed paths: not full YAML or
INI syntax, not a config kept somewhere else, and not a reference or an
environment placeholder. In `.env*`, shell, MCP and AI tool settings files, a
value that only its name marks as secret is not reported when it is shorter
than 8 characters (12 in MCP server configs and JSON settings files, 16 in
OAuth token files) or looks like a sample or placeholder. In the files listed
above for variables, and in an MCP server's environment and headers, such a
value is not reported either when its name says the key is public or
publishable or when it looks like a file path: one that starts with `~/`, `./`, `../`, `$HOME/` or a folder
at the root of a Mac such as `/Users/`; one through folders in small letters
from `/`, such as `/app/.ssh/id_rsa`, or from a hidden folder or a `keys`,
`certs`, `secrets`, `ssl` or `tls` folder, such as `.ssh/id_ed25519`; an SSH
key's file name, such as `id_ed25519_work`; or one that ends in a key or
credential file extension (`.json`, `.pem`, `.key`, `.p8`, `.p12`, `.pfx`,
`.crt`, `.der`, `.jks`, `.keystore`, `.gpg`, `.asc`). In the files listed for
variables, a value that names another variable named like a secret, such as
`OPENAI_API_KEY`, is not reported either, and a password in a URL is held to
the same length and placeholder limits. A note password that is a single
lowercase word is not reported either. JSON MCP server configs and settings
files are read 6 levels deep.

The scanner does not execute credential helpers, contact services or show
secret values. It does not follow symlinks, with one exception: when a known
sign-in location such as `~/.npmrc` or `~/.aws` is a link to somewhere else
inside your home folder (as dotfile managers set up), the real file is checked
and reported at its real path. A link that leaves the home folder is reported
as not checked. When the command runs as root, it follows none of these links
and reports each one as not checked. It does not determine whether a
credential is valid or authorized. An empty report means none of the supported
patterns turned up in the places it looked, not that the Mac is clean. A
matched header can be an empty template. A file's permission bits do not show
who can actually read it: ACLs and parent folders count too.

Discovery includes hidden folders and nested backups. It skips directories
ending in `.git`, `node_modules`, `target`, `.venv`, `venv`, `__pycache__`,
`.cache`, `Library/Caches`, `vendor`, the app's own
`Library/Application Support/dev.loosekeys.desktop`, or package download caches
(`.bun/install/cache`, `.npm/_cacache`, `.cargo/registry`,
`.rustup/toolchains`). It also stays out of the folders where macOS keeps the
data of its own apps (`Library/Calendars`,
`Library/Application Support/AddressBook`, `Library/Reminders`,
`Library/Photos`, `Photos Library.photoslibrary`), other apps' data
(`Library/Group Containers`, `Library/Containers`) and the TV and Music apps'
libraries (`Movies/TV`, `Music/Music`), and does not open the Contacts or TV
settings files (`Library/Preferences/com.apple.AddressBook.plist`,
`Library/Preferences/com.apple.TV.plist`): no rule reads them, and for each
one macOS would ask you for your calendar, contacts, reminders, photos,
media library or other apps' data in the scanner's name. It also skips the
app data macOS refuses without Full Disk Access, which would otherwise be
listed as not checked after every scan: in `Library`, `Mail`, `Messages`,
`Safari`, `Cookies`, `HomeKit`, `IdentityServices`, `Suggestions`, `Biome`,
`PersonalizationPortrait`, `Accounts`, `Sharing`, `Shortcuts`, `StatusKit`,
`CoreFollowUp`, `DuetExpertCenter`, `Metadata/CoreSpotlight`,
`Metadata/com.apple.IntelligentSuggestions`, `Assistant/SiriVocabulary`,
`DoNotDisturb`, `Trial`, `AppleMediaServices`, `IntelligencePlatform`,
`com.apple.aiml.instrumentation`, `Weather`, `Daemon Containers`,
`ContainerManager` and `WebDriver`; in `Library/Application Support`,
`CallHistoryDB`, `CallHistoryTransactions`, `Knowledge`, `com.apple.TCC`,
`MobileSync` (iPhone and iPad backups), `com.apple.sharedfilelist`,
`com.apple.avfoundation/Frecents`, `FileProvider`, `CloudDocs/session/db`,
`FaceTime` and `DifferentialPrivacy`; and Messages' and Home's settings files
in `Library/Preferences` (`com.apple.MobileSMS.plist`,
`com.apple.madrid.plist`, `com.apple.homed.plist`,
`com.apple.homed.notbackedup.plist`). It also skips the Trash (`.Trash`) and
unsaved document autosaves (`Library/Autosave Information`), which macOS
protects though they hold your own files: a key file you deleted but haven't
emptied from the Trash isn't found. Any other place macOS refuses is still
listed as not checked; a refusal that an older version's automatic scan
saved for one of these is no longer shown. A known sign-in location inside any
of these folders, such as Telegram's App Store copy, is still read, and macOS
may ask then. Links and special files that discovery meets are passed
over without a gap, as is macOS's `.com.apple.containermanagerd.metadata.plist`.
Where a repository's
`.git` is a file pointing elsewhere (a worktree or submodule) or a link, it is
not followed. Repeat `--select DIR` to add folders or mounted drives;
explicitly selecting one of the folders above scans that root, while they are
still skipped below it. Relative paths are accepted, but a path containing `..`
is refused, and a folder reached through a link is listed as not checked: give
its real path. Repeat `--exclude DIR` to leave out up to 32 folders. It takes
a path relative to the current folder too, refuses one containing `..`, the
home folder or a folder above it (also as spelled under
`/System/Volumes/Data`), a file, a link and a path through a link,
and accepts a path it cannot look up, such as a folder that is not there or
one inside a folder you cannot open. A folder given in another case, such as
`~/documents` for `~/Documents`, is taken as the disk spells it, for
`--select` too. Leaving a folder out does not make the scan partial, and a
folder selected inside it, or selected as well, is left out with it, and
neither report lists it among the folders scanned. A scan
still reads known sign-in files in a folder left out, such as
`~/.aws/credentials`, and files directly in an AI tool's own folder. Where
your home folder is reached through a link, a path through that link, as the
shell writes `~/notes`, names the folder in your home.

Both text and JSON reports state the requested roots and exclusions. The JSON
report also states the detection limits, which the command's text summary
prints only with `--limits`; **Copy Summary** always includes them. A place
the scan could not check appears under `not_checked` with one of these
reasons, and makes the scan partial:

- `permission-denied`: file permissions or macOS privacy settings blocked it.
  Allow access, then scan again;
- `unreadable`: reading failed, the file changed while it was read, or it is a
  known file in a form the scanner does not read. A browser database, or
  gcloud's `credentials.db`, with pending changes is listed this way: quit the
  browser, or wait for gcloud to finish (unverified), and scan again. So is a
  selected folder that is missing or reached through a link;
- `too-large`: the file is over a read limit below;
- `cloud-only-file`: the folder holds files kept only in the cloud, which are
  not downloaded. Download them, then scan again;
- `scan-limit`: a work limit below was reached;
- `symlink`: a known sign-in location is a link that is not followed, as
  described above.

The limits:

- discovery: 64 folder levels, 10,000 entries per folder and 100,000 entries
  per root. It is breadth-first, with the home's `Library`, `Movies`, `Music`
  and `Pictures` last, so one large folder cannot use up the budget before the
  rest is seen;
- reads: 4 KiB for a header, and 1 MiB for a file read whole, such as a
  config, shell history, note, Terraform state or browser database. A larger
  one is a `too-large` gap, except that a `.txt`, `.rtf`, `.conf` or
  `*_tokens.json` file over 1 MiB with nothing matching in its first 4 KiB
  is passed over, not listed as not checked. A token, Bitwarden export,
  Google service-account key, kubeconfig or WireGuard config is confirmed by
  reading the whole file, so in a file over 1 MiB, one in the first 4 KiB
  gives that gap, not a finding;
- matches: some rules list only the first 100 matches in a file, and the
  notes rule the first 20 lines. Past its first 100, the service-token rule
  lists only new tokens, up to 100 different ones. When more are omitted, the
  listed findings stay and a `scan-limit` gap makes the scan partial;
- findings: a scan in the app stops at 4096 findings, and a `scan-limit` gap
  makes it partial. The command line has no such limit;
- agent records: 16 levels deep, 50,000 entries per tree, 256 MiB per file
  and 50 different tokens listed per file. A larger file is a `too-large`
  gap, and a record with more tokens a `scan-limit` gap. A deeper folder is
  reported once. Discovery still reaches it, unless it is in a skipped folder
  such as `Library/Caches`, and checks its files as it checks any other file;
- time: the app stops a scan after 30 seconds, once the file it is reading is
  finished, or when you press **Stop Scan**, and gives one agent record at most
  60 seconds. The command line has no time limit: stop it with Control-C.

These are work limits: a slow filesystem call can still hold a scan. Known
credential locations are checked before discovery and keep their own limits:
each known folder is listed to 10,000 entries. If results show the entry or
depth limit of a root, add an omitted subfolder as another root, with
`--select` or **Add Folder or Drive…** in Settings: each root gets its own
budget and depth start. That doesn't help a folder with more than 10,000
entries: the limit applies whichever root it is reached from, and which
entries are kept depends on the order the filesystem lists them.
`scan --limits` prints what is not detected.

