# Usage and detection limits

[Project README](../README.md) · [Documentation index](README.md)

## The app

On the first page, click **Scan Now**. When the scan finishes, the Overview
says what it found and offers **Scan Automatically**: turned on, a helper
checks your home folder on its own, and its findings appear without a manual
scan. If macOS requires approval, Overview offers **Open System Settings**
to give it. Allow notifications separately if you want alerts while the app
is closed.

**Scan Now** gives a detailed point-in-time report. The sidebar lists
what is worth reviewing and the sign-ins that are stored. When a scan could
not read some places, **Show Places Not Checked** on the Overview lists them
with the reasons. Select a finding to see what it is, why it matters and
what to do. **Export** saves the full report or a counts-only file, and copies
the text summary. Opening the app does not turn on automatic scanning or
notifications.

Manual scan details, including Stored Sign-ins and the places a manual scan
could not read, last only until you quit the app. Saved review findings and
decisions remain available. Use **Scan Now** for current details, and
**Export** to save the report before quitting. After a new launch, Stored
Sign-ins says **No Manual Scan This Session**, not that this Mac has never
been scanned, and the Overview counts Worth Reviewing from saved findings.

The app follows the language macOS uses for it: English or Spanish, with
the words Latin American macOS uses, such as Configuración del Sistema, in
Latin American Spanish. Saved reports, the copied summary and the
`loose-keys` command are always in English.

Before a scan or turning on automatic scanning, the app asks macOS for
Desktop, Documents and Downloads, one at a time. The rest are still checked
when you deny one. After the scan, the Overview names the folder it could not
read, with **Open System Settings** to allow it under Privacy & Security, Files
& Folders; scan again after allowing it. **Cancel Preparation**
stops once the open prompt is answered. Other protected folders may still
prompt later. Full Disk Access is not needed.

The app never writes over a file. If you choose to replace one when saving,
the app writes the new file beside it and then moves the old one to the Trash.
The app and `--export`/`--feedback` refuse a folder that gives its new files
an access list, as some shared folders do; save the file somewhere only you
can read.
File names with unusual characters are shown escaped, and **Copy Path** and
**Show in Finder** work only on plain names. A copied path stays on this Mac's
clipboard.

Worth Reviewing has one item for a password or token the app can pick out,
however many files it is in. Other findings, such as a private key, are not
matched across files: the same key in two files is two items. The saved report
and the copied summary list each finding, so their count can be higher. When
the list is full, the Overview says so; save the report to see every finding.

**Filter** searches every listed copy's path, including fixed and set-aside
copies. Matching secondary paths appear under the row's representative path;
the row still identifies the same grouped finding. A copy-count hint counts
the files it is listed in, including fixed and set-aside copies; two rules
matching the same text in one file are one copy. Filtered lists say how many
rows match out of this page's total, or **No Matches**; **Clear Filter**
brings all rows back. The inspector starts hidden to leave space for the list
and opens when you select an item. Its toolbar button, or **View > Show
Inspector** (Option-Command-I), can show or hide it at any time.

Every toolbar button is also in the menu bar: **File > Stop Scan**
(Command-Period) and **File > Copy Summary**. The **Item** menu has **Show in
Finder**, **Copy Path** (Option-Command-C), **Set Aside** and **Move to Worth
Reviewing** for the items selected in the list.

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
finding that is not fixed. In Set Aside, you can also select several findings
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
choices. When it needs room for another, it forgets the oldest choices about
findings no longer on its list, so such a credential found again appears in
Worth Reviewing.

**Keeping It Here on Purpose** covers one file. The same credential turning
up elsewhere is still reported. It covers the credential in that file
whichever checks found it there, as GitHub CLI's check and the general token
check both do in `~/.config/gh/hosts.yml`, and **Move to Worth Reviewing**
returns it for each. It still applies if you change the value in
that file, and ends if the file becomes readable by others, if a different kind
of credential appears there, or after six months. For npm, RubyGems and Bundler
registry entries, it covers that entry's scope, not a new scope in the same file.

An update that removes unsafe registry labels clears earlier personal choices
for npm, RubyGems and Bundler, so those findings may need review again. Old
labels are removed even from fixed history. An old unresolved entry whose scope
cannot be recovered can remain beside newly found entries until a full recheck
finds none of that credential kind in its file; it is not marked fixed merely
because its label was removed.

Earlier versions listed a token twice when a sign-in file's own check and the
general token check both found it in that file, as in `~/.npmrc`; it is now
one item, which shows the file's own check's steps unless only that copy has
been set aside. A token in `~/.config/gh/hosts.yml` shows GitHub CLI's steps
at High, the general token check's risk, though GitHub CLI's check rates it
Medium. Any item shows the highest risk among its findings that still need a
decision, or, when none does, among those set aside, or else the fixed ones.
A choice made earlier at the token check's listing (any
reason but
**Keeping It Here on Purpose**) now covers both. One made at the file's own
listing still covers that copy only, so the item stays in Worth Reviewing
until the other copy is set aside too, as choosing **Keeping It Here on
Purpose** for the item does. A file holding several credentials of
one kind, such as a Kubernetes config with several tokens, now lists each, and
one not listed before may be reported as new once.

**Expected by your organization** appears when a managed setting from your
organization lists the finding's rule and file. It covers only that file; a
different kind of credential there is still reported. **Move to Worth
Reviewing** reviews it anyway, and it stays in Worth Reviewing until your
organization's list changes.

Setting an item aside moves it out of Worth Reviewing into **Set Aside**, under
Findings in the sidebar. You stay in Worth Reviewing. The inspector of a
set-aside finding shows your reason under **Set Aside**, with **Move to Worth
Reviewing** to undo it later. **Show Details** explains which copies the reason
covers and when the finding needs review again. If you keep just one copy of a
credential, the other copies remain in Worth Reviewing.

Setting an item aside never stops it being found or counted in scan results,
saved reports or copied summaries. The counts under the window's title still
include it ("3 to review, 5 set aside"). To leave a folder out, choose **Stop
Checking** followed by the folder's name. It then appears in every summary as
not checked, and in Settings under Places to Check as Skipped, where
**Include Again** brings it back. Known sign-in
files in it, and
the files directly in an AI tool's own folder, are still read by a scan and by
the weekly pass, though not when they change. Nothing inside a scanned folder
can silence the scanner: there is no ignore file or inline comment, by design.

A scan in the app, and each automatic full pass as it ends, look at each
pending item's own file again. When the file is gone or no longer matches, the
item is marked fixed, even if the scan could not read everything else, but not
by a scan you stop with **Stop Scan**. In a folder you stopped checking, an
item is looked at again only when a scan still checks its file for it, so other
items there stay open, even after you remove the credential, until you choose
**Include Again** and scan. A file on a drive, network share or disk image that
is not connected is not gone: its item stays open until the volume is back and
the file can be looked at. The app cannot tell one volume from another mounted
at the same place, so a second drive mounted under the first one's name reads
as the file being gone. Fixed does not mean other copies are gone or that the
credential was revoked. A fixed item stays in Worth Reviewing, greyed, with
**Fixed** beside its name.

The app keeps pending review in owner-only local storage at
`~/Library/Application Support/dev.loosekeys.desktop/state.json`. It stores
file paths, added scan folders, rule identifiers, keyed fingerprints, consent,
and review choices, not credential values. Your answer about update checks is also kept in
`update-check.json` beside it. The directory uses mode `0700`; the files use
`0600`. The CLI does not use this review state. Earlier versions kept it in
`~/.loose-keys-review`; the app moves it from there on first start, unless
the new folder already holds state.

#### Expected findings set by MDM

An organization can list findings its own tools create on purpose, so they
start out in Set Aside instead of Worth Reviewing. Deliver a configuration
profile with a payload of type `dev.loosekeys.desktop` holding the key
`ExpectedFindings`: an array of dictionaries, each with `rule` (an id from
`loose-keys --list-rules`) and `path` (`~/` and the file's path inside the
home folder, plain ASCII, one file per entry). The first 32 entries are used.
The app reads the key only from a managed value; a plist in
`~/Library/Preferences` is ignored.

```xml
<key>ExpectedFindings</key>
<array>
  <dict>
    <key>rule</key><string>key.ssh.private</string>
    <key>path</key><string>~/.safe-chain/certs/ca-key.pem</string>
  </dict>
</array>
```

Expected findings are still found and counted, and stay in saved reports and
copied summaries. The background helper follows the list the app last read, so
a changed profile takes effect the next time the app opens. The `loose-keys`
command does not read the list: scripts that collect its reports apply the same
rule and path pairs themselves.

### Background helper and notifications

Checks react to filesystem events. Busy files, work limits, sleep, Low Power
Mode and macOS permission prompts can delay detection. Added folders and
drives are included in one-time scans, not watched by the helper.

Folders added with **Add Folder or Drive…** in Settings, or dropped on the
Settings window, are kept for later launches and manual scans until you remove
them. Up to eight are saved. Disconnected drives
stay listed; their unavailable paths are listed under **Show Places Not
Checked** rather than silently removed. An older app or helper can forget these saved folders
when it writes its state, so check the folder list after downgrading.

Automatic scanning is done by a separate helper with no window or Dock icon.
Giving consent registers it with macOS as a launchd job, which starts it at
login and restarts it if it stops unexpectedly. It checks a file when it
changes, works through the whole home folder in short slices at low priority,
repeats that pass weekly, and marks an item fixed when its file no longer
matches. Closing the window quits the app, unless it is in the menu bar, and
quitting the app does not stop the helper. **Pause Scanning** in Settings
stops its checks; turning **Scan Automatically** off, on the Overview or in
Settings, also removes the launchd job. Settings shows when the helper last
checked a file and last finished a full pass.

If automatic scanning could not read some places, **Show Places Not Checked** on
the Overview lists the saved paths and reasons. Opening this list does not run
another scan. It is dated to the last completed
automatic full pass; later file or permission changes do not rewrite that
result. Manual-scan details are listed separately, and saved reports still
contain only the manual scan. The automatic list keeps up to 4096 paths with
their reasons, within 512 KiB, and says when it is incomplete. Older versions saved
only the count; their details become available after the next automatic full
pass. A scan in the app keeps up to 4096 places not checked; when there are more,
the last of them is `~/` with the reason `scan-limit`.

The build signs ad hoc unless `LOOSE_KEYS_SIGN_IDENTITY` names a
code-signing identity. An ad-hoc identity changes with every build; an Apple
Development identity stays the same, so sign with one from the first install
if you will rebuild. `security find-identity -v -p codesigning` lists yours:

```sh
LOOSE_KEYS_SIGN_IDENTITY="Apple Development" sh gui/build-macos.sh
```

If registering the helper fails, the app shows an error and keeps your
consent, and the status still says whether the helper is running. While it
is not running, Settings offers **Restart Helper** to try again.

A new finding worth reviewing, or one whose credential changed or whose file
became readable by others, can produce one grouped alert. Stored sign-ins and
scan gaps do not alert, an unresolved item does not alert again across scans
or restarts, and nothing is sent while the app is in front.

### Menu bar

**Show in Menu Bar**, in Settings, is on until you turn it off. The key in the menu bar
has a dot while items are open in Worth Reviewing or the list is full, and is
a warning triangle when the list cannot be read. A key with no dot means
nothing is open in what was checked, or the list is still being read, not
that nothing is exposed. Its menu shows the count and the state of automatic
scanning, and opens the window or Settings; it changes nothing. Before any
check, with nothing on the list, the menu says **No scan this session**, or
**Checking existing files…** while automatic scanning makes its first pass,
instead of a count.

While it is on, closing the window leaves the app in the menu bar, with no Dock icon
until a window opens. With automatic scanning also on, the app is in Login
Items and opens at login in the menu bar; turning either off removes it.
Quit lasts until the next login.

### Updates

After your first scan, or automatic scanning's first full pass, Loose Keys
asks, at the bottom of the Overview, whether it may check for updates. If
you allow it, the app asks GitHub for the latest release when it starts and
once a day while it is open. GitHub sees your IP address and that
Loose Keys checked; nothing about your files or findings is sent. A newer
version appears at the bottom of Overview, and **Download** opens its release
page. Loose Keys never installs anything: download and replace the app
yourself.

**Check for Updates…**, in the Loose Keys menu, checks once whatever the
setting and shows the answer in the main window, opening it if it is closed.
Turn automatic checks on or off in Settings. The `loose-keys`
command and the background helper never go online.

### Removing Loose Keys

1. In Settings, turn off **Show in Menu Bar** and **Scan Automatically**.
   This removes the app from Login Items, stops the helper and removes its
   launchd job.
2. Quit the app and move it to the Trash. If you linked the `loose-keys`
   command, remove the link: `sudo rm /usr/local/bin/loose-keys`.
3. Delete `~/Library/Application Support/dev.loosekeys.desktop`, and
   `~/.loose-keys-review` if an earlier version left one.
4. Optionally, remove the window sizes macOS saved and the folder access you
   granted: `defaults delete dev.loosekeys.desktop` and
   `tccutil reset All dev.loosekeys.desktop`.

macOS keeps its own record of the helper after step 1, and no command removes
one app's record. Whether deleting the app removes it is unverified. While it
remains, a later install of a build with a different signature can have its
helper refused.

## Supported checks

- possible password-export CSV and private-key headers recursively across your
  home directory, regardless of extension (including renamed files);
- unencrypted Bitwarden JSON exports of a personal vault that hold login
  passwords;
- Docker registry passwords and tokens stored in `~/.docker/config.json`
  (`auth`, `identitytoken` and `registrytoken` fields); the same fields in
  `~/.config/containers/auth.json` and
  `~/Library/Preferences/helm/registry/config.json` are also checked;
- AWS access keys in `~/.aws/credentials`;
- HTTP(S) username/password URLs in `~/.git-credentials`;
- `user:password` pairs, and tokens in a known issuer format, inside remote
  URLs in each repository's `.git/config` (nothing else in a `.git` folder is
  read);
- GitHub CLI `oauth_token` fields in `~/.config/gh/hosts.yml`;
- npm auth, token and password fields in `~/.npmrc`;
- service tokens in about 140 known issuer formats (AWS, GitHub, GitLab, OpenAI,
  Anthropic, Google Gemini, Stripe, Slack, npm, PyPI, Cloudflare, Vercel and
  more) and Slack and Discord webhook URLs, in the first 4 KiB of any file,
  and anywhere in `.env*`, `*.env`, `.envrc`, `.dev.vars`, `secrets.toml`,
  `*.tfvars`, shell startup and history files. Stripe test-mode keys are listed
  at low risk;
- AI agent records: the folders where Claude Code, Codex, Gemini, Cursor,
  Continue, Copilot, Cline, Roo Code, Windsurf, OpenCode and Goose keep session
  transcripts and logs, and VS Code's workspace storage, are read in full for
  tokens, up to 256 MiB per file (`--list-rules` has each folder);
- variables named like secrets and set to a value in `.env*` and shell files;
- cloud and infrastructure: Google service-account key files anywhere, kubeconfig
  credentials in `~/.kube` and in a kubeconfig saved anywhere else, secrets in
  Terraform state files (`*.tfstate`), passwords in dbt and Snowflake client
  configs, rclone's saved passwords and keys, 1Password export files (`.1pux`),
  Terraform and Vault tokens, Azure service principal secrets, and
  the stored sign-ins of gcloud, the Azure CLI and the AWS CLI (listed, not flagged);
- package registries and build tools: project and home `.npmrc`, Yarn, pnpm,
  `.pypirc`, Poetry, Cargo, RubyGems, Bundler, Composer, Maven, Gradle, and
  passwords inside URLs in Git and pip config;
- other developer files: `.netrc`, `.pgpass`, `.my.cnf`, GnuPG private keys,
  FileZilla and DBeaver saved passwords, VPN profiles with an embedded key, and
  the stored sign-ins of about twenty deploy and AI command-line tools;
- literal secrets in MCP server configs and AI tool settings files, including
  ones written with comments (Zed, VS Code, opencode), and OAuth token files
  such as mcp-remote keeps in `~/.mcp-auth` (listed, not flagged);
- browsers: whether Chromium-family and Firefox-family profiles hold saved
  passwords or payment cards. Only a count is read from the database file,
  and nothing is decrypted; a table longer than one page is counted as
  "many". A database the scanner cannot read (truncated, UTF-16, WITHOUT
  ROWID tables or overflow pages) is listed as not checked, as is one with
  pending changes in its `-wal` or `-journal` file, which an open browser may
  have. A leftover journal can keep it that way after the browser closes. A
  crafted file, or damage in a part the reader skips, can still give a wrong
  count;
- crypto wallets: listed wallet extensions and desktop wallet folders (reported
  by presence, without reading their contents), and recovery phrases written
  into files. The phrase heuristic skips sorted word lists, repetitive
  phrases and two common public 12-word BIP-39 test vectors; it does not
  validate checksums or wallet use;
- Telegram Desktop's session folder, KeePass databases, and password-looking
  lines in `.txt` and `.rtf` notes.

`loose-keys --list-rules` prints every rule and where it looks.

Each finding has a risk level and numbered steps for dealing with it. The
summary also says what a finding concerns, such as the AWS profile or registry
host; the JSON report leaves that out and names only the kind of token. Not
covered: browser cookies and sessions, Safari, Notes, the Keychain, images and
password-manager vaults. The rules for known files read simple literal fields
at the listed paths: not full YAML or INI syntax, not a config kept somewhere
else, and not a reference or an environment placeholder.

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
media library or other apps' data in the scanner's name. A known sign-in
location inside them, such as Telegram's App Store copy, is still read, and
macOS may ask then. Where a repository's
`.git` is a file pointing elsewhere (a worktree or submodule) or a link, it is
not followed. Repeat `--select DIR` to add folders or mounted drives;
explicitly selecting an excluded directory scans that root, while exclusions
still apply below it. Relative paths are accepted, but `..` and symlinked path
components are not followed. Where your home folder is reached through a link,
a path through that link, as the shell writes `~/notes`, names the folder in
your home.

Both text and JSON reports state the requested roots, exclusions and detection
limits. Access failures, cloud-only candidates, unavailable roots and work
limits appear under `not_checked` and make the scan partial. The limits:

- discovery: 64 folder levels, 10,000 entries per folder and 100,000 entries
  per root. It is breadth-first, with the home's `Library`, `Movies`, `Music`
  and `Pictures` last, so one large folder cannot use up the budget before the
  rest is seen;
- reads: 4 KiB for a header, 1 MiB for a JSON or config file;
- matches: each rule lists a fixed number of matches per file. When more are
  omitted, the listed findings stay and a `scan-limit` gap makes the scan
  partial;
- agent records: 16 levels deep, 50,000 entries per tree, 256 MiB per file
  and 50 different tokens listed per file. A larger file is a `too-large`
  gap, and a record with more tokens a `scan-limit` gap. A deeper folder is
  reported once; added as its own root, only the first 4 KiB of its files are
  read;
- time: the app stops a scan after 30 seconds, once the file it is reading is
  finished, or when you press **Stop**, and gives one agent record at most 60
  seconds. The command line has no time limit: stop it with Control-C.

These are work limits: a slow filesystem call can still hold a scan. Known
credential locations are checked before discovery and keep their own limits.
If results show a work limit, select an omitted subfolder as another root:
each `--select` root gets its own budget and depth start. `scan --limits`
prints what is not detected.

