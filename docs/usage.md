# Usage and detection limits

[Project README](../README.md) · [Documentation index](README.md)

## The app

On the first page, click **Scan Automatically**. A helper then checks your
home folder on its own, and its findings appear without a manual scan.
If macOS requires approval, Overview tells you where to give it. Allow
notifications separately if you want alerts while the app is closed.

For a detailed point-in-time report, click **Scan Now**. The sidebar lists
what is worth reviewing, the sign-ins that are stored, and the places that
could not be checked. Select a finding to see what it is, why it matters and
what to do. **Export** saves the full report or a counts-only file, and copies
the text summary. Opening the app turns on neither automatic scanning nor
notifications.

Before a scan or turning on automatic scanning, the app asks macOS for
Desktop, Documents and Downloads, one at a time. A folder you deny is listed
under **Not Checked**; the rest are still checked. **Cancel Preparation**
stops once the open prompt is answered. Other protected folders may still
prompt later. Full Disk Access is not needed.

The app never writes over a file. If you choose to replace one when saving,
the app writes the new file beside it and then moves the old one to the Trash.
File names are shown in escaped form, and the app acts ("Copy Path", "Show in
Finder") only on plain names. A copied path stays on this Mac's clipboard.

Worth Reviewing has one item for a credential, however many rules or files
found it. The saved report and the copied summary list each finding, so their
count can be higher; the Overview says so when it is.

### Reviewing findings

Findings that do not need fixing can be set aside (**Set Aside…**), for one of
four reasons:

- **Not a Password or Key**
- **Used Only for Testing**
- **No Longer Works**
- **Keeping It Here Intentionally**

The first three cover matching copies wherever they are stored. If a password
or key is replaced, the new one appears in Worth Reviewing. For **Not a Password
or Key**, changed text appears there if it is flagged again. A finding set
aside under the earlier combined reason, for testing or no longer working,
stays set aside and is shown as a previous choice.

**Keeping It Here Intentionally** is about one place. The same credential turning
up elsewhere is still reported. It survives rotating the value in place, and
ends if the file becomes readable by others, if a different kind of credential
appears there, or after six months.

Setting an item aside moves it out of Worth Reviewing into **Set Aside**, under
Findings in the sidebar. You stay in Worth Reviewing. The inspector of a
set-aside finding shows your reason under **Set Aside**, with **Move to Worth
Reviewing** to undo it later. **Show Details** explains which copies the reason
covers and when the finding needs review again. If you keep just one copy of a
credential, the other copies remain in Worth Reviewing.

Setting an item aside never stops it being found or counted in scan results,
saved reports or copied summaries. The counts under the window's title still
include it ("3 to review, 5 set aside"). A folder can be left out (**Stop
Checking** and the folder's name); it then appears in every summary as not
checked, and Not Checked can include it again. Known sign-in files in it, and
the files directly in an AI tool's own folder, are still read by a scan and by
the weekly pass, though not when they change. Nothing inside a scanned folder
can silence the scanner: there is no ignore file or inline comment, by design.

Every check looks at each pending item's own file again. When the file is gone
or no longer matches, the item is marked fixed, even if the rest of the scan was
incomplete. A file on a drive, network share or disk image that is not connected
is not gone: its item stays open until the volume is back and the file can be
looked at. The app cannot tell one volume from another mounted at the same
place, so a second drive mounted under the first one's name reads as the file
being gone. Fixed does not mean other copies are gone or that the credential
was revoked. A fixed item stays in Worth Reviewing, greyed, with **Fixed**
beside its name.

The app keeps pending review in owner-only local storage at
`~/Library/Application Support/dev.loosekeys.desktop/state.json`. It stores
file paths, rule identifiers, keyed fingerprints, consent, and review choices,
not credential values. The directory uses mode `0700`; the file uses `0600`.
The CLI does not use this review state. Earlier versions kept it in
`~/.loose-keys-review`; the app moves it from there on first start, unless
the new folder already holds state.

### Background helper and notifications

Checks react to filesystem events. Busy files, work limits, sleep, Low Power
Mode and macOS permission prompts can delay detection. Added folders and
drives are included in one-time scans, not watched by the helper.

Automatic scanning is done by a separate helper with no window or Dock icon.
Giving consent registers it with macOS as a launchd job, which starts it at
login and restarts it if it stops unexpectedly. It checks a file when it
changes, works through the whole home folder in short slices at low priority,
repeats that pass weekly, and marks an item fixed when its file no longer
matches. Closing the window quits the app, unless it is in the menu bar, and
quitting the app does not stop the helper. **Pause Scanning** stops its
checks; turning **Scan Automatically** off also removes the launchd job.

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
scanning, and opens the window or Settings; it changes nothing.

While it is on, closing the window leaves the app in the menu bar, with no Dock icon
until a window opens. With automatic scanning also on, the app is in Login
Items and opens at login in the menu bar; turning either off removes it.
Quit lasts until the next login.

### Removing Loose Keys

1. In Settings, turn off **Show in Menu Bar** and **Scan Automatically**.
   This removes the app from Login Items, stops the helper and removes its
   launchd job.
2. Quit the app and move it to the Trash.
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
- Docker registry passwords stored inline in `~/.docker/config.json`;
- AWS access keys in `~/.aws/credentials`;
- HTTP(S) username/password URLs in `~/.git-credentials`;
- `user:password` pairs, and tokens in a known issuer format, inside remote
  URLs in each repository's `.git/config` (nothing else in a `.git` folder is
  read);
- GitHub CLI inline `oauth_token` fields in `~/.config/gh/hosts.yml`;
- npm inline auth/token/password fields in `~/.npmrc`;
- service tokens in about 90 known issuer formats (AWS, GitHub, GitLab, OpenAI,
  Anthropic, Stripe, Slack, npm, PyPI, Cloudflare, Vercel and more) in the first
  4 KiB of any file, and anywhere in `.env*`, `*.env`, `.envrc`, `.dev.vars`,
  `secrets.toml`, `*.tfvars`, shell startup and history files. Stripe test-mode
  keys are listed at low risk;
- AI agent records: the folders where Claude Code, Codex, Gemini, Cursor,
  Continue, Copilot, Cline, Roo Code, Windsurf, OpenCode and Goose keep session
  transcripts and logs, and VS Code's workspace storage, are read in full for
  tokens, up to 256 MiB per file (`--list-rules` has each folder);
- variables named like secrets with literal values in `.env*` and shell files;
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

Each finding has a risk level and numbered steps to remove the exposure. The
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
as not checked. It does not determine whether a credential is valid or
authorized. An empty report means none of the supported patterns turned up in
the places it looked, not that the Mac is clean. A matched header can be an
empty template. A file's permission bits do not show who can actually read
it: ACLs and parent folders count too.

Discovery includes hidden folders and nested backups. It skips directories
ending in `.git`, `node_modules`, `target`, `.venv`, `venv`, `__pycache__`,
`.cache`, `Library/Caches`, `vendor`, the app's own
`Library/Application Support/dev.loosekeys.desktop`, or package download caches
(`.bun/install/cache`, `.npm/_cacache`, `.cargo/registry`,
`.rustup/toolchains`). It also stays out of the folders where macOS keeps the
data of its own apps (`Library/Calendars`,
`Library/Application Support/AddressBook`, `Library/Reminders`,
`Library/Photos`, `Photos Library.photoslibrary`) and does not open the
Contacts settings file, `Library/Preferences/com.apple.AddressBook.plist`: no
rule reads them, and for each one macOS would ask you for your calendar,
contacts, reminders or photos in the scanner's name. Where a repository's
`.git` is a file pointing elsewhere (a worktree or submodule) or a link, it is
not followed. Repeat `--select DIR` to add folders or mounted drives;
explicitly selecting an excluded directory scans that root, while exclusions
still apply below it. Relative paths are accepted, but `..` and symlinked path
components are not followed.

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

