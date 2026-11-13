# Detection and limits

[Project README](../README.md) · [Documentation index](README.md)

Look here to see whether Loose Keys checks for a kind of credential, or why a
scan missed something. The page also covers how to read results, what Loose
Keys leaves out on purpose, and the limits on a scan.

## Reading the results

A match means Loose Keys found a known format. It didn't check the credential
or test whether it works. A matched header can also be an empty template.

An empty result doesn't mean your Mac is clean. It means none of the supported
patterns turned up in the places Loose Keys looked.

A file's permission bits don't show who can actually read it. Access lists and
parent folders matter too.

Each finding has a risk level and numbered steps for dealing with it.

| Risk | What it means |
|---|---|
| High | Anyone who copies it can use it from any computer until it's revoked or expires. |
| Medium | Someone who copies it would need something more to use it, such as a password or this Mac's keychain, or it gives access to less. |
| Low | It's protected, for example by a passphrase, or it's only for testing. |

In the tables below, "Listed in" says where a finding goes. Loose Keys doesn't
flag items in Stored Sign-ins. The app lists them under **Stored Sign-ins**,
and the text summary lists them under STORED SIGN-INS. See
[What each list holds](usage.md#what-each-list-holds).

## Supported checks

Run `loose-keys --list-rules` to print every rule and where it looks. The
checks below are grouped by what they find.

### Keys and exports

Where a row says "every file", Loose Keys reads every file in your home folder,
whatever its extension. That way it finds a renamed file.

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Possible password-export CSV | every file | Worth Reviewing | the header isn't the file's first line |
| PEM or OpenSSH private key | every file | Worth Reviewing | it isn't near the start of the file (note 1) |
| PuTTY `.ppk` key | every file | Worth Reviewing | its first line isn't the header |
| Key with a passphrase | every file | Stored Sign-ins | – |
| OpenSSH key held on a security key (`ed25519-sk`, `ecdsa-sk`) (note 2) | every file | Stored Sign-ins | – |
| PGP private-key block (note 2) | every file | Stored Sign-ins | – |
| Unencrypted Bitwarden JSON export, from a personal vault or an organization | every file up to 1 MiB | Worth Reviewing | it holds no login passwords |
| 1Password export (note 2) | `.1pux` files, and `.1pif` files from 1Password 7 and earlier | Worth Reviewing | – |

1. Loose Keys finds a PEM or OpenSSH key only in the first 4 KiB, and only if
   nothing but blank lines, certificates or openssl's attributes comes before
   it. It doesn't find a key pasted under other text in a note, or written
   into code.
2. An OpenSSH security-key file is no use without the hardware. A PGP
   block's armor doesn't show whether it has a passphrase. Loose Keys finds a
   `.1pif` file by its first item.

### Developer and cloud sign-in files

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Docker registry passwords and tokens | `~/.docker/config.json`: `auth`, `identitytoken`, `registrytoken` | Worth Reviewing | – |
| Same fields as Docker | `~/.config/containers/auth.json`, `~/Library/Preferences/helm/registry/config.json` | Worth Reviewing | – |
| AWS access keys | `~/.aws/credentials`, `~/.aws/config` | Worth Reviewing | – |
| HTTP(S) username/password URLs | `~/.git-credentials`, `~/.config/git/credentials` | Worth Reviewing | – |
| Passwords and tokens in a repository's Git config | each repository's `.git/config` | Worth Reviewing | see note 1 |
| GitHub CLI `oauth_token` | `~/.config/gh/hosts.yml` | Worth Reviewing | – |
| npm auth, token and password fields | `~/.npmrc` | Worth Reviewing | – |
| Package registry and build tool credentials | project and home `.npmrc`, Yarn, pnpm, `.pypirc`, Poetry, Cargo, RubyGems, Bundler, Composer, Maven, Gradle | Worth Reviewing | – |
| Passwords inside URLs | Git and pip config, `~/.curlrc` | Worth Reviewing | – |
| Google service-account keys | anywhere | Worth Reviewing | – |
| Kubeconfig credentials | `~/.kube`, and a kubeconfig saved anywhere else | Worth Reviewing | – |
| Passwords in client configs | dbt and Snowflake | Worth Reviewing | – |
| Saved passwords and keys | rclone | Worth Reviewing | – |
| Tokens and secrets | Terraform, Vault, Azure service principal | Worth Reviewing | – |
| Terraform state values named like secrets or marked sensitive | `*.tfstate`, `terraform.tfstate*` | Worth Reviewing | the value isn't named like a secret or marked sensitive (Loose Keys doesn't read other values) |
| Saved passwords or private keys | `.netrc`, `.pgpass`, `.my.cnf`, FileZilla, DBeaver | Worth Reviewing | – |
| GnuPG private keys | GnuPG files | Worth Reviewing | – |
| GnuPG private key with a passphrase | GnuPG files | Stored Sign-ins | – |
| OpenVPN profile with a private key inside | `.ovpn` | Worth Reviewing | – |
| WireGuard config with a private key | `.conf`, in the `[Interface]` section | Worth Reviewing | – |
| Sign-ins of rclone, gcloud, the Azure CLI, the AWS CLI and about thirty deploy and AI command-line tools | their sign-in files, including `~/.azure/accessTokens.json` of older Azure CLI versions | Stored Sign-ins | – |

1. In `.git/config`, Loose Keys finds `user:password` pairs inside URLs, a
   token written alone where a URL's user name goes, and tokens in a known
   issuer format anywhere. A lone token has to be in a known issuer format, or
   be 32 or more letters and digits, with at least one of each. That's why a
   name such as `git` never matches. Loose Keys reads nothing else in a `.git` folder.

### Service tokens

In this section and the next, *variable files* means `.env*`, `*.env`,
`.envrc`, `.dev.vars*`, `secrets.toml`, `*.tfvars`, shell startup and history
files, `~/.gradle/gradle.properties`, `~/.codex/config.toml` and
`~/.config/goose/secrets.yaml`.

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Service tokens in about 140 known issuer formats (AWS, GitHub, GitLab, OpenAI, Anthropic, Google Gemini, Stripe, Slack, npm, PyPI, Cloudflare, Vercel and more), and Slack and Discord webhook URLs | the first 4 KiB of any file up to 1 MiB, and anywhere in the files in note 1 | Worth Reviewing | it's past the first 4 KiB of a file not in note 1. In a file over 1 MiB, you get a `too-large` gap instead |
| Stripe test-mode keys | as above | Stored Sign-ins, at low risk | – |
| Keys whose prefix doesn't name the service: Google API keys starting `AIza` (including Gemini keys in that form), Notion keys starting `secret_`, and Twilio, Dropbox and ElevenLabs keys | variable files, and the MCP and AI tool settings files below | Worth Reviewing | the variable or setting isn't named like a secret |

1. Loose Keys looks anywhere in these files, not only the first 4 KiB:
   variable files, the history files of psql, MySQL, redis-cli, Python,
   Node.js and irb, Aider's `.aider.chat.history.md` and
   `.aider.input.history`, and `~/.cache/huggingface/token`.

### Variables and tool settings

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Variables named like secrets and set to a value | variable files | Worth Reviewing | see [What isn't reported](#what-isnt-reported) |
| Variables of any name set to a private key or a URL with a password in it | variable files | Worth Reviewing | see [What isn't reported](#what-isnt-reported) |
| Literal secrets | MCP server configs and AI tool settings files, including ones written with comments (Zed, VS Code, opencode) | Worth Reviewing | see [What isn't reported](#what-isnt-reported) |
| OAuth token files like the ones mcp-remote keeps | `~/.mcp-auth` | Stored Sign-ins | – |

### AI agent records

Loose Keys reads the session transcripts and logs that Claude Code, Codex,
Gemini, Cursor, Continue, Copilot, Cline, Roo Code, Windsurf, OpenCode and
Goose keep, and VS Code's workspace storage. It reads them in full for tokens,
within the agent-record limits in [Limits](#limits). `--list-rules` lists each
folder.

Some folders inside them hold programs or caches: `extensions`, `plugins`,
`packages`, `bin`, `Cache`, `Code Cache` and `GPUCache`. Loose Keys doesn't
read these in full. It checks their files like any other file.

When Loose Keys recognizes base64 PNG, JPEG, GIF or WebP data, it doesn't
look for tokens inside it. It still checks the text around it, here and in
every other file it checks for tokens.

### Browsers and wallets

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Saved passwords, and payment cards in Chromium browsers | profiles of Chrome (and Chrome Beta and Canary), Brave, Edge, Arc, Chromium, Vivaldi, Opera, Opera GX, Yandex, Firefox, Waterfox, LibreWolf and Zen | Worth Reviewing | it's another browser or channel (notes 1–2) |
| Crypto wallets | listed wallet extensions in those Chromium browsers' profiles, and desktop wallet folders | Worth Reviewing | the wallet isn't listed (Loose Keys reports a wallet's presence without reading its contents) |
| Recovery phrases from the English BIP-39 word list | the first 4 KiB of a file | Worth Reviewing | see note 3 |

1. Loose Keys only counts what's in a browser's database file. It doesn't
   decrypt anything. It counts a table longer than one page as "many". A
   crafted file, or damage in a part Loose Keys skips, can still give a wrong
   count.
2. If Loose Keys can't read a database, it lists it as not checked. It does the
   same for a database with pending changes in its `-wal` or `-journal` file. An
   open browser may leave changes like that. A leftover journal can keep it
   that way after the browser closes.
3. The check skips sorted word lists, repetitive phrases and two common public
   12-word BIP-39 test vectors. It doesn't check the phrase's checksum or
   whether a wallet uses it.

### Other

| What | Where it looks | Listed in | Not found when |
|---|---|---|---|
| Telegram Desktop session | its session folder | Worth Reviewing | – |
| KeePass 2 database | every file | Stored Sign-ins | it's a KeePass 1 `.kdb` file (Loose Keys doesn't recognise those) |
| Password-looking lines | `.txt` and `.rtf` notes | Worth Reviewing | – |

## What isn't reported

Loose Keys doesn't check browser cookies and sessions, the app data macOS
protects (see [Where the scanner looks](#where-the-scanner-looks)), the
Keychain, images or password-manager vaults. It doesn't open archives.

For known files, Loose Keys reads simple fields at the listed paths. It doesn't
understand full YAML or INI syntax. It doesn't follow a config kept somewhere
else, or resolve a reference or an environment placeholder. Loose Keys reads
JSON MCP server configs and settings files up to 6 levels deep.

When only a value's name marks it as a secret, Loose Keys doesn't report it in
these cases:

| Value not reported | In which files | Example |
|---|---|---|
| Shorter than 8 characters (12 in MCP server configs and JSON settings files, 16 in OAuth token files), or looks like a sample or placeholder | `.env*`, shell, MCP and AI tool settings files | – |
| Its name says the key is public or publishable | variable files, and an MCP server's environment and headers | – |
| Looks like a file path (note 1) | variable files, and an MCP server's environment and headers | `/app/.ssh/id_rsa`, `.ssh/id_ed25519`, `id_ed25519_work` |
| Names another variable named like a secret | variable files | `OPENAI_API_KEY` |
| Repeats its variable's name or a word of it, or ends in `...` | variable files | `POSTGRES_PASSWORD=postgres` |
| A password in a URL that is shorter than the limits above, looks like a placeholder, is `password`, or repeats the URL's user name | variable files | – |
| A variable whose prefix tells a framework to build its value into the app (note 2) | variable files | `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`, `PUBLIC_`, `GATSBY_` |
| A 1Password reference | every file | `op://…` |
| A value sops encrypted | every file | `ENC[…]` |
| A note password that is a single lowercase word | every file | – |

1. A value counts as a file path if any of these is true:
   - It starts with `~/`, `./`, `../`, `$HOME/` or a folder at the root of a
     Mac such as `/Users/`.
   - It's a path of lowercase folders from `/`, such as `/app/.ssh/id_rsa`.
   - It's that kind of path starting from a hidden folder, such as
     `.ssh/id_ed25519`. It's also that kind of path starting from a `keys`,
     `certs`, `secrets`, `ssl` or `tls` folder.
   - It's an SSH key's file name, such as `id_ed25519_work`.
   - It ends in a key or credential file extension. Those are `.json`, `.pem`,
     `.key`, `.p8`, `.p12`, `.pfx`, `.crt`, `.der`, `.jks`, `.keystore`, `.gpg`
     and `.asc`.
2. With such a prefix, Loose Keys only finds a secret in a known issuer format,
   a private key or a password in a URL.

## Where the scanner looks

Loose Keys doesn't run credential helpers, contact services or show secret
values. It doesn't determine whether a credential is valid or authorized.

It doesn't follow links, with one exception. A known sign-in location such
as `~/.npmrc` or `~/.aws` can be a link to somewhere else inside your home
folder, the way dotfile managers set things up. Then Loose Keys checks the
real file and reports it at its real path. It reports a link that leaves the home folder as
not checked. When the command runs as root, it follows none of these links and
reports each one as not checked.

As Loose Keys walks your folders, it includes hidden folders and nested
backups. It passes over links and special files without listing them as not
checked. It doesn't follow a repository's `.git` when that's a file pointing
elsewhere (a worktree or submodule) or a link. It skips the folders and files
below. It matches them by the end of their path:

| Skipped | Why |
|---|---|
| Build, cache and version-control folders, such as `.git` and `node_modules`, and the app's own data | Loose Keys still reads `.git/config`, as listed above |
| Package download caches and installed language versions, such as `.npm/_cacache` | they ship their own test keys, and Loose Keys won't find a key of yours kept in one |
| Data of macOS's own apps and other apps, such as Photos and `Library/Containers`, and the TV and Music libraries and settings | no rule reads them, and macOS would ask you to let Loose Keys see your calendar, contacts, reminders, photos, media library or other apps' data |
| Folders in `Library` that macOS protects, such as `Mail`, `Messages` and `Safari`, and Messages' and Home's settings files | macOS refuses them without Full Disk Access, so Loose Keys would list them as not checked after every scan |
| The Trash and unsaved document autosaves | macOS protects them even though they hold your own files, so Loose Keys won't find a key file you deleted but haven't emptied from the Trash |

Here are the full paths, row by row:

- Build, cache and version-control folders: `.git`, `node_modules`, `target`,
  `.venv`, `venv`, `__pycache__`, `.cache`, `Library/Caches`, `vendor`, and the
  app's own `Library/Application Support/dev.loosekeys.desktop`.
- Package caches and language versions: `.bun/install/cache`,
  `.npm/_cacache`, `.cargo/registry`, `.rustup/toolchains`, `go/pkg/mod`,
  `.pyenv/versions`, `.rbenv/versions`, `Library/pnpm/store`.
- App data: macOS's own apps' data (`Library/Calendars`,
  `Library/Application Support/AddressBook`, `Library/Reminders`,
  `Library/Photos`, `Photos Library.photoslibrary`) and other apps' data
  (`Library/Group Containers`, `Library/Containers`). Also the TV and Music
  libraries (`Movies/TV`, `Music/Music`). Loose Keys doesn't open the
  Contacts, TV and Music settings files either
  (`Library/Preferences/com.apple.AddressBook.plist`,
  `Library/Preferences/com.apple.TV.plist`,
  `Library/Preferences/com.apple.Music.plist`).
- Protected folders in `Library`: `Mail`, `Messages`, `Safari`, `Cookies`,
  `HomeKit`, `IdentityServices`, `Suggestions`, `Biome`,
  `PersonalizationPortrait`, `Accounts`, `Sharing`, `Shortcuts`, `StatusKit`,
  `CoreFollowUp`, `DuetExpertCenter`, `Metadata/CoreSpotlight`,
  `Metadata/com.apple.IntelligentSuggestions`, `Assistant/SiriVocabulary`,
  `DoNotDisturb`, `Trial`, `AppleMediaServices`, `IntelligencePlatform`,
  `com.apple.aiml.instrumentation`, `Weather`, `Daemon Containers`,
  `ContainerManager`, `WebDriver`.
- Protected folders in `Library/Application Support`: `CallHistoryDB`,
  `CallHistoryTransactions`, `Knowledge`, `com.apple.TCC`, `MobileSync`
  (iPhone and iPad backups), `com.apple.sharedfilelist`,
  `com.apple.avfoundation/Frecents`, `FileProvider`, `CloudDocs/session/db`,
  `FaceTime`, `DifferentialPrivacy`.
- Protected settings files in `Library/Preferences`: Messages' and Home's
  (`com.apple.MobileSMS.plist`, `com.apple.madrid.plist`,
  `com.apple.homed.plist`, `com.apple.homed.notbackedup.plist`).
- The Trash and autosaves: `.Trash` and `Library/Autosave Information`.

Loose Keys still lists any other place macOS refuses as not checked. It still
reads a known sign-in location inside any of these folders, such as Telegram's
App Store copy. macOS may ask for access when it does. If you select one of
these folders, Loose Keys scans it as a root, meaning a folder or drive the
scan starts from: your home folder, or one you add. It still skips any of
these folders inside it.

## Choosing folders on the command line

| Option | What it does | What it refuses, and notes |
|---|---|---|
| `--select DIR`, repeated | adds folders or mounted drives | a selected folder reached through a link is listed as not checked, so give its real path |
| `--exclude DIR`, repeated | leaves out up to 32 folders | refuses the home folder or a folder above it, also when spelled under `/System/Volumes/Data`. Also refuses a file, a link and a path through a link. Accepts a path it can't look up, such as a folder that isn't there or one inside a folder you can't open |
| Both | take relative paths | refuse a path containing `..`. Loose Keys uses the disk's spelling for a folder given in another case, such as `~/documents` for `~/Documents` |

Leaving a folder out doesn't make the scan partial. If you also select a
folder inside it, or select the same folder, Loose Keys leaves that out too.
Neither the text nor the JSON report lists it among the folders scanned. As
in the app ([Choosing folders](usage.md#choosing-folders)), Loose Keys still
reads known sign-in files there, such as `~/.aws/credentials`.

Your home folder might be reached through a link. If so, a path through that
link, such as `~/notes` as your shell writes it, still points to the folder in
your home.

The text and JSON reports both list the folders you asked to scan and the
folders you left out. The JSON report also lists the detection limits. The command's
text summary prints them only with `--limits`. **Copy Summary** always includes
them.

## Places not checked: reasons

When Loose Keys can't check a place, the report lists it under `not_checked`
with one of these reasons. The scan then counts as partial. The window and the
text summary each show the reason in their own words.

| Reason | Window heading | Summary label | Meaning | What to do |
|---|---|---|---|---|
| `permission-denied` | No Access | Access denied by macOS | file permissions or macOS privacy settings blocked it | allow access, then scan again |
| `unreadable` | Couldn't Be Read | Could not be read | reading failed, or the file changed while Loose Keys read it (note 1) | quit the browser, or wait for gcloud to finish (unverified), and scan again (note 1) |
| `too-large` | Too Large to Check | Too large to check | the file is bigger than one of the read limits below | Loose Keys didn't read the file, so check it yourself |
| `cloud-only-file` | Stored Only in the Cloud | Cloud-only, not downloaded | the folder holds files kept only in the cloud, and they aren't downloaded | download them, then scan again |
| `scan-limit` | Only Partly Checked | Scan limit reached | a work limit below was reached | add the folder as another root, as the end of [Limits](#limits) explains |
| `symlink` | Link Not Followed | Not followed: link outside the home folder (note 2) | a known sign-in location is a link, and Loose Keys doesn't follow it (note 2) | check the real file yourself (note 2) |

1. `unreadable` also covers a known file in a form Loose Keys doesn't read,
   and a selected folder that's missing or reached through a link. It also
   covers a browser database, or gcloud's `credentials.db`, with pending
   changes. For a selected folder reached through a link, select its real path.
   An AI agent record gets this gap too when image data in it turns out to
   be damaged after Loose Keys has skipped part of it.
2. A `symlink` gap means the link leads outside the home folder, or the
   command ran as root. As root, Loose Keys follows no link, and the summary
   label is "Not followed: link (no link is followed as root)". Run the scan as
   your own user, and Loose Keys follows links inside the home folder.

## Limits

| Limit | Value | When it's reached |
|---|---|---|
| Walking folders | 64 folder levels, 10,000 entries per folder and 100,000 entries per root | Loose Keys stops there, and a `scan-limit` gap makes the scan partial. Note 1 has the order it visits folders in |
| Header reads | 4 KiB | – |
| Whole-file reads | 1 MiB, for a file read whole, such as a config, shell history, note, Terraform state or browser database | a larger file is a `too-large` gap (note 2) |
| Matches | some rules list only the first 100 matches in a file, and the notes check lists only the first 20 lines | after the first 100, the service-token check lists only new tokens, up to 100 different ones. If any are still left out, Loose Keys keeps what it listed, and a `scan-limit` gap makes the scan partial |
| Findings | 4096 in an app scan | the scan stops and a `scan-limit` gap makes it partial. The command line has no such limit |
| Agent records | 16 levels deep, 50,000 entries per tree, 256 MiB per file and 50 different tokens listed per file | A larger file is a `too-large` gap. A record with more tokens is a `scan-limit` gap. A deeper folder is reported once (note 3) |
| Time | the app stops a scan after 30 seconds, and gives one agent record at most 60 seconds | the app stops once it finishes the file it's reading, or when you press **Stop Scan**. The command line has no time limit, so stop it with Control-C |

1. Loose Keys goes through folders one level at a time, and leaves `Library`,
   `Movies`, `Music` and `Pictures` in your home for last. That way one large
   folder can't use up the budget before Loose Keys sees the rest.
2. There's one exception. If a `.txt`, `.rtf`, `.conf` or `*_tokens.json` file
   is over 1 MiB and nothing matches in its first 4 KiB, Loose Keys passes over
   it. It doesn't list it as not checked. Loose Keys confirms a token, Bitwarden
   export, Google service-account key, kubeconfig or WireGuard config by
   reading the whole file. So when one of these over 1 MiB matches in its first
   4 KiB, you get a `too-large` gap, not a finding.
3. Loose Keys still reaches a deeper folder, unless it's in a skipped folder
   such as `Library/Caches`. Loose Keys checks that folder's files like any
   other file.

These are work limits, so a slow filesystem call can still hold up a scan.
Loose Keys checks known credential locations before it walks your folders. They have
their own limit: Loose Keys lists up to 10,000 entries in each known folder.

If the results show a root reached its entry or depth limit, add a subfolder it
missed as another root, with `--select` or **Add Folder or Drive…** in
Settings. Each root gets its own budget, and depth counts from that root. That
doesn't help a folder with more than 10,000 entries. The limit applies
whichever root Loose Keys reaches it from. Which entries it keeps depends on
the order the filesystem lists them in.
