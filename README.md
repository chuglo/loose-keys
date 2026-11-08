# Loose Keys

Loose Keys is a Mac app that finds credentials left in plain files. It checks
your home folder and any other folders or drives you add.

It looks for password exports, private keys, API tokens, saved sign-ins, and
secrets left by AI agents. For each finding, it explains what it found and how
to deal with it.

Loose Keys never changes the files it scans, and it goes online only to
check for a new version, if you let it.

Version 0.9.0 · MIT licensed

## Install the beta

Loose Keys requires a Mac with Apple silicon and macOS 14 or later.

1. Download the app from the [latest release](https://github.com/chuglo/loose-keys/releases/latest).
   To check the download, run `shasum -a 256` on it and compare the result
   with that file's checksum in the release notes.
2. Unzip it and move **Loose Keys** to Applications. If the release includes a
   `.dmg`, you can open it instead, drag **Loose Keys** onto its **Applications**
   shortcut, and eject the disk.
3. Open Loose Keys from Applications.

The beta isn't notarized by Apple, so macOS will block it the first time you
open it. Click **Done**:

![“Loose Keys” Not Opened, with Move to Trash and Done buttons](docs/images/not-opened.png)

Then open **System Settings › Privacy & Security**, scroll to **Security**, and
click **Open Anyway** beside the message about Loose Keys. Confirm when asked:

![Privacy & Security: “Loose Keys” was blocked to protect your Mac, with an Open Anyway button](docs/images/open-anyway.png)

Choose **Scan Now** for a first check. Afterwards, turn on **Scan
Automatically** on the Overview to keep checking after you close the window.

## Build the app

You'll need Rust 1.88 or later and Apple's command-line developer tools.

```sh
sh gui/build-macos.sh
open "target/release/bundle/macos/Loose Keys.app"
```

The build signs the app ad hoc unless `LOOSE_KEYS_SIGN_IDENTITY` names a
code-signing identity. An ad-hoc identity changes with every build, which can
stop the background helper working after a rebuild (unverified); an Apple
Development identity stays the same. If you'll rebuild, sign with one from
the first install. `security find-identity -v -p codesigning` lists yours:

```sh
LOOSE_KEYS_SIGN_IDENTITY="Apple Development" sh gui/build-macos.sh
```

Move the app to Applications if you want to keep it. To make a disk image with
a drag-to-Applications shortcut, run `sh gui/package-dmg.sh`. It writes
`target/release/bundle/macos/Loose-Keys-<version>.dmg` and won't overwrite an
existing image.

## Use the command line

The app includes a `loose-keys` command for one-time scans in a terminal or
script. To make it available on your `PATH`, link it and run a scan:

```sh
sudo mkdir -p /usr/local/bin
sudo ln -s "/Applications/Loose Keys.app/Contents/MacOS/loose-keys" /usr/local/bin/
loose-keys scan
```

The command uses the same scanner as the app, but doesn't use the app's saved
state. Findings you set aside in the app will still appear in command-line
results.

```sh
loose-keys scan --limits                  # also print what the scan can't detect
loose-keys scan --select /Volumes/Backup  # include another folder or drive
loose-keys scan --export report.json      # full JSON report
loose-keys scan --feedback counts.json    # counts only, no paths
loose-keys --list-rules                   # every rule and where it looks
```

Run `loose-keys --help` for the remaining options and exit codes. The
summary, JSON written to `-`, `--help`, `--version` and `--list-rules` go to
standard output; errors, and the usage text after a mistake in the command,
go to standard error with exit code 2.

The export file is written only when the scan ends, as a new file. If it
already exists or can't be created, nothing is written, no summary is
printed, and the exit code is 2.

A full report contains file paths. A counts file leaves out paths, but still
shows which kinds of credentials you have. Check either file before sharing it.

A counts file's `schema` is `loose-keys/feedback/1`, or
`loose-keys/device-counts/1` with `--device-id`, which adds `device_id` and
`generated_at`. It also gives `tool_version`, `platform`, `architecture`, the
scan's `status` and `context`, `requested_roots` (how many folders the scan
was asked to check, the home folder included), `excluded_by_user` (how many
folders were skipped, not which) and `not_checked_by_reason`. For each risk
level, `review` counts the findings worth reviewing (`open` and
`open_by_rule`), the ones `--fail-on-open` checks.
`findings_by_rule` and `findings_by_severity` count every finding, stored
sign-ins included, and `findings_by_token_type` counts service tokens by type.
The app's **Save Counts Only…** writes the same file, and counts findings set
aside there as open.

The command checks the home folder that `HOME` names. When a device-management
tool runs it as root, set `HOME` to the user's home folder. With root's `HOME`,
it checks root's home instead and can still report the scan as complete.
Run as root, the scan's `context` is `system` instead of `user`, and
`--export` and `--feedback` write only into a folder owned by root that
others can't write to or change, by its mode or its access list, with no
link or `..` in its path. `/tmp` doesn't qualify.

From a terminal, macOS may ask in the terminal app's name before the scan
enters protected folders such as Desktop, Documents and Downloads, and the
scan waits for your answer (unverified). Places macOS refuses are listed as
"Access denied by macOS" and make the scan partial, with exit code 1. To
include them, allow the terminal app in **System Settings › Privacy &
Security**, under **Files & Folders** (unverified), then scan again.

## Development

This repository is one Cargo workspace. The scanner is a library in `src/`,
with the `loose-keys` command on top. The app's engine is in `gui/` and links
into a Swift window.

Before making changes, read [AGENTS.md](AGENTS.md) and the
[development standards](docs/development/standards.md). All checks run
locally; see [local checks](docs/testing/local-verification.md) for the list.

- [Usage and detection limits](docs/usage.md)
- [All documentation](docs/README.md)
- [JSON report schema](schema/report-1.schema.json)
- [Reporting a security problem](SECURITY.md)
- [License](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES)
