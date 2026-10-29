# Loose Keys

Loose Keys is a Mac app that finds credentials left in plain files. It checks
your home folder and any other folders or drives you add.

It looks for password exports, private keys, API tokens, saved sign-ins, and
secrets left by AI agents. For each finding, it explains what it found and how
to deal with it.

Loose Keys works offline and never changes the files it scans.

Version 0.5.0 · MIT licensed

## Install the beta

Loose Keys requires macOS 14 or later.

1. Download the app from the [latest release](https://github.com/chuglo/loose-keys/releases/latest).
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

Choose **Scan Now** for a one-time check, or **Scan Automatically** to keep
checking after you close the window.

## Build the app

You'll need Rust 1.88 or later and Apple's command-line developer tools.

```sh
sh gui/build-macos.sh
open "target/release/bundle/macos/Loose Keys.app"
```

Move the app to Applications if you want to keep it. To make a disk image with
a drag-to-Applications shortcut, run `sh gui/package-dmg.sh`. It writes
`target/release/bundle/macos/Loose-Keys-<version>.dmg` and won't overwrite an
existing image.

## Use the command line

The app includes a `loose-keys` command for one-time scans in a terminal or
script. To make it available on your `PATH`, link it and run a scan:

```sh
ln -s "/Applications/Loose Keys.app/Contents/MacOS/loose-keys" /usr/local/bin/
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
loose-keys --list-rules                   # every rule and its advice
```

Run `loose-keys --help` for the remaining options and exit codes.

A full report contains file paths. A counts file leaves out paths, but still
shows which kinds of credentials you have. Check either file before sharing it.

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
- [License](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES)
