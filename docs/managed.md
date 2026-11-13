# Deploying to managed Macs

[Project README](../README.md) · [Documentation index](README.md)

This page covers three things: running `loose-keys` from a device-management
tool (like an MDM), the counts files it writes, and how to list findings your
organization's own tools create on purpose.

## Running from a management tool

The command checks the home folder that `HOME` names.

- When a device-management tool runs it as root, set `HOME` to the user's
  home folder. If you leave `HOME` set to root's home, the command checks
  that folder instead, and it can still report the scan as complete.
- Run as root, the command reports its `context` as `system`. Run as a user, it
  reports `user`.
- When you run it as root, `--export` and `--feedback` write only into a
  folder that root owns. Neither the folder's mode nor its access list may let
  other users write to it or change it. Its path can't contain a link or `..`.
  So `/tmp` won't work.

## Counts files

`--feedback` writes counts only, with no paths. The app's
**Save Counts Only…** writes the same file. Findings you set aside
in the app count as open in this file.

The file's `schema` is `loose-keys/feedback/1`. With `--device-id`, it's
`loose-keys/device-counts/1`, and the file also has `device_id` and
`generated_at`.

| Field | Meaning |
|---|---|
| `tool_version`, `platform`, `architecture` | The version of Loose Keys and the Mac it ran on. |
| `status` | How the scan ended. |
| `context` | `user`, or `system` when run as root. |
| `requested_roots` | How many folders the scan covered, including the home folder. |
| `excluded_by_user` | How many folders you skipped, not which ones. |
| `not_checked_by_reason` | What couldn't be checked, grouped by reason. |
| `review` | For each risk level, the findings worth reviewing (`open` and `open_by_rule`). These are the ones `--fail-on-open` checks. |
| `findings_by_rule`, `findings_by_severity` | Every finding, including stored sign-ins. |
| `findings_by_token_type` | Service tokens, grouped by type. |

## Expected findings set by MDM

An organization can list findings that its own tools create on purpose. Those
findings then start out in Set Aside instead of Worth Reviewing.

To do this, deliver a configuration profile with a payload of type
`dev.loosekeys.desktop`. The payload holds the key `ExpectedFindings`, an array
of dictionaries. Each dictionary has a `rule` and a `path`:

- `rule` is an id from `loose-keys --list-rules`.
- `path` is `~/` followed by the file's path inside the home folder. Use plain
  ASCII, and give one file per entry.

The app uses the first 32 entries in that form. If an entry names a rule this
version doesn't have, or its path is in another form, the app ignores it without
telling you. The app reads the key only when a
configuration profile sets it. It ignores the same key in a plist in
`~/Library/Preferences`.

Testing so far covers only a profile installed by hand, on a test Mac with SIP
off. Delivery from an MDM server and a user-scope profile are unverified
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

An entry covers only the rule it names. Sometimes two checks find the same
credential in one file. List an entry for each, or the item stays in Worth
Reviewing and can alert. For a token in `~/.config/gh/hosts.yml`, that means
`dev.gh.inline-token` and `secret.service-token`.

Loose Keys still finds and counts expected findings. They stay in saved reports and
copied summaries. The background helper follows the list the app last read. A
changed or removed profile takes effect when the app next opens or comes to the
front.

The `loose-keys` command doesn't read the list. So `--fail-on-open` and the counts
files treat expected findings as open. To honor the list, have a script read the
full report (`--export`) and match each finding's rule and path against it.
