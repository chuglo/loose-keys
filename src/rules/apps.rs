//! Apps whose local data lets a thief sign in as the user: chat sessions,
//! file-transfer and VPN profiles, password databases and password notes.

use super::*;

pub const TELEGRAM_SESSION: Rule = Rule {
    id: "app.telegram.session",
    category: "app-session",
    kind: "review",
    severity: "medium",
    title: "Telegram session stored on this Mac",
    explanation: "Telegram Desktop keeps its signed-in session in this folder. Nothing in it was read; the folder being there is the finding.",
    reason: Some("A copied session may let someone access the account without signing in again. The scanner does not check whether a local passcode protects it."),
    next_step: Some("Set a local passcode in Telegram, and check which devices are signed in."),
    advice: Advice {
        steps: &[
            "In Telegram, open Settings > Privacy and Security > Local Passcode and set one. The stored session is then encrypted with it.",
            "In Settings > Devices (Active Sessions), end any session you do not recognize.",
            "Turn on Two-Step Verification to protect new sign-ins. If this session may have been copied, terminate it from a trusted device; enabling Two-Step Verification does not terminate existing sessions.",
        ],
        link: None,
    },
    // The direct download, and the App Store build's container.
    targets: &[
        Target::Present(
            "Library/Application Support/Telegram Desktop/tdata/key_datas",
            "Telegram Desktop",
        ),
        Target::Present(
            "Library/Containers/org.telegram.desktop/Data/Library/Application Support/Telegram Desktop/tdata/key_datas",
            "Telegram Desktop",
        ),
    ],
    matcher: Matcher::Present,
    samples: &[],
};

pub const DBEAVER_PASSWORDS: Rule = Rule {
    id: "app.dbeaver.saved-passwords",
    category: "developer-cloud",
    title: "Database passwords saved by DBeaver",
    explanation: "This is a known location for DBeaver saved credentials. The file was not read, so its contents and encryption settings were not checked.",
    reason: Some("Copied credential files may expose database access. Protection depends on the DBeaver version and security settings."),
    next_step: Some("Change the saved database passwords, and set a master password in DBeaver or stop saving them."),
    advice: Advice {
        steps: &[
            "For shared or production databases saved here, change the password on the server.",
            "Check the credential-storage protections available in your DBeaver version, or stop saving passwords on each connection.",
            "Remove connections you no longer use.",
        ],
        link: None,
    },
    targets: &[Target::Present(
        "Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json",
        "DBeaver",
    )],
    ..TELEGRAM_SESSION
};

pub const KEEPASS_DATABASE: Rule = Rule {
    id: "export.keepass-database",
    category: "password-export",
    kind: "inventory",
    severity: "low",
    title: "KeePass password database",
    explanation: "The file header matches a KeePass password database. Its contents were not decrypted, and its password or key-file protection was not checked.",
    reason: None,
    next_step: Some("Check that the master password is long and used nowhere else. Stealers copy these files and guess weak master passwords offline."),
    advice: Advice {
        steps: &[
            "Use a master password of several random words, used nowhere else.",
            "Add a key file kept on a separate device, so the database alone is not enough.",
            "Delete old copies and backups of the database you no longer need.",
        ],
        link: None,
    },
    targets: &[Target::Discovery],
    matcher: Matcher::Head(is_keepass),
    samples: &[
        (b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5\x01\x00\x04\x00synthetic", true),
        (b"\x03\xd9\xa2\x9a ordinary data", false),
    ],
};

fn is_keepass(head: &[u8]) -> bool {
    head.starts_with(b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5")
}

pub const FILEZILLA_PASSWORD: Rule = Rule {
    id: "app.filezilla.saved-password",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Server password saved by FileZilla",
    explanation: "A saved password field was found in a FileZilla configuration. Base64 encoding does not protect a password. The value was checked for presence, not decoded or tested against a server.",
    reason: Some("A program able to read this file may be able to reuse the saved credentials. Their validity was not checked."),
    next_step: Some("Change the saved passwords at each server, then protect or stop saving them in FileZilla."),
    advice: Advice {
        steps: &[
            "At each server named here, change the password, or switch the account to SSH key sign-in.",
            "In FileZilla, open Settings > Interface > Passwords and choose 'Protect passwords with a master password', or 'Do not save passwords'.",
            "Remove sites you no longer use from the Site Manager.",
        ],
        link: None,
    },
    targets: &[
        Target::File(".config/filezilla/sitemanager.xml"),
        Target::File(".config/filezilla/recentservers.xml"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: filezilla_hits,
    },
    samples: &[
        (b"<FileZilla3><Servers><Server><Host>ftp.example.invalid</Host><Pass encoding=\"base64\">c3ludGhldGlj</Pass></Server></Servers></FileZilla3>", true),
        (b"<Server><Pass note=\"a > b\" encoding = 'base64'>\n c3ludGhldGlj\n</Pass></Server>", true),
        (b"<Server><Pass>synthetic-only</Pass></Server>", true),
        (b"<Server><Pass encoding='crypt' pubkey='fixture'>c3ludGhldGlj</Pass></Server>", false),
        (b"<Server><Pass encoding = \"crypt\">c3ludGhldGlj</Pass></Server>", false),
        (b"<Server><Pass/><Pass>  </Pass><Password>synthetic-only</Password></Server>", false),
        (b"<Server><!-- <Pass>synthetic-only</Pass> --><note><![CDATA[<Pass>synthetic-only</Pass>]]></note><note>&lt;Pass&gt;synthetic-only&lt;/Pass&gt;</note></Server>", false),
        (b"<Server>\n<Host>ftp.example.invalid</Host>\n<Pass encoding=\"base64\">c3ludGhldGlj</Pass>\n</Server>\n", true),
        (b"<Server>\n<Host>ftp.example.invalid</Host>\n<Pass encoding=\"base64\"></Pass>\n</Server>\n", false),
        (b"<Server>\n<Host>ftp.example.invalid</Host>\n<Pass encoding=\"crypt\" pubkey=\"x\">c3ludGhldGlj</Pass>\n</Server>\n", false),
    ],
};

/// A nonempty <Pass> element that is not encrypted with a master password,
/// labelled with the nearest <Host> before it.
fn filezilla_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        let mut host = String::new();
        let mut out = Vec::new();
        xml_tags(text, |name, attributes, value, line| {
            if matches!(name, "Server" | "/Server") {
                host.clear();
            } else if name == "Host" {
                host = value.to_owned();
            } else if name == "Pass"
                && xml_attribute(attributes, "encoding") != Some("crypt")
                && !value.is_empty()
            {
                out.push(Hit::line(line).about(&host));
            }
        });
        out
    })
}

pub const VPN_PROFILE_KEY: Rule = Rule {
    id: "app.openvpn.embedded-key",
    title: "VPN profile with its private key inside",
    explanation: "This OpenVPN profile contains a private-key block. Whether the key is valid, encrypted or sufficient to connect to the VPN was not checked.",
    reason: Some("Stealers collect .ovpn files. A copied profile with an embedded key gives access to the network behind the VPN unless a separate password or code is also required."),
    next_step: Some("Ask whoever runs the VPN to revoke this profile's certificate and issue a new one, and keep the new profile out of Downloads."),
    advice: Advice {
        steps: &[
            "If this is a work VPN, tell IT the profile was stored unprotected and ask for it to be reissued.",
            "Import the new profile into the VPN app, then delete the .ovpn file and empty the Trash. The app keeps what it needs.",
            "Ask for the VPN to require a second factor, so a copied profile is not enough on its own.",
        ],
        link: None,
    },
    targets: &[Target::Name("*.ovpn")],
    matcher: Matcher::Whole {
        candidate: any,
        test: ovpn_hits,
    },
    samples: &[
        (concat!("client\nremote vpn.example.invalid 1194\n<key>\n-----BEGIN ", "PRIVATE KEY-----\nsynthetic\n</key>\n").as_bytes(), true),
        (b"client\nremote vpn.example.invalid 1194\nkey client.key\n", false),
        (concat!("client\n<key>\n-----BEGIN ENCRYPTED ", "PRIVATE KEY-----\nsynthetic\n</key>\n").as_bytes(), false),
    ],
    ..FILEZILLA_PASSWORD
};

fn ovpn_hits(bytes: &[u8]) -> Hits {
    let text = String::from_utf8_lossy(bytes);
    let mut inside = false;
    capped_hits(
        text.lines().enumerate().filter_map(|(i, raw)| {
            let line = raw.trim();
            match line {
                "<key>" => inside = true,
                "</key>" => inside = false,
                _ => {}
            }
            (inside
                && line.starts_with("-----BEGIN ")
                && line.ends_with("PRIVATE KEY-----")
                && !line.contains("ENCRYPTED"))
            .then(|| Hit::line(i + 1))
        }),
        // A profile holds one key. This many are listed, so a planted
        // profile cannot fill the findings one scan keeps.
        100,
    )
}

pub const PASSWORD_NOTE: Rule = Rule {
    id: "export.password-note",
    category: "password-export",
    kind: "review",
    severity: "medium",
    title: "Possible passwords in a text note",
    explanation: "This text file has lines that look like saved passwords, such as 'password: ...'. The values were not read beyond ruling out placeholders, and they may be notes about something else.",
    reason: Some("Infostealers collect small text files from Desktop, Documents and Downloads because people keep passwords in them."),
    next_step: Some("Move these passwords into a password manager and delete the note."),
    advice: Advice {
        steps: &[
            "Open the file and check whether it holds passwords you still use.",
            "Add each one to the Passwords app built into macOS, or to a password manager such as 1Password or Bitwarden.",
            "Delete the file and empty the Trash. Look for other copies in iCloud Drive and other synced folders.",
            "If this Mac may have had malware, change the passwords for your email and bank accounts first.",
        ],
        link: None,
    },
    targets: &[Target::Name("*.txt"), Target::Name("*.rtf")],
    matcher: Matcher::Whole {
        candidate: has_password_line,
        test: password_note_hits,
    },
    samples: &[
        (b"wifi at home\nrouter admin password: synthetic-value-9\n", true),
        (b"Bank login\nuser dana\nPasswort = synthetic-value-9\n", true),
        (b"router admin password: !Synth$tic-9\n", true),
        (b"password: $password\npassword = ${DB_PASSWORD}\npassword: `generate-password`\n", false),
        (b"Reminder: change my password: tomorrow\n", false),
        (b"password: <your password here>\nPassword: changeme\n", false),
        (b"if (password == null) { return; }\nconst password = req.body.password;\n", false),
    ],
};

fn has_password_line(head: &[u8]) -> bool {
    !password_lines(&String::from_utf8_lossy(head)).is_empty()
}

fn password_note_hits(bytes: &[u8]) -> Hits {
    capped_hits(
        password_lines(&String::from_utf8_lossy(bytes))
            .into_iter()
            .map(Hit::line),
        20,
    )
}

/// Lines of the form "<words> password: <value>", where the value is one
/// word that is not a placeholder, an ordinary word or code.
fn password_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let (label, value) = raw.split_once([':', '='])?;
            let label = label.trim().to_ascii_lowercase();
            let named = ["password", "passwort", "passwd", "passcode", "pwd"]
                .iter()
                .any(|word| label.ends_with(word));
            let value = value.trim();
            // An ordinary lowercase word ("password: tomorrow") is prose.
            let mixed = !value.bytes().all(|b| b.is_ascii_lowercase());
            (named
                && label.len() <= 60
                && !label.contains(['(', '{', '.', '"'])
                && value.len() >= 6
                && mixed
                // People put "$" and "!" in passwords. A value that starts
                // with "$" or "`" is taken from somewhere else, and one that
                // starts with "*" or "<" stands in for a password.
                && !value.chars().any(char::is_whitespace)
                && !value.starts_with(['$', '`', '*', '<'])
                && !value.contains(['(', ')', '{', ';', '"', '\''])
                && plausible(value))
            .then_some(i + 1)
        })
        .collect()
}

pub const RCLONE_SECRET: Rule = Rule {
    id: "app.rclone.stored-secret",
    title: "Storage password or key saved by rclone",
    explanation: "A password or key field was found in an rclone configuration. Obscured passwords can be recovered by rclone. The scanner checked for stored values but did not test access to a remote.",
    reason: Some("A copied configuration may allow access to its remotes while the stored credentials remain valid."),
    next_step: Some("Set a password on the rclone config, and change what was stored here if the file may have been copied."),
    advice: Advice {
        steps: &[
            "Encrypt the config: run 'rclone config', choose 's' (Set configuration password).",
            "If the file may have been copied, change the password or rotate the key of each remote named here at its service.",
            "Remove remotes you no longer use: rclone config delete <name>",
        ],
        link: None,
    },
    targets: &[
        Target::File(".config/rclone/rclone.conf"),
        Target::File(".rclone.conf"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: |bytes| rclone_hits(bytes, false),
    },
    samples: &[
        (b"[fixture]\ntype = sftp\nhost = sftp.example.invalid\npass = c3ludGhldGljLW9ubHk\n", true),
        (concat!("[fixture]\ntype = sftp\nkey_pem = -----BEGIN OPENSSH ", "PRIVATE KEY-----\\nsynthetic\\n-----END\n").as_bytes(), true),
        (b"[drive]\ntype = drive\ntoken = {\"access_token\":\"synthetic\",\"refresh_token\":\"synthetic-only\"}\n", false),
        (b"# Encrypted rclone configuration File\n\nRCLONE_ENCRYPT_V0:\nc3ludGhldGljLW9ubHktdmFsdWU=\n", false),
        (b"[fixture]\ntype = sftp\nhost = sftp.example.invalid\npass = \nkey_file = ~/.ssh/id_ed25519\n", false),
    ],
    ..FILEZILLA_PASSWORD
};

/// The sign-ins rclone made itself: an OAuth token per remote.
pub const RCLONE_LOGIN: Rule = Rule {
    id: "app.rclone.stored-login",
    kind: "inventory",
    severity: "medium",
    title: "Cloud storage sign-in stored by rclone",
    explanation: "rclone keeps the sign-in token of a cloud storage remote in this file as plain text. This is how the tool stores it; validity and permissions were not checked.",
    reason: None,
    next_step: Some("Set a password on the rclone config to encrypt these tokens."),
    matcher: Matcher::Whole {
        candidate: any,
        test: |bytes| rclone_hits(bytes, true),
    },
    samples: &[
        (b"[drive]\ntype = drive\ntoken = {\"access_token\":\"synthetic\",\"refresh_token\":\"synthetic-only\"}\n", true),
        (b"[fixture]\ntype = sftp\nhost = sftp.example.invalid\npass = c3ludGhldGljLW9ubHk\n", false),
        (b"[fixture]\ntype = local\n", false),
    ],
    ..RCLONE_SECRET
};

/// One hit per remote: its OAuth token when `logins`, its saved passwords
/// and keys otherwise.
fn rclone_hits(bytes: &[u8], logins: bool) -> Hits {
    let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
    let mut remotes: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for (line, remote, _) in rclone_secrets(text, logins) {
        // By the name as written: one that cannot be shown is still a remote.
        if !remotes.contains(&remote) {
            if out.len() == 100 {
                return Err(Incomplete {
                    reason: "scan-limit",
                    hits: out,
                });
            }
            remotes.push(remote);
            out.push(Hit::line(line).about(remote));
        }
    }
    Ok(out)
}

/// What the app fingerprints for these rules: every stored secret of every
/// remote, with the remote's name. Never export this.
pub(super) fn rclone_material(bytes: &[u8], logins: bool) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    // A sign-in is its refresh token: rclone replaces the access token and
    // its expiry by itself. One without a refresh token is its whole line.
    let lasting = |line: &str| {
        let token: serde_json::Value = serde_json::from_str(line.split_once('=')?.1).ok()?;
        token["refresh_token"].as_str().map(str::to_string)
    };
    let mut secrets: Vec<_> = rclone_secrets(text, logins)
        .into_iter()
        .map(|(_, remote, line)| {
            let sign_in = lasting(line).filter(|token| logins && !token.is_empty());
            (remote, sign_in.unwrap_or_else(|| line.to_string()))
        })
        .collect();
    secrets.sort();
    serde_json::to_vec(&secrets).ok()
}

/// Each line that stores a secret, as (line number, remote, the line).
fn rclone_secrets(text: &str, logins: bool) -> Vec<(usize, &str, &str)> {
    const SECRETS: &[&str] = &[
        "pass",
        "password",
        "password2",
        "key_file_pass",
        "key_pem",
        "secret_access_key",
        "key",
        "client_secret",
        "bearer_token",
        "sas_url",
        "service_account_credentials",
    ];
    let mut remote = "";
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            remote = &line[1..line.len() - 1];
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let found = if logins {
            key == "token"
                && (value.contains("\"access_token\"") || value.contains("\"refresh_token\""))
        } else {
            SECRETS.contains(&key) && !value.is_empty() && !value.starts_with(['#', ';', '$'])
        };
        if found {
            out.push((i + 1, remote, line));
        }
    }
    out
}
