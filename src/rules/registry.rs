//! Package registry and network sign-ins kept in plain files: PyPI, crates.io,
//! RubyGems and ~/.netrc.

use super::*;

pub const PYPI_PASSWORD: Rule = Rule {
    id: "dev.pypi.inline-credentials",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "PyPI password or token stored in a file",
    explanation: "A password or API token is stored in the Python package upload config. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("A PyPI token can publish packages under your name, which is why malware that spreads through packages collects this file."),
    next_step: Some("Revoke the token and keep the replacement in the Keychain. Removing the line does not revoke it."),
    advice: Advice {
        steps: &[
            "In your PyPI account settings, delete the API token that was stored here.",
            "Create a replacement scoped to one project, and store it in the Keychain: keyring set https://upload.pypi.org/legacy/ __token__",
            "Remove the password line from ~/.pypirc. twine reads the Keychain entry automatically.",
            "For projects built in CI, use PyPI trusted publishing, which needs no stored token.",
        ],
        link: Some("https://pypi.org/manage/account/token/"),
    },
    // Poetry falls back to this file when it cannot use the Keychain.
    targets: &[
        Target::File(".pypirc"),
        Target::File("Library/Application Support/pypoetry/auth.toml"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: pypi_hits,
    },
    samples: &[
        (b"[pypi]\nusername = __token__\npassword = synthetic-only\n", true),
        (b"[pypi]\nusername = __token__\n", false),
        (b"[pypi]\npassword = ${PYPI_TOKEN}\n", false),
        // Poetry's auth.toml names a token by its repository.
        (b"[pypi-token]\nprivate-repository = \"synthetic-only-value\"\n", true),
        (b"[http-basic.private-repository]\nusername = \"fixture-user-name\"\n", false),
    ],
};

fn pypi_hits(bytes: &[u8]) -> Hits {
    let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
    let mut hits = ini_hits(text, &["password"]);
    // Poetry: under [pypi-token], each name is a repository and each
    // value its token.
    let mut tokens = false;
    let mut limited = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') {
            tokens = line == "[pypi-token]";
        } else if let Some((repository, value)) = line.split_once('=').filter(|_| tokens) {
            if scalar_literal(value).is_some() {
                if hits.len() < 100 {
                    hits.push(Hit::line(i + 1).about(repository.trim().trim_matches('"')));
                } else {
                    limited = true;
                }
            }
        }
    }
    if limited {
        Err(Incomplete {
            reason: "scan-limit",
            hits,
        })
    } else {
        Ok(hits)
    }
}

/// Lines in an INI or TOML file that set one of `keys` to a literal, labelled
/// with their section.
fn ini_hits(text: &str, keys: &[&str]) -> Vec<Hit> {
    let mut section = "";
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
        } else if let Some((key, value)) = line.split_once(['=', ':']) {
            if keys.contains(&key.trim()) && scalar_literal(value).is_some() {
                out.push(Hit::line(i + 1).about(section));
            }
        }
    }
    out
}

pub const CARGO_TOKEN: Rule = Rule {
    id: "dev.cargo.inline-token",
    title: "crates.io token stored in a file",
    explanation: "A registry token is stored in Cargo's credentials file as plain text. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("A crates.io token can publish crates under your name."),
    next_step: Some("Revoke the token and let Cargo keep the replacement in the Keychain. Removing the line does not revoke it."),
    advice: Advice {
        steps: &[
            "Remove the stored token: cargo logout",
            "On crates.io, open Account Settings > API Tokens and revoke the token.",
            "Tell Cargo to use the Keychain by adding to ~/.cargo/config.toml: [registry] global-credential-providers = [\"cargo:macos-keychain\"]",
            "When you next publish, 'cargo login' stores the new token in the Keychain. Give the token an expiry date and only the scopes you need.",
        ],
        link: Some("https://crates.io/settings/tokens"),
    },
    targets: &[
        Target::File(".cargo/credentials.toml"),
        Target::File(".cargo/credentials"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: cargo_hits,
    },
    samples: &[
        (b"[registry]\ntoken = \"synthetic-only\"\n", true),
        (b"[registry]\n# token = \"synthetic-only\"\n", false),
    ],
    ..PYPI_PASSWORD
};

fn cargo_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| ini_hits(text, &["token", "secret-key"]))
}

pub const GEM_KEY: Rule = Rule {
    id: "dev.rubygems.inline-key",
    title: "RubyGems API key stored in a file",
    explanation: "An API key is stored in the RubyGems credentials file as plain text. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("A RubyGems API key can publish gems under your name."),
    next_step: Some("Revoke the key in your RubyGems account. Removing the line does not revoke it."),
    advice: Advice {
        steps: &[
            "Remove the stored key: gem signout",
            "On rubygems.org, open Settings > API keys and delete the key.",
            "If you still publish, create a new key with only the scopes you need and turn on MFA for it.",
        ],
        link: Some("https://rubygems.org/profile/api_keys"),
    },
    targets: &[Target::File(".gem/credentials")],
    matcher: Matcher::Whole {
        candidate: any,
        test: gem_hits,
    },
    samples: &[
        (b"---\n:rubygems_api_key: rubygems_synthetic-only\n", true),
        (b"---\n", false),
    ],
    ..PYPI_PASSWORD
};

fn gem_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter_map(|(i, raw)| {
                let (key, value) = raw.trim().strip_prefix(':')?.split_once(':')?;
                scalar_literal(value).map(|_| Hit::line(i + 1).about(key))
            })
            .collect()
    })
}

pub const NETRC_PASSWORD: Rule = Rule {
    id: "dev.netrc.inline-password",
    title: "Password stored in .netrc",
    explanation: "A password or token for a network host is stored in ~/.netrc as plain text. Loose Keys did not check whether it still works.",
    reason: Some("Tools such as curl, git and package managers read this file, and so can any other program running as you."),
    next_step: Some("Change the password or revoke the token at the host named here, then keep the replacement in the Keychain."),
    advice: Advice {
        steps: &[
            "At the host named here, change the password or revoke the token.",
            "If Git used this entry, switch it to the Keychain: git config --global credential.helper osxkeychain",
            "Remove the machine entry from ~/.netrc, or delete the file if nothing else is in it.",
        ],
        link: None,
    },
    targets: &[Target::File(".netrc")],
    matcher: Matcher::Whole {
        candidate: any,
        test: netrc_hits,
    },
    samples: &[
        (b"machine example.invalid login fixture password synthetic-only\n", true),
        (b"machine example.invalid\n  login fixture\n  password synthetic-only\n", true),
        (b"machine example.invalid login fixture password !Synth$tic-0nly\n", true),
        (b"machine example.invalid login fixture\n", false),
        (b"machine example.invalid login fixture password <password>\n", false),
    ],
    ..PYPI_PASSWORD
};

pub const PGPASS_PASSWORD: Rule = Rule {
    id: "dev.postgres.pgpass",
    severity: "medium",
    title: "Database password stored in .pgpass",
    explanation: "psql reads passwords from ~/.pgpass, where they are stored as plain text. Loose Keys did not check whether this one is for a local test database or a production one.",
    reason: Some("Any program running as you can read this file and connect to the databases it lists."),
    next_step: Some("For anything but a local test database, change the password and stop storing it in this file."),
    advice: Advice {
        steps: &[
            "Check which database the entry is for. A local development database needs nothing more.",
            "For a shared or production database, change the password on the server.",
            "Remove the entry and let psql prompt, or use a method with no stored password: short-lived tokens (for example cloud IAM database sign-in) or a client certificate.",
        ],
        link: None,
    },
    targets: &[Target::File(".pgpass")],
    matcher: Matcher::Whole {
        candidate: any,
        test: pgpass_hits,
    },
    samples: &[
        (b"db.example.invalid:5432:shop:shop_user:synthetic-only\n", true),
        (b"db.example.invalid:5432:shop:shop_user:Synth$tic-0nly\n", true),
        (b"# host:port:db:user:password\nlocalhost:5432:*:dev:\n", false),
    ],
    ..PYPI_PASSWORD
};

/// host:port:database:user:password, one per line.
fn pgpass_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| {
        text.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim_start().starts_with('#'))
            .filter_map(|(i, l)| {
                let fields: Vec<&str> = l.trim().split(':').collect();
                // The file has no references: whatever is in the field is the password.
                (fields.len() >= 5 && !fields[4].is_empty())
                    .then(|| Hit::line(i + 1).about(fields[0]))
            })
            .collect()
    })
}

pub const MYCNF_PASSWORD: Rule = Rule {
    id: "dev.mysql.mycnf",
    title: "Database password stored in .my.cnf",
    explanation: "A MySQL password is stored in ~/.my.cnf as plain text. Loose Keys did not check whether it is for a local test database or a production one.",
    targets: &[Target::File(".my.cnf")],
    matcher: Matcher::Whole {
        candidate: any,
        test: mycnf_hits,
    },
    samples: &[
        (b"[client]\nuser = shop\npassword = synthetic-only\n", true),
        (b"[client]\nuser = shop\n", false),
    ],
    advice: Advice {
        steps: &[
            "Check which database the entry is for. A local development database needs nothing more.",
            "For a shared or production database, change the password on the server.",
            "Store the login with 'mysql_config_editor set', or remove the password line and let the client prompt.",
        ],
        link: None,
    },
    ..PGPASS_PASSWORD
};

pub const WAREHOUSE_PASSWORD: Rule = Rule {
    id: "dev.warehouse.inline-password",
    title: "Data warehouse password stored in a client config",
    explanation: "A password or token for a data warehouse is written in this dbt or Snowflake client config as plain text. Loose Keys did not check whether it still works.",
    targets: &[
        Target::File(".dbt/profiles.yml"),
        Target::File(".snowsql/config"),
        Target::File(".snowflake/config.toml"),
        Target::File(".snowflake/connections.toml"),
        Target::File("Library/Application Support/snowflake/config.toml"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: warehouse_hits,
    },
    samples: &[
        (b"fixture:\n  outputs:\n    prod:\n      type: redshift\n      password: synthetic-only-value\n", true),
        (b"[connections.fixture]\naccountname = fixture\npassword = synthetic-only-value\n", true),
        // A service-account key written into a dbt profile.
        (concat!("      keyfile_json:\n        type: service_account\n        private_key: \"-----BEGIN ", "PRIVATE KEY-----\\nsynthetic\\n\"\n").as_bytes(), true),
        (b"      password: \"{{ env_var('DBT_PASSWORD') }}\"\n      sslkey: /Users/fixture/certs/client.key\n", false),
        (b"      authenticator: externalbrowser\n      private_key_path: /Users/fixture/keys/rsa_key.p8\n", false),
    ],
    advice: Advice {
        steps: &[
            "Check which warehouse the entry is for, and change the password or revoke the token there.",
            "In dbt, read it from the environment instead: password: \"{{ env_var('DBT_PASSWORD') }}\"",
            "Prefer browser sign-in or key-pair sign-in with a passphrase where the warehouse offers it.",
        ],
        link: None,
    },
    ..PGPASS_PASSWORD
};

/// Exact field names only: these files also have fields such as `sslkey`
/// that hold a path.
fn warehouse_hits(bytes: &[u8]) -> Hits {
    let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
    let mut hits = ini_hits(
        text,
        &[
            "password",
            "pass",
            "token",
            "private_key_passphrase",
            "client_secret",
            "refresh_token",
            "secret_access_key",
        ],
    );
    // A key written into the file itself, as dbt allows for a service
    // account. Its value has blanks in it, which no other field's may.
    let keys = text.lines().enumerate().filter_map(|(i, raw)| {
        let (name, value) = raw.trim().split_once([':', '='])?;
        let value = value.trim().trim_start_matches(['"', '\'']);
        (name.trim().trim_matches('"') == "private_key" && value.starts_with("-----BEGIN "))
            .then(|| Hit::line(i + 1))
    });
    match capped_hits(keys, 100) {
        Ok(keys) => {
            hits.extend(keys);
            Ok(hits)
        }
        Err(mut incomplete) => {
            hits.append(&mut incomplete.hits);
            incomplete.hits = hits;
            Err(incomplete)
        }
    }
}

fn mycnf_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, |text| ini_hits(text, &["password"]))
}

/// One word of a netrc file.
struct NetrcWord<'a> {
    line: usize,
    /// As written, without the quotes around a quoted word.
    text: &'a str,
    /// Only blanks stand before it on its line.
    opens_line: bool,
    /// An empty line stands before it, which is where a macro ends.
    after_empty_line: bool,
    /// Where it ends cannot be told. A quote opened it and none closed it, so
    /// that it runs to the end of the file, or one closed it with no blank
    /// after, as where a second word that opens with a quote ends the first.
    unended: bool,
}

/// The words of a netrc file, each byte passed once. Blanks, tabs and line
/// ends part words, and nothing else does. A word that opens with a quote
/// runs to the next quote, over blanks and lines, and a backslash anywhere
/// takes the byte after it into the word. That is how Python reads the file;
/// where curl reads less into a word, the longer word is the safe one, since
/// a word may be a password.
struct NetrcWords<'a> {
    text: &'a str,
    at: usize,
    line: usize,
}

impl<'a> NetrcWords<'a> {
    /// The next word. Where a directive is expected (`directive`), one that
    /// opens with "#" is a comment to the end of its line and is passed.
    /// Where a value is expected it is the value.
    fn next(&mut self, directive: bool) -> Option<NetrcWord<'a>> {
        let bytes = self.text.as_bytes();
        let mut opens_line = self.at == 0;
        let (mut ends, mut after_empty_line) = (0, false);
        loop {
            match *bytes.get(self.at)? {
                b'\n' => {
                    self.line += 1;
                    ends += 1;
                    opens_line = true;
                    after_empty_line |= ends == 2;
                }
                b'\r' => {}
                b' ' | b'\t' => ends = 0,
                b'#' if directive => {
                    let rest = &bytes[self.at..];
                    self.at += rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
                    ends = 0;
                    continue;
                }
                _ => break,
            }
            self.at += 1;
        }
        let line = self.line;
        let quoted = bytes[self.at] == b'"';
        let start = self.at + usize::from(quoted);
        let mut end = start;
        let mut open = quoted;
        while let Some(b) = bytes.get(end) {
            match b {
                b'"' if quoted => {
                    open = false;
                    break;
                }
                b' ' | b'\t' | b'\n' | b'\r' if !quoted => break,
                b'\\' => end += 1,
                _ => {}
            }
            end += 1;
        }
        // A backslash may be the last byte of the file.
        let end = end.min(bytes.len());
        self.line += bytes[start..end].iter().filter(|b| **b == b'\n').count();
        self.at = end + usize::from(quoted && !open);
        let parted = matches!(
            bytes.get(self.at),
            None | Some(b' ' | b'\t' | b'\n' | b'\r')
        );
        Some(NetrcWord {
            line,
            text: &self.text[start..end],
            opens_line,
            after_empty_line,
            unended: open || !parted,
        })
    }
}

/// Each password in a netrc file, labelled with its host, the word after
/// `machine`. A word of a value is never read as a directive, whatever it
/// says. So a file that leaves the format cannot be read on from there: the
/// word that stands where a directive should may be part of a password, and
/// a directive after it the value of one before. Nothing found in such a
/// file is all it holds, and no host in it is known, so the file is a gap,
/// not a list that stops short. It is one where a word that is no directive
/// stands for one, where a value opens a line, as the next directive does
/// when a value is missing, and where a word's end cannot be told. A macro
/// holds commands and runs to the next empty line: a password in one is
/// still listed, with no host, and no other word of it is questioned.
fn netrc_hits(bytes: &[u8]) -> Hits {
    let text = std::str::from_utf8(bytes).map_err(|_| "unreadable")?;
    let mut words = NetrcWords {
        text,
        at: 0,
        line: 1,
    };
    let mut in_macro = false;
    let mut machine = "";
    let mut out = Vec::new();
    while let Some(word) = words.next(true) {
        if word.unended {
            return Err("unreadable".into());
        }
        in_macro &= !word.after_empty_line;
        let takes_value = match word.text {
            "machine" | "login" | "account" | "password" => true,
            // In a macro it is a word of a command, and the word after it
            // may be a directive.
            "macdef" => !in_macro,
            _ => false,
        };
        if !takes_value {
            match word.text {
                "default" => machine = if in_macro { "" } else { "default" },
                _ if in_macro => {}
                _ => return Err("unreadable".into()),
            }
            continue;
        }
        // A file that ends here holds nothing more that could be missed.
        let before_value = (words.at, words.line);
        let Some(value) = words.next(false) else {
            break;
        };
        if in_macro && value.after_empty_line {
            // The macro ended before this word. Read it again as a
            // directive, not as the last macro command's argument.
            words.at = before_value.0;
            words.line = before_value.1;
            in_macro = false;
            continue;
        }
        if value.unended || (value.opens_line && !in_macro) {
            return Err("unreadable".into());
        }
        match word.text {
            // No references in this format either; "<password>" is a template.
            "password" => {
                if !value.text.is_empty() && !value.text.starts_with('<') {
                    out.push(Hit::line(word.line).about(machine));
                }
            }
            "machine" => machine = if in_macro { "" } else { value.text },
            "macdef" => {
                in_macro = true;
                machine = "";
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hits_name_their_section_or_host_and_never_the_value() {
        let hits = ini_hits(
            "[pypi]\npassword = synthetic-one\n[testpypi]\npassword: synthetic-two\n",
            &["password"],
        );
        assert_eq!(hits[0].subject.as_deref(), Some("pypi"));
        assert_eq!(
            (hits[1].line, hits[1].subject.as_deref()),
            (Some(4), Some("testpypi"))
        );

        let hits = netrc_hits(
            b"machine a.example.invalid login x password synthetic-one\nmachine b.example.invalid\nlogin x\npassword synthetic-two\n",
        )
        .unwrap();
        assert_eq!(hits[0].subject.as_deref(), Some("a.example.invalid"));
        assert_eq!(
            (hits[1].line, hits[1].subject.as_deref()),
            (Some(4), Some("b.example.invalid"))
        );
    }

    /// The line and the host of each password found in a netrc file.
    fn netrc(file: &str) -> Vec<(usize, Option<String>)> {
        let hits = netrc_hits(file.as_bytes()).unwrap();
        hits.into_iter()
            .map(|hit| (hit.line.unwrap(), hit.subject))
            .collect()
    }

    fn host(name: &str) -> Option<String> {
        Some(name.to_string())
    }

    #[test]
    fn a_netrc_password_is_one_word_whatever_words_it_holds() {
        let secret = "prefix machine synthetic-sensitive-fragment password suffix";
        for value in [
            // In quotes, as curl and Python read it.
            format!("\"{secret}\""),
            // A quote written with a backslash does not end it.
            "\"pre\\\" machine synthetic-sensitive-fragment password suf\"".to_string(),
            // Blanks written with a backslash, in a word with no quotes.
            secret.replace(' ', "\\ "),
            // Over several lines.
            secret.replace(' ', "\n").replace("prefix", "\"prefix") + "\"",
            // Only a blank, a tab or a line end parts two words.
            secret.replace(' ', "\u{2003}"),
        ] {
            let file = format!("machine fixture.invalid login fixture password {value}\n");
            assert_eq!(netrc(&file), [(1, host("fixture.invalid"))], "{file}");
        }
        // What follows a password over two lines keeps its own line and host.
        assert_eq!(
            netrc("machine a.example.invalid password \"synthetic\none\"\nmachine b.example.invalid password synthetic-two\n"),
            [(1, host("a.example.invalid")), (3, host("b.example.invalid"))]
        );
    }

    #[test]
    fn a_netrc_value_is_never_read_as_a_directive() {
        for login in ["password", "machine", "\"machine other.invalid password\""] {
            let file = format!("machine fixture.invalid login {login} password synthetic-only\n");
            assert_eq!(netrc(&file), [(1, host("fixture.invalid"))], "{file}");
        }
        assert_eq!(
            netrc("machine password account machine password synthetic-only\n"),
            [(1, host("password"))]
        );
        // Several entries on a line, and the entry for any other host.
        assert_eq!(
            netrc("machine a.example.invalid password synthetic-one machine b.example.invalid password synthetic-two\ndefault login anonymous password synthetic-three\n"),
            [
                (1, host("a.example.invalid")),
                (1, host("b.example.invalid")),
                (2, host("default"))
            ]
        );
        // A template or nothing, in quotes or not, is no password.
        for value in ["<password>", "\"<password>\"", "\"\"", ""] {
            let file = format!("machine fixture.invalid login fixture password {value}\n");
            assert_eq!(netrc(&file), [], "{file}");
        }
    }

    #[test]
    fn a_netrc_file_that_leaves_the_format_names_no_host_from_what_follows() {
        for file in [
            // A password with blanks and no quotes: its later words stand
            // where directives do. Which of the words after them are values
            // cannot be told, so no host is taken from them and no password
            // either.
            "machine a.example.invalid login fixture password prefix more machine synthetic-sensitive-fragment password suffix\nmachine b.example.invalid login fixture password synthetic-two\n",
            // A word that is no directive may be the rest of a value, or a
            // key some other tool reads, with a value after it or none.
            "machine a.example.invalid port 443 user fixture password synthetic-only\n",
            // A quote that never closes takes in all that follows it, which
            // may be more passwords or the rest of one.
            "machine a.example.invalid password \"prefix\nmachine synthetic-sensitive-fragment password suffix\n",
            "machine a.example.invalid login \"fixture\nmachine synthetic-sensitive-fragment password suffix\n",
            "machine a.example.invalid password synthetic-one\nmachine \"synthetic-sensitive-fragment\npassword suffix\n",
            "machine a.example.invalid password synthetic-one\n\"machine synthetic-sensitive-fragment password suffix\n",
        ] {
            // Nothing is listed, so that nothing is taken to be all there
            // is: the file is a gap.
            assert_eq!(
                netrc_hits(file.as_bytes()).err().map(|e| e.reason),
                Some("unreadable"),
                "{file}"
            );
        }
    }

    #[test]
    fn a_netrc_file_out_of_step_with_the_format_is_a_gap_and_swallows_no_password() {
        for file in [
            // Two passwords that each open with a quote and close none: the
            // first would run to the second's quote, and take its entry in.
            "machine a.example.invalid login fixture password \"synthetic-one\nmachine b.example.invalid login fixture password \"synthetic-two\n",
            // The same, where what is left of the second is a directive.
            "machine a.example.invalid password \"synthetic-one\nmachine b.example.invalid password \"default\n",
            "machine a.example.invalid password \"synthetic\"one\n",
            // A login with no value: `password` is taken for it, on its
            // line or the next, and the password stands where a directive
            // should.
            "machine a.example.invalid login password synthetic-one\n",
            "machine a.example.invalid login\npassword synthetic-one\n",
            "machine a.example.invalid\n  login\n  password synthetic-one\nmachine b.example.invalid login fixture password synthetic-two\n",
            // A password with none: the next entry's first word is taken for
            // it, and its password would be listed under this host.
            "machine a.example.invalid login fixture password\ndefault login fixture password synthetic-two\n",
            "machine a.example.invalid login fixture password\nmachine b.example.invalid login fixture password synthetic-two\n",
            // A backslash at a line's end takes the next line's first word
            // into the password, and the host after it is no directive's.
            "machine a.example.invalid password synthetic-one\\\nmachine b.example.invalid password synthetic-two\n",
            "machine a.example.invalid password synthetic-one\\\nmachine b.example.invalid\n  password synthetic-two\n",
            // A quote left open in a macro runs past its end, to the quote
            // that opens a password, and the password is a word of no entry.
            "macdef init\necho \"synthetic\n\nmachine b.example.invalid login fixture password \"synthetic-two\n",
        ] {
            assert_eq!(
                netrc_hits(file.as_bytes()).err().map(|e| e.reason),
                Some("unreadable"),
                "{file}"
            );
        }
        // What the format allows is still read: a login that is a
        // directive's name, a password over two lines, and a file that ends
        // where a value would stand, which holds nothing more to miss.
        assert_eq!(
            netrc("machine a.example.invalid\n  login password\n  password \"synthetic\none\"\nmachine b.example.invalid login login password synthetic\\ two\n"),
            [(3, host("a.example.invalid")), (5, host("b.example.invalid"))]
        );
        assert_eq!(
            netrc("machine a.example.invalid login fixture password synthetic-one\nmachine b.example.invalid login\n"),
            [(1, host("a.example.invalid"))]
        );
    }

    #[test]
    fn netrc_comments_and_macros_are_not_entries() {
        assert_eq!(
            netrc("# machine synthetic-sensitive-fragment password synthetic-only\nmachine a.example.invalid login fixture # password synthetic-only\n  password synthetic-one\n"),
            [(3, host("a.example.invalid"))]
        );
        // Where a value is expected, a word that opens with "#" is the value.
        assert_eq!(
            netrc("machine a.example.invalid password #synthetic-only\n"),
            [(1, host("a.example.invalid"))]
        );
        // A macro runs to the next empty line and is not in this format: a
        // word in it names no host, here or after it.
        assert_eq!(
            netrc("machine a.example.invalid login fixture password synthetic-one\nmacdef init\ncd machine synthetic-sensitive-fragment\nput password synthetic-two\n\nmachine b.example.invalid password synthetic-three\n"),
            [
                (1, host("a.example.invalid")),
                (4, None),
                (6, host("b.example.invalid"))
            ]
        );
    }

    #[test]
    fn a_netrc_macro_cannot_take_a_value_past_its_empty_line() {
        for word in ["machine", "login", "account", "password"] {
            let file = format!(
                "macdef init\n{word}\n\nmachine fixture.invalid login fixture password synthetic-only\n"
            );
            assert_eq!(netrc(&file), [(4, host("fixture.invalid"))], "{word}");
            let malformed = format!(
                "macdef init\n{word}\n\nunknown fixture\nmachine fixture.invalid password synthetic-only\n"
            );
            assert_eq!(
                netrc_hits(malformed.as_bytes()).err().map(|e| e.reason),
                Some("unreadable")
            );
            let commented = format!(
                "macdef init\n{word}\n\n# fixture comment\nmachine fixture.invalid password synthetic-only\n"
            );
            assert_eq!(netrc(&commented), [(5, host("fixture.invalid"))]);
        }
    }

    #[test]
    fn a_netrc_file_is_read_once_however_it_is_written() {
        let size = 1000 * 1024;
        for file in [
            "\"".repeat(size),
            "\\".repeat(size),
            "password \"".repeat(size / 10),
            "macdef x\n\n".repeat(size / 10),
            "#\n".repeat(size / 2),
        ] {
            let started = std::time::Instant::now();
            let _ = netrc_hits(file.as_bytes());
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(10),
                "reading {} bytes took {took:?}",
                file.len()
            );
        }
    }
}
