//! Secrets assigned to variables in .env files and shell startup or history files.

use super::*;

pub const ENV_SECRET: Rule = Rule {
    id: "secret.env-assignment",
    category: "developer-cloud",
    kind: "review",
    severity: "medium",
    title: "Password or key in a plain-text settings file",
    explanation: "A variable in this file is named like a password, key or token, or holds a private key or a URL with a password in it. Loose Keys only checked that the value isn't a placeholder. It may be a local or test value.",
    reason: Some("Password-stealing malware collects .env and shell files, because they often hold working passwords and keys in plain text."),
    next_step: Some("Decide whether this is a real credential. If it is, revoke it at the service and load the replacement from a password manager instead of this file."),
    advice: Advice {
        steps: &[
            "Check what the variable is for. A value for a local test database needs nothing more.",
            "For a real credential, revoke or change it at the service that issued it. Removing the line doesn't do that.",
            "Load the replacement at run time instead of storing it. A password manager CLI, such as 'op run' or 'security find-generic-password', can fill the variable when the program starts.",
            "Remove the old value from this file. Check that the file is in .gitignore and was never committed.",
        ],
        link: None,
    },
    targets: &[
        Target::Name(".env*"),
        Target::Name("*.tfvars"),
        Target::File(".gradle/gradle.properties"),
        // Codex keeps MCP server environments here.
        Target::File(".codex/config.toml"),
        Target::File(".config/goose/secrets.yaml"),
        // Other names tools use for a file of settings and secrets.
        Target::Name("*.env"),
        Target::Name(".dev.vars*"),
        Target::Name("secrets.toml"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: env_hits,
    },
    samples: &[
        (b"DATABASE_PASSWORD=synthetic-only-value\n", true),
        (b"\xef\xbb\xbfDATABASE_PASSWORD=synthetic-only-value\n", true),
        (b": 1700000000:0;export API_TOKEN=\"synthetic-only-value\"\n", true),
        (b"fixtureSecretKey=synthetic-only-value\n", true),
        (b"fixtureAccessKeyId=synthetic-only-value\nsecretKeyFile=/run/secrets/fixture\n", false),
        (b"API_TOKEN=${OTHER}\nDB_PASSWORD=changeme\nPORT=8080\nAUTHOR=someone-else\n", false),
        (b"# API_TOKEN=synthetic-only-value\nPASSWORD_MIN_LENGTH=12\n", false),
        // A value runs to the end of its line here, and this one is prose.
        (b"PASSWORD_RESET_SUBJECT=Password reset requested\n", false),
        // Only a shell or .env file expands "$", and not inside single quotes.
        // A leading "!" or "&" means something in YAML alone.
        (b"DB_PASSWORD='!synthetic-only-value'\n", true),
        (b"DB_PASSWORD='synthetic$only-value'\n", true),
        (
            b"DB_PASSWORD=\"synthetic$only-value\"\nGOOGLE_API_KEY: !synthetic-only-value\n",
            false,
        ),
        // A password in a URL, and a private key, under any name.
        (
            b"DATABASE_URL=postgres://fixture:synthetic-only-value@db.example.invalid/app\n",
            true,
        ),
        (
            b"DATABASE_URL=postgres://fixture:${DB_PASSWORD}@db.example.invalid/app\nREDIS_URL=redis://cache.example.invalid:6379\n",
            false,
        ),
        (
            concat!(
                "TLS_CERT_PEM=\"-----BEGIN ",
                "PRIVATE KEY-----\\nc3ludGhldGljLW9ubHktdmFsdWU\\n-----END ",
                "PRIVATE KEY-----\\n\"\n"
            )
            .as_bytes(),
            true,
        ),
        (
            concat!(
                "JWT_PRIVATE_KEY=\"-----BEGIN ",
                "PRIVATE KEY-----\nc3ludGhldGljLW9ubHktdmFsdWU\n-----END ",
                "PRIVATE KEY-----\"\n"
            )
            .as_bytes(),
            true,
        ),
        (
            concat!(
                "JWT_PRIVATE_KEY=\"-----BEGIN ",
                "PRIVATE KEY-----\\nYOUR_KEY_HERE\\n-----END ",
                "PRIVATE KEY-----\"\n"
            )
            .as_bytes(),
            false,
        ),
        (b"SMTP_PASS=synthetic-only-value\nAPP_KEY=synthetic-only-value\n", true),
        (
            b"SSO_BYPASS=synthetic-only-value\nSTRIPE_PUBLISHABLE_KEY=synthetic-only-value\nSSH_KEY=~/.ssh/id_ed25519\n",
            false,
        ),
        // Where a key file is, and the name of the variable a key is in.
        (
            b"GOOGLE_APPLICATION_CREDENTIALS=credentials.json\nSSH_KEY=/app/.ssh/id_rsa\nTLS_KEY=certs/server.key\nenv_key = \"AZURE_OPENAI_API_KEY\"\n",
            false,
        ),
        (
            b"REPO_URL=https://synthetic-only-value:x-oauth-basic@git.example.invalid/app\n",
            true,
        ),
        // Keys that hold an ID or a setting, and key files from the current
        // folder or by name.
        (
            b"GPG_KEY=0123456789ABCDEF\nSORT_KEY=created_at_desc\nVITE_STORAGE_KEY=app_state_v2\n",
            false,
        ),
        (
            b"SIGNING_KEY=keys/signing\nPRIVATE_KEY=.ssh/id_ed25519\nPRIVATE_KEY=id_ed25519_work\nPRIVATE_KEY='$HOME/.ssh/id_rsa'\n",
            false,
        ),
        // A password in capitals is not another variable's name.
        (b"DB_PASSWORD=HUNTER2_HUNTER2\n", true),
    ],
};

/// The same in what a shell reads and records, where a variable can be given
/// to one command: "NAME=value command". Listed first, so that a file both
/// forms name, such as .envrc, is read as a shell would read it.
pub const SHELL_SECRET: Rule = Rule {
    targets: &[
        Target::Name(".envrc"),
        Target::File(".zsh_history"),
        Target::File(".bash_history"),
        Target::File(".zshrc"),
        Target::File(".zshenv"),
        Target::File(".zprofile"),
        Target::File(".bashrc"),
        Target::File(".bash_profile"),
        Target::File(".profile"),
        Target::File(".zlogin"),
        Target::File(".bash_login"),
        Target::File(".sh_history"),
        Target::File(".config/fish/config.fish"),
        Target::File(".local/share/fish/fish_history"),
        // Terminal.app keeps a history file per window here.
        Target::Dir(".zsh_sessions"),
        Target::Dir(".bash_sessions"),
        // The name zsh's first-run setup suggests for its history.
        Target::File(".histfile"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: shell_hits,
    },
    samples: &[
        (
            b"PGPASSWORD=synthetic-only-value psql -h db.example.invalid shop\n",
            true,
        ),
        (
            b": 1700000000:0;export API_TOKEN=\"synthetic-only-value\"; make deploy\n",
            true,
        ),
        (b"export DB_PASSWORD='synthetic$only-value'\n", true),
        (
            b": 1700000001:0;PGUSER=fixture PGPASSWORD=synthetic-only-value psql shop\n",
            true,
        ),
        (b"cd app && env DB_PASSWORD=synthetic-only-value ./run\n", true),
        (
            b"PASSWORD_MIN_LENGTH=12 make check\nDB_PASSWORD=$(pass show db) psql\n",
            false,
        ),
        (
            b"make deploy DEPLOY_TOKEN=synthetic-only-value\necho 'cd app && DB_PASSWORD=synthetic-only-value ./run'\n",
            false,
        ),
        (b"MYSQL_PWD=synthetic-only-value mysql -h db.example.invalid\n", true),
        (b"export OLDPWD=/Users/fixture/project\nPWD=synthetic-only-value ls\n", false),
        (
            b"DATABASE_URL=postgres://fixture:synthetic-only-value@db.example.invalid/app psql\n",
            true,
        ),
    ],
    ..ENV_SECRET
};

fn env_hits(bytes: &[u8]) -> Hits {
    assignments(bytes, false)
}

fn shell_hits(bytes: &[u8]) -> Hits {
    assignments(bytes, true)
}

/// Shell files are parsed leniently, so one invalid byte never hides the rest.
fn assignments(bytes: &[u8], shell: bool) -> Hits {
    let text = String::from_utf8_lossy(bytes);
    // Positions in `text` are positions in the file only if nothing was replaced.
    let exact = matches!(text, std::borrow::Cow::Borrowed(_));
    let start = text.as_ptr() as usize;
    // A byte order mark is not part of the first line. Skipping it keeps
    // positions counted from the start of the file.
    let lines = text.trim_start_matches('\u{feff}').lines();
    capped_hits(
        lines.enumerate().flat_map(|(i, raw)| {
            let table = raw.trim().split_once('=').and_then(|(name, value)| {
                is_name(unquoted(name))
                    .then(|| value.trim().strip_prefix('{'))
                    .flatten()
            });
            let first = table
                .is_none()
                .then(|| {
                    secret_assignment(raw, shell).or_else(|| {
                        let rest = &text[raw.as_ptr() as usize - start..];
                        multiline_key(raw, rest, shell)
                    })
                })
                .flatten();
            // A shell line can give a command several variables, or run
            // several commands. Each assignment after the first is read too.
            let more = (shell && table.is_none())
                .then(|| shell_assignments(raw))
                .into_iter()
                .flatten()
                .filter_map(|(name, value)| secret(name, value))
                .filter(move |(name, _)| {
                    first.is_none_or(|(seen, _)| seen.as_ptr() != name.as_ptr())
                });
            let pairs = table
                .into_iter()
                .flat_map(inline_table_pairs)
                .filter_map(|(name, value)| secret(unquoted(name), value))
                .chain(first)
                .chain(more);
            pairs.filter_map(move |(name, value)| {
                // A recognizable service token is reported by its own rule.
                if token::is_token(value.as_bytes()) {
                    return None;
                }
                let at = value.as_ptr() as usize - start;
                let mut hit = Hit::line(i + 1).about(name);
                hit.span = exact.then_some(at..at + value.len());
                Some(hit)
            })
        }),
        100,
    )
}

/// The variable name and the value, if this line assigns a literal to a
/// secret-named variable.
fn secret_assignment(raw: &str, shell: bool) -> Option<(&str, &str)> {
    let (name, value) = assignment(raw, shell)?;
    // Codex writes a server's variables on one line: env = { "NAME" = "value" }
    if let Some(table) = value.trim().strip_prefix('{') {
        return inline_table_pairs(table).find_map(|(name, value)| secret(unquoted(name), value));
    }
    secret(name, value)
}

/// The variable name and the value as the line gives them. In a `shell`
/// file the value is one word and a command may follow it; in a settings
/// file it runs to the end of the line.
fn assignment(raw: &str, shell: bool) -> Option<(&str, &str)> {
    let mut line = raw.trim();
    // zsh extended history: ": <time>:<duration>;command"
    if let Some(rest) = line.strip_prefix(": ") {
        line = rest.split_once(';')?.1.trim_start();
    }
    // fish history: "- cmd: command"
    let line = line.strip_prefix("- cmd: ").unwrap_or(line);
    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    // fish: "set -gx NAME value"; everything else: "NAME=value" or "NAME = value"
    let fish = ["set -x ", "set -gx ", "set -Ux "]
        .iter()
        .find_map(|set| line.strip_prefix(set));
    let (name, value) = match fish {
        Some(rest) => rest.trim_start().split_once(' ')?,
        // "NAME: value" is a YAML file of secrets, as goose keeps one. It is
        // tried second, because a value can end in "=".
        None => line
            .split_once('=')
            .map(|(name, value)| (unquoted(name), value))
            .map(|(name, value)| (name, if shell { shell_word(value) } else { value }))
            .filter(|(name, _)| is_name(name))
            // In YAML a value that starts with "!" or "&" is a tag or an anchor.
            .or_else(|| {
                line.split_once(": ")
                    .filter(|(_, v)| !v.trim_start().starts_with(['!', '&']))
                    .map(|(name, v)| (unquoted(name), v))
            })?,
    };
    Some((name, value))
}

pub(super) fn inline_table_pairs(table: &str) -> impl Iterator<Item = (&str, &str)> {
    let (mut quote, mut escaped) = (None, false);
    let end = table
        .char_indices()
        .find_map(|(i, c)| {
            if escaped {
                escaped = false;
            } else if quote == Some('"') && c == '\\' {
                escaped = true;
            } else if quote == Some(c) {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else if quote.is_none() && c == '}' {
                return Some(i);
            }
            None
        })
        .unwrap_or(table.len());
    let (mut quote, mut escaped) = (None, false);
    table[..end]
        .trim_end()
        .split(move |c| {
            if escaped {
                escaped = false;
            } else if quote == Some('"') && c == '\\' {
                escaped = true;
            } else if quote == Some(c) {
                quote = None;
            } else if quote.is_none() && matches!(c, '\'' | '"') {
                quote = Some(c);
            } else if quote.is_none() && c == ',' {
                return true;
            }
            false
        })
        .filter_map(|pair| pair.split_once('='))
}

/// A name as TOML may write it, in quotes.
fn unquoted(name: &str) -> &str {
    name.trim().trim_matches(['"', '\''])
}

/// Gradle property names have dots: "signing.password".
fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// The name and the secret, if the name says it holds one and the value is
/// a literal, or the value is a URL with a password or a private key, which
/// are secrets under any name. For a URL, the secret is its password.
fn secret<'a>(name: &'a str, value: &'a str) -> Option<(&'a str, &'a str)> {
    if !is_name(name) {
        return None;
    }
    let literal = shell_literal(value);
    if let Some(password) = literal.and_then(url_password) {
        return Some((name, password));
    }
    if let Some(key) = scalar_literal_by(value, |value, _| private_key_value(value)) {
        return Some((name, key));
    }
    let value = literal?;
    (secret_name(name)
        && value.len() >= 8
        && plausible(value)
        && !path_value(value)
        && !variable_name(value))
    .then_some((name, value))
}

/// A value that names another variable a secret is in, as "OPENAI_API_KEY"
/// does: capitals, digits and an "_", in a name that says it holds a
/// secret. A password in capitals, such as "HUNTER2_HUNTER2", is none.
fn variable_name(value: &str) -> bool {
    secret_name(value)
        && value.starts_with(|c: char| c.is_ascii_uppercase())
        && value.contains('_')
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether the name says the variable holds a secret.
fn secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ([
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "ACCESSKEY",
        "PRIVATE_KEY",
        "PRIVATEKEY",
        "SECRETKEY",
        "CREDENTIAL",
        "CREDENTIALS",
        "SIGNING_KEY",
        "SIGNINGKEY",
        "ENCRYPTION_KEY",
        "ENCRYPTIONKEY",
    ]
    .iter()
    .any(|word| upper.ends_with(word) || upper.contains(&format!("{word}_")))
        // Laravel's key. Other names that end in "KEY", such as "GPG_KEY",
        // "SORT_KEY" or "PUSHER_APP_KEY", often hold an ID or a setting.
        || upper == "APP_KEY"
        || ["PASS", "PWD"].iter().any(|word| last_word(name, word)))
        && !public_key_name(&upper)
        // Settings about secrets, not secrets, and where a service is.
        && ![
            "_LENGTH", "_FILE", "_PATH", "_URL", "_URI", "_ENDPOINT", "_NAME", "_ID", "_TTL",
            "_EXPIRY", "_VAR",
        ]
        .iter()
        .any(|suffix| upper.ends_with(suffix))
}

/// Whether `word`, in capitals, is the last word of `name`: after "_" or
/// ".", or as a capital after a small letter, as in "SMTP_PASS", "smtp.pass"
/// and "smtpPass". "BYPASS", "MONKEY" and the shell's "OLDPWD" end in none.
fn last_word(name: &str, word: &str) -> bool {
    let at = name.len().saturating_sub(word.len());
    let (Some(head), Some(tail)) = (name.get(..at), name.get(at..)) else {
        return false;
    };
    tail.eq_ignore_ascii_case(word)
        && (head.ends_with(['_', '.'])
            || (tail.starts_with(|c: char| c.is_ascii_uppercase())
                && head.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())))
}

/// The password in a URL's "user:password@host", when it is written out:
/// not a variable, a template or a placeholder. In GitHub's
/// "token:x-oauth-basic@host" the token is where the user goes.
fn url_password(value: &str) -> Option<&str> {
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, host) = authority.rsplit_once('@')?;
    let (user, password) = userinfo.split_once(':')?;
    let password = if password.eq_ignore_ascii_case("x-oauth-basic") {
        user
    } else {
        password
    };
    // A URL has "<", ">", "{" and "}" only encoded, so these mark a template.
    (!host.is_empty()
        && !password.starts_with('$')
        && !password.contains(['<', '>', '{', '}'])
        && password.len() >= 8
        && plausible(password))
    .then_some(password)
}

/// A private key in PEM form, from its header on, where what follows the
/// header is not a placeholder. Its line breaks may be written "\n".
fn private_key_value(value: &str) -> bool {
    let Some((label, body)) = value
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.split_once("-----"))
    else {
        return false;
    };
    let Some((body, _)) = body.split_once(&format!("-----END {label}-----")) else {
        return false;
    };
    label.ends_with("PRIVATE KEY") && body.len() >= 16 && plausible(body)
}

/// A private key over several lines inside quotes, as a .env file can hold
/// one, if `raw` opens it: the name, and the key up to where the quote
/// closes. `rest` is the file from `raw` on. Only lines a key has are read
/// past `raw`: base64, an encrypted key's header fields, a blank line and its
/// last line. The line that opens the next key in the same quote ends the
/// read, so a line is read for at most one key in each kind of quote.
fn multiline_key<'a>(raw: &'a str, rest: &'a str, shell: bool) -> Option<(&'a str, &'a str)> {
    let (name, value) = assignment(raw, shell)?;
    let value = value.trim();
    let quote = value.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let opened = &value[1..];
    if !is_name(name) || !opened.starts_with("-----BEGIN ") || opened.contains(quote) {
        return None;
    }
    let start = (opened.as_ptr() as usize).checked_sub(rest.as_ptr() as usize)?;
    let mut at = raw.len();
    for line in rest.get(at..)?.split_inclusive('\n') {
        if let Some(close) = line.find(quote) {
            let after = line[close + 1..].trim();
            let key = rest.get(start..at + close)?.trim_end();
            return ((after.is_empty() || after.starts_with('#')) && private_key_value(key))
                .then_some((name, key));
        }
        let text = line.trim();
        let of_key = text.starts_with("Proc-Type: ")
            || text.starts_with("DEK-Info: ")
            || text.starts_with("-----END ")
            || text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
        if !of_key {
            return None;
        }
        at += line.len();
    }
    None
}

/// A value as a shell or .env file holds it: "$" and "`" are expanded
/// unless single quotes hold them, and a leading "!" or "&" is text.
fn shell_literal(raw: &str) -> Option<&str> {
    scalar_literal_by(raw, |value, quote| {
        verbatim_literal(value) && (quote == Some('\'') || !value.contains(['$', '`']))
    })
}

/// The value in "NAME=value command", which is how a shell gives a variable
/// to one command and how it then sits in history: up to the first blank, or
/// to the quote that closes it. Where a blank follows the "=", the line is in
/// some other format and is left whole.
fn shell_word(value: &str) -> &str {
    let end = match value.chars().next() {
        Some(quote @ ('\'' | '"')) => value[1..].find(quote).map(|at| at + 2),
        Some(c) if !c.is_whitespace() => value.find(char::is_whitespace),
        _ => None,
    };
    match end {
        // Before a command, a ";" ends the assignment and is not part of it.
        Some(end) if value[end..].starts_with(|c: char| c.is_whitespace() || c == ';') => {
            let word = &value[..end];
            word.strip_suffix(';').unwrap_or(word)
        }
        _ => value,
    }
}

/// Each "NAME=value" word a shell takes as an assignment: before a command,
/// after "env" or "sudo", or after "export" and its kin, at the start of the
/// line or after a ";", "&" or "|". A word ends at a blank or one of those
/// outside quotes, and the value is the rest of it, quotes and all. Other
/// words are a command's arguments, where "a=b" is only text.
fn shell_assignments(raw: &str) -> impl Iterator<Item = (&str, &str)> {
    #[derive(Clone, Copy)]
    enum At {
        Command,
        Env,
        Export,
        Arguments,
    }
    let line = raw.trim_start();
    // fish history: "- cmd: command". zsh's ": <time>:<duration>;command"
    // needs nothing: it is the ":" command, then this one after the ";".
    let mut rest = line.strip_prefix("- cmd: ").unwrap_or(line);
    let mut at = At::Command;
    std::iter::from_fn(move || loop {
        rest = rest.trim_start();
        let next = rest.chars().next()?;
        if matches!(next, ';' | '&' | '|') {
            rest = &rest[1..];
            at = At::Command;
            continue;
        }
        // A comment runs to the end of the line.
        if next == '#' {
            return None;
        }
        let (mut quote, mut escaped) = (None, false);
        let end = rest
            .char_indices()
            .find_map(|(i, c)| {
                if escaped {
                    escaped = false;
                } else if c == '\\' && quote != Some('\'') {
                    escaped = true;
                } else if quote == Some(c) {
                    quote = None;
                } else if quote.is_none() && matches!(c, '\'' | '"') {
                    quote = Some(c);
                } else if quote.is_none() && (c.is_whitespace() || matches!(c, ';' | '&' | '|')) {
                    return Some(i);
                }
                None
            })
            .unwrap_or(rest.len());
        let word = &rest[..end];
        rest = &rest[end..];
        let assignment = word.split_once('=').filter(|(name, _)| {
            name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
        match (at, assignment) {
            (At::Arguments, _) => {}
            (_, Some(pair)) => return Some(pair),
            // env's and sudo's options come before their variables.
            (At::Env, None) if word.starts_with('-') => {}
            // What env or sudo runs is a command, as "sudo env" is.
            (At::Command | At::Env, None) => {
                at = match word {
                    "env" | "sudo" => At::Env,
                    "export" | "declare" | "typeset" | "local" | "readonly" => At::Export,
                    _ => At::Arguments,
                }
            }
            (At::Export, None) => {}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_environment_keeps_each_secret_even_beside_a_service_token() {
        let line = concat!(
            "env = { \"FIRST_PASSWORD\" = \"synthetic-first-value\", ",
            "\"SERVICE_TOKEN\" = \"gh",
            "p_0123456789abcdefghijABCDEFGHIJ012345\", ",
            "\"SECOND_PASSWORD\" = \"synthetic-second-value\" }\n"
        );
        let hits = env_hits(line.as_bytes()).unwrap();
        let names: Vec<_> = hits.iter().map(|hit| hit.subject.as_deref()).collect();
        assert_eq!(names, [Some("FIRST_PASSWORD"), Some("SECOND_PASSWORD")]);
        assert_eq!(
            &line[hits[0].span.clone().unwrap()],
            "synthetic-first-value"
        );
        assert_eq!(
            &line[hits[1].span.clone().unwrap()],
            "synthetic-second-value"
        );
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_line() {
        let file = b"\xef\xbb\xbfDATABASE_PASSWORD=synthetic-only-value\nAPI_TOKEN=synthetic-second-value\n";
        for hits in [env_hits(file), shell_hits(file)] {
            let hits = hits.unwrap();
            let found: Vec<_> = hits
                .iter()
                .map(|hit| (hit.line, hit.subject.as_deref()))
                .collect();
            assert_eq!(
                found,
                [
                    (Some(1), Some("DATABASE_PASSWORD")),
                    (Some(2), Some("API_TOKEN"))
                ]
            );
            // Positions are in the file as read, mark included.
            assert_eq!(
                &file[hits[0].span.clone().unwrap()],
                b"synthetic-only-value"
            );
            assert_eq!(
                &file[hits[1].span.clone().unwrap()],
                b"synthetic-second-value"
            );
        }
    }

    #[test]
    fn inline_tables_keep_commas_inside_quoted_values() {
        for line in [
            r#"env = { DATABASE_PASSWORD = "synthetic,only-value" }"#,
            r#"env = { DATABASE_PASSWORD = 'synthetic,only-value' }"#,
            r#"env = { NOTE = "fixture,notes", DATABASE_PASSWORD = "synthetic,only-value" }"#,
            r#"env = { NOTE = "fixture\",notes", DATABASE_PASSWORD = "synthetic,only-value" }"#,
            r#"env = { NOTE = "fixture\\", DATABASE_PASSWORD = "synthetic,only-value" }"#,
            r#"env = { NOTE = 'fixture\', DATABASE_PASSWORD = "synthetic,only-value" }"#,
        ] {
            let hits = env_hits(line.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].line, Some(1));
            assert_eq!(hits[0].subject.as_deref(), Some("DATABASE_PASSWORD"));
            let span = hits[0].span.clone().expect("literal has a value span");
            assert!(line.get(span) == Some("synthetic,only-value"));
        }
    }

    #[test]
    fn commas_inside_an_inline_environment_value_are_not_pair_separators() {
        let line = "env = { FIRST_PASSWORD = 'synthetic,first-value', SECOND_PASSWORD = 'synthetic-second-value' }";
        let hits = env_hits(line.as_bytes()).unwrap();
        let names: Vec<_> = hits.iter().map(|hit| hit.subject.as_deref()).collect();
        assert_eq!(names, [Some("FIRST_PASSWORD"), Some("SECOND_PASSWORD")]);
        assert_eq!(
            &line[hits[0].span.clone().unwrap()],
            "synthetic,first-value"
        );
    }

    #[test]
    fn a_comment_after_an_inline_environment_does_not_hide_the_last_value() {
        let line = "env = { FIRST_PASSWORD = 'synthetic-first-value', SECOND_PASSWORD = 'synthetic-second-value' } # comment";
        let hits = env_hits(line.as_bytes()).unwrap();
        let names: Vec<_> = hits.iter().map(|hit| hit.subject.as_deref()).collect();
        assert_eq!(names, [Some("FIRST_PASSWORD"), Some("SECOND_PASSWORD")]);
    }

    #[test]
    fn a_token_inside_a_longer_password_does_not_hide_the_password() {
        let line = concat!(
            "PASSWORD=synthetic.prefix.gh",
            "p_0123456789abcdefghijABCDEFGHIJ012345",
            ".suffix\n"
        );
        let hits = env_hits(line.as_bytes()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].subject.as_deref(), Some("PASSWORD"));
        assert_eq!(
            &line[hits[0].span.clone().unwrap()],
            line.trim().strip_prefix("PASSWORD=").unwrap()
        );
    }

    #[test]
    fn inline_environment_reports_the_assignment_limit() {
        let pairs = |count| {
            (0..count)
                .map(|n| format!("PASSWORD_{n}_TOKEN = \"synthetic-value-{n}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let exact = format!("env = {{ {} }}", pairs(100));
        assert_eq!(env_hits(exact.as_bytes()).unwrap().len(), 100);
        let more = format!("env = {{ {} }}", pairs(101));
        let incomplete = env_hits(more.as_bytes()).err().expect("assignment limit");
        assert_eq!(incomplete.reason, "scan-limit");
        assert_eq!(incomplete.hits.len(), 100);
    }

    #[test]
    fn every_assignment_a_shell_gives_a_command_is_read() {
        for (line, want) in [
            (
                "PGUSER=fixture PGPASSWORD=synthetic-only-value psql -h db.example.invalid shop",
                &[("PGPASSWORD", "synthetic-only-value")][..],
            ),
            (
                ": 1700000001:0;PGHOST=db.example.invalid PGPASSWORD=synthetic-only-value psql shop",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "- cmd: PGUSER=fixture PGPASSWORD=synthetic-only-value psql shop",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "env PGPASSWORD=synthetic-only-value psql -h db.example.invalid",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "env -i PGUSER=fixture PGPASSWORD='synthetic-only-value' psql",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "sudo -E PGPASSWORD=synthetic-only-value psql",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "sudo env PGPASSWORD=synthetic-only-value psql",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "cd app && DB_PASSWORD=synthetic-only-value ./run",
                &[("DB_PASSWORD", "synthetic-only-value")],
            ),
            (
                "make check; PGPASSWORD=\"synthetic-only-value\" psql | grep fixture",
                &[("PGPASSWORD", "synthetic-only-value")],
            ),
            (
                "make check || API_TOKEN=synthetic-only-value make deploy",
                &[("API_TOKEN", "synthetic-only-value")],
            ),
            (
                "export LOG_LEVEL=debug DB_PASSWORD=synthetic-only-value",
                &[("DB_PASSWORD", "synthetic-only-value")],
            ),
            (
                "declare -x LOG_LEVEL=debug API_TOKEN=synthetic-only-value",
                &[("API_TOKEN", "synthetic-only-value")],
            ),
            (
                "DB_PASSWORD=synthetic-only-value API_TOKEN=synthetic-second-value ./run",
                &[
                    ("DB_PASSWORD", "synthetic-only-value"),
                    ("API_TOKEN", "synthetic-second-value"),
                ],
            ),
            // Text after the command is its arguments, not assignments, and
            // a separator or blank inside quotes splits nothing.
            ("make deploy DEPLOY_TOKEN=synthetic-only-value", &[]),
            ("sudo -n make deploy DEPLOY_TOKEN=synthetic-only-value", &[]),
            ("psql --password=synthetic-only-value shop", &[]),
            (
                "curl https://api.example.invalid/?api_token=synthetic-only-value",
                &[],
            ),
            (
                "[[ $DB_PASSWORD == synthetic-only-value ]] && echo API_TOKEN=synthetic-only-value",
                &[],
            ),
            ("echo 'cd app && DB_PASSWORD=synthetic-only-value ./run'", &[]),
            ("echo \"done; API_TOKEN=synthetic-only-value\"", &[]),
            ("# PGUSER=fixture PGPASSWORD=synthetic-only-value psql", &[]),
            ("PGUSER=fixture PGPASSWORD=$(pass show db) psql", &[]),
            ("PGUSER=fixture PGPASSWORD=changeme psql", &[]),
        ] {
            let hits = shell_hits(line.as_bytes()).unwrap();
            let found: Vec<_> = hits
                .iter()
                .map(|hit| {
                    let span = hit.span.clone().expect("literal has a value span");
                    (hit.subject.as_deref().unwrap(), line.get(span).unwrap())
                })
                .collect();
            assert_eq!(found, want, "{line}");
            assert!(hits.iter().all(|hit| hit.line == Some(1)));
        }
    }

    #[test]
    fn a_value_is_text_where_its_format_gives_its_symbols_no_meaning() {
        for (line, want) in [
            // A .env or shell file: "!" and "&" are text, and so is "$"
            // inside single quotes.
            (
                "DB_PASSWORD=!synthetic-only-value",
                Some("!synthetic-only-value"),
            ),
            (
                "DB_PASSWORD='!synthetic-only-value'",
                Some("!synthetic-only-value"),
            ),
            (
                "DB_PASSWORD=\"!synthetic-only-value\"",
                Some("!synthetic-only-value"),
            ),
            (
                "DB_PASSWORD='&synthetic-only-value'",
                Some("&synthetic-only-value"),
            ),
            (
                "export DB_PASSWORD='!synthetic-only-value'",
                Some("!synthetic-only-value"),
            ),
            (
                "export DB_PASSWORD='synthetic$only-value'",
                Some("synthetic$only-value"),
            ),
            // A shell expands "$" and "`" outside single quotes.
            ("DB_PASSWORD=synthetic$only-value", None),
            ("export DB_PASSWORD=\"synthetic$only-value\"", None),
            ("DB_PASSWORD=\"synthetic`only`value\"", None),
            // A template stands in for a value, quoted or not.
            ("DB_PASSWORD='${OTHER}'", None),
            ("env = { DB_PASSWORD = '${OTHER}' }", None),
            // In YAML a leading "!" is a tag and "&" an anchor, unless quoted.
            ("GOOGLE_API_KEY: !synthetic-only-value", None),
            ("GOOGLE_API_KEY: &synthetic-only-value", None),
            (
                "GOOGLE_API_KEY: '!synthetic-only-value'",
                Some("!synthetic-only-value"),
            ),
        ] {
            let hits = shell_hits(line.as_bytes()).unwrap();
            let found = hits
                .first()
                .and_then(|hit| line.get(hit.span.clone().expect("a value span")));
            assert_eq!(found, want, "{line}");
        }
    }

    #[test]
    fn names_and_values_are_filtered() {
        for (line, want) in [
            (
                "STRIPE_SECRET_KEY=synthetic-only-value",
                Some("STRIPE_SECRET_KEY"),
            ),
            (
                "export  DB_PASSWORD='synthetic-only-value'",
                Some("DB_PASSWORD"),
            ),
            (
                "AWS_SECRET_ACCESS_KEY=synthetic-only-value",
                Some("AWS_SECRET_ACCESS_KEY"),
            ),
            ("TOKENIZER=synthetic-only-value", None),
            // Where a sign-in service is, not a secret.
            ("GOOGLE_TOKEN_URI=https://oauth2.googleapis.com/token", None),
            (
                "OIDC_TOKEN_ENDPOINT=https://login.microsoftonline.com/common/oauth2/v2.0/token",
                None,
            ),
            ("DB_PASSWORD=short", None),
            ("DB_PASSWORD=$(pass show db)", None),
            ("DB_PASSWORD_FILE=/run/secrets/db-password", None),
            // The name of the variable that holds it, as Codex keeps one.
            ("bearer_token_env_var = \"FIXTURE_TOKEN\"", None),
            ("echo API_TOKEN=synthetic-only-value", None),
            // A value given to one command, as it is kept in shell history.
            (
                "PGPASSWORD=synthetic-only-value psql -h db.example.invalid shop",
                Some("PGPASSWORD"),
            ),
            (
                ": 1700000000:0;PGPASSWORD='synthetic-only-value' psql -h db.example.invalid",
                Some("PGPASSWORD"),
            ),
            (
                "export DEPLOY_TOKEN=synthetic-only-value && make deploy",
                Some("DEPLOY_TOKEN"),
            ),
            (
                "DB_PASSWORD=$(pass show db) psql -h db.example.invalid",
                None,
            ),
            ("DB_PASSWORD= psql-with-a-long-name -h db", None),
            ("DB_PASSWORD='two words' psql", None),
            // A YAML file of secrets, as goose keeps one, also with a value
            // that ends in "=".
            (
                "GOOGLE_API_KEY: synthetic-only-value-1234",
                Some("GOOGLE_API_KEY"),
            ),
            (
                "GOOGLE_API_KEY: c3ludGhldGljLW9ubHk=",
                Some("GOOGLE_API_KEY"),
            ),
            ("GOOGLE_API_KEY: ${GOOGLE_API_KEY}", None),
            ("Reminder: rotate the API_TOKEN: tomorrow-morning", None),
            // TOML with the name in quotes, and Codex's one-line table of a
            // server's environment.
            (
                "\"FIXTURE_API_KEY\" = \"synthetic-only-value\"",
                Some("FIXTURE_API_KEY"),
            ),
            (
                "env = { \"LOG_LEVEL\" = \"verbose-logging\", \"FIXTURE_TOKEN\" = \"synthetic-only-value\" }",
                Some("FIXTURE_TOKEN"),
            ),
            ("env = { \"LOG_LEVEL\" = \"verbose-logging\" }", None),
            // Terraform variables, fish, and fish's history format.
            (
                "db_password = \"synthetic-only-value\"",
                Some("db_password"),
            ),
            (
                "set -gx DEPLOY_TOKEN synthetic-only-value",
                Some("DEPLOY_TOKEN"),
            ),
            (
                "- cmd: export API_TOKEN=synthetic-only-value",
                Some("API_TOKEN"),
            ),
            ("set -gx EDITOR vim-with-plugins", None),
            (
                "signing.password=synthetic-only-value",
                Some("signing.password"),
            ),
            (
                "ossrhPassword = synthetic-only-value",
                Some("ossrhPassword"),
            ),
            // Joined forms of the names, as Gradle's AwsCredentials reads
            // "<repo>AccessKey" and "<repo>SecretKey".
            (
                "awsSecretKey=synthetic-only-value",
                Some("awsSecretKey"),
            ),
            ("secretKey=synthetic-only-value", Some("secretKey")),
            ("SECRETKEY=synthetic-only-value", Some("SECRETKEY")),
            ("privateKey=synthetic-only-value", Some("privateKey")),
            ("accessKey=synthetic-only-value", Some("accessKey")),
            (
                "awsSecretAccessKey=synthetic-only-value",
                Some("awsSecretAccessKey"),
            ),
            ("awsAccessKeyId=synthetic-only-value", None),
            ("secretKeyFile=/run/secrets/fixture", None),
            ("SECRETKEY_PATH=/run/secrets/fixture", None),
        ] {
            assert_eq!(
                secret_assignment(line, true).map(|found| found.0),
                want,
                "{line}"
            );
        }
        // The value is what a shell would take: not the command after it,
        // and not the ";" that ends the assignment.
        for line in [
            "API_TOKEN=synthetic-only-value curl https://api.example.invalid",
            "export API_TOKEN=synthetic-only-value; make deploy",
            "API_TOKEN='synthetic-only-value' make deploy",
        ] {
            let value = secret_assignment(line, true).map(|found| found.1);
            assert_eq!(value, Some("synthetic-only-value"), "{line}");
        }
        let quoted = "export API_TOKEN=\"synthetic-only-value\"; make deploy";
        let value = secret_assignment(quoted, true).map(|found| found.1);
        assert_eq!(value, Some("synthetic-only-value"));
        // In a settings file a ";" at the end belongs to the value.
        let value = secret_assignment("API_TOKEN=synthetic-only-value;", true);
        assert_eq!(value.map(|found| found.1), Some("synthetic-only-value;"));
        // A settings file is not a shell: there a value runs to the end of
        // its line, so words after the first are not a command.
        for line in [
            "PASSWORD_RESET_SUBJECT=Password reset requested",
            "SMTP_PASSWORD=correcthorse battery staple",
            "PGPASSWORD=synthetic-only-value psql -h db.example.invalid shop",
        ] {
            assert_eq!(secret_assignment(line, false), None, "{line}");
        }
        let whole = secret_assignment("API_TOKEN=synthetic-only-value", false);
        assert_eq!(whole.map(|found| found.1), Some("synthetic-only-value"));
    }

    #[test]
    fn more_names_that_hold_a_secret_are_read() {
        for (line, want) in [
            ("SMTP_PASS=synthetic-only-value", Some("SMTP_PASS")),
            ("smtp.pass=synthetic-only-value", Some("smtp.pass")),
            ("smtpPass=synthetic-only-value", Some("smtpPass")),
            ("MYSQL_PWD=synthetic-only-value", Some("MYSQL_PWD")),
            (
                "GOOGLE_CREDENTIALS=synthetic-only-value",
                Some("GOOGLE_CREDENTIALS"),
            ),
            (
                "JWT_SIGNING_KEY=synthetic-only-value",
                Some("JWT_SIGNING_KEY"),
            ),
            (
                "ENCRYPTION_KEY=synthetic-only-value",
                Some("ENCRYPTION_KEY"),
            ),
            (
                "APP_KEY=base64:c3ludGhldGljLW9ubHktdmFsdWU=",
                Some("APP_KEY"),
            ),
            ("signingKey=synthetic-only-value", Some("signingKey")),
            // Words that end in the same letters, and the shell's own
            // variables for folders.
            ("BYPASS=synthetic-only-value", None),
            ("SSO_BYPASS=synthetic-only-value", None),
            ("COMPASS=synthetic-only-value", None),
            ("MONKEY=synthetic-only-value", None),
            ("PWD=synthetic-only-value", None),
            ("OLDPWD=synthetic-only-value", None),
            ("export OLDPWD=/Users/fixture/project", None),
            // Keys that are public by design, and where a key file is.
            ("STRIPE_PUBLISHABLE_KEY=synthetic-only-value", None),
            ("JWT_PUBLIC_KEY=synthetic-only-value", None),
            ("SSH_KEY=~/.ssh/id_ed25519", None),
            ("DEPLOY_KEY=/Users/fixture/.ssh/deploy_key", None),
            (
                "GOOGLE_APPLICATION_CREDENTIALS=/Users/fixture/service.json",
                None,
            ),
            ("TLS_KEY=./certs/server.key", None),
            ("GOOGLE_APPLICATION_CREDENTIALS=credentials.json", None),
            ("GOOGLE_APPLICATION_CREDENTIALS=/app/credentials.json", None),
            ("SSH_KEY=/app/.ssh/id_rsa", None),
            ("TLS_KEY=certs/server.key", None),
            ("SSL_KEY=/certs/tls.key", None),
            ("JWT_KEY=/secrets/jwt.pem", None),
            // A secret can have "/" in it, as base64 does.
            (
                "AWS_SECRET_ACCESS_KEY=fixture/Synthetic/OnlyValue",
                Some("AWS_SECRET_ACCESS_KEY"),
            ),
            // Codex names the variable a provider's key is read from.
            ("env_key = \"AZURE_OPENAI_API_KEY\"", None),
            ("API_KEY_ENV=OPENAI_API_KEY", None),
            // A password in capitals is not a variable's name.
            ("DB_PASSWORD=HUNTER2_HUNTER2", Some("DB_PASSWORD")),
            // Keys that are not secrets: an ID, a sort order, a storage name.
            ("GPG_KEY=0123456789ABCDEF", None),
            ("SORT_KEY=created_at_desc", None),
            ("VITE_STORAGE_KEY=app_state_v2", None),
            // A realtime service's app key is a public client ID.
            ("PUSHER_APP_KEY=abcdefghij0123456789", None),
            // Where a key file is, from the current folder or by its name.
            ("SSH_KEY=.ssh/id_ed25519", None),
            ("SSH_KEY=id_ed25519_work", None),
            ("SSH_KEY='$HOME/.ssh/id_rsa'", None),
            ("PRIVATE_KEY=.ssh/id_ed25519", None),
            ("PRIVATE_KEY=id_ed25519_work", None),
            ("PRIVATE_KEY='$HOME/.ssh/id_rsa'", None),
            ("SIGNING_KEY=keys/signing", None),
            // A password in small letters with a "/" is not a path.
            ("DB_PASSWORD=synthetic/only-value", Some("DB_PASSWORD")),
        ] {
            assert_eq!(
                secret_assignment(line, true).map(|found| found.0),
                want,
                "{line}"
            );
        }
    }

    #[test]
    fn a_password_in_a_url_is_found_under_any_name() {
        for (line, name) in [
            (
                "DATABASE_URL=postgres://fixture:synthetic-only-value@db.example.invalid/app",
                "DATABASE_URL",
            ),
            (
                "DATABASE_URL=\"postgres://fixture:synthetic-only-value@db.example.invalid:5432/app?sslmode=require\"",
                "DATABASE_URL",
            ),
            (
                "REDIS_URL=redis://:synthetic-only-value@cache.example.invalid:6379",
                "REDIS_URL",
            ),
            (
                "database_url = \"postgres://fixture:synthetic-only-value@db.example.invalid/app\"",
                "database_url",
            ),
            (
                "export DATABASE_URL='postgres://fixture:synthetic-only-value@db.example.invalid/app'",
                "DATABASE_URL",
            ),
        ] {
            for hits in [env_hits(line.as_bytes()), shell_hits(line.as_bytes())] {
                let hits = hits.unwrap();
                assert_eq!(hits.len(), 1, "{line}");
                assert_eq!(hits[0].subject.as_deref(), Some(name), "{line}");
                let span = hits[0].span.clone().expect("a value span");
                assert_eq!(line.get(span), Some("synthetic-only-value"), "{line}");
            }
        }
        // A value given to one command, as shell history keeps it.
        let line = ": 1700000000:0;DATABASE_URL=postgres://fixture:synthetic-only-value@db.example.invalid/app psql";
        let hits = shell_hits(line.as_bytes()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(
            line.get(hits[0].span.clone().unwrap()),
            Some("synthetic-only-value")
        );
        // GitHub's form puts the token where the user goes.
        for line in [
            "REPO_URL=https://synthetic-only-value:x-oauth-basic@git.example.invalid/app",
            "REPO_URL=https://synthetic-only-value:X-OAuth-Basic@git.example.invalid/app",
        ] {
            let hits = env_hits(line.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1, "{line}");
            assert_eq!(
                line.get(hits[0].span.clone().unwrap()),
                Some("synthetic-only-value"),
                "{line}"
            );
        }
        for line in [
            "DATABASE_URL=postgres://db.example.invalid/app",
            "DATABASE_URL=postgres://fixture@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:${DB_PASSWORD}@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:$DB_PASSWORD@db.example.invalid/app",
            "DATABASE_URL='postgres://fixture:$DB_PASSWORD@db.example.invalid/app'",
            "DATABASE_URL=postgres://fixture:<password>@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:{{password}}@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:changeme@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:your_password@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:short@db.example.invalid/app",
            "DATABASE_URL=postgres://fixture:synthetic-only-value@/app",
            "# DATABASE_URL=postgres://fixture:synthetic-only-value@db.example.invalid/app",
            "HOMEPAGE=https://example.invalid/@fixture:synthetic-only-value",
        ] {
            assert!(env_hits(line.as_bytes()).unwrap().is_empty(), "{line}");
            assert!(shell_hits(line.as_bytes()).unwrap().is_empty(), "{line}");
        }
    }

    #[test]
    fn a_private_key_in_a_value_is_found_on_one_line_or_several() {
        let begin = concat!("-----BEGIN ", "PRIVATE KEY-----");
        let end = concat!("-----END ", "PRIVATE KEY-----");
        let body = "c3ludGhldGljLW9ubHktdmFsdWU";
        let several = format!("PORT=8080\nGITHUB_APP_PEM=\"{begin}\n{body}\n{body}\n{end}\"\nAPI_URL=https://api.example.invalid\n");
        for file in [
            format!("PORT=8080\nJWT_PRIVATE_KEY=\"{begin}\\n{body}\\n{body}\\n{end}\\n\"\n"),
            format!("PORT=8080\nexport JWT_PRIVATE_KEY='{begin}\\n{body}\\n{end}'\n"),
            several.clone(),
            several.replace('\n', "\r\n"),
            // The closing quote on a line of its own.
            format!("PORT=8080\nTLS_KEY='{begin}\n{body}\n{end}\n'\n"),
        ] {
            for hits in [env_hits(file.as_bytes()), shell_hits(file.as_bytes())] {
                let hits = hits.unwrap();
                assert_eq!(hits.len(), 1, "{file}");
                assert_eq!(hits[0].line, Some(2), "{file}");
                let value = file
                    .get(hits[0].span.clone().expect("a value span"))
                    .unwrap();
                assert!(value.starts_with(begin), "{file}");
                assert!(value.contains(end), "{file}");
                assert!(!value.contains(['"', '\'']), "{file}");
            }
        }
        // An encrypted key has header fields and a blank line.
        let file = format!(
            "TLS_KEY=\"{}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233\n\n{body}\n{}\"\n",
            concat!("-----BEGIN RSA ", "PRIVATE KEY-----"),
            concat!("-----END RSA ", "PRIVATE KEY-----"),
        );
        assert_eq!(env_hits(file.as_bytes()).unwrap().len(), 1, "{file}");
        let public = concat!("-----BEGIN ", "PUBLIC KEY-----");
        for file in [
            format!("JWT_KEY=\"{public}\\n{body}\\n-----END PUBLIC KEY-----\"\n"),
            format!("JWT_PRIVATE_KEY=\"{begin}\\nYOUR_KEY_HERE\\n{end}\"\n"),
            format!("JWT_PRIVATE_KEY=\"{begin}\n...\n{end}\"\n"),
            // A quote that never closes.
            format!("JWT_PRIVATE_KEY=\"{begin}\n{body}\n{end}\nPORT=8080\n"),
            // Prose in between is not a key.
            format!("JWT_PRIVATE_KEY=\"{begin}\nsee the wiki for this one\n{body}\"\n"),
            format!("JWT_PRIVATE_KEY=\"{begin}\nTODO: paste the key here\n{end}\"\n"),
            // The end of something else, or no end at all.
            format!("JWT_PRIVATE_KEY=\"{begin}\\n{body}\\n-----END CERTIFICATE-----\"\n"),
            format!("JWT_PRIVATE_KEY=\"{begin}\\n{body}\\n\"\n"),
        ] {
            assert!(env_hits(file.as_bytes()).unwrap().is_empty(), "{file}");
            assert!(shell_hits(file.as_bytes()).unwrap().is_empty(), "{file}");
        }
    }
}
