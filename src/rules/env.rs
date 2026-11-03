//! Secrets assigned to variables in .env files and shell startup or history files.

use super::*;

pub const ENV_SECRET: Rule = Rule {
    id: "secret.env-assignment",
    category: "developer-cloud",
    kind: "review",
    severity: "medium",
    title: "Password or key in a plain-text settings file",
    explanation: "A variable named like a password, key or token is set to a value in this file. Loose Keys only checked that the value is not a placeholder. It may be a local or test value.",
    reason: Some("Malware often collects .env and shell files, because they hold working passwords and keys in plain text."),
    next_step: Some("Decide whether this is a real credential. If it is, revoke it at the service and load the replacement from a password manager instead of this file."),
    advice: Advice {
        steps: &[
            "Check what the variable is for. A value for a local test database needs nothing more.",
            "For a real credential, revoke or change it at the service that issued it. Removing the line does not do that.",
            "Load the replacement at run time instead of storing it: a password manager CLI (for example 'op run' or 'security find-generic-password') can fill the variable when the program starts.",
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
                .then(|| secret_assignment(raw, shell))
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
/// secret-named variable. In a `shell` file the value is one word and a
/// command may follow it; in a settings file it runs to the end of the line.
fn secret_assignment(raw: &str, shell: bool) -> Option<(&str, &str)> {
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
    // Codex writes a server's variables on one line: env = { "NAME" = "value" }
    if let Some(table) = value.trim().strip_prefix('{') {
        return inline_table_pairs(table).find_map(|(name, value)| secret(unquoted(name), value));
    }
    secret(name, value)
}

fn inline_table_pairs(table: &str) -> impl Iterator<Item = (&str, &str)> {
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

/// The pair, if the name says it holds a secret and the value is a literal.
fn secret<'a>(name: &'a str, value: &'a str) -> Option<(&'a str, &'a str)> {
    if !is_name(name) {
        return None;
    }
    let upper = name.to_ascii_uppercase();
    let secret_name = [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|word| upper.ends_with(word) || upper.contains(&format!("{word}_")))
        // Settings about secrets, not secrets, and where a service is.
        && ![
            "_LENGTH", "_FILE", "_PATH", "_URL", "_URI", "_ENDPOINT", "_NAME", "_ID", "_TTL",
            "_EXPIRY",
        ]
        .iter()
        .any(|suffix| upper.ends_with(suffix));
    let value = shell_literal(value)?;
    (secret_name && value.len() >= 8 && plausible(value)).then_some((name, value))
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
}
