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
        (b": 1700000000:0;export API_TOKEN=\"synthetic-only-value\"\n", true),
        (b"API_TOKEN=${OTHER}\nDB_PASSWORD=changeme\nPORT=8080\nAUTHOR=someone-else\n", false),
        (b"# API_TOKEN=synthetic-only-value\nPASSWORD_MIN_LENGTH=12\n", false),
        // A value runs to the end of its line here, and this one is prose.
        (b"PASSWORD_RESET_SUBJECT=Password reset requested\n", false),
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
        (
            b"PASSWORD_MIN_LENGTH=12 make check\nDB_PASSWORD=$(pass show db) psql\n",
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
    capped_hits(
        text.lines().enumerate().filter_map(|(i, raw)| {
            // A recognizable service token is reported by its own rule.
            let (name, value) =
                secret_assignment(raw, shell).filter(|_| !token::has_token(raw.as_bytes()))?;
            let at = value.as_ptr() as usize - text.as_ptr() as usize;
            let mut hit = Hit::line(i + 1).about(name);
            hit.span = exact.then_some(at..at + value.len());
            Some(hit)
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
            .or_else(|| line.split_once(": ").map(|(name, v)| (unquoted(name), v)))?,
    };
    // Codex writes a server's variables on one line: env = { "NAME" = "value" }
    if let Some(table) = value.trim().strip_prefix('{') {
        let pairs = table.trim_end().trim_end_matches('}').split(',');
        return pairs
            .filter_map(|pair| pair.split_once('='))
            .find_map(|(name, value)| secret(unquoted(name), value));
    }
    secret(name, value)
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
        // Settings about secrets, not secrets.
        && !["_LENGTH", "_FILE", "_PATH", "_URL", "_NAME", "_ID", "_TTL", "_EXPIRY"]
            .iter()
            .any(|suffix| upper.ends_with(suffix));
    let value = scalar_literal(value)?;
    (secret_name && value.len() >= 8 && plausible(value)).then_some((name, value))
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

#[cfg(test)]
mod tests {
    use super::*;

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
