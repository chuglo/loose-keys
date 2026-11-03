//! AI coding tools: secrets written into MCP server configs, and the tools'
//! own stored sign-ins.

use super::*;

pub const MCP_SECRET: Rule = Rule {
    id: "dev.mcp.inline-secret",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Secret written into an MCP server config",
    explanation: "An MCP server entry in this file has a key, token or password written out in full. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("Any program that can read this file can copy the credential."),
    next_step: Some("Revoke the key at its service and stop storing it in the config. Removing the entry does not revoke it."),
    advice: Advice {
        steps: &[
            "Revoke or replace the key at the service this MCP server connects to.",
            "If the server supports sign-in (OAuth), use that instead of a key: remove the key and let the tool prompt you.",
            "Otherwise keep the key out of the config: start the server through a wrapper that reads it from the Keychain, for example: security find-generic-password -s <name> -w",
            "Remove the value from this file, and check that the file was never committed or synced.",
        ],
        link: None,
    },
    targets: &[
        Target::File(".cursor/mcp.json"),
        Target::File(".claude.json"),
        Target::File("Library/Application Support/Claude/claude_desktop_config.json"),
        Target::File(".codeium/windsurf/mcp_config.json"),
        Target::File(".gemini/settings.json"),
        Target::File("Library/Application Support/Code/User/mcp.json"),
        Target::File(".config/devin/mcp_config.json"),
        Target::File(".cline/data/settings/cline_mcp_settings.json"),
        Target::File("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
        Target::File("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"),
        Target::File(".copilot/mcp-config.json"),
        Target::File(".config/zed/settings.json"),
        Target::File(".config/opencode/opencode.json"),
        Target::File(".config/opencode/opencode.jsonc"),
        Target::File(".config/amp/settings.json"),
        // Settings files can set environment variables and model keys inline.
        Target::File(".claude/settings.json"),
        Target::Name("settings.local.json"),
        Target::File(".continue/config.json"),
        Target::Name("mcp.json"),
        Target::Name(".mcp.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: mcp_hits,
    },
    samples: &[
        (br#"{"mcpServers": {"fixture": {"command": "npx", "env": {"FIXTURE_API_KEY": "synthetic-only-value"}}}}"#, true),
        (br#"{"servers": {"fixture": {"url": "https://example.invalid", "headers": {"Authorization": "Bearer synthetic-only-value"}}}}"#, true),
        // Any scheme, in any case, comes before the value.
        (br#"{"servers": {"fixture": {"url": "https://example.invalid", "headers": {"Authorization": "Basic c3ludGhldGljOm9ubHktdmFsdWU="}}}}"#, true),
        (br#"{"servers": {"fixture": {"url": "https://example.invalid", "headers": {"Authorization": "bearer synthetic-only-value"}}}}"#, true),
        (br#"{"servers": {"fixture": {"url": "https://example.invalid", "headers": {"Authorization": "token synthetic-only-value"}}}}"#, true),
        (br#"{"servers": {"fixture": {"url": "https://example.invalid", "headers": {"Authorization": "token ${FIXTURE_TOKEN}"}}}}"#, false),
        (br#"{"mcpServers": {"fixture": {"command": "npx", "env": {"FIXTURE_API_KEY": "${env:FIXTURE_API_KEY}", "LOG_LEVEL": "verbose-logging"}}}}"#, false),
        (br#"{"mcpServers": {}}"#, false),
        (br#"{"env": {"FIXTURE_API_KEY": "synthetic-only-value"}, "permissions": {}}"#, true),
        (br#"{"models": [{"title": "fixture", "apiKey": "synthetic-only-value"}]}"#, true),
        (br#"{"context_servers": {"fixture": {"command": "npx", "env": {"FIXTURE_TOKEN": "synthetic-only-value"}}}}"#, true),
        (br#"{"env": {"FIXTURE_API_KEY": "${FIXTURE_API_KEY}"}, "models": [{"apiKey": ""}]}"#, false),
        // With comments and a trailing comma, as Zed and VS Code write and accept.
        (b"// Zed settings\n{\"context_servers\": {\"fixture\": {\"command\": \"npx\", \"env\": {\"FIXTURE_TOKEN\": \"synthetic-only-value\"},},},}\n", true),
        (br#"{"mcp": {"fixture": {"type": "local", "command": ["npx"], "environment": {"FIXTURE_API_KEY": "{env:FIXTURE_API_KEY}"}}}}"#, false),
        // Amp names its server map with its own prefix.
        (br#"{"amp.mcpServers": {"fixture": {"command": "npx", "env": {"FIXTURE_API_KEY": "synthetic-only-value"}}}}"#, true),
    ],
};

fn mcp_hits(bytes: &[u8]) -> Hits {
    let v = settings(bytes).ok_or("unreadable")?;
    let mut found = Vec::new();
    secrets(&v, 0, &mut found);
    let mut names: Vec<&str> = found.iter().map(|secret| secret.0).collect();
    names.sort();
    names.dedup();
    capped_hits(
        names
            .into_iter()
            .map(|name| Hit::file().about(&format!("server {name}"))),
        100,
    )
}

/// What the app fingerprints for this rule: each literal secret, with the
/// server and field that hold it. The tools rewrite the rest of such a file
/// as they run, which is no change to what was found. Never export this.
pub(super) fn mcp_material(bytes: &[u8]) -> Option<Vec<u8>> {
    let v = settings(bytes)?;
    let mut found = Vec::new();
    secrets(&v, 0, &mut found);
    found.sort();
    found.dedup();
    serde_json::to_vec(&found).ok()
}

/// The file as JSON. Zed, VS Code and opencode allow comments and trailing
/// commas in theirs, so a file that is not strict JSON is tried without them.
fn settings(bytes: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(bytes)
        .or_else(|_| serde_json::from_slice(&without_comments(bytes)))
        .ok()
}

/// JSON with `//` and `/* */` comments left out and trailing commas dropped,
/// both only outside strings. Line breaks stay where they were.
fn without_comments(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(bytes.len());
                out.extend_from_slice(&bytes[start..i]);
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                    if bytes[i] == b'\n' {
                        out.push(b'\n');
                    }
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            b'}' | b']' => {
                // Drop a comma that only white space separates from here.
                let kept = out.iter().rposition(|b| !b.is_ascii_whitespace());
                if let Some(at) = kept.filter(|at| out[*at] == b',') {
                    out[at] = b' ';
                }
                out.push(bytes[i]);
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Each literal secret, as what holds it (a server, or the file's own
/// settings), the field it is in, and the value. Server maps sit at the top
/// level or under per-project settings.
fn secrets<'a>(v: &'a serde_json::Value, depth: usize, out: &mut Vec<(&'a str, &'a str, &'a str)>) {
    let Some(object) = v.as_object().filter(|_| depth < 6) else {
        return;
    };
    // A settings file's own environment block and model keys count as well.
    if depth == 0 {
        server_secrets("settings", v, out);
    }
    for (key, value) in object {
        if let Some(s) = value.as_str().filter(|_| key == "apiKey") {
            if s.len() >= 12 && !reference(s) && inline_literal(s) && plausible(s) {
                out.push(("apiKey", "apiKey", s));
            }
        }
        if let Some(list) = value.as_array() {
            for entry in list {
                secrets(entry, depth + 1, out);
            }
        }
        match value.as_object() {
            Some(servers)
                if matches!(
                    key.as_str(),
                    "mcpServers" | "servers" | "context_servers" | "mcp" | "amp.mcpServers"
                ) =>
            {
                for (name, server) in servers {
                    server_secrets(name, server, out);
                }
            }
            _ => secrets(value, depth + 1, out),
        }
    }
}

/// The literal secrets in one server's environment, headers and arguments.
fn server_secrets<'a>(
    holder: &'a str,
    server: &'a serde_json::Value,
    out: &mut Vec<(&'a str, &'a str, &'a str)>,
) {
    // Zed once kept the command, its arguments and its environment together
    // in one object, and files it has not opened since still do.
    for part in [server, &server["command"]] {
        // "environment" is opencode's name for it.
        for field in ["env", "environment", "headers"] {
            for (name, value) in part[field].as_object().into_iter().flatten() {
                if let Some(s) = value.as_str().filter(|s| secret(name, s)) {
                    out.push((holder, name, s));
                }
            }
        }
        // opencode gives the command and its arguments as one list.
        for field in ["args", "command"] {
            for argument in part[field].as_array().into_iter().flatten() {
                if let Some(s) = argument.as_str().filter(|s| secret("", s)) {
                    out.push((holder, field, s));
                }
            }
        }
    }
}

/// A token in a known format under any name, or a literal under a name that
/// says it holds a secret.
fn secret(name: &str, s: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let named = ["KEY", "TOKEN", "SECRET", "PASSWORD", "AUTHORIZATION", "PAT"]
        .iter()
        .any(|word| upper.ends_with(word));
    // "Bearer <value>", "Basic <value>" or "token <value>" is a literal after
    // its scheme; "${VAR}" and "$VAR" are references.
    let literal = s
        .split_once(' ')
        .filter(|(scheme, _)| !scheme.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphabetic()))
        .map_or(s, |(_, value)| value);
    token::has_token(s.as_bytes())
        || (named
            && literal.len() >= 12
            && !reference(literal)
            && inline_literal(literal)
            && plausible(literal))
}

/// opencode's way of naming a variable or a file to read the value from.
fn reference(s: &str) -> bool {
    s.starts_with("{env:") || s.starts_with("{file:")
}

/// Continue's current config is YAML; config.json above is its older form.
pub const CONTINUE_YAML: Rule = Rule {
    targets: &[Target::File(".continue/config.yaml")],
    matcher: Matcher::Whole {
        candidate: any,
        test: |bytes| utf8_lines(bytes, |text| keyed_secret_lines(text, &["apiKey"])),
    },
    samples: &[
        (
            b"models:\n  - name: fixture\n    apiKey: synthetic-only-value\n",
            true,
        ),
        (
            b"models:\n  - name: fixture\n    apiKey: ${{ secrets.FIXTURE_KEY }}\n",
            false,
        ),
    ],
    ..MCP_SECRET
};

/// Codex keeps its MCP servers in TOML, each under [mcp_servers.<name>], and
/// a remote server's HTTP headers in its "http_headers" table. Its
/// "env_http_headers" and "bearer_token_env_var" name variables instead.
pub const CODEX_MCP: Rule = Rule {
    targets: &[Target::File(".codex/config.toml")],
    matcher: Matcher::Whole {
        candidate: any,
        test: codex_hits,
    },
    samples: &[
        (b"[mcp_servers.fixture]\nurl = \"https://mcp.example.invalid/mcp\"\nhttp_headers = { \"Authorization\" = \"Bearer synthetic-only-value\" }\n", true),
        (b"[mcp_servers.fixture.http_headers]\n\"X-Api-Key\" = \"synthetic-only-value\"\n", true),
        (b"[mcp_servers.fixture]\nbearer_token_env_var = \"FIXTURE_TOKEN\"\nenv_http_headers = { \"X-Api-Key\" = \"FIXTURE_API_KEY\" }\n", false),
        (b"[mcp_servers.fixture]\nhttp_headers = { \"Authorization\" = \"Bearer ${FIXTURE_TOKEN}\" }\n", false),
    ],
    ..MCP_SECRET
};

/// Each line that gives a Codex server a header holding a literal secret,
/// judged as the JSON configs' headers are. The file is read line by line:
/// a table's heading, then keys, dotted or not, set to a string or to a
/// table on one line.
fn codex_hits(bytes: &[u8]) -> Hits {
    let text = String::from_utf8_lossy(bytes);
    // The first parts of the current heading, which are all a path below
    // needs: split once, not again for every line under a long heading.
    let mut table = Vec::new();
    // A byte order mark is not part of the first line.
    let lines = text.trim_start_matches('\u{feff}').lines();
    capped_hits(
        lines.enumerate().filter_map(|(i, raw)| {
            let line = raw.trim();
            if let Some(heading) = line.strip_prefix('[') {
                table.clear();
                if let Some((key, _)) = heading.split_once(']') {
                    table.extend(key_parts(key).take(5));
                }
                return None;
            }
            if line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let mut path = table.iter().copied().chain(key_parts(key));
            if path.next() != Some("mcp_servers") {
                return None;
            }
            let name = path.next()?;
            if path.next() != Some("http_headers") {
                return None;
            }
            let found = match (path.next(), path.next()) {
                (Some(header), None) => toml_string(value).is_some_and(|s| secret(header, s)),
                (None, _) => value.trim().strip_prefix('{').is_some_and(|headers| {
                    env::inline_table_pairs(headers).any(|(header, value)| {
                        let header = header.trim().trim_matches(['"', '\'']);
                        toml_string(value).is_some_and(|s| secret(header, s))
                    })
                }),
                _ => false,
            };
            found.then(|| Hit::line(i + 1).about(&format!("server {name}")))
        }),
        100,
    )
}

/// The parts of a dotted TOML key, each without its quotes.
fn key_parts(key: &str) -> impl Iterator<Item = &str> {
    let mut quote = None;
    key.split(move |c| {
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, '"' | '\'') {
            quote = Some(c);
        }
        quote.is_none() && c == '.'
    })
    .map(|part| part.trim().trim_matches(['"', '\'']))
}

/// A TOML string's text, without its quotes, when only a comment follows it.
fn toml_string(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let quote = raw.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let end = raw[1..].find(quote)? + 1;
    let rest = raw[end + 1..].trim_start();
    (rest.is_empty() || rest.starts_with('#')).then(|| &raw[1..end])
}

pub const AI_TOOL_LOGIN: Rule = Rule {
    id: "dev.ai.stored-login",
    category: "developer-cloud",
    kind: "inventory",
    severity: "medium",
    title: "AI coding tool sign-in stored in a file",
    explanation: "An AI coding tool keeps its sign-in token or API key in this file as plain text. That is how the tool works. Loose Keys did not check whether it still works or what it can access.",
    reason: None,
    next_step: Some("Sign out of tools you no longer use, which removes the stored token."),
    advice: Advice {
        steps: &[
            "For a tool you still use, leave this in place. Prefer signing in with your account over pasting an API key, so the stored token can be revoked by signing out.",
            "For a tool you no longer use, sign out in the tool (for example 'codex logout' or 'gh auth logout'), then delete this file.",
            "If the file holds an API key, revoke that key at the provider when you stop using the tool.",
        ],
        link: None,
    },
    targets: &[
        Target::File(".codex/auth.json"),
        Target::File(".claude/.credentials.json"),
        Target::File(".gemini/oauth_creds.json"),
        Target::File(".config/github-copilot/apps.json"),
        Target::File(".config/github-copilot/hosts.json"),
        Target::File(".copilot/config.json"),
        Target::File(".codex/.credentials.json"),
        Target::File(".gemini/mcp-oauth-tokens.json"),
        Target::File(".cline/data/secrets.json"),
        Target::File(".local/share/opencode/auth.json"),
        Target::File(".local/share/amp/secrets.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: ai_login_hits,
    },
    samples: &[
        (br#"{"tokens": {"refresh_token": "synthetic-only-value"}}"#, true),
        (br#"{"OPENAI_API_KEY": null, "tokens": {}}"#, false),
    ],
};

/// An OAuth sign-in kept as the token response a server gave. mcp-remote,
/// which desktop AI apps use to reach remote MCP servers, keeps one such
/// file for each server in ~/.mcp-auth.
pub const OAUTH_TOKENS: Rule = Rule {
    id: "dev.oauth.token-file",
    title: "OAuth sign-in tokens stored in a file",
    explanation: "This file holds an OAuth sign-in token as plain text. Tools like mcp-remote keep sign-ins this way, in ~/.mcp-auth. Loose Keys did not check whether it still works or what it can access.",
    next_step: Some("Remove connections you no longer use, which removes the stored token."),
    advice: Advice {
        steps: &[
            "For a connection you still use, leave this in place.",
            "For one you no longer use, remove it in the tool that made it, then delete this file.",
            "At the service, open your account's connected or authorized apps and revoke the ones you no longer use: deleting the file does not do that.",
        ],
        link: None,
    },
    targets: &[Target::Name("*_tokens.json")],
    // Design systems use this file name too, for files of any size.
    matcher: Matcher::Whole {
        candidate: |head| head.windows(12).any(|w| w == b"\"token_type\""),
        test: oauth_token_hits,
    },
    samples: &[
        (br#"{"access_token":"synthetic-only-value-1234","token_type":"Bearer","refresh_token":"synthetic-only-value-5678"}"#, true),
        (br##"{"color":{"primary":{"value":"#0055ff"}}}"##, false),
        (br#"{"access_token":"","token_type":"Bearer"}"#, false),
        (b"not json", false),
    ],
    ..AI_TOOL_LOGIN
};

/// Only an OAuth token response counts. Other tools use this file name for
/// other things, so anything else is no hit and no gap.
fn oauth_token_hits(bytes: &[u8]) -> Hits {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(vec![]);
    };
    let stored = |key: &str| {
        v[key]
            .as_str()
            .is_some_and(|s| s.len() >= 16 && inline_literal(s) && plausible(s))
    };
    Ok(
        (v["token_type"].is_string() && (stored("access_token") || stored("refresh_token")))
            .then(Hit::file)
            .into_iter()
            .collect(),
    )
}

fn ai_login_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| {
        json_has_secret(
            v,
            &[
                "refresh_token",
                "refreshToken",
                "access_token",
                "accessToken",
                "oauth_token",
                "OPENAI_API_KEY",
                "personal_access_token",
                "apiKey",
                "token",
                "access",
                "refresh",
                "key",
            ],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_server_with_a_literal_secret_is_named() {
        let config = serde_json::json!({
            "projects": {"/work/app": {"mcpServers": {
                "db": {"command": "npx", "args": ["server", "--token", "plain-argument"],
                       "env": {"DATABASE_PASSWORD": "synthetic-only-value"}},
                "docs": {"command": "npx", "env": {"DOCS_API_KEY": "$DOCS_API_KEY"}},
            }}},
            "mcpServers": {
                "search": {"url": "https://example.invalid",
                           "headers": {"X-Api-Key": "synthetic-only-value"}},
                "local": {"command": "node", "args": ["server.js"]},
            },
        });
        let hits = mcp_hits(config.to_string().as_bytes()).unwrap();
        let names: Vec<_> = hits.iter().map(|h| h.subject.as_deref().unwrap()).collect();
        assert_eq!(names, ["server db", "server search"]);
    }

    #[test]
    fn settings_files_may_have_comments_and_trailing_commas() {
        let zed = b"// Zed settings\n//\n// documentation: https://zed.dev/docs/configuring-zed\n{\n  \"theme\": {\"mode\": \"system\",},\n  /* servers */\n  \"context_servers\": {\n    \"fixture\": {\"command\": \"npx\", \"env\": {\"FIXTURE_TOKEN\": \"synthetic-only-value\"},},\n  },\n}\n";
        let hits = mcp_hits(zed).expect("a settings file with comments is readable");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].subject.as_deref(), Some("server fixture"));
        // Comment markers inside strings are data.
        let urls = br#"{"servers": {"fixture": {"url": "https://example.invalid/a/*b*/", "headers": {"Authorization": "Bearer synthetic//only/*value*/"}}}}"#;
        assert_eq!(mcp_hits(urls).unwrap().len(), 1);
        // A commented-out secret is not a secret, and no secret is not a gap.
        let off = b"{\n  \"mcpServers\": {\n    // \"fixture\": {\"env\": {\"FIXTURE_TOKEN\": \"synthetic-only-value\"}}\n  }\n}\n";
        assert!(mcp_hits(off).unwrap().is_empty());
        // Still a gap when it is not JSON at all.
        assert!(mcp_hits(b"// only a comment, then garbage {").is_err());
        // Text that never closes a string or a comment ends where the file does.
        for open in [
            "{\"a\": \"never closed\\",
            "{/* never closed",
            "{\"a\": 1, // a",
        ] {
            assert!(mcp_hits(open.as_bytes()).is_err(), "{open}");
        }
    }

    #[test]
    fn each_tool_s_own_way_of_writing_a_server_is_read() {
        let named = |config: serde_json::Value| -> Vec<String> {
            let hits = mcp_hits(config.to_string().as_bytes()).unwrap();
            hits.into_iter().filter_map(|h| h.subject).collect()
        };
        // opencode: a command with its arguments in one list, "environment",
        // and its own form of reference.
        let token = concat!("gh", "p_0123456789abcdefghijABCDEFGHIJ012345");
        assert_eq!(
            named(serde_json::json!({"mcp": {
                "local": {"type": "local", "command": ["npx", "-y", "fixture-server"],
                          "environment": {"FIXTURE_API_KEY": "synthetic-only-value"}},
                "argument": {"type": "local", "command": ["fixture-server", "--token", token]},
                "remote": {"type": "remote", "url": "https://example.invalid",
                           "headers": {"Authorization": "Bearer {env:FIXTURE_API_TOKEN}"}},
                "file": {"type": "local", "command": ["fixture-server"],
                         "environment": {"FIXTURE_API_KEY": "{file:~/.secrets/fixture-key}"}},
            }})),
            ["server argument", "server local"]
        );
        // Zed before late 2025: the command, its arguments and environment together.
        assert_eq!(
            named(
                serde_json::json!({"context_servers": {"fixture": {"command": {
                    "path": "npx", "args": ["-y", "fixture-server"],
                    "env": {"FIXTURE_TOKEN": "synthetic-only-value"},
                }}}})
            ),
            ["server fixture"]
        );
    }

    #[test]
    fn material_is_the_secrets_and_not_the_rest_of_the_file() {
        // Claude Code rewrites its settings file on every run.
        let config = |runs: u32, key: &str| {
            let file = serde_json::json!({
                "numStartups": runs,
                "mcpServers": {"fixture": {"command": "npx",
                    "env": {"FIXTURE_API_KEY": key, "LOG_LEVEL": "verbose-logging"}}},
                "models": [{"title": "fixture", "apiKey": "synthetic-only-value"}],
            });
            crate::rules::material("dev.mcp.inline-secret", file.to_string().as_bytes())
        };
        assert_eq!(
            config(1, "synthetic-first-value"),
            config(2, "synthetic-first-value")
        );
        assert_ne!(
            config(1, "synthetic-first-value"),
            config(1, "synthetic-second-value")
        );
        // Continue's YAML is read by the same rule's other form.
        let yaml = |key: &str| {
            let file = format!("models:\n  - name: fixture\n    apiKey: {key}\n");
            crate::rules::material("dev.mcp.inline-secret", file.as_bytes())
        };
        assert_ne!(
            yaml("synthetic-first-value"),
            yaml("synthetic-second-value")
        );
    }

    /// What this rule finds in Codex's config, by line and holder.
    fn codex(file: &str) -> Vec<(Option<usize>, Option<String>)> {
        RULES
            .iter()
            .filter(|rule| rule.id == MCP_SECRET.id)
            .filter(|rule| rule.targets.contains(&Target::File(".codex/config.toml")))
            .flat_map(|rule| match rule.matcher {
                Matcher::Whole { test, .. } => test(file.as_bytes()).unwrap(),
                _ => Vec::new(),
            })
            .map(|hit| (hit.line, hit.subject))
            .collect()
    }

    #[test]
    fn a_codex_server_s_literal_headers_are_found() {
        let server = "[mcp_servers.fixture]\nurl = \"https://mcp.example.invalid/mcp\"\n";
        let fixture = || Some("server fixture".to_string());
        // A table on one line, its own table, or dotted keys.
        let inline = format!(
            "{server}http_headers = {{ \"Authorization\" = \"Bearer synthetic-only-value\", \"X-Api-Key\" = \"synthetic-second-value\" }}\n"
        );
        assert_eq!(codex(&inline), [(Some(3), fixture())]);
        // A byte order mark is not part of the first heading.
        assert_eq!(codex(&format!("\u{feff}{inline}")), [(Some(3), fixture())]);
        let table = format!(
            "{server}\n[mcp_servers.fixture.http_headers]\nAuthorization = \"Bearer synthetic-only-value\" # fixture\n\"X-Api-Key\" = \"synthetic-second-value\"\n"
        );
        assert_eq!(codex(&table), [(Some(5), fixture()), (Some(6), fixture())]);
        let dotted = "[mcp_servers]\nfixture.http_headers.\"X-Api-Key\" = 'synthetic-only-value'\n";
        assert_eq!(codex(dotted), [(Some(2), fixture())]);
        // Variable names, references, a header that names no secret, and
        // headers that are not a server's.
        let none = [
            format!("{server}bearer_token_env_var = \"FIXTURE_TOKEN\"\nenv_http_headers = {{ \"X-Api-Key\" = \"FIXTURE_API_KEY\" }}\n"),
            format!("{server}\n[mcp_servers.fixture.env_http_headers]\n\"X-Api-Key\" = \"FIXTURE_API_KEY\"\n"),
            format!("{server}http_headers = {{ \"Authorization\" = \"Bearer ${{FIXTURE_TOKEN}}\", \"X-Fixture\" = \"synthetic-only-value\" }}\n"),
            format!("{server}# http_headers = {{ \"X-Api-Key\" = \"synthetic-only-value\" }}\n"),
            "[profiles.fixture]\nhttp_headers = { \"X-Api-Key\" = \"synthetic-only-value\" }\n".to_string(),
            "[mcp_servers.fixture.http_headers]\n[mcp_servers.fixture.env]\n\"X-Api-Key\" = \"synthetic-only-value\"\n".to_string(),
        ];
        for file in none {
            assert_eq!(codex(&file), [], "{file}");
        }
        // Codex rewrites its config as it runs: the headers, not the rest of
        // the file, are what the app fingerprints.
        let material = |model: &str, key: &str| {
            let file = format!(
                "model = \"{model}\"\n{server}http_headers = {{ \"X-Api-Key\" = \"{key}\" }}\n"
            );
            crate::rules::material(MCP_SECRET.id, file.as_bytes())
        };
        assert_eq!(
            material("fixture-a", "synthetic-first-value"),
            material("fixture-b", "synthetic-first-value")
        );
        assert_ne!(
            material("fixture-a", "synthetic-first-value"),
            material("fixture-a", "synthetic-second-value")
        );
    }

    #[test]
    fn codex_headers_report_the_line_limit() {
        let servers = |count| {
            (0..count)
                .map(|n| format!("[mcp_servers.fixture-{n}]\nhttp_headers = {{ \"X-Api-Key\" = \"synthetic-value-{n}\" }}\n"))
                .collect::<String>()
        };
        assert_eq!(codex_hits(servers(100).as_bytes()).unwrap().len(), 100);
        let incomplete = codex_hits(servers(101).as_bytes())
            .err()
            .expect("line limit");
        assert_eq!(incomplete.reason, "scan-limit");
        assert_eq!(incomplete.hits.len(), 100);
    }

    #[test]
    fn a_codex_heading_is_read_once_for_the_lines_under_it() {
        // A long heading, and as many short lines under it as fit in the
        // 1 MiB a config is read up to.
        let long = "a".repeat(500 * 1024);
        for heading in [format!("[{long}]\n"), format!("[mcp_servers.{long}]\n")] {
            let file = heading + &"x=\n".repeat(170_000);
            assert!(file.len() < 1024 * 1024);
            let started = std::time::Instant::now();
            assert!(codex_hits(file.as_bytes()).unwrap().is_empty());
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(10),
                "reading {} bytes took {took:?}",
                file.len()
            );
        }
    }
}
