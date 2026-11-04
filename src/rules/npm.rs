//! Inline tokens and passwords in npm's user config.

use super::git::GIT_CREDENTIALS;
use super::*;

pub const NPM_CREDENTIALS: Rule = Rule {
    id: "dev.npm.inline-credentials",
    title: "Possible npm token stored in a config file",
    severity: "high",
    explanation: "A token or password is stored in npm's user config. Malware that spreads through packages often looks for npm tokens, because they can publish packages. Loose Keys did not check whether it still works or what it can access.",
    next_step: Some("Revoke this token and replace it with a narrower one. Removing the line does not revoke it."),
    advice: Advice {
        steps: &[
            "List your tokens with 'npm token list', then revoke this one: npm token revoke <id>",
            "If you still publish from this Mac, create a granular access token limited to the packages you need, with an expiry date.",
            "npm has no Keychain storage. To keep the value out of this file, write //registry.npmjs.org/:_authToken=${NPM_TOKEN} and supply NPM_TOKEN from a password manager when you publish.",
            "If you only install public packages, delete the line: no token is needed.",
        ],
        link: Some("https://docs.npmjs.com/revoking-access-tokens"),
    },
    // Project folders have their own .npmrc, and malware reads those as well.
    // Yarn and pnpm keep the same token in their own files.
    targets: &[
        Target::File(".npmrc"),
        Target::Name(".npmrc"),
        Target::File(".yarnrc.yml"),
        Target::Name(".yarnrc.yml"),
        Target::File("Library/Preferences/pnpm/auth.ini"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: npm_hits,
    },
    samples: &[
        (b"//registry.npmjs.org/:_authToken=synthetic\n", true),
        (b"\xef\xbb\xbf//registry.npmjs.org/:_authToken=synthetic\n", true),
        (b"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", false),
        (b"npmScopes:\n  fixture:\n    npmAuthToken: synthetic\n", true),
        (b"npmAuthToken: \"${NPM_TOKEN}\"\n", false),
        // A comment is not a value.
        (b"_authToken=#comment-only\n_password=;comment-only\n_auth= # comment\n", false),
    ],
    ..GIT_CREDENTIALS
};

fn npm_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, npm_credential_lines)
}

fn npm_credential_lines(text: &str) -> Vec<Hit> {
    // A byte order mark is not part of the first line.
    text.trim_start_matches('\u{feff}')
        .lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.trim();
            if line.starts_with(['#', ';']) {
                return None;
            }
            // Yarn: "npmAuthToken: value" at any depth.
            if let Some((key, value)) = line.split_once(':') {
                if matches!(key.trim(), "npmAuthToken" | "npmAuthIdent") {
                    return scalar_literal(value).map(|value| Hit::line(i + 1).at(text, value));
                }
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            let field = if key.starts_with("//") {
                key.rsplit_once(':')?.1
            } else {
                key
            };
            if !matches!(field, "_authToken" | "_auth" | "_password" | "password") {
                return None;
            }
            let registry = key
                .rsplit_once(':')
                .map_or("", |(r, _)| r.trim_matches('/'));
            scalar_literal(value).map(|value| {
                Hit::line(i + 1)
                    .about(url_host(registry))
                    .scoped(text, key)
                    .at(text, value)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_subjects_exclude_userinfo_and_paths() {
        for registry in [
            "fixture:synthetic-pass@registry.invalid",
            "fixture:synthetic@pass@registry.invalid",
            "registry.invalid/private-scope",
            "registry.invalid/path://synthetic-tail",
            "registry.invalid?synthetic-query",
            "registry.invalid#synthetic-fragment",
        ] {
            let file = format!("//{registry}/:_authToken=synthetic-stored-value\n");
            let hits = npm_hits(file.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].line, Some(1));
            assert!(
                hits[0].subject.as_deref() == Some("registry.invalid"),
                "only the registry host may be shown"
            );
        }
    }

    // Registry keys can themselves hold credentials. Ambiguous tails keep
    // their findings, but supply no display subject.
    #[test]
    fn ambiguous_registry_keys_have_no_label() {
        for key in [
            "//fixture:synthetic/pass@registry.invalid/:_authToken",
            "//registry.invalid/path@synthetic-tail/:_authToken",
            "//fixture:synthetic-pass@/:_auth",
            "_authToken",
        ] {
            let file = format!("{key}=synthetic-stored-value\n");
            let hits = npm_hits(file.as_bytes()).unwrap();
            assert_eq!(hits.len(), 1);
            assert!(hits[0].subject.is_none());
        }
        let hits = npm_hits(b"//registry.invalid:8443/:password=synthetic-stored-value\n").unwrap();
        assert_eq!(hits[0].subject.as_deref(), Some("registry.invalid:8443"));
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_line() {
        let npmrc = b"\xef\xbb\xbf//registry.npmjs.org/:_authToken=synthetic-only-value\n";
        let hits = npm_hits(npmrc).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, Some(1));
        assert_eq!(hits[0].subject.as_deref(), Some("registry.npmjs.org"));
        let yarnrc = b"\xef\xbb\xbfnpmAuthToken: synthetic-only-value\n";
        let hits = npm_hits(yarnrc).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, Some(1));
    }
}
