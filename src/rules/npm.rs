//! Inline tokens and passwords in npm's user config.

use super::git::GIT_CREDENTIALS;
use super::*;

pub const NPM_CREDENTIALS: Rule = Rule {
    id: "dev.npm.inline-credentials",
    title: "Possible npm inline credential",
    severity: "high",
    explanation: "A token or password is stored in npm's user config. npm tokens are a common target of supply-chain malware because they can publish packages. Validity and permissions were not checked.",
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
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.trim();
            if line.starts_with(['#', ';']) {
                return None;
            }
            // Yarn: "npmAuthToken: value" at any depth.
            if let Some((key, value)) = line.split_once(':') {
                if matches!(key.trim(), "npmAuthToken" | "npmAuthIdent") {
                    return scalar_literal(value).map(|_| Hit::line(i + 1));
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
            scalar_literal(value).map(|_| Hit::line(i + 1).about(registry))
        })
        .collect()
}
