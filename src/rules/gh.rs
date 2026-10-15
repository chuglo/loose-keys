//! Inline oauth_token values in GitHub CLI's hosts file.

use super::git::GIT_CREDENTIALS;
use super::*;

pub const GH_TOKEN: Rule = Rule {
    id: "dev.gh.inline-token",
    title: "Possible GitHub CLI inline token",
    severity: "medium",
    explanation: "GitHub CLI's sign-in token is stored as plain text in its hosts file instead of the Keychain. The token's validity and permissions were not checked.",
    next_step: Some("Sign in again so GitHub CLI stores the token in the Keychain. Removing the line does not revoke the token."),
    advice: Advice {
        steps: &[
            "Sign out, which also removes the stored token: gh auth logout",
            "Sign in again: gh auth login. It uses the system credential store when available but can fall back to a plain-text file. Use gh auth status to check the storage location.",
            "In GitHub Settings > Applications > Authorized OAuth Apps, revoke 'GitHub CLI' if the old token may have been copied.",
        ],
        link: Some("https://github.com/settings/applications"),
    },
    targets: &[Target::File(".config/gh/hosts.yml")],
    matcher: Matcher::Whole {
        candidate: any,
        test: gh_hits,
    },
    samples: &[
        (b"github.com:\n    oauth_token: synthetic\n", true),
        (b"github.com:\n    oauth_token: ${GH_TOKEN}\n", false),
        (b"example.invalid:\n  oauth_token: #comment-only\n", false),
    ],
    ..GIT_CREDENTIALS
};

fn gh_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, gh_token_lines)
}

fn gh_token_lines(text: &str) -> Vec<Hit> {
    let mut parents: Vec<(usize, &str, bool)> = Vec::new();
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = raw.bytes().take_while(|b| *b == b' ').count();
        while parents.last().is_some_and(|(level, _, _)| *level >= indent) {
            parents.pop();
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let supported_parent = parents.first().is_some_and(|(level, _, _)| *level == 0)
            && parents.iter().all(|(_, _, mapping)| *mapping)
            && (parents.len() == 1 || (parents.len() == 3 && parents[1].1 == "users"));
        if key == "oauth_token" && supported_parent && scalar_literal(value).is_some() {
            out.push(Hit::line(i + 1).about(parents[0].1));
        }
        // Retain nonempty scalar parents as barriers to avoid interpreting
        // text inside block scalars as host/user token mappings.
        parents.push((
            indent,
            key,
            value.trim().is_empty() || value.trim().starts_with('#'),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_block_scalar_text_is_not_a_mapping() {
        assert!(gh_token_lines("example.invalid: |\n  oauth_token: not-a-token\n").is_empty());
        assert!(gh_token_lines(
            "example.invalid:\n  users: |\n    account:\n      oauth_token: not-a-token\n"
        )
        .is_empty());
    }
}
