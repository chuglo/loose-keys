//! username:password URLs in Git's plaintext credential store.

use super::*;

pub const GIT_CREDENTIALS: Rule = Rule {
    id: "dev.git.inline-credentials",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "Possible Git password stored as plain text",
    explanation: "Git's plain-text credential file has a URL with a username and password in it. Loose Keys did not check whether they still work.",
    reason: Some("Any program that can read this file can copy the password."),
    next_step: Some("Let Git keep this in the Keychain instead. Deleting the line does not revoke the password; revoke it at the host."),
    advice: Advice {
        steps: &[
            "Tell Git to use the macOS Keychain: git config --global credential.helper osxkeychain",
            "At the host named here, revoke this token or change this password (GitHub: Settings > Developer settings > Personal access tokens).",
            "Delete the line from ~/.git-credentials, or the whole file if nothing else is in it.",
            "The next push or pull asks you to sign in once and stores the new credential in the Keychain.",
        ],
        link: None,
    },
    targets: &[
        Target::File(".git-credentials"),
        Target::File(".config/git/credentials"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: git_hits,
    },
    samples: &[
        (b"https://user:synthetic@example.com\n", true),
        (b"https://user@example.com\n", false),
    ],
};

fn git_hits(bytes: &[u8]) -> Hits {
    utf8_lines(bytes, git_credential_lines)
}

fn git_credential_lines(text: &str) -> Vec<Hit> {
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.trim();
            let (scheme, rest) = line.split_once("://")?;
            if !matches!(scheme, "http" | "https") {
                return None;
            }
            let authority = rest.split(['/', '?', '#']).next()?;
            let (userinfo, host) = authority.rsplit_once('@')?;
            let (user, password) = userinfo.split_once(':')?;
            (!host.is_empty() && !user.is_empty() && inline_literal(password))
                .then(|| Hit::line(i + 1).about(host).at(text, password))
        })
        .collect()
}
