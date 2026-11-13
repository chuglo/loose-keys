//! Static access keys in the AWS shared credentials file.

use super::*;

pub const AWS_KEYS: Rule = Rule {
    id: "dev.aws.inline-credentials",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "AWS access keys stored in a file",
    explanation: "This file has an AWS secret access key. Loose Keys didn't check whether it still works or what it can access.",
    reason: Some("Static AWS access keys don't expire and work from any computer. Any program that can read this file can copy them."),
    next_step: Some("Switch to short-lived sign-in, and deactivate the old keys in IAM. Deleting this file doesn't revoke them."),
    advice: Advice {
        steps: &[
            "Find out what still uses this profile. In the IAM console, the key's 'Last used' column shows when and for which service.",
            "Switch to short-lived credentials: run 'aws configure sso' (IAM Identity Center), which stores no long-lived secret.",
            "In IAM > Users > Security credentials, choose Actions > Deactivate for the old access key. When everything works without it, choose Actions > Delete.",
            "Remove the profile's aws_access_key_id and aws_secret_access_key lines from ~/.aws/credentials.",
        ],
        link: Some("https://console.aws.amazon.com/iam/home#/security_credentials"),
    },
    // Keys are allowed in the config file as well.
    targets: &[Target::File(".aws/credentials"), Target::File(".aws/config")],
    matcher: Matcher::Whole {
        candidate: any,
        test: aws_hits,
    },
    samples: &[
        (b"[default]\naws_access_key_id = AKIASYNTHETIC\naws_secret_access_key = synthetic\n", true),
        (b"\xef\xbb\xbf[default]\naws_secret_access_key = synthetic\n", true),
        (b"[default]\naws_secret_access_key = synthetic\naws_session_token = synthetic\n", true),
        (b"[default]\nregion = us-east-1\n", false),
        (b"[fixture]\naws_secret_access_key = #comment-only\n", false),
        // botocore reads the file raw: "$" and "!" are the key's own.
        (b"[default]\naws_secret_access_key = !Synth$tic-0nly\n", true),
    ],
};

/// For a profile that also has a session token: keys that AWS STS issued,
/// which expire on their own and which IAM can't deactivate.
pub const TEMPORARY_KEYS: Wording = Wording {
    explanation: "This file has temporary AWS keys: a secret access key with a session token. Loose Keys didn't check whether they've expired or what they can access.",
    reason: Some("Temporary AWS keys work from any computer until they expire. Any program that can read this file can copy them."),
    next_step: Some("Remove these keys from the file. Deleting them doesn't end them, so if they may have been copied, revoke the role's active sessions."),
    advice: Advice {
        steps: &[
            "Remove the profile's aws_access_key_id, aws_secret_access_key and aws_session_token lines from this file.",
            "If the keys may have been copied, end them before they expire: in the IAM console, open the role they're for, and on its Revoke sessions tab choose Revoke active sessions. This ends every session of that role issued until now, including other people's.",
            "To sign in again without keys in this file, use 'aws configure sso' (IAM Identity Center).",
        ],
        link: Some("https://console.aws.amazon.com/iam/home#/roles"),
    },
};

/// AWS files are parsed leniently, so invalid UTF-8 never hides other keys.
fn aws_hits(bytes: &[u8]) -> Hits {
    let text = String::from_utf8_lossy(bytes);
    // Positions in `text` are positions in the file only if nothing was replaced.
    let exact = matches!(text, std::borrow::Cow::Borrowed(_));
    let hits = aws_profiles_with_keys(&text).into_iter().map(|mut hit| {
        if !exact {
            hit.span = None;
        }
        hit
    });
    capped_hits(hits, 100)
}

/// Profile headers whose section contains aws_secret_access_key, with the
/// temporary keys' wording where the section has a session token too. A
/// hit's position is its section's access key ID, which is what the
/// service-token rule finds in the same file: the two are one credential.
pub fn aws_profiles_with_keys(text: &str) -> Vec<Hit> {
    // Each section: its header's line, its profile, whether it has a secret
    // access key and a session token, and its access key ID.
    let mut sections: Vec<(usize, &str, bool, bool, Option<&str>)> = Vec::new();
    // A byte order mark is not part of the first line.
    for (i, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let l = raw.trim();
        if l.starts_with('[') && l.ends_with(']') {
            let name = &l[1..l.len() - 1];
            // ~/.aws/config writes "[profile name]" for all but the default.
            let profile = name.strip_prefix("profile ").map_or(name, str::trim);
            sections.push((i + 1, profile, false, false, None));
        } else if let (Some(section), Some((k, v))) = (sections.last_mut(), l.split_once('=')) {
            // botocore reads the file raw: "$" and "!" are part of a value.
            if let Some(value) = scalar_literal_by(v, raw_literal) {
                match k.trim().to_ascii_lowercase().as_str() {
                    "aws_access_key_id" => section.4 = Some(value),
                    "aws_secret_access_key" => section.2 = true,
                    // The older name, which botocore also reads (unverified).
                    "aws_session_token" | "aws_security_token" => section.3 = true,
                    _ => {}
                }
            }
        }
    }
    sections
        .into_iter()
        .filter(|(_, _, secret, _, _)| *secret)
        .map(|(line, profile, _, session, id)| {
            let hit = Hit {
                wording: session.then_some(&TEMPORARY_KEYS),
                ..Hit::line(line).about(&format!("profile {profile}"))
            };
            match id {
                Some(id) => hit.at(text, id),
                None => hit,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_sections() {
        let ini = "[default]\naws_access_key_id = A\naws_secret_access_key = B\n\n[sso]\nsso_start_url = x\n\n[other]\nAWS_SECRET_ACCESS_KEY=C\n[empty]\naws_secret_access_key =\n";
        let hits = aws_profiles_with_keys(ini);
        assert_eq!(
            hits.iter().map(|h| h.line).collect::<Vec<_>>(),
            vec![Some(1), Some(8)]
        );
        assert_eq!(hits[0].subject.as_deref(), Some("profile default"));
    }

    /// The service-token rule finds the access key ID in the same file, so
    /// the profile's hit is at that ID and the two can be one item. A
    /// profile with no ID has no position.
    #[test]
    fn a_profile_is_found_at_its_access_key_id() {
        let ini = "\u{feff}[default]\naws_access_key_id = fixture-id\naws_secret_access_key = synthetic-only\n[bare]\naws_secret_access_key = synthetic-only\n";
        let hits = aws_profiles_with_keys(ini);
        let at = hits[0].span.clone().unwrap();
        assert_eq!(&ini[at], "fixture-id");
        assert_eq!(hits[1].span, None);
    }

    /// ~/.aws/config names a profile "[profile name]", the credentials file "[name]".
    #[test]
    fn a_profile_is_named_once() {
        let hits = aws_profiles_with_keys(
            "[profile prod]\naws_secret_access_key = synthetic-only\n[default]\naws_secret_access_key = synthetic-only\n",
        );
        let named: Vec<_> = hits.iter().map(|h| h.subject.as_deref()).collect();
        assert_eq!(named, [Some("profile prod"), Some("profile default")]);
    }

    /// Keys with a session token are temporary, as tools that sign in
    /// through AWS STS write them, wherever the token stands in the profile.
    #[test]
    fn temporary_keys_have_their_own_wording() {
        let hits = aws_profiles_with_keys(concat!(
            "[static]\naws_secret_access_key = synthetic-only\n",
            "[sts]\naws_session_token = synthetic-only\naws_secret_access_key = synthetic-only\n",
            "[legacy]\naws_secret_access_key = synthetic-only\naws_security_token = synthetic-only\n",
            "[empty]\naws_secret_access_key = synthetic-only\naws_session_token =\n",
            "[token-only]\naws_session_token = synthetic-only\n",
        ));
        let found: Vec<_> = hits
            .iter()
            .map(|h| (h.subject.as_deref(), h.wording.is_some()))
            .collect();
        assert_eq!(
            found,
            [
                (Some("profile static"), false),
                (Some("profile sts"), true),
                (Some("profile legacy"), true),
                (Some("profile empty"), false),
            ]
        );
    }

    #[test]
    fn a_byte_order_mark_does_not_hide_the_first_profile() {
        let file = b"\xef\xbb\xbf[default]\naws_access_key_id = AKIASYNTHETIC\naws_secret_access_key = synthetic\n";
        let hits = aws_hits(file).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, Some(1));
        assert_eq!(hits[0].subject.as_deref(), Some("profile default"));
    }
}
