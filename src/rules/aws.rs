//! Static access keys in the AWS shared credentials file.

use super::*;

pub const AWS_KEYS: Rule = Rule {
    id: "dev.aws.inline-credentials",
    category: "developer-cloud",
    kind: "review",
    severity: "high",
    title: "AWS access keys stored in a file",
    explanation: "This file has an AWS secret access key. Loose Keys did not check whether it still works or what it can access.",
    reason: Some("Static AWS access keys do not expire and work from any computer. Any program that can read this file can copy them."),
    next_step: Some("Replace static keys with short-lived sign-in. Deleting this file does not revoke keys; deactivate them in IAM."),
    advice: Advice {
        steps: &[
            "Find out what still uses this profile. In the IAM console, the key's 'Last used' column shows when and for which service.",
            "Switch to short-lived credentials: run 'aws configure sso' (IAM Identity Center), which stores no long-lived secret.",
            "In IAM > Users > Security credentials, make the old access key inactive, confirm nothing broke, then delete it.",
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
        (b"[default]\nregion = us-east-1\n", false),
        (b"[fixture]\naws_secret_access_key = #comment-only\n", false),
    ],
};

/// AWS files are parsed leniently, so invalid UTF-8 never hides other keys.
fn aws_hits(bytes: &[u8]) -> Hits {
    Ok(aws_profiles_with_keys(&String::from_utf8_lossy(bytes)))
}

/// Profile headers whose section contains aws_secret_access_key.
pub fn aws_profiles_with_keys(text: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut section: Option<(usize, &str)> = None;
    let mut counted = false;
    for (i, raw) in text.lines().enumerate() {
        let l = raw.trim();
        if l.starts_with('[') && l.ends_with(']') {
            section = Some((i + 1, &l[1..l.len() - 1]));
            counted = false;
        } else if let (Some((line, profile)), false) = (section, counted) {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim().eq_ignore_ascii_case("aws_secret_access_key")
                    && scalar_literal(v).is_some()
                {
                    out.push(Hit::line(line).about(&format!("profile {profile}")));
                    counted = true;
                }
            }
        }
    }
    out
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
}
