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

/// For an access key ID the service-token rule finds in a file: it does
/// nothing without its secret access key, so the steps start by looking for
/// one, and most often end there.
pub const KEY_ID: Wording = Wording {
    explanation: "This file has text in the format of an AWS access key ID. Loose Keys didn't check whether the key still works.",
    reason: KEY_ID_REASON,
    next_step: KEY_ID_NEXT_STEP,
    advice: Advice {
        steps: &[
            LOOK,
            DEACTIVATE,
            REVOKE_SESSIONS,
            "Remove the ID and the secret access key from this file.",
            NOTHING_MORE,
        ],
        link: AWS_KEYS.advice.link,
    },
};

/// As `KEY_ID`, for an ID in an agent's records, which are deleted, not
/// edited.
pub const RECORD_KEY_ID: Wording = Wording {
    explanation: "An AI coding agent's session record or log has text in the format of an AWS access key ID. Loose Keys didn't check whether the key still works.",
    reason: KEY_ID_REASON,
    next_step: KEY_ID_NEXT_STEP,
    advice: Advice {
        steps: &[
            LOOK,
            DEACTIVATE,
            REVOKE_SESSIONS,
            token::DELETE_RECORD,
            NOTHING_MORE,
        ],
        link: AWS_KEYS.advice.link,
    },
};

const DEACTIVATE: &str = "If it's there, in IAM > Users > Security credentials, choose Actions > Deactivate for this access key. When everything works without it, choose Actions > Delete.";
const KEY_ID_REASON: Option<&str> = Some("An access key ID works only with its secret access key. If that secret is stored nearby, any program that can read this file can copy both.");
const KEY_ID_NEXT_STEP: Option<&str> = Some("Look for the secret access key that goes with this ID. If it's there, deactivate the key in IAM.");
const LOOK: &str = "Look for the secret access key that goes with this ID, in this file and in other files in its folder.";
const REVOKE_SESSIONS: &str = "For a temporary access key, open the role it's for in IAM instead, and on its Revoke sessions tab choose Revoke active sessions. This ends other people's sessions of that role too.";
const NOTHING_MORE: &str = "If you don't find a secret access key, there's nothing more to do.";

pub(crate) use super::token::aws_access_key_id;

const MAX_PROFILES: usize = 100;

/// AWS files are parsed leniently, so invalid UTF-8 never hides other keys.
pub(crate) fn aws_hits(bytes: &[u8]) -> Hits {
    capped_hits(aws_profiles_with_keys(bytes), MAX_PROFILES)
}

/// Profiles containing an access secret. The two byte positions pair the
/// secret with the public ID found by the service-token rule.
fn aws_profiles_with_keys(bytes: &[u8]) -> impl Iterator<Item = Hit> + '_ {
    let mut profiles = Vec::new();
    let mut current: Option<Hit> = None;
    let mut line_start = 0;
    for (i, raw) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let text = String::from_utf8_lossy(raw);
        let line = if i == 0 {
            text.trim_start_matches('\u{feff}').trim()
        } else {
            text.trim()
        };
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            // ~/.aws/config writes "[profile name]" for all but the default.
            let profile = name.strip_prefix("profile ").map_or(name, str::trim);
            if let Some(completed) = current.take().filter(|h| h.span.is_some()) {
                profiles.push(completed);
                if profiles.len() > MAX_PROFILES {
                    break;
                }
            }
            current = Some(Hit::line(i + 1).about(&format!("profile {profile}")));
        } else if let (Some(hit), Some((key, value))) = (current.as_mut(), line.split_once('=')) {
            // botocore reads the file raw: "$" and "!" are part of a value.
            if let Some(value) = scalar_literal_by(value, raw_literal) {
                match key.trim().to_ascii_lowercase().as_str() {
                    "aws_access_key_id" => {
                        hit.aws_pair = aws_value_span(raw, &text, value, line_start)
                    }
                    "aws_secret_access_key" => {
                        hit.span = aws_value_span(raw, &text, value, line_start)
                    }
                    // The older name, which botocore also reads (unverified).
                    "aws_session_token" | "aws_security_token" => {
                        hit.wording = Some(&TEMPORARY_KEYS)
                    }
                    _ => {}
                }
            }
        }
        line_start += raw.len();
    }
    profiles.extend(current.filter(|h| h.span.is_some()));
    profiles.into_iter()
}

/// Lossy decoding can widen invalid bytes to a three-byte replacement
/// character. Map both ends back to the file before hashing the value.
fn aws_value_span(
    raw: &[u8],
    text: &str,
    value: &str,
    line_start: usize,
) -> Option<std::ops::Range<usize>> {
    let span = Hit::file().at(text, value).span?;
    if raw.len() == text.len() {
        return Some(line_start + span.start..line_start + span.end);
    }
    let offset = |at| {
        let (mut decoded, mut source) = (0, line_start);
        for chunk in raw.utf8_chunks() {
            let valid = chunk.valid().len();
            if at <= decoded + valid {
                return Some(source + (at - decoded));
            }
            decoded += valid + '\u{fffd}'.len_utf8();
            source += valid + chunk.invalid().len();
        }
        (at == text.len()).then_some(line_start + raw.len())
    };
    Some(offset(span.start)?..offset(span.end)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_sections() {
        let ini = "[default]\naws_access_key_id = A\naws_secret_access_key = B\n\n[sso]\nsso_start_url = x\n\n[other]\nAWS_SECRET_ACCESS_KEY=C\n[empty]\naws_secret_access_key =\n";
        let hits = aws_profiles_with_keys(ini.as_bytes()).collect::<Vec<_>>();
        assert_eq!(
            hits.iter().map(|h| h.line).collect::<Vec<_>>(),
            vec![Some(1), Some(8)]
        );
        assert_eq!(hits[0].subject.as_deref(), Some("profile default"));
    }

    /// The service-token rule finds the access key ID in the same file, so
    /// the profile carries its position separately from the secret.
    #[test]
    fn a_profile_keeps_both_positions() {
        let ini = "\u{feff}[default]\naws_access_key_id = fixture-id\naws_secret_access_key = synthetic-only\n[bare]\naws_secret_access_key = synthetic-only\n";
        let hits = aws_profiles_with_keys(ini.as_bytes()).collect::<Vec<_>>();
        let at = hits[0].aws_pair.clone().unwrap();
        assert_eq!(&ini[at], "fixture-id");
        assert_eq!(hits[1].aws_pair, None);
        for hit in hits {
            assert_eq!(&ini[hit.span.unwrap()], "synthetic-only");
        }
    }

    /// ~/.aws/config names a profile "[profile name]", the credentials file "[name]".
    #[test]
    fn a_profile_is_named_once() {
        let hits = aws_profiles_with_keys(
            b"[profile prod]\naws_secret_access_key = synthetic-only\n[default]\naws_secret_access_key = synthetic-only\n",
        );
        let named: Vec<_> = hits.map(|h| h.subject).collect();
        assert_eq!(
            named,
            [Some("profile prod".into()), Some("profile default".into())]
        );
    }

    /// Keys with a session token are temporary, as tools that sign in
    /// through AWS STS write them, wherever the token stands in the profile.
    #[test]
    fn temporary_keys_have_their_own_wording() {
        let hits: Vec<_> = aws_profiles_with_keys(concat!(
            "[static]\naws_secret_access_key = synthetic-only\n",
            "[sts]\naws_session_token = synthetic-only\naws_secret_access_key = synthetic-only\n",
            "[legacy]\naws_secret_access_key = synthetic-only\naws_security_token = synthetic-only\n",
            "[empty]\naws_secret_access_key = synthetic-only\naws_session_token =\n",
            "[token-only]\naws_session_token = synthetic-only\n",
        ).as_bytes()).collect();
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
    fn invalid_bytes_do_not_change_the_positions_of_values() {
        let ini = b"[default]\naws_access_key_id = fixture-id # \xff\naws_secret_access_key = part-\xfe-\xff # literal\n";
        let hits = aws_hits(ini).unwrap();
        assert_eq!(&ini[hits[0].aws_pair.clone().unwrap()], b"fixture-id");
        assert_eq!(&ini[hits[0].span.clone().unwrap()], b"part-\xfe-\xff");
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
