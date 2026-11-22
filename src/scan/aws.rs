//! Private identity of an AWS access secret and its paired public ID.

use super::recheck::linked;
use crate::rules::{aws, Hit, Rule, Target, SERVICE_TOKEN_ID};
use std::collections::HashMap;
use std::path::Path;

/// Pair only an ID in a profile with a secret, in one of AWS's known files.
/// An ID by itself, including one in another profile, keeps its own value.
pub(super) fn pair_ids(home: &Path, path: &Path, rule: &Rule, bytes: &[u8], hits: &mut [Hit]) {
    let aws_id = |hit: &Hit| {
        matches!(
            hit.token_type,
            Some("AWS access key" | "AWS temporary access key")
        )
    };
    if rule.id != SERVICE_TOKEN_ID || !hits.iter().any(aws_id) {
        return;
    }
    let at = aws::AWS_KEYS.targets.iter().any(|target| match target {
        Target::File(name) => {
            path.strip_prefix(home) == Ok(Path::new(name)) || linked(target, path, home)
        }
        _ => false,
    });
    if !at {
        return;
    }
    let profiles = aws::aws_hits(bytes).unwrap_or_else(|incomplete| incomplete.hits);
    let pairs: HashMap<_, _> = profiles
        .into_iter()
        .filter_map(|h| Some((h.aws_pair?, h.span?)))
        .collect();
    for hit in hits.iter_mut().filter(|hit| aws_id(hit)) {
        hit.aws_pair = hit.span.as_ref().and_then(|id| pairs.get(id)).cloned();
    }
}

pub(super) fn value_digest(
    rule: &Rule,
    hit: &Hit,
    bytes: &[u8],
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<String> {
    let (span, access_secret) = if rule.id == aws::AWS_KEYS.id {
        (hit.span.as_ref()?, true)
    } else if let Some(secret) = &hit.aws_pair {
        (secret, true)
    } else {
        let aws_env_secret = rule.id == "secret.env-assignment"
            && hit
                .subject
                .as_deref()
                .is_some_and(|subject| subject.eq_ignore_ascii_case("AWS_SECRET_ACCESS_KEY"));
        (hit.span.as_ref()?, aws_env_secret)
    };
    let value = bytes.get(span.clone())?;
    if access_secret && aws::aws_access_key_id(value) {
        // An access secret uses its usual value identity, including across
        // file formats. A literal shaped like a public ID in a secret field
        // must stay distinct even when the bytes coincide.
        let material = [b"loose-keys/aws-access-secret/1\0".as_slice(), value].concat();
        Some(digest("", &material, false))
    } else {
        Some(digest("", value, false))
    }
}
