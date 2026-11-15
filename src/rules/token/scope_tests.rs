use super::super::*;
use crate::rules::{env::ENV_SECRET, Matcher};

// Split so this source file never holds a complete token-shaped string.
fn key() -> String {
    ["AKIA", "ABCDEFGHIJKLMNOP"].concat()
}

fn temporary() -> String {
    ["ASIA", "QRSTUVWXYZ234567"].concat()
}

const SIGNATURE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A presigned link whose credential scope's slashes are written as `sep`.
fn link(key: &str, sep: &str) -> String {
    format!(
        "https://bucket.s3.amazonaws.com/f.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={key}{sep}20251203{sep}us-east-1{sep}s3{sep}aws4_request&X-Amz-Date=20251203T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature={SIGNATURE}"
    )
}

/// Where each token is, in a file read whole and in one piece of an agent's
/// record, which must agree, as (start, end). Positions only, so a failure
/// prints no value.
fn found(text: &str) -> Vec<(usize, usize)> {
    let spans = |hits: Vec<Hit>| {
        hits.into_iter()
            .map(|h| h.span.map(|s| (s.start, s.end)).unwrap())
            .collect::<Vec<_>>()
    };
    let whole = spans(token_hits(text.as_bytes()).unwrap());
    let record = record_hits(text.as_bytes(), 1, &mut StreamState::default()).unwrap();
    assert_eq!(whole, spans(record));
    assert_eq!(has_token(text.as_bytes()), !whole.is_empty());
    whole
}

#[test]
fn a_key_id_in_a_signed_link_is_not_reported() {
    let key = key();
    let header = format!("Authorization: AWS4-HMAC-SHA256 Credential={key}/20251203/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={SIGNATURE}");
    let session = format!(
        "{}&X-Amz-Security-Token=synthetic-session-value",
        link(&temporary(), "%2F")
    );
    let escaped = |amp: &str| {
        format!(
            "{{\"type\":\"tool_result\",\"content\":\"curl -L '{}'\"}}",
            link(&key, "%2F").replace('&', amp)
        )
    };
    let nested = format!(
        "https://redirect.invalid/?to=https%3A%2F%2Fbucket.s3.amazonaws.com%2Ff%3FX-Amz-Credential%3D{key}%252F20251203%252Fus-east-1%252Fs3%252Faws4_request%26X-Amz-Date%3D20251203T000000Z"
    );
    let parsed = format!(
        "{{\"name\":\"X-Amz-Credential\",\"value\":\"{key}/20251203/eu-west-1/s3/aws4_request\"}}"
    );
    let scoped = |region: &str, service: &str| {
        format!("Credential={key}/20251203/{region}/{service}/aws4_request,")
    };
    for text in [
        link(&key, "%2F"),
        link(&key, "%2f"),
        link(&key, "/"),
        link(&key, "%252F"),
        link(&key, "%25252f"),
        link(&key, "\\/"),
        link(&key, "\\\\\\\\/"),
        header,
        session,
        escaped("\\u0026"),
        escaped("\\\\u0026"),
        escaped("&amp;"),
        nested,
        parsed,
        scoped("us-gov-west-1", "s3"),
        scoped("cn-north-1", "s3"),
        scoped("us-east-1", "execute-api"),
        // SigV4a: the region is in its own header, not in the scope.
        format!("Credential={key}/20251203/s3/aws4_request,"),
        // A scope may end the input.
        format!("Credential={key}/20251203/us-east-1/s3/aws4_request"),
        // AWS's documentation sample is never reported.
        link(&["AKIA", "IOSFODNN7EXAMPLE"].concat(), "%2F"),
    ] {
        assert!(found(&text).is_empty(), "{}", text.len());
    }
}

#[test]
fn a_key_id_without_a_complete_scope_is_reported() {
    let key = key();
    let at = |text: &str| text.find(&key).unwrap();
    for text in [
        format!("The key {key} is in the notes."),
        format!("aws_access_key_id = {key}\n"),
        format!("X-Amz-Credential={key}&X-Amz-Date=20251203T000000Z"),
        format!("X-Amz-Credential={key}%2F20251203&X-Amz-Date=20251203T000000Z"),
        format!("{key}/20251203/us-east-1/s3/aws4_requests&"),
        format!("{key}/20251203/us-east-1/s3/aws4_reques&"),
        format!("{key}/2025120/us-east-1/s3/aws4_request&"),
        format!("{key}/20251203//s3/aws4_request&"),
        format!("{key}/20251203/{}/s3/aws4_request&", "a".repeat(33)),
        format!("{key}/20251203/US-EAST-1/s3/aws4_request&"),
        format!("{key}/20251203/us-east-1/s3/extra/aws4_request&"),
        format!("{key}/20251203/us-east-1/s3/extra/more/aws4_request&"),
        format!("{key} /20251203/us-east-1/s3/aws4_request&"),
        format!("{key}\n/20251203/us-east-1/s3/aws4_request&"),
        format!("{key}\\\\\\\\\\/20251203/us-east-1/s3/aws4_request&"),
        format!("{key}%2525252F20251203%2Fus-east-1%2Fs3%2Faws4_request&"),
        // Scope text before the key, or elsewhere on its line.
        format!("20251203/us-east-1/s3/aws4_request {key}"),
        format!("X-Amz-Credential=%2F20251203%2Fus-east-1%2Fs3%2Faws4_request {key}"),
        format!("{key} and later /20251203/us-east-1/s3/aws4_request"),
        // Input that ends inside the scope: a head or a piece cut there.
        format!("{key}%2F20251203%2Fus-east-1%2Fs3%2Faws4_req"),
        format!("{key}/20251203/us-east-1/s3/"),
        format!("{key}%2"),
        format!("{key}%25"),
    ] {
        let start = at(&text);
        assert_eq!(found(&text), [(start, start + key.len())], "{}", text.len());
    }
}

#[test]
fn a_key_id_written_bare_beside_its_signed_link_is_reported_at_the_bare_one() {
    let key = key();
    for text in [
        format!("{} then {key}\n", link(&key, "%2F")),
        format!("{key} then {}\n", link(&key, "%2F")),
    ] {
        let bare = if text.starts_with(&key) {
            0
        } else {
            text.rfind(&key).unwrap()
        };
        assert_eq!(found(&text), [(bare, bare + key.len())]);
    }
}

#[test]
fn only_aws_key_ids_are_passed_over_before_a_scope() {
    let token = ["gh", "p_", "0123456789abcdefghijABCDEFGHIJ012345"].concat();
    let text = format!("Credential={token}/20251203/us-east-1/s3/aws4_request,");
    assert_eq!(found(&text), [(11, 11 + token.len())]);
}

/// A key ID left out takes none of the room for different tokens, so many
/// signed links neither end the search early nor hide a token after them.
#[test]
fn signed_links_do_not_use_up_the_token_limit() {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut text = String::new();
    for n in 0..3 * MAX_HITS {
        let mut body = *b"QRSTUVWXYZ2345AA";
        body[14] = alphabet[n / alphabet.len()];
        body[15] = alphabet[n % alphabet.len()];
        let key = ["AKIA", std::str::from_utf8(&body).unwrap()].concat();
        text.push_str(&link(&key, "%2F"));
        text.push('\n');
    }
    let token = ["gh", "p_", "0123456789abcdefghijABCDEFGHIJ012345"].concat();
    text.push_str(&format!("export GITHUB_TOKEN={token}\n"));
    let at = text.find(&token).unwrap();
    assert_eq!(found(&text), [(at, at + token.len())]);
}

#[test]
fn a_secret_key_beside_a_signed_link_is_still_found_by_its_name() {
    let text = format!(
        "DOWNLOAD_URL={}\nAWS_SECRET_ACCESS_KEY=fixture/Synthetic/OnlyValue\n",
        link(&key(), "%2F")
    );
    assert!(found(&text).is_empty());
    let Matcher::Whole { test, .. } = ENV_SECRET.matcher else {
        panic!("the .env rule reads whole files");
    };
    let hits = test(text.as_bytes()).unwrap();
    let names: Vec<_> = hits.iter().map(|h| h.subject.as_deref()).collect();
    assert_eq!(names, [Some("AWS_SECRET_ACCESS_KEY")]);
}

#[test]
fn a_bare_key_id_is_still_a_token() {
    assert!(is_token(key().as_bytes()));
    assert!(is_token(temporary().as_bytes()));
}
