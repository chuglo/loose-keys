//! The credential scope that follows an AWS access key ID in a signed
//! request: `<key id>/<yyyymmdd>/<region>/<service>/aws4_request` for SigV4,
//! and the same without the region for SigV4a. Signed download links and
//! `Authorization` headers carry the signer's key ID this way. The ID is not
//! a secret, and nothing in such a link is a credential the reader can revoke.

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;

/// The most bytes after a key ID that are looked at. A complete scope with
/// its longest separators and segments, and the byte after it, is shorter.
const LIMIT: usize = 128;
const SEGMENT: usize = 32;
const END: &[u8] = b"aws4_request";

/// Whether `rest`, the bytes right after a key ID, start with a complete
/// credential scope that ends before a word character could continue it.
/// Anything less, including `rest` ending partway, is not a scope.
pub(super) fn follows(rest: &[u8]) -> bool {
    let window = rest.get(..LIMIT).unwrap_or(rest);
    let Some(n) = scope(window) else {
        return false;
    };
    match window.get(n) {
        Some(b) => !(b.is_ascii_alphanumeric() || *b == b'_'),
        None => n == rest.len(),
    }
}

/// The length of the scope at the start of `s`.
fn scope(s: &[u8]) -> Option<usize> {
    let mut at = separator(s)?;
    let date = s.get(at..at + 8)?;
    if !date.iter().all(u8::is_ascii_digit) {
        return None;
    }
    at += 8;
    at += separator(s.get(at..)?)?;
    // A region, then a service; or, for SigV4a, the service alone.
    for _ in 0..2 {
        at += segment(s.get(at..)?)?;
        at += separator(s.get(at..)?)?;
        if s.get(at..)?.starts_with(END) {
            return Some(at + END.len());
        }
    }
    None
}

/// A slash, after up to four backslashes as JSON and shell quoting add, or
/// "%2F" in either case, percent-encoded again up to twice ("%252F").
fn separator(s: &[u8]) -> Option<usize> {
    let slashes = s.iter().take(5).take_while(|b| **b == b'\\').count();
    if slashes < 5 && s.get(slashes) == Some(&b'/') {
        return Some(slashes + 1);
    }
    if s.first() != Some(&b'%') {
        return None;
    }
    let mut at = 1;
    for _ in 0..2 {
        if s.get(at..at + 2) != Some(b"25") {
            break;
        }
        at += 2;
    }
    matches!(s.get(at..at + 2), Some(b"2F" | b"2f")).then_some(at + 2)
}

/// A region or service code: lowercase letters, digits and "-".
fn segment(s: &[u8]) -> Option<usize> {
    let n = s
        .iter()
        .take(SEGMENT + 1)
        .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || **b == b'-')
        .count();
    (1..=SEGMENT).contains(&n).then_some(n)
}
