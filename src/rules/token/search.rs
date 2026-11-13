//! Token search shared by whole files and streamed agent records.

use super::*;

#[cfg(test)]
#[path = "search_tests.rs"]
mod tests;

/// Per-file state retained between pieces of an agent record.
pub struct StreamState {
    images: images::Images,
}

impl Default for StreamState {
    fn default() -> Self {
        Self {
            images: images::Images::new(true),
        }
    }
}

impl StreamState {
    /// A malformed image run already omitted in an earlier piece is unknown,
    /// so an incomplete recheck cannot treat an old finding as removed.
    pub fn finish(&mut self) -> Result<(), crate::fsutil::Gap> {
        self.images.finish().then_some(()).ok_or("unreadable")
    }
}

/// Every token in one piece of a record, with where it sits so the scanner
/// can report each distinct one once. The rule's own steps apply (delete the
/// record), with the issuer's page for revoking.
pub(super) fn record_hits(piece: &[u8], first_line: usize, state: &mut StreamState) -> Hits {
    let text = !piece.contains(&0);
    let (mut line, mut counted) = (first_line, 0);
    let (found, limited) = find_with_images(piece, &mut state.images);
    let hits = found
        .into_iter()
        .map(|(at, p)| {
            line += piece[counted..at].iter().filter(|b| **b == b'\n').count();
            counted = at;
            let length = token_at(&piece[at..]).map_or(0, |(_, n)| n);
            Hit {
                line: text.then_some(line),
                subject: label(p.name),
                token_type: Some(p.name),
                link: p.advice.link,
                span: Some(at..at + length),
                low: p.test,
                ..Hit::default()
            }
        })
        .collect();
    if limited || state.images.failed() {
        Err(Incomplete {
            reason: if state.images.failed() {
                "unreadable"
            } else {
                "scan-limit"
            },
            hits,
        })
    } else {
        Ok(hits)
    }
}

/// Whether a token may start at `i`: not inside a longer word. In a JSON
/// string a line break or tab is written as a backslash and a letter, and a
/// terminal colour code ends in "m" ("[32m"), so neither letter makes a word
/// of what follows it.
pub(super) fn starts_word(bytes: &[u8], i: usize) -> bool {
    if i == 0 || !word(bytes[i - 1]) {
        return true;
    }
    let before = &bytes[..i - 1];
    let digits = |b: &&u8| b.is_ascii_digit() || **b == b';';
    match bytes[i - 1] {
        b'n' | b'r' | b't' => before.last() == Some(&b'\\'),
        b'm' => {
            let code = before.iter().rev().take(8).take_while(digits).count();
            code > 0 && before.len() > code && before[before.len() - code - 1] == b'['
        }
        _ => false,
    }
}

/// (byte offset, provider) of each token, in file order. The first MAX_HITS
/// are all kept. After that only a value not seen before is, up to MAX_HITS
/// different values, so one token repeated often cannot hide another.
pub(super) fn find(bytes: &[u8]) -> (Vec<(usize, &'static Provider)>, bool) {
    find_with_images(bytes, &mut images::Images::new(false))
}

fn find_with_images(
    bytes: &[u8],
    images: &mut images::Images,
) -> (Vec<(usize, &'static Provider)>, bool) {
    let mut out = Vec::new();
    let mut values = std::collections::HashSet::new();
    let mut counted = [(0, 0); PROVIDERS.len()];
    let (mut i, mut limited) = (0, false);
    while i < bytes.len() {
        if let Some(end) = images.skip(bytes, i) {
            i = end;
            continue;
        }
        if limited {
            i += 1;
            continue;
        }
        if may_start(bytes, i) && starts_word(bytes, i) {
            if let Some((p, len)) = token_counted(bytes, i, &mut counted) {
                let value = &bytes[i..i + len];
                let new = !values.contains(value);
                if new && values.len() == MAX_HITS {
                    limited = true;
                    continue;
                }
                if new {
                    values.insert(value);
                }
                if new || out.len() < MAX_HITS {
                    out.push((i, p));
                }
                i += len;
                continue;
            }
        }
        i += 1;
    }
    images.end_piece(bytes);
    (out, limited)
}
