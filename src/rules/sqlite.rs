//! Bounded, read-only interpretation of ordinary UTF-8 SQLite table b-trees.
//! No SQL, file access or recovery. Unsupported layouts return no count.
//! Format: https://www.sqlite.org/fileformat2.html (schema and b-tree records).
//!
//! It reads bytes `fsutil` already read, within the 1 MiB config limit: the
//! schema table from page 1, then the named table's b-tree, without
//! recursion. Page and header bounds, live cell pointers, serial lengths,
//! overlapping cells and repeated pages are checked before a count is
//! accepted. UTF-16, index b-trees (WITHOUT ROWID tables) and overflow
//! payloads give no count, which callers report as an `unreadable` gap, never
//! zero. It is not an integrity check: free lists, key order across pages,
//! unvisited pages and a consistent snapshot are not established.

use super::browser::Rows;
use std::collections::HashSet;

fn u16_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn u32_at(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
}

fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..9 {
        let byte = *bytes.get(*at)?;
        *at += 1;
        if i == 8 {
            return Some((value << 8) | u64::from(byte));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Serial types and their slices, borrowing only this record's payload.
fn fields(payload: &[u8]) -> Option<Vec<(u64, &[u8])>> {
    let mut at = 0;
    let header = usize::try_from(varint(payload, &mut at)?).ok()?;
    let mut body = header;
    let header_bytes = payload.get(..header)?;
    if header < at {
        return None;
    }
    let mut fields = Vec::new();
    while at < header {
        let kind = varint(header_bytes, &mut at)?;
        let length = match kind {
            0 | 8 | 9 => 0,
            1..=4 => kind as usize,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return None,
            _ => usize::try_from((kind - 12) / 2).ok()?,
        };
        let end = body.checked_add(length)?;
        fields.push((kind, payload.get(body..end)?));
        body = end;
    }
    (body == payload.len()).then_some(fields)
}

fn text<'a>(field: &(u64, &'a [u8])) -> Option<&'a [u8]> {
    (field.0 >= 13 && field.0 % 2 == 1).then_some(field.1)
}

fn positive_integer(field: &(u64, &[u8])) -> Option<usize> {
    match field.0 {
        9 => Some(1),
        1..=6 if field.1.first()? & 0x80 == 0 => field
            .1
            .iter()
            .try_fold(0usize, |n, b| n.checked_mul(256)?.checked_add(*b as usize))
            .filter(|n| *n > 0),
        _ => None,
    }
}

struct Database<'a> {
    bytes: &'a [u8],
    page_size: usize,
    usable: usize,
    // Shared by the schema and target walks: pages cannot alias or cycle.
    visited: HashSet<usize>,
}

impl<'a> Database<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        // The scanner already limits configs; retain that bound for direct calls.
        if bytes.len() > 1024 * 1024 || !super::browser::is_sqlite(bytes) {
            return None;
        }
        let page_size = match u16_at(bytes, 16)? {
            1 => 65536,
            n => n,
        };
        if !(512..=65536).contains(&page_size)
            || !page_size.is_power_of_two()
            || !bytes.len().is_multiple_of(page_size)
            || !matches!(bytes.get(18), Some(1 | 2))
            || !matches!(bytes.get(19), Some(1 | 2))
            || bytes.get(21..24)? != [64, 32, 32]
            || !(1..=4).contains(&u32_at(bytes, 44)?)
            || u32_at(bytes, 56)? != 1
        {
            return None;
        }
        let usable = page_size.checked_sub(*bytes.get(20)? as usize)?;
        if usable < 480 {
            return None;
        }
        let declared = u32_at(bytes, 28)?;
        if declared != 0
            && u32_at(bytes, 24)? == u32_at(bytes, 92)?
            && declared != bytes.len() / page_size
        {
            return None;
        }
        Some(Self {
            bytes,
            page_size,
            usable,
            visited: HashSet::new(),
        })
    }

    /// Follow only live cell pointers. No search through free or deleted bytes.
    /// Each page is visited once; cell count, allocations and work are bounded
    /// by the supplied database. Overflow payloads and index b-trees are refused.
    fn table(&mut self, root: usize, mut row: impl FnMut(&[u8]) -> Option<()>) -> Option<Rows> {
        let mut pending = vec![root];
        let mut count = 0usize;
        let mut multiple_pages = false;
        while let Some(number) = pending.pop() {
            if !self.visited.insert(number) {
                return None;
            }
            let start = number.checked_sub(1)?.checked_mul(self.page_size)?;
            let page = self.bytes.get(start..start.checked_add(self.usable)?)?;
            let header = if number == 1 { 100 } else { 0 };
            let leaf = match *page.get(header)? {
                0x0d => true,
                0x05 => {
                    multiple_pages = true;
                    false
                }
                _ => return None,
            };
            let cells = u16_at(page, header + 3)?;
            let pointers = header + if leaf { 8 } else { 12 };
            let pointers_end = pointers + cells * 2;
            let content = match u16_at(page, header + 5)? {
                0 if self.page_size == 65536 => 65536,
                n => n,
            };
            if pointers_end > content || content > self.usable || *page.get(header + 7)? > 60 {
                return None;
            }
            if !leaf {
                pending.push(u32_at(page, header + 8)?);
            }
            let mut spans = Vec::with_capacity(cells);
            let mut previous = None;
            for i in 0..cells {
                let cell = u16_at(page, pointers + i * 2)?;
                if cell < content {
                    return None;
                }
                let mut at = cell;
                let length = if leaf {
                    usize::try_from(varint(page, &mut at)?).ok()?
                } else {
                    pending.push(u32_at(page, at)?);
                    at += 4;
                    0
                };
                let key = varint(page, &mut at)? as i64;
                if previous.is_some_and(|p| p >= key) {
                    return None;
                }
                previous = Some(key);
                if leaf {
                    // Table-leaf payloads larger than this use overflow pages.
                    if length > self.usable - 35 {
                        return None;
                    }
                    let end = at.checked_add(length)?;
                    row(page.get(at..end)?)?;
                    at = end;
                    count += 1;
                }
                spans.push((cell, at));
            }
            spans.sort_unstable();
            if spans.windows(2).any(|w| w[0].1 > w[1].0) {
                return None;
            }
            // Avoid growing the queue with repeated pointers in a corrupt tree.
            if pending.len() > self.bytes.len() / self.page_size {
                return None;
            }
        }
        Some(if multiple_pages && count > 0 {
            Rows::Many
        } else {
            Rows::Exactly(count)
        })
    }
}

pub(super) fn table_rows(bytes: &[u8], name: &[u8]) -> Option<Rows> {
    let mut db = Database::new(bytes)?;
    let mut root = None;
    db.table(1, |payload| {
        let record = fields(payload)?;
        if record.len() != 5 {
            return None;
        }
        if text(&record[0])? == b"table" && text(&record[1])? == name {
            if text(&record[2])? != name || root.is_some() {
                return None;
            }
            root = Some(positive_integer(&record[3])?);
        }
        Some(())
    })?;
    db.table(root?, |payload| fields(payload).map(|_| ()))
}
