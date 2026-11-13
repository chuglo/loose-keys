//! Recognize encoded image runs without parsing records or decoding images.

const HEADER: usize = 24;

#[derive(Clone, Copy, Default)]
struct Run {
    modulo: u8,
    padding: u8,
    invalid: bool,
}

impl Run {
    fn feed(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.modulo = (self.modulo + 1) % 4;
            if *b == b'=' {
                self.padding = self.padding.saturating_add(1);
                self.invalid |= self.padding > 2;
            } else {
                self.invalid |= self.padding != 0;
            }
        }
    }

    fn complete(self) -> bool {
        !self.invalid && self.modulo == 0
    }
}

pub(super) struct Images {
    streaming: bool,
    image: Option<Run>,
    prefix: [u8; HEADER],
    prefix_len: usize,
    /// The last two bytes of earlier pieces, nearest first.
    last: [Option<u8>; 2],
    failed: bool,
}

impl Images {
    pub(super) fn new(streaming: bool) -> Self {
        Self {
            streaming,
            image: None,
            prefix: [0; HEADER],
            prefix_len: 0,
            last: [None; 2],
            failed: false,
        }
    }

    pub(super) fn failed(&self) -> bool {
        self.failed
    }

    pub(super) fn finish(&mut self) -> bool {
        if let Some(run) = self.image.take() {
            self.failed |= !run.complete();
        }
        !self.failed
    }

    pub(super) fn end_piece(&mut self, bytes: &[u8]) {
        for b in &bytes[bytes.len().saturating_sub(2)..] {
            self.last = [Some(*b), self.last[0]];
        }
    }

    /// Return only spans of encoded image data. Delimiters stay available to
    /// the token matcher, and the original bytes and offsets stay untouched.
    pub(super) fn skip(&mut self, bytes: &[u8], at: usize) -> Option<usize> {
        if at == 0 {
            if let Some(run) = self.image.take() {
                return self.continue_image(bytes, run);
            }
            if self.prefix_len != 0 {
                return self.continue_prefix(bytes);
            }
        }
        let back = |k: usize| match at.checked_sub(k) {
            Some(i) => bytes.get(i).copied(),
            None => self.last.get(k - at - 1).copied().flatten(),
        };
        let rest = bytes.get(at..)?;
        if !starts_after(back(1), back(2)) || !could_start(rest) {
            return None;
        }
        // Counting stops after the padding, so a run started after "=" never
        // counts bytes another run counted.
        let data = rest
            .iter()
            .take_while(|b| encoded(**b) && **b != b'=')
            .count();
        let n = data + rest[data..].iter().take_while(|b| **b == b'=').count();
        if rest.get(n).is_some_and(|b| encoded(*b)) {
            return None;
        }
        let run = rest.get(..n)?;
        if n < HEADER {
            if self.streaming && at + n == bytes.len() && n == data {
                self.prefix[..n].copy_from_slice(run);
                self.prefix_len = n;
                return (n > 0).then_some(at + n);
            }
            return None;
        }
        if !image_header(run) {
            return None;
        }
        let mut state = Run::default();
        state.feed(run);
        let continues = self.streaming && at + n == bytes.len();
        if state.invalid || (!continues && !state.complete()) {
            return None;
        }
        self.image = continues.then_some(state);
        Some(at + n)
    }

    fn continue_image(&mut self, bytes: &[u8], mut run: Run) -> Option<usize> {
        let n = bytes.iter().take_while(|b| encoded(**b)).count();
        run.feed(&bytes[..n]);
        if run.invalid || (n < bytes.len() && !run.complete()) {
            // Earlier pieces have already been omitted. Keep this piece's
            // raw matches and report the uncertainty instead of resolving it.
            self.failed = true;
            return None;
        }
        self.image = (n == bytes.len()).then_some(run);
        (n > 0).then_some(n)
    }

    fn continue_prefix(&mut self, bytes: &[u8]) -> Option<usize> {
        let old = self.prefix_len;
        self.prefix_len = 0;
        let n = bytes.iter().take_while(|b| encoded(**b)).count();
        let take = n.min(HEADER - old);
        self.prefix[old..old + take].copy_from_slice(&bytes[..take]);
        if old + take < HEADER {
            if n == bytes.len() && !bytes.contains(&b'=') && could_start(&self.prefix[..old + take])
            {
                self.prefix_len = old + take;
                return (n > 0).then_some(n);
            }
            return None;
        }
        if !image_header(&self.prefix) {
            return None;
        }
        let mut run = Run::default();
        run.feed(&self.prefix[..old]);
        self.continue_image(bytes, run)
    }
}

fn encoded(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+/=".contains(&b)
}

/// Whether a run may start after these bytes, nearest first. "=" ends a
/// name ("src=") and a JSON escape ends in a letter ("\n"); neither makes
/// one word of what follows.
fn starts_after(before: Option<u8>, earlier: Option<u8>) -> bool {
    match before {
        None | Some(b'=') => true,
        Some(b'n' | b'r' | b't') if earlier == Some(b'\\') => true,
        Some(b) => !(b.is_ascii_alphanumeric() || b"_-/+".contains(&b)),
    }
}

fn could_start(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(4)];
    !head.is_empty()
        && [b"iVBO", b"/9j/", b"R0lG", b"UklG"]
            .iter()
            .any(|prefix| prefix.starts_with(head))
}

/// Only 18 header bytes are decoded, regardless of the payload's length.
/// This identifies image encodings; it does not validate their pixels.
fn image_header(encoded: &[u8]) -> bool {
    let Some(header) = encoded.get(..HEADER) else {
        return false;
    };
    let mut raw = [0u8; 18];
    let value = |b| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    for (chunk, out) in header
        .as_chunks::<4>()
        .0
        .iter()
        .zip(raw.as_chunks_mut::<3>().0.iter_mut())
    {
        let (Some(a), Some(b), Some(c), Some(d)) = (
            value(chunk[0]),
            value(chunk[1]),
            value(chunk[2]),
            value(chunk[3]),
        ) else {
            return false;
        };
        out[0] = (a << 2) | (b >> 4);
        out[1] = ((b & 15) << 4) | (c >> 2);
        out[2] = ((c & 3) << 6) | d;
    }
    let png = raw.starts_with(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR");
    let jpeg = raw.starts_with(b"\xff\xd8\xff") && (0xc0..=0xfe).contains(&raw[3]);
    let gif = (raw.starts_with(b"GIF87a") || raw.starts_with(b"GIF89a"))
        && raw[6..8] != [0, 0]
        && raw[8..10] != [0, 0];
    let webp = raw.starts_with(b"RIFF")
        && raw.get(8..12) == Some(b"WEBP")
        && [b"VP8 ", b"VP8L", b"VP8X"]
            .iter()
            .any(|kind| raw.get(12..16) == Some(kind.as_slice()));
    png || jpeg || gif || webp
}
