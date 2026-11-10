//! Checking one file again outside a scan, to learn whether a review item is
//! still there.

use super::read::{settled, take_piece, value_key, READ_PIECE};
use super::{is_root, CONFIG_MAX, HEADER, STREAM_MAX};
use crate::fsutil::{
    list_dir, open_regular, read_config, read_head, through_links, FOLDER_ENTRIES,
};
use crate::rules::{Hit, Matcher, Rule, Target, RULES};
use std::io::Read;
use std::path::Path;

/// Check one file against one rule, outside a scan, to learn whether a review
/// item is still there. None: the file could not be checked, so nothing is
/// known. Some: what is still worth reviewing there, by subject; empty when
/// the file is gone or no longer matches. `mount` is what the finding kept
/// about the volume the file was on, if it kept anything: a file that is not
/// there because its volume is not is one that could not be checked.
pub fn recheck(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
) -> Option<Vec<Option<String>>> {
    let found = recheck_values(rule, path, home, mount, &|_, _, _| String::new())?;
    Some(found.into_iter().map(|(subject, _)| subject).collect())
}

/// As `recheck`, with which value each thing still found holds: the digest
/// a scan given `digest` lists that value by, or None where the hit has no
/// single value. Two credentials of one kind at one place are told apart by
/// it, so that one of them being gone is something a fresh read can say. A
/// record read in full gives each different value once, as a scan does.
pub(super) fn recheck_values(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    recheck_by(rule, path, home, mount, digest, None, &|| false)
}

/// Which kind of item a recheck is for: one worth reviewing, or a stored
/// sign-in. Each keeps what a scan would list as that kind.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Want {
    Review,
    Stored,
}

/// As `recheck_values`, with private registry-place identities instead of
/// display labels where available, keeping only what a scan would list as
/// `want`'s kind of item. Only for private review-state comparisons.
/// `stop` is asked between the pieces of a file read through, which can be
/// large; once it says to stop, nothing is known.
pub fn recheck_identities(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
    want: Want,
    stop: &dyn Fn() -> bool,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    recheck_by(rule, path, home, mount, digest, Some(want), stop)
}

pub(super) fn scope_digest(
    hit: &Hit,
    bytes: &[u8],
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<String> {
    let key = bytes.get(hit.scope.clone()?)?;
    // Domain-separated from secret values and material fingerprints. The
    // bytes are bounded by the file read and are discarded with this call.
    let material = [b"loose-keys/registry-scope/1\0".as_slice(), key].concat();
    Some(digest("", &material, false))
}

/// `identities`: private registry-place identities, keeping what a scan would
/// list as that kind of item; None, display labels, for an item worth
/// reviewing.
fn recheck_by(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
    identities: Option<Want>,
    stop: &dyn Fn() -> bool,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    let mut still = Vec::new();
    // What a scan lists as `identities`' kind, as `Scan::add_from` decides
    // it. A stored sign-in: a test credential, or what its rule stores while
    // others cannot read the file. Worth reviewing: anything else.
    let kept = |rule: &Rule, hit: &Hit, shared: bool| match identities {
        Some(Want::Stored) => hit.low || (rule.kind == "inventory" && !shared),
        _ => !hit.low && (rule.kind == "review" || shared),
    };
    // The value alone, under no rule's name, as `Scan::add_from` asks for it.
    let valued = |hit: Hit, bytes: &[u8]| {
        let scope = identities.and_then(|_| scope_digest(&hit, bytes, digest));
        let value = hit.span.and_then(|s| bytes.get(s));
        (scope.or(hit.subject), value.map(|v| digest("", v, false)))
    };
    // One id can have a rule for each format its files come in. The rules
    // whose targets are this file, by its name or through a link, are the
    // ones the scan reads it with, and only they are asked. Where none is,
    // as for a file discovery found, every form is tried, and one that
    // cannot read the file means nothing is known.
    let same = || RULES.iter().filter(|r| r.id == rule);
    let reads = |r: &&Rule| {
        let mut targets = r.targets.iter();
        targets.any(|t| names(t, path) || linked(t, path, home))
    };
    // Asked once of each rule: a known folder may be listed to answer it.
    let mut forms: Vec<&Rule> = same().filter(reads).collect();
    if forms.is_empty() {
        forms = same().collect();
    }
    // A rule this build does not have reads nothing, so nothing is known.
    if forms.is_empty() {
        return None;
    }
    for rule in forms {
        match rule.matcher {
            // Presence alone is never a stored sign-in.
            Matcher::Present if identities == Some(Want::Stored) => continue,
            // Presence is the finding: say what is still there, by its name.
            Matcher::Present => {
                // A link on the way is followed as a scan follows it: into
                // the home folder only, and never as root. Past any other,
                // nothing is known.
                let at = match through_links(path, home) {
                    None => path.to_path_buf(),
                    Some(Ok(real)) if !is_root() => real,
                    Some(_) => return None,
                };
                // Past a link that leads nowhere, nothing is known.
                if crate::fsutil::dangling_link(&at, home).is_some() {
                    return None;
                }
                if std::fs::symlink_metadata(at).is_ok() {
                    let named = rule.targets.iter().filter_map(|t| match *t {
                        Target::Present(_, what) | Target::Extension(_, what)
                            if names(t, path) || linked(t, path, home) =>
                        {
                            Some((crate::rules::label(what), None))
                        }
                        _ => None,
                    });
                    let before = still.len();
                    still.extend(named);
                    // There, but at a place this rule does not look: its
                    // presence says nothing about what the item was.
                    if still.len() == before {
                        return None;
                    }
                } else if !crate::fsutil::checked_or_absent(path, mount, home) {
                    return None;
                }
                continue;
            }
            Matcher::Stream(test) => {
                let Some((file, len, shared)) = open_regular(path).ok()? else {
                    return crate::fsutil::checked_or_absent(path, mount, home).then_some(still);
                };
                if len > STREAM_MAX {
                    return None;
                }
                // As long as it was when opened, in pieces as the scan reads
                // it: one large file read whole could take longer than the
                // rechecks are given.
                let mut file = file.take(len);
                let mut buffer = vec![0u8; READ_PIECE];
                let mut carry = Vec::new();
                // Each value once, as the scan lists it.
                let mut seen = std::collections::HashSet::new();
                loop {
                    if stop() {
                        return None;
                    }
                    let read = file.read(&mut buffer).ok()?;
                    carry.extend_from_slice(buffer.get(..read)?);
                    if let Some(piece) = take_piece(&mut carry, read == 0) {
                        let wanted = |hit: &Hit| kept(rule, hit, shared);
                        for hit in test(&piece, 1).ok()?.into_iter().filter(wanted) {
                            if seen.insert(value_key(&hit, &piece)) {
                                still.push(valued(hit, &piece));
                            }
                        }
                    }
                    if read == 0 {
                        break;
                    }
                }
                continue;
            }
            _ => {}
        }
        let read = match rule.matcher {
            Matcher::Head(_) => read_head(path, HEADER),
            _ => read_config(path, CONFIG_MAX).and_then(|read| match read {
                Some(h) => settled(path, h),
                None => Ok(None),
            }),
        };
        let Some(h) = read.ok()? else {
            // Links and special files are not evidence of removal.
            return crate::fsutil::checked_or_absent(path, mount, home).then_some(still);
        };
        let hits = match rule.matcher {
            Matcher::Head(m) => m(&h.bytes).then(Hit::file).into_iter().collect(),
            Matcher::Whole { test, .. } => test(&h.bytes).ok()?,
            _ => Vec::new(),
        };
        let hits = hits.into_iter().filter(|hit| kept(rule, hit, h.shared));
        still.extend(hits.map(|hit| valued(hit, &h.bytes)));
    }
    Some(still)
}

/// Whether a target is this path: the place a rule knows, or a name it reads.
fn names(target: &Target, path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default();
    let inside = |dir: &str| path.parent().is_some_and(|p| p.ends_with(dir));
    match *target {
        Target::Discovery => false,
        Target::File(f) | Target::Present(f, _) | Target::Extension(f, _) => path.ends_with(f),
        Target::Dir(d) => inside(d),
        Target::Each(d, f) => {
            name == f
                && path
                    .parent()
                    .and_then(Path::parent)
                    .is_some_and(|p| p.ends_with(d))
        }
        Target::Name(_) => target.names(name),
        Target::Profiles(f) => name == f,
        Target::Tree(d) => path.ancestors().any(|a| a.ends_with(d)),
        Target::Repo(f) => name == f && inside(".git"),
    }
}

/// Whether a target is this path through a link: the known location is a
/// link, or is under one, that leads here.
fn linked(target: &Target, path: &Path, home: &Path) -> bool {
    let through = |at: &Path| match through_links(at, home) {
        Some(Ok(real)) => Some(real),
        _ => None,
    };
    let real = |at: &str| through(&home.join(at));
    // An entry of a known folder that is itself a link, which the scan
    // follows: the entry, or the named file in it.
    let entry = |d: &str, file: Option<&str>| {
        let dir = real(d).unwrap_or_else(|| home.join(d));
        let mut remaining = FOLDER_ENTRIES;
        list_dir(&dir, false, &mut remaining).is_ok_and(|listing| {
            listing.entries.iter().any(|(p, _)| {
                let at = file.map_or_else(|| p.clone(), |f| p.join(f));
                through(&at).is_some_and(|real| real == path)
            })
        })
    };
    match *target {
        Target::File(f) | Target::Present(f, _) => real(f).is_some_and(|real| real == path),
        Target::Dir(d) => {
            real(d).is_some_and(|real| path.parent() == Some(&real)) || entry(d, None)
        }
        Target::Each(d, f) => {
            real(d).is_some_and(|real| {
                path.file_name() == Some(f.as_ref())
                    && path.parent().and_then(Path::parent) == Some(&real)
            }) || entry(d, Some(f))
        }
        Target::Tree(d) => real(d).is_some_and(|real| path.starts_with(real)),
        _ => false,
    }
}
