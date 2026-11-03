//! Checking one file again outside a scan, to learn whether a review item is
//! still there.

use super::read::settled;
use super::{CONFIG_MAX, HEADER, STREAM_MAX};
use crate::fsutil::{list_dir, open_regular, read_config, read_head, through_links};
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
pub fn recheck_values(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    recheck_by(rule, path, home, mount, digest, false)
}

/// As `recheck_values`, with private registry-place identities instead of
/// display labels where available. Only for private review-state comparisons.
pub fn recheck_identities(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    recheck_by(rule, path, home, mount, digest, true)
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

fn recheck_by(
    rule: &str,
    path: &Path,
    home: &Path,
    mount: Option<u32>,
    digest: &dyn Fn(&str, &[u8], bool) -> String,
    identities: bool,
) -> Option<Vec<(Option<String>, Option<String>)>> {
    let mut still = Vec::new();
    // The value alone, under no rule's name, as `Scan::add_from` asks for it.
    let valued = |hit: Hit, bytes: &[u8]| {
        let scope = identities
            .then(|| scope_digest(&hit, bytes, digest))
            .flatten();
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
            // Presence is the finding: say what is still there, by its name.
            Matcher::Present => {
                if std::fs::symlink_metadata(path).is_ok() {
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
                let Some((mut file, len, _)) = open_regular(path).ok()? else {
                    return crate::fsutil::checked_or_absent(path, mount, home).then_some(still);
                };
                if len > STREAM_MAX {
                    return None;
                }
                // Rechecks are rare; reading it in one piece keeps this simple.
                // As long as it was when opened, as the scan reads it.
                let mut bytes = Vec::new();
                (&mut file).take(len).read_to_end(&mut bytes).ok()?;
                // Compared here, where the bytes are: nothing of them is kept.
                let value = |hit: &Hit| hit.span.clone().and_then(|s| bytes.get(s));
                let mut hits: Vec<Hit> = Vec::new();
                for hit in test(&bytes, 1).ok()? {
                    let seen = |h: &Hit| h.subject == hit.subject && value(h) == value(&hit);
                    if !hits.iter().any(seen) {
                        hits.push(hit);
                    }
                }
                still.extend(hits.into_iter().map(|hit| valued(hit, &bytes)));
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
        if rule.kind == "review" || h.shared {
            still.extend(hits.into_iter().map(|hit| valued(hit, &h.bytes)));
        }
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
        let mut remaining = 10_000;
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
