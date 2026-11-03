//! What a scan is given and runs as: the home folder, folders named or
//! skipped, the place a change is checked at, and whether it runs as root.

use super::EXCLUDED;
use crate::rules::{Target, RULES};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The home folder, which every scan includes.
pub fn home() -> Result<PathBuf, &'static str> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or("HOME is not set to an absolute path")?;
    // A home reached through a link (a relocated or network home) is scanned
    // at its real location, where no path component is a link.
    Ok(std::fs::canonicalize(&home).unwrap_or(home))
}

/// A folder named on the command line, as the scan sees it. The shell writes
/// `~/notes` with `HOME` as it is set, but a home reached through a link is
/// scanned where `home` resolved it, and through the link the path names
/// nothing the scan reads. So a path that begins with `HOME` as set begins
/// with the home folder instead. Only that prefix, which `home` resolved,
/// changes: no other link is followed.
pub fn named_folder(path: &OsStr, home: &Path) -> PathBuf {
    let given = std::env::var_os("HOME").map(PathBuf::from);
    in_home(Path::new(path), given.as_deref(), home)
}

pub(super) fn in_home(path: &Path, given: Option<&Path>, home: &Path) -> PathBuf {
    match given.map(|given| path.strip_prefix(given)) {
        Some(Ok(rest)) if rest.as_os_str().is_empty() => home.to_path_buf(),
        Some(Ok(rest)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

/// An extra folder to scan: made absolute, and never containing `..`.
pub fn selected_root(path: &OsStr) -> Result<PathBuf, &'static str> {
    let path = std::path::absolute(path).map_err(|_| "could not resolve selected path")?;
    if path.components().any(|c| c == Component::ParentDir) {
        return Err("selected paths must not contain '..'");
    }
    Ok(path)
}

/// What to check for a change at `p`. Inside a folder that discovery passes
/// over, `Scan::changed` reads only known locations and the files rules name
/// in a repository's `.git`, and checking the outermost such folder reads all
/// of those. So a build that writes thousands of files there is one change of
/// that folder. Where such a folder holds a known location, as
/// `Library/Caches` holds a tree of records, a change is folded only as far
/// as a folder that holds none, and one at or in the location is checked as
/// it is, so a change elsewhere does not read the location again. Any other
/// path is checked as it is.
pub fn change_at(home: &Path, p: &Path) -> PathBuf {
    let Ok(below) = p.strip_prefix(home) else {
        return p.to_path_buf();
    };
    // From `p` upwards, so the last match is the outermost.
    let Some(left_out) = below
        .ancestors()
        .filter(|a| EXCLUDED.iter().any(|name| a.ends_with(name)))
        .last()
    else {
        return p.to_path_buf();
    };
    let inside: Vec<&Path> = RULES
        .iter()
        .flat_map(|r| r.targets)
        .filter_map(|t| match *t {
            Target::File(at)
            | Target::Present(at, _)
            | Target::Dir(at)
            | Target::Each(at, _)
            | Target::Tree(at) => Some(Path::new(at)),
            _ => None,
        })
        .filter(|at| at.starts_with(left_out) && *at != left_out)
        .collect();
    if inside.iter().any(|at| below.starts_with(at)) {
        return p.to_path_buf();
    }
    let fold = below
        .ancestors()
        .take_while(|a| a.starts_with(left_out))
        .take_while(|a| !inside.iter().any(|at| at.starts_with(a)))
        .last();
    fold.map_or_else(|| p.to_path_buf(), |a| home.join(a))
}

/// A folder the person asks not to be checked: absolute, with no "..", and
/// never the home folder or a folder above it.
pub fn skipped_folder(path: &OsStr, home: &Path) -> Result<PathBuf, &'static str> {
    let path = selected_root(path)?;
    if home.starts_with(&path) {
        return Err("the home folder, or a folder above it, cannot be skipped");
    }
    Ok(path)
}
