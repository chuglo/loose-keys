//! Paths that are reported for presence alone and must stay unopened.

use super::{is_root, paths};
use crate::fsutil::{list_dir, through_links, FOLDER_ENTRIES};
use crate::rules::browser::CHROMIUM;
use crate::rules::{Target, RULES};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct Unopened {
    roots: HashSet<PathBuf>,
    existing_roots: bool,
    extensions: HashMap<PathBuf, Vec<&'static str>>,
    browsers: HashSet<PathBuf>,
    ids: HashSet<&'static str>,
}

impl Unopened {
    pub(super) fn at(home: &Path, stop: &dyn Fn() -> bool) -> Self {
        let mut unopened = Self::default();
        for rule in RULES {
            for target in rule.targets {
                match *target {
                    Target::Present(at, _) => {
                        let at = home.join(at);
                        if rule.id == "app.telegram.session" {
                            if let Some(session) = at.parent() {
                                unopened.protect(home, session);
                            }
                        }
                        unopened.protect(home, &at);
                    }
                    Target::Extension(id, _) => {
                        unopened.ids.insert(id);
                    }
                    _ => {}
                }
            }
        }
        for browser in CHROMIUM {
            if stop() {
                break;
            }
            let at = home.join(browser);
            unopened.browsers.insert(at.clone());
            let Some(browser) = real_location(home, &at) else {
                continue;
            };
            unopened.browsers.insert(browser.clone());
            if unopened.contains(&browser) {
                continue;
            }
            let mut remaining = FOLDER_ENTRIES;
            let Ok(listing) = list_dir(&browser, false, &mut remaining) else {
                continue;
            };
            let top = std::iter::once((browser, true));
            for (profile, is_dir) in top.chain(listing.entries) {
                if stop() {
                    return unopened;
                }
                // Listing gives directory types without following links.
                // No entry other than a folder or linked folder holds settings.
                let profile = if is_dir {
                    Some(profile)
                } else if is_link(&profile) {
                    real_location(home, &profile)
                } else {
                    None
                };
                let Some(profile) = profile else {
                    continue;
                };
                let Some(settings) = child_folder(home, &profile.join("Local Extension Settings"))
                else {
                    continue;
                };
                for &id in &unopened.ids {
                    if let Some(real) = child_folder(home, &settings.join(id)) {
                        unopened.extensions.entry(real).or_default().push(id);
                    }
                }
            }
        }
        unopened
    }

    fn protect(&mut self, home: &Path, at: &Path) {
        self.roots.insert(at.to_path_buf());
        if let Some(real) = real_location(home, at) {
            self.existing_roots = true;
            self.roots.insert(real);
        }
    }

    pub(super) fn contains(&self, path: &Path) -> bool {
        path.ancestors().any(|at| {
            self.roots.contains(at) || self.extensions.contains_key(at) || self.named_store(at)
        })
    }

    pub(super) fn protected_spelling(&self, path: &Path, home: &Path) -> Option<PathBuf> {
        if self.contains(path) {
            return Some(path.to_path_buf());
        }
        if self.existing_roots || !self.extensions.is_empty() {
            return paths::on_disk(path, home).filter(|on_disk| self.contains(on_disk));
        }
        None
    }

    pub(super) fn extension<'a>(&self, path: &'a Path, id: &str) -> Option<&'a Path> {
        path.ancestors().find(|at| {
            self.extensions
                .get(*at)
                .is_some_and(|ids| ids.contains(&id))
        })
    }

    fn named_store(&self, path: &Path) -> bool {
        let Some(id) = path.file_name().and_then(|id| id.to_str()) else {
            return false;
        };
        self.ids.contains(id)
            && path
                .parent()
                .filter(|s| {
                    s.file_name()
                        .is_some_and(|n| n == "Local Extension Settings")
                })
                .and_then(Path::parent)
                .is_some_and(|profile| {
                    self.browsers.contains(profile)
                        || profile.parent().is_some_and(|p| self.browsers.contains(p))
                })
    }
}

// The parent has already been resolved as a known location.
fn child_folder(home: &Path, at: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(at).ok()?;
    if meta.is_dir() {
        return paths::on_disk(at, home);
    }
    if meta.file_type().is_symlink() {
        let real = real_location(home, at)?;
        return std::fs::symlink_metadata(&real)
            .is_ok_and(|m| m.is_dir())
            .then_some(real);
    }
    None
}

fn is_link(at: &Path) -> bool {
    std::fs::symlink_metadata(at).is_ok_and(|m| m.file_type().is_symlink())
}

fn real_location(home: &Path, at: &Path) -> Option<PathBuf> {
    match through_links(at, home) {
        Some(Ok(real)) if !is_root() && !at.starts_with(&real) => Some(real),
        Some(_) => None,
        None => {
            std::fs::symlink_metadata(at).ok()?;
            paths::on_disk(at, home)
        }
    }
}
