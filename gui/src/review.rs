//! Local review state. Delivery never resolves a finding, and a
//! decision to set a finding aside never stops it being found: it is a label
//! on the item, applied when deciding what to bring to the person's attention.
use crate::fsutil;
use crate::report::{Finding, Report};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

#[derive(Clone, Deserialize, Serialize)]
pub struct Item {
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub revision: u64,
    pub rule: String,
    pub path: String,
    pub line: Option<usize>,
    pub title: String,
    pub explanation: String,
    pub reason: Option<String>,
    pub next_step: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub link: Option<String>,
    /// What the item concerns (profile, host, variable or token type). Never a value.
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub resolved_at: Option<String>,
    /// Always false. Builds that had "Remind me in a week" cannot read state
    /// without it, so it is still written; what they wrote is not read, and an
    /// item they snoozed is open.
    #[serde(default, skip_deserializing)]
    pub(crate) deferred: bool,
    /// Stable across restarts and pruning; what the app names an item by.
    #[serde(default)]
    pub id: u64,
    /// Keyed digest of the secret value alone: the same credential has the
    /// same one in every file. None for rules with no single value.
    #[serde(default)]
    pub secret: Option<String>,
    /// A count or similar that can change without this being a new item.
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    /// Whether group/other read mode bits are set on the file.
    #[serde(default)]
    pub shared: bool,
    /// Where the volume holding the file was mounted when it was last found,
    /// as `fsutil::mounted_at` counts it. None for an item listed before this
    /// was kept. Stays on this side, like the fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<u32>,
}

/// Why a person set a finding aside. All reasons except Kept concern the
/// value and follow it to every file. Kept concerns one place only.
#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    NotACredential,
    Testing,
    NoLongerWorks,
    // Retained for decisions saved before testing and no longer works split.
    TestOrRevoked,
    Kept,
    /// Listed by the organization's settings. About the place, like Kept,
    /// and never chosen by the person: `decide` refuses it.
    Expected,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct Decision {
    pub reason: Reason,
    /// The credential, for a decision about the value.
    #[serde(default)]
    pub secret: Option<String>,
    /// The place, for "kept", and for rules with no single value.
    pub rule: String,
    pub path: String,
    #[serde(default)]
    pub subject: Option<String>,
    /// What the place held when decided, where there is no `secret`.
    #[serde(default)]
    pub fingerprint: Option<String>,
    // What "kept" was agreed to: it ends if any of these gets worse.
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub shared: bool,
    #[serde(default)]
    pub severity: String,
    pub decided: String,
    pub decided_at: u64,
}

/// A folder the person asked not to be checked, as a `~/...` path.
#[derive(Clone, Deserialize, Serialize)]
pub struct Skip {
    pub path: String,
    pub added: String,
}

/// One entry of the organization's expected-findings list: a rule at a file.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Expected {
    pub rule: String,
    pub path: String,
}

/// How many of the organization's entries are honoured.
pub const MAX_EXPECTED: usize = 32;

/// A `~/...` path below the home folder, in plain components with no "..".
fn below_home(path: &str) -> bool {
    let mut parts = Path::new(path).components();
    parts.next() == Some(Component::Normal("~".as_ref()))
        && parts.clone().next().is_some()
        && parts.all(|part| matches!(part, Component::Normal(_)))
}

/// An entry of the organization's list that is honoured: a rule the scanner
/// has, at a plain file path below the home folder, no longer than a path
/// the report lists.
fn accepted(entry: &Expected) -> bool {
    loose_keys::rules::RULES.iter().any(|r| r.id == entry.rule)
        && entry.path.len() <= 4096
        && crate::plain(&entry.path)
        && below_home(&entry.path)
}

/// "Kept" is asked about again after this long, in the app, without an alert.
pub const RECONFIRM: u64 = 180 * 24 * 3600;
pub const MAX_ITEMS: usize = 4096;
/// The largest state the store saves or reads back.
const STORE_BYTES: usize = 8 * 1024 * 1024;
/// Where the app and its helper keep their state, inside the home folder:
/// where macOS apps keep their data, named for the app's bundle identifier.
pub const STATE_DIR: &str = "Library/Application Support/dev.loosekeys.desktop";
/// Where versions before it kept their state, in the home folder. Opening
/// the store moves it.
const OLD_STATE_DIR: &CStr = c".loose-keys-review";
/// Room for the items, as they are stored: three quarters of what the store
/// takes. A refused save loses every finding of that scan, so the list
/// counts as full before that. The rest is for decisions and settings,
/// which are limited by number and not measured.
const ITEM_BYTES: usize = STORE_BYTES / 4 * 3;

fn stored_size<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value).map_or(ITEM_BYTES, |json| json.len())
}
pub const MAX_SKIPS: usize = 32;
/// The scanner keeps this many distinct hits when it reads a file through
/// (`stream` in `src/scan.rs`), and no rule that tells values apart keeps
/// fewer for a file it reads whole. A report with that many for one file
/// may have left others out, and so may a fresh read of it.
const HITS_PER_FILE: usize = 50;

/// What reading an item's file again finds there now, as
/// `scan::recheck_values` gives it: the subject of each thing still found
/// and, where it has one value, that value's digest.
pub type Still = Vec<(Option<String>, Option<String>)>;

/// Said to a press on a row that was drawn for something else.
const CHANGED: &str =
    "That review item has changed since it was shown. Nothing was done; look at it again.";

fn rank(severity: &str) -> usize {
    ["high", "medium", "low"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(0)
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Review {
    pub items: Vec<Item>,
    #[serde(default)]
    pub monitoring: bool,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub key: Vec<u8>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub notified_revision: u64,
    #[serde(default)]
    pub attempts: u8,
    #[serde(default)]
    pub retry_at: u64,
    /// Written by the background agent; shown by the app.
    #[serde(default)]
    pub agent: Agent,
    #[serde(default)]
    pub next_id: u64,
    #[serde(default)]
    pub decisions: Vec<Decision>,
    #[serde(default)]
    pub skipped: Vec<Skip>,
    /// What the organization's settings list as expected, as `set_expected`
    /// checked it: decisions with `Reason::Expected`, applied for the place.
    #[serde(default)]
    pub expected: Vec<Decision>,
    /// Expected places the person moved back to review. Forgotten for a
    /// place the list no longer has, or that the person then decides on.
    #[serde(default)]
    pub returned: Vec<Expected>,
    /// A finding has been left out for lack of room, and no scan the person
    /// ran to its end has since found room on the list. `ingest` only sets it.
    #[serde(default)]
    pub full: bool,
    /// Show in Menu Bar turned off. The icon is shown unless the person
    /// turns it off. With `monitoring` it also puts the app in Login Items.
    #[serde(default)]
    pub menu_bar_off: bool,
}

/// What the background agent last did, and where its file-change history is.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Agent {
    pub pid: u32,
    pub started: Option<String>,
    pub last_check: Option<String>,
    /// When the last full pass over the home folder finished.
    pub baseline: Option<String>,
    pub baseline_at: u64,
    /// Folders the current full pass has not reached yet.
    pub left: usize,
    /// Changed files and folders checked since the agent started.
    pub changes: u64,
    pub error: Option<String>,
    /// The last file-change event handled, and the volume it belongs to.
    pub event_id: u64,
    pub volume: String,
    /// Places the last full pass listed as not checked, excluding slice limits.
    #[serde(default)]
    pub unread: usize,
    /// None in older state, which retained only the count.
    #[serde(default)]
    pub unread_places: Option<UnreadPlaces>,
}

pub const MAX_UNREAD: usize = 4096;
const UNREAD_BYTES: usize = 512 * 1024;

/// A bounded snapshot, published with the completed pass's timestamp.
/// Contains paths and fixed reasons only, never bytes from scanned files.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct UnreadPlaces {
    pub places: std::collections::BTreeSet<(String, String)>,
    pub truncated: bool,
}

impl UnreadPlaces {
    pub fn record(&mut self, report: &Report) {
        let mut used = stored_size(self);
        for gap in report
            .not_checked
            .iter()
            .filter(|g| g.reason != "scan-limit")
        {
            let entry = (gap.path.clone(), gap.reason.to_owned());
            if self.places.contains(&entry) {
                continue;
            }
            let size = stored_size(&entry) + 1;
            if self.places.len() >= MAX_UNREAD || used + size > UNREAD_BYTES {
                self.truncated = true;
                continue;
            }
            used += size;
            self.places.insert(entry);
        }
    }

    fn within_bounds(&self) -> bool {
        self.places.len() <= MAX_UNREAD && stored_size(self) <= UNREAD_BYTES
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq)]
pub enum Delivery {
    Inline,
    Native,
    None,
}

#[cfg(test)]
pub fn delivery(new: bool, persisted: bool, foreground: bool, authorized: bool) -> Delivery {
    if !new {
        Delivery::None
    } else if foreground {
        Delivery::Inline
    } else if persisted && authorized {
        Delivery::Native
    } else {
        Delivery::None
    }
}

/// Whether a fresh read shows that an item's value has left its place:
/// nothing of its kind is there, or everything of its kind that is there
/// has a value, and none has this one. A read that returns as many hits as
/// the scanner keeps for one file may have left others out, of this kind as
/// of any other, and cannot tell either. Nor can an item stored with no
/// value be told from what is of its kind there now.
fn absent(item: &Item, still: &Still) -> bool {
    if still.len() >= HITS_PER_FILE {
        return false;
    }
    let mut here = still
        .iter()
        .filter(|(subject, _)| *subject == item.subject)
        .peekable();
    here.peek().is_none()
        || (item.secret.is_some()
            && here.all(|(_, value)| value.is_some() && *value != item.secret))
}

impl Review {
    /// Whether an item is still what the front end drew when it was given
    /// `revision` for it. The front end names an item by its id, and an id
    /// stays with its place when the value there is replaced: the revision
    /// rises then, as it does whenever the item is news again. So a press on
    /// a row drawn for one value is not taken as a decision about another
    /// the person has not seen. Asked of the state as it was just loaded,
    /// with the store locked. An item that is no longer listed is each
    /// action's own to answer for.
    pub fn as_shown(&self, id: u64, revision: u64) -> Result<(), String> {
        match self.items.iter().find(|i| i.id == id) {
            Some(item) if item.revision != revision => Err(CHANGED.into()),
            _ => Ok(()),
        }
    }

    /// Give every item an id. State written before ids existed has none.
    pub fn number(&mut self) {
        for item in &mut self.items {
            if item.id == 0 {
                self.next_id += 1;
                item.id = self.next_id;
            }
        }
    }

    /// The other places the same credential is stored, plus this one.
    fn copies(&self, id: u64) -> Vec<usize> {
        let Some(at) = self.items.iter().position(|i| i.id == id) else {
            return Vec::new();
        };
        let secret = self.items[at].secret.clone();
        (0..self.items.len())
            .filter(|n| *n == at || (secret.is_some() && self.items[*n].secret == secret))
            .collect()
    }

    /// The decision that sets this item aside, if one applies now. Where the
    /// place was kept and the value in it was also decided on, it is the one
    /// about the value: that is what the person said of this very credential.
    pub fn decision(&self, item: &Item, now: u64) -> Option<&Decision> {
        let mut applying = self.decisions.iter().chain(&self.expected).filter(|d| {
            let place = d.rule == item.rule && d.path == item.path && d.subject == item.subject;
            match d.reason {
                // The organization's: the rule at the file, whatever it concerns.
                Reason::Expected => d.rule == item.rule && d.path == item.path,
                // About the value: wherever it is, and only while it is that value.
                Reason::NotACredential
                | Reason::Testing
                | Reason::NoLongerWorks
                | Reason::TestOrRevoked => match &d.secret {
                    Some(secret) => item.secret.as_ref() == Some(secret),
                    None => place && d.fingerprint == item.fingerprint,
                },
                // About the place: a rotated value of the same kind stays
                // quiet, but not anything worse than what was agreed to.
                Reason::Kept => {
                    place
                        && d.token_type == item.token_type
                        && (d.shared || !item.shared)
                        && rank(&item.severity) >= rank(&d.severity)
                        && now < d.decided_at.saturating_add(RECONFIRM)
                }
            }
        });
        let first = applying.next()?;
        Some(match first.reason {
            Reason::Kept => applying
                .find(|d| !matches!(d.reason, Reason::Kept | Reason::Expected))
                .unwrap_or(first),
            _ => first,
        })
    }

    /// Take in the organization's list. Entries of another shape are not
    /// honoured, and a place the person moved back to review stays open
    /// until the list no longer has it.
    pub fn set_expected(&mut self, list: Vec<Expected>) {
        (self.expected, self.returned) = self.planned(list);
    }

    /// Whether `set_expected` with this list would change anything: the
    /// window sends the list each time the app comes to the front.
    pub fn expected_changes(&self, list: &[Expected]) -> bool {
        self.planned(list.to_vec()) != (self.expected.clone(), self.returned.clone())
    }

    /// What `set_expected` would store for this list.
    fn planned(&self, list: Vec<Expected>) -> (Vec<Decision>, Vec<Expected>) {
        let mut kept: Vec<Expected> = Vec::new();
        for entry in list {
            if kept.len() == MAX_EXPECTED {
                break;
            }
            if accepted(&entry) && !kept.contains(&entry) {
                kept.push(entry);
            }
        }
        let returned: Vec<Expected> = self
            .returned
            .iter()
            .filter(|r| kept.contains(r))
            .cloned()
            .collect();
        let expected = kept
            .into_iter()
            .filter(|e| !returned.contains(e))
            .map(|e| Decision {
                reason: Reason::Expected,
                secret: None,
                rule: e.rule,
                path: e.path,
                subject: None,
                fingerprint: None,
                token_type: None,
                shared: false,
                severity: String::new(),
                decided: "organization".into(),
                decided_at: 0,
            })
            .collect();
        (expected, returned)
    }

    /// Set an item aside for a reason. Replaces any earlier decision on it,
    /// and for a reason about the value, on every other copy of it too.
    pub fn decide(
        &mut self,
        id: u64,
        reason: Reason,
        now: u64,
        stamp: String,
    ) -> Result<(), String> {
        if reason == Reason::Expected {
            return Err("That reason is set by your organization's settings.".into());
        }
        let item = self
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or("That review item is no longer available.")?
            .clone();
        self.forget(&item);
        self.returned
            .retain(|r| !(r.rule == item.rule && r.path == item.path));
        let value = reason != Reason::Kept;
        if value {
            // About the value, so about every place it is in: a place that
            // was kept must not go on saying the credential is real.
            for n in self.copies(id) {
                let copy = self.items[n].clone();
                self.forget(&copy);
            }
        }
        if self.decisions.len() >= MAX_ITEMS {
            return Err(
                "Too many findings are set aside. Move some back to Worth Reviewing.".into(),
            );
        }
        self.decisions.push(Decision {
            reason,
            secret: item.secret.clone().filter(|_| value),
            rule: item.rule,
            path: item.path,
            subject: item.subject,
            fingerprint: item.fingerprint,
            token_type: item.token_type,
            shared: item.shared,
            severity: item.severity,
            decided: stamp,
            decided_at: now,
        });
        Ok(())
    }

    /// Remove the person's decisions that set this item aside. The
    /// organization's list is left as it is.
    fn forget(&mut self, item: &Item) {
        self.decisions.retain(|d| {
            let place = d.rule == item.rule && d.path == item.path && d.subject == item.subject;
            match &d.secret {
                Some(secret) => item.secret.as_ref() != Some(secret),
                None => !place,
            }
        });
    }

    /// Move to Worth Reviewing: remove whatever sets this item aside, the
    /// person's decision or the organization's entry, which is then kept as
    /// returned so the list sent again does not set it aside once more.
    pub fn undo(&mut self, id: u64) {
        let Some(item) = self.items.iter().find(|i| i.id == id).cloned() else {
            return;
        };
        self.forget(&item);
        let before = self.expected.len();
        self.expected
            .retain(|d| !(d.rule == item.rule && d.path == item.path));
        if self.expected.len() < before {
            let pair = Expected {
                rule: item.rule,
                path: item.path,
            };
            if !self.returned.contains(&pair) {
                self.returned.push(pair);
            }
        }
    }

    /// Whether this item should be brought to the person's attention now.
    pub fn alerting(&self, item: &Item, now: u64) -> bool {
        !item.resolved
            && item.revision > self.notified_revision
            && self.decision(item, now).is_none()
    }

    /// The folders the person asked not to be checked, as `skip_folder` adds
    /// them: a folder below the home, in a plain name, with no "..", and no
    /// more of them than it allows. The store is a file other programs can
    /// edit, and an entry of another shape, such as "/", was not put there
    /// by this app: it is not honoured. It stays listed, where it can be
    /// seen and removed.
    pub fn honoured_skips(&self) -> impl Iterator<Item = &Skip> {
        let added = |skip: &&Skip| crate::plain(&skip.path) && below_home(&skip.path);
        self.skipped.iter().filter(added).take(MAX_SKIPS)
    }

    /// Whether a path is inside a folder the person asked not to be checked.
    pub fn skips(&self, path: &str) -> bool {
        self.honoured_skips()
            .any(|s| Path::new(path).starts_with(&s.path))
    }

    /// Whether another finding would fit: fewer open items than the limit,
    /// and space for one more as large as the largest of them. Fixed items
    /// do not count, because `ingest` drops them when it needs their room.
    pub fn has_room(&self) -> bool {
        let sizes: Vec<usize> = self
            .items
            .iter()
            .filter(|i| !i.resolved)
            .map(stored_size)
            .collect();
        // As a stored list: each item, a comma between two, and the brackets.
        let used = sizes.iter().sum::<usize>() + sizes.len() + 1;
        // With the allowance `ingest` makes for a new item's two numbers.
        let largest = sizes.iter().copied().max().unwrap_or(0) + 48;
        sizes.len() < MAX_ITEMS && used + largest <= ITEM_BYTES
    }

    pub fn ingest(&mut self, report: &Report) -> bool {
        self.number();
        let mut new = false;
        // Measured when the first new finding arrives, and once more if room is made.
        let mut bytes: Option<usize> = None;
        let mut made_room = false;
        let findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.kind == "review")
            .collect();
        // One place can hold several credentials of one kind: two tokens in
        // one session record are two findings with the same rule, path and
        // subject. Each is its own item, known by its value. A finding goes
        // to the item that holds its value. Failing that, it takes an item at
        // its place that no finding of this report claims and whose value is
        // gone, which is a value changed in place. Failing that, it is a new
        // item. The items claimed by value are settled first, so that a new
        // value met earlier in the report does not take the item of one that
        // is still there.
        //
        // That a report leaves a value out does not show the value is gone:
        // the report says what its scan read, and an older scan can be saved
        // after a newer one. So the item taken is one already marked fixed,
        // which `resolve` does on a fresh read (`merge` asks it first), or
        // one stored with no value to lose. An open item keeps its value, and
        // what was decided about another value cannot come to cover it.
        let place =
            |i: &Item, f: &Finding| i.rule == f.rule && i.path == f.path && i.subject == f.subject;
        let mut claimed: std::collections::HashSet<u64> = self
            .items
            .iter()
            .filter(|i| {
                i.secret.is_some() && findings.iter().any(|f| place(i, f) && f.secret == i.secret)
            })
            .map(|i| i.id)
            .collect();
        for f in findings {
            let at = self
                .items
                .iter()
                .position(|i| f.secret.is_some() && place(i, f) && i.secret == f.secret)
                // A finding with no value to go by takes the item at its place.
                .or_else(|| {
                    self.items.iter().position(|i| {
                        let free = !claimed.contains(&i.id) && (i.resolved || i.secret.is_none());
                        place(i, f) && (f.secret.is_none() || free)
                    })
                });
            if let Some(item) = at.map(|at| &mut self.items[at]) {
                claimed.insert(item.id);
                // Where the value itself is known, only its changing counts:
                // another line of the same file changing does not. Old shipped
                // state has no digest; establish its baseline silently.
                let differs = match (&item.secret, &f.secret) {
                    (Some(old), Some(now)) => old != now,
                    _ => {
                        item.fingerprint.is_some()
                            && f.fingerprint.is_some()
                            && item.fingerprint != f.fingerprint
                    }
                };
                let changed = item.resolved || differs || (f.shared && !item.shared);
                // Another value taking the item was first seen now.
                if matches!((&item.secret, &f.secret), (Some(old), Some(now)) if old != now) {
                    item.first_seen = Some(report.generated_at.clone());
                }
                if changed {
                    self.revision = self.revision.saturating_add(1);
                    item.revision = self.revision;
                    new = true;
                }
                item.fingerprint = f.fingerprint.clone();
                item.secret = f.secret.clone();
                item.detail = f.detail.clone();
                item.token_type = f.token_type.map(str::to_string);
                item.shared = f.shared;
                // A finding that could not tell leaves what was known.
                item.mount = f.mount.or(item.mount);
                item.resolved = false;
                item.resolved_at = None;
                item.line = f.line;
                item.title = f.title.into();
                item.explanation = f.explanation.into();
                item.reason = f.reason.clone();
                item.next_step = f.next_step.map(str::to_string);
                item.severity = f.severity.into();
                item.steps = f.steps.iter().map(|s| s.to_string()).collect();
                item.link = f.link.map(str::to_string);
                continue;
            }
            let mut item = Item {
                fingerprint: f.fingerprint.clone(),
                resolved: false,
                // The revision and id are given once it is known to fit.
                revision: 0,
                rule: f.rule.into(),
                path: f.path.clone(),
                line: f.line,
                title: f.title.into(),
                explanation: f.explanation.into(),
                reason: f.reason.clone(),
                next_step: f.next_step.map(str::to_string),
                severity: f.severity.into(),
                steps: f.steps.iter().map(|s| s.to_string()).collect(),
                link: f.link.map(str::to_string),
                subject: f.subject.clone(),
                first_seen: Some(report.generated_at.clone()),
                resolved_at: None,
                deferred: false,
                id: 0,
                secret: f.secret.clone(),
                detail: f.detail.clone(),
                token_type: f.token_type.map(str::to_string),
                shared: f.shared,
                mount: f.mount,
            };
            // Its two numbers are not known yet; allow for their digits.
            let size = stored_size(&item) + 48;
            let mut used = *bytes.get_or_insert_with(|| stored_size(&self.items));
            let fits = |count: usize, used: usize| count < MAX_ITEMS && used + size <= ITEM_BYTES;
            // Make room by dropping items already fixed. If that is not
            // enough, say so instead of leaving findings out silently.
            if !fits(self.items.len(), used) && !made_room {
                self.items.retain(|i| !i.resolved);
                used = stored_size(&self.items);
                made_room = true;
            }
            if !fits(self.items.len(), used) {
                // Set here and never cleared here. A report can be one slice
                // of the agent's pass or one batch of changed files, and a
                // finding of its own that fits says nothing about one left
                // out before. The app's scan clears this for a report of
                // everything, and then what is decided here stands.
                self.full = true;
                bytes = Some(used);
                continue;
            }
            // Another copy of a credential already on the list is not news.
            // A copy the person keeps where it is does not count: "kept"
            // covers that place and nowhere else. Nor does a copy at a place
            // the organization expects, for the same reason.
            let kept = |i: &Item| {
                self.decisions.iter().any(|d| {
                    d.reason == Reason::Kept
                        && d.rule == i.rule
                        && d.path == i.path
                        && d.subject == i.subject
                }) || self
                    .expected
                    .iter()
                    .any(|d| d.rule == i.rule && d.path == i.path)
            };
            let known = f.secret.as_ref().and_then(|secret| {
                self.items
                    .iter()
                    .find(|i| !i.resolved && i.secret.as_ref() == Some(secret) && !kept(i))
                    .map(|i| i.revision)
            });
            match known {
                Some(revision) => item.revision = revision,
                None => {
                    new = true;
                    self.revision = self.revision.saturating_add(1);
                    item.revision = self.revision;
                }
            }
            self.next_id += 1;
            item.id = self.next_id;
            claimed.insert(item.id);
            self.items.push(item);
            bytes = Some(used + size);
        }
        if new {
            self.attempts = 0;
            self.retry_at = 0;
        }
        new
    }

    pub fn pending(&self, now: u64) -> bool {
        self.attempts < 3
            && now >= self.retry_at
            && self.items.iter().any(|i| self.alerting(i, now))
    }

    /// Take in what a check found: `resolve`, then `ingest`. In that order a
    /// value changed in place is one item, changed: the old value is marked
    /// fixed on a fresh read, and the new one then takes its item.
    pub fn merge(&mut self, report: &Report, recheck: impl Fn(&Item) -> Option<Still>) -> bool {
        self.resolve(report, recheck);
        self.ingest(report)
    }

    /// Mark items resolved when their own file was checked again and no longer
    /// matches. This does not depend on how much of the home the scan covered.
    /// `recheck` returns what is found at an item's path now, or None when
    /// the file could not be checked. Only that marks an item fixed, never
    /// the report: a report says what its scan read, and it can be saved
    /// after a later check of the same file has been.
    pub fn resolve(&mut self, report: &Report, recheck: impl Fn(&Item) -> Option<Still>) {
        // The values the report holds at each place, and how much it holds
        // for each file.
        let mut seen: std::collections::HashMap<_, Vec<Option<&str>>> = Default::default();
        let mut hits: std::collections::HashMap<&str, usize> = Default::default();
        for f in report.findings.iter().filter(|f| f.kind == "review") {
            seen.entry((f.rule, f.path.as_str(), f.subject.as_deref()))
                .or_default()
                .push(f.secret.as_deref());
            *hits.entry(f.path.as_str()).or_default() += 1;
        }
        // The places this scan was asked to read and could not: a drive that
        // is not connected, a share that is not mounted. A file under one is
        // not there either, and that is not the file having been removed. A
        // place the scan was stopped in is not one of these: it is there, and
        // a file in it can be looked at.
        let unread: Vec<&str> = report
            .coverage
            .iter()
            .flat_map(|c| &c.roots)
            .filter(|root| {
                report.not_checked.iter().any(|g| {
                    g.path == **root && matches!(g.reason, "unreadable" | "permission-denied")
                })
            })
            .map(String::as_str)
            .collect();
        let skipped: Vec<bool> = self.items.iter().map(|i| self.skips(&i.path)).collect();
        for (i, skipped) in self.items.iter_mut().zip(skipped) {
            // Nothing is read in a folder the person asked not to be checked.
            if i.resolved || skipped {
                continue;
            }
            if let Some(values) =
                seen.get(&(i.rule.as_str(), i.path.as_str(), i.subject.as_deref()))
            {
                // The file was read and had something of this kind. A value
                // the report leaves out may be gone from it, unless the
                // report cannot tell: a finding with no value to compare, a
                // file it says it did not finish, or as many hits for the
                // file as the scanner keeps.
                let left_out = i.secret.is_some()
                    && values
                        .iter()
                        .all(|v| v.is_some() && *v != i.secret.as_deref())
                    && hits[i.path.as_str()] < HITS_PER_FILE
                    && !report.not_checked.iter().any(|g| g.path == i.path);
                // Whether it is gone is asked of the file as it is now, and
                // of its values: the others of its kind are still there.
                if left_out && recheck(i).is_some_and(|still| absent(i, &still)) {
                    i.resolved = true;
                    i.resolved_at = Some(report.generated_at.clone());
                }
                continue;
            }
            if unread
                .iter()
                .any(|root| Path::new(&i.path).starts_with(root))
            {
                continue;
            }
            // The report has nothing at this place, and may not have come by
            // the file. Asked of the file's values here too: another value
            // of its kind there does not keep this one open.
            if recheck(i).is_some_and(|still| absent(i, &still)) {
                i.resolved = true;
                i.resolved_at = Some(report.generated_at.clone());
            }
        }
    }

    /// A notification was delivered, for everything found up to `revision`.
    /// The count of attempts starts afresh: it is for deliveries that fail.
    pub fn delivered(&mut self, revision: u64) {
        self.notified_revision = self.notified_revision.max(revision);
        self.attempts = 0;
        self.retry_at = 0;
    }

    pub fn attempted(&mut self, now: u64) {
        self.attempts = self.attempts.saturating_add(1).min(3);
        self.retry_at = now.saturating_add(match self.attempts {
            1 => 60,
            2 => 300,
            _ => 900,
        });
    }
}

/// The app and the background agent share this store. Each holds it open for
/// as long as it runs and takes the lock only while reading or changing it.
pub struct Store {
    dir: File,
    /// The file lock excludes other processes; this excludes other threads.
    local: std::sync::Mutex<()>,
}

struct Locked<'a>(&'a File);
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The folder `name` in `parent`, opened without following a link. With
/// `make`, it is made first if missing, private; without, None if missing.
fn folder(parent: &File, name: &CStr, make: bool) -> Result<Option<File>, String> {
    // SAFETY: an open folder and a NUL-terminated name.
    if make
        && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err("Cannot create local review storage.".into());
    }
    // SAFETY: an open folder and a NUL-terminated name. O_NOFOLLOW refuses a
    // link, and O_DIRECTORY anything that is not a folder.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if !make && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err("Cannot open local review storage.".into())
        };
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

/// Whether anything is at `name` in `dir`. A link counts and is not followed.
fn present(dir: &File, name: &CStr) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an open folder, a NUL-terminated name and room for one stat.
    unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        ) == 0
    }
}

/// Whether `name` in `dir` is a regular file of this user's that no one else
/// can read and that has no other name. A link is not followed.
fn private_file(dir: &File, name: &CStr) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: an open folder, a NUL-terminated name and room for one stat,
    // read only once fstatat has filled it.
    unsafe {
        if libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        ) != 0
        {
            return false;
        }
        let stat = stat.assume_init();
        stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == libc::geteuid()
            && stat.st_mode & 0o077 == 0
            && stat.st_nlink == 1
    }
}

impl Store {
    fn lock(&self, kind: libc::c_int) -> Result<Locked<'_>, String> {
        if unsafe { libc::flock(self.dir.as_raw_fd(), kind) } != 0 {
            return Err("Cannot lock local review storage.".into());
        }
        Ok(Locked(&self.dir))
    }

    /// One thread at a time. The mutex holds no data, so a holder that
    /// panicked leaves nothing in it to distrust: what it was changing was
    /// never saved.
    fn alone(&self) -> std::sync::MutexGuard<'_, ()> {
        self.local.lock().unwrap_or_else(|held| held.into_inner())
    }

    /// The current state, never a half-written one.
    pub fn read(&self) -> Result<Review, String> {
        let _local = self.alone();
        let _lock = self.lock(libc::LOCK_SH)?;
        self.load()
    }

    /// Load, change and save as one step that no other process or thread can
    /// interleave with. Nothing is saved if `change` fails.
    pub fn update<T>(
        &self,
        change: impl FnOnce(&mut Review) -> Result<T, String>,
    ) -> Result<(Review, T), String> {
        let _local = self.alone();
        let _lock = self.lock(libc::LOCK_EX)?;
        let mut review = self.load()?;
        if review.key.is_empty() {
            review.key = vec![0; 32];
            unsafe {
                libc::arc4random_buf(review.key.as_mut_ptr().cast(), 32);
            }
        }
        review.number();
        let out = change(&mut review)?;
        self.save(&review)?;
        Ok((review, out))
    }

    /// The store in `home`, at `STATE_DIR`. Each folder on the way is made if
    /// it is missing and opened without following a link.
    pub fn open(home: &Path) -> Result<Self, String> {
        let home = fsutil::open_directory(home).map_err(str::to_string)?;
        let mut dir = None;
        for name in STATE_DIR.split('/') {
            let name = CString::new(name).expect("STATE_DIR holds no NUL");
            let next = folder(dir.as_ref().unwrap_or(&home), &name, true)?
                .ok_or("Cannot create local review storage.")?;
            dir = Some(next);
        }
        let dir = dir.expect("STATE_DIR names a folder");
        let meta = dir.metadata().map_err(|e| e.to_string())?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("Local review storage must be private and owned by this user.".into());
        }
        let store = Self {
            dir,
            local: std::sync::Mutex::new(()),
        };
        store.move_old(&home)?;
        Ok(store)
    }

    /// Versions before this one kept the state in `OLD_STATE_DIR`. It is moved
    /// here once, holding both folders' locks, unless there is state here
    /// already; the emptied old folder is removed. An old helper still running
    /// keeps writing to that folder, now removed, until it is restarted.
    fn move_old(&self, home: &File) -> Result<(), String> {
        // Anything there but a folder of this user's is left as it is.
        let Ok(Some(old)) = folder(home, OLD_STATE_DIR, false) else {
            return Ok(());
        };
        let meta = old.metadata().map_err(|e| e.to_string())?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Ok(());
        }
        let _local = self.alone();
        let _lock = self.lock(libc::LOCK_EX)?;
        // SAFETY: `old` is an open folder for the whole call; its lock is
        // released when it is closed.
        if unsafe { libc::flock(old.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("Cannot lock local review storage.".into());
        }
        let state = c"state.json";
        if present(&self.dir, state) || !private_file(&old, state) {
            return Ok(());
        }
        // SAFETY: two open folders and a NUL-terminated name; the file itself
        // is moved, not anything it might point to.
        let moved = unsafe {
            libc::renameat(
                old.as_raw_fd(),
                state.as_ptr(),
                self.dir.as_raw_fd(),
                state.as_ptr(),
            )
        };
        if moved != 0 {
            return Err("Cannot move local review storage to its new folder.".into());
        }
        // SAFETY: an open folder and a NUL-terminated name. Removal fails,
        // and is left, if anything else is in the folder.
        unsafe { libc::unlinkat(home.as_raw_fd(), OLD_STATE_DIR.as_ptr(), libc::AT_REMOVEDIR) };
        Ok(())
    }

    pub fn load(&self) -> Result<Review, String> {
        let name = CString::new("state.json").unwrap();
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(Review::default())
            } else {
                Err("Cannot read local review storage.".into())
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata().map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || m.len() > STORE_BYTES as u64
        {
            return Err(
                "Local review storage is not a private regular file within the size limit.".into(),
            );
        }
        let mut json = String::new();
        file.take(STORE_BYTES as u64 + 1)
            .read_to_string(&mut json)
            .map_err(|e| e.to_string())?;
        let review: Review = serde_json::from_str(&json)
            .map_err(|_| "Local review storage could not be decoded.")?;
        if review.items.len() > 4096
            || (!review.key.is_empty() && review.key.len() != 32)
            || (review.key.is_empty() && review.items.iter().any(|i| i.fingerprint.is_some()))
            || review
                .agent
                .unread_places
                .as_ref()
                .is_some_and(|p| !p.within_bounds())
            || review.attempts > 3
        {
            return Err("Local review storage exceeds monitoring bounds.".into());
        }
        Ok(review)
    }

    pub fn save(&self, review: &Review) -> Result<(), String> {
        if review.items.len() > 4096
            || review
                .agent
                .unread_places
                .as_ref()
                .is_some_and(|p| !p.within_bounds())
        {
            return Err("Local review storage reached its item limit.".into());
        }
        let json = serde_json::to_vec(review).map_err(|e| e.to_string())?;
        if json.len() > STORE_BYTES {
            return Err("Local review storage reached its size limit.".into());
        }
        let name = CString::new("state.tmp").unwrap();
        let dest = CString::new("state.json").unwrap();
        // Callers hold the store lock, which excludes another writer. Recover only our private
        // regular temporary file after an interrupted atomic replacement.
        let stale = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if stale >= 0 {
            let file = unsafe { File::from_raw_fd(stale) };
            let meta = file
                .metadata()
                .map_err(|_| "Cannot inspect interrupted review storage.")?;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
                || meta.nlink() != 1
            {
                return Err("Interrupted review storage is not a private regular file.".into());
            }
            if unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err("Cannot recover interrupted review storage.".into());
            }
        } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Err("Cannot inspect interrupted review storage.".into());
        }
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("Cannot save local review storage.".into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = file
            .write_all(&json)
            .and_then(|_| file.sync_all())
            .and_then(|_| {
                if unsafe {
                    libc::renameat(
                        self.dir.as_raw_fd(),
                        name.as_ptr(),
                        self.dir.as_raw_fd(),
                        dest.as_ptr(),
                    )
                } == 0
                {
                    self.dir.sync_all()
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result.map_err(|_| "Cannot save local review storage.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, NotChecked};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn report(findings: &[(&str, &str)]) -> Report {
        Report {
            schema: "loose-keys/report/1",
            tool_version: "0.1.0",
            generated_at: "synthetic".into(),
            status: "partial",
            context: "user",
            coverage: None,
            findings: findings
                .iter()
                .map(|(kind, path)| Finding {
                    fingerprint: None,
                    rule: "export.password-csv",
                    category: "password-export",
                    kind: if *kind == "review" {
                        "review"
                    } else {
                        "inventory"
                    },
                    path: (*path).into(),
                    title: "Synthetic file",
                    explanation: "Synthetic reason.",
                    next_step: Some("Confirm why this file is stored here before you change it."),
                    ..Finding::default()
                })
                .collect(),
            not_checked: vec![NotChecked {
                path: "~/unreadable".into(),
                reason: "permission-denied",
            }],
        }
    }

    #[test]
    fn unread_snapshot_is_bounded_and_marks_omissions() {
        let mut r = report(&[]);
        r.not_checked = (0..MAX_UNREAD)
            .map(|i| NotChecked {
                path: format!("~/synthetic-{i}"),
                reason: "unreadable",
            })
            .collect();
        let mut snapshot = UnreadPlaces::default();
        snapshot.record(&r);
        assert_eq!(snapshot.places.len(), MAX_UNREAD);
        assert!(!snapshot.truncated);
        // Repeated slices must neither duplicate entries nor imply omissions.
        snapshot.record(&r);
        assert!(!snapshot.truncated);
        r.not_checked = vec![NotChecked {
            path: "~/one-more".into(),
            reason: "unreadable",
        }];
        snapshot.record(&r);
        assert_eq!(snapshot.places.len(), MAX_UNREAD);
        assert!(snapshot.truncated);
        assert!(snapshot.within_bounds());

        let mut snapshot = UnreadPlaces::default();
        r.not_checked = vec![NotChecked {
            path: "x".repeat(UNREAD_BYTES),
            reason: "unreadable",
        }];
        snapshot.record(&r);
        assert!(snapshot.places.is_empty());
        assert!(snapshot.truncated);
        assert!(snapshot.within_bounds());
    }

    #[test]
    fn old_unread_count_has_no_invented_details() {
        let mut saved = serde_json::to_value(Agent::default()).unwrap();
        saved.as_object_mut().unwrap().remove("unread_places");
        saved["unread"] = 403.into();
        let old: Agent = serde_json::from_value(saved).unwrap();
        assert_eq!(old.unread, 403);
        assert!(old.unread_places.is_none());
    }

    /// A report of review findings: (rule, path, subject, secret).
    fn found(findings: &[(&'static str, &str, Option<&str>, Option<&str>)]) -> Report {
        let mut r = report(&[]);
        r.findings = findings
            .iter()
            .map(|(rule, path, subject, secret)| Finding {
                rule,
                category: "developer-cloud",
                kind: "review",
                severity: "high",
                title: "Synthetic finding",
                explanation: "Synthetic reason.",
                path: (*path).into(),
                subject: subject.map(str::to_string),
                secret: secret.map(str::to_string),
                fingerprint: Some(format!("file-digest-of-{path}")),
                token_type: Some("Synthetic token"),
                ..Finding::default()
            })
            .collect();
        r
    }

    fn seen(state: &mut Review) {
        state.notified_revision = state.revision;
    }

    /// What reading a file again finds when it has not changed since the
    /// report's scan read it: what the report lists there.
    fn as_reported(report: &Report) -> impl Fn(&Item) -> Option<Still> + '_ {
        |item| {
            let there = report.findings.iter();
            let there = there.filter(|f| f.rule == item.rule && f.path == item.path);
            Some(
                there
                    .map(|f| (f.subject.clone(), f.secret.clone()))
                    .collect(),
            )
        }
    }

    /// Save a report as the app and the helper do, for a file that has not
    /// changed since it was read.
    fn checked(state: &mut Review, report: &Report) -> bool {
        state.merge(report, as_reported(report))
    }

    #[test]
    fn a_harmless_value_is_set_aside_wherever_it_appears() {
        for (reason, name) in [
            (Reason::NotACredential, "not-a-credential"),
            (Reason::Testing, "testing"),
            (Reason::NoLongerWorks, "no-longer-works"),
            (Reason::TestOrRevoked, "test-or-revoked"),
        ] {
            let mut state = Review::default();
            let token = (
                "secret.service-token",
                "~/app/.env",
                Some("Test token"),
                Some("digest-a"),
            );
            assert!(state.ingest(&found(&[token])));
            let id = state.items[0].id;
            state.decide(id, reason, 100, "then".into()).unwrap();
            let saved = serde_json::to_string(&state).unwrap();
            let state_again: Review = serde_json::from_str(&saved).unwrap();
            assert_eq!(state_again.decisions[0].reason, reason);
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert!(!state.pending(200));
            // The same value in an agent record, under another rule: no alert.
            let copy = (
                "secret.agent-record",
                "~/.claude/projects/p/s.jsonl",
                Some("Test token"),
                Some("digest-a"),
            );
            state.ingest(&found(&[token, copy]));
            assert_eq!(state.items.len(), 2);
            assert!(!state.pending(200));
            assert!(state.items.iter().all(|i| state.decision(i, 200).is_some()));
            // A different value in the same place is a new matter.
            let rotated = (
                "secret.service-token",
                "~/app/.env",
                Some("Test token"),
                Some("digest-b"),
            );
            assert!(state.ingest(&found(&[rotated])));
            assert!(state.pending(200));
            // Undoing brings the first value back.
            state.undo(state.items[1].id);
            assert!(state.decision(&state.items[1], 200).is_none());
        }
    }

    #[test]
    fn kept_covers_one_place_and_ends_when_it_gets_worse() {
        let mut state = Review::default();
        let npm = (
            "dev.npm.inline-credentials",
            "~/.npmrc",
            Some("registry.example.invalid"),
            Some("digest-a"),
        );
        state.ingest(&found(&[npm]));
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        seen(&mut state);
        assert!(state.decision(&state.items[0], 200).is_some());
        // Rotating the token in place stays quiet.
        let rotated = (
            "dev.npm.inline-credentials",
            "~/.npmrc",
            Some("registry.example.invalid"),
            Some("digest-b"),
        );
        checked(&mut state, &found(&[rotated]));
        assert_eq!(state.items.len(), 1);
        assert!(
            !state.pending(200),
            "a rotated token of the same kind must not alert"
        );
        seen(&mut state);
        // The same credential somewhere else is not covered.
        let elsewhere = (
            "secret.service-token",
            "~/notes.md",
            Some("npm access token"),
            Some("digest-b"),
        );
        state.ingest(&found(&[rotated, elsewhere]));
        assert!(state.decision(&state.items[1], 200).is_none());
        // Readable by others now: no longer what was agreed to.
        let mut worse = found(&[rotated]);
        worse.findings[0].shared = true;
        assert!(state.ingest(&worse));
        assert!(state.decision(&state.items[0], 200).is_none());
        assert!(state.pending(200));
        // A different kind of credential in that place is not covered either.
        let mut other_kind = found(&[rotated]);
        other_kind.findings[0].token_type = Some("Another token");
        let mut fresh = Review::default();
        fresh.ingest(&found(&[npm]));
        fresh
            .decide(fresh.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        checked(&mut fresh, &other_kind);
        assert_eq!(fresh.items.len(), 1);
        assert!(fresh.decision(&fresh.items[0], 200).is_none());
        // After six months it returns to the list, without an alert.
        let mut old = Review::default();
        old.ingest(&found(&[npm]));
        old.decide(old.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        seen(&mut old);
        assert!(old.decision(&old.items[0], 100 + RECONFIRM).is_none());
        assert!(!old.pending(100 + RECONFIRM));
    }

    #[test]
    fn a_decision_about_the_value_replaces_keeping_it_in_each_place() {
        let mut state = Review::default();
        let copy = |path| {
            (
                "secret.service-token",
                path,
                Some("Synthetic token"),
                Some("digest-a"),
            )
        };
        state.ingest(&found(&[
            copy("~/a/.env"),
            copy("~/b/.env"),
            copy("~/c/.env"),
        ]));
        let ids: Vec<u64> = state.items.iter().map(|i| i.id).collect();
        let reasons = |state: &Review| -> Vec<Option<Reason>> {
            state
                .items
                .iter()
                .map(|i| state.decision(i, 200).map(|d| d.reason))
                .collect()
        };
        // Kept in two of its three places, each by a decision of its own.
        for id in &ids[..2] {
            state.decide(*id, Reason::Kept, 100, "then".into()).unwrap();
        }
        assert_eq!(
            reasons(&state),
            [Some(Reason::Kept), Some(Reason::Kept), None]
        );
        // At the third the person says the value no longer works. That is
        // about the credential, so no place goes on calling it real and kept.
        state
            .decide(ids[2], Reason::TestOrRevoked, 150, "later".into())
            .unwrap();
        assert_eq!(reasons(&state), [Some(Reason::TestOrRevoked); 3]);
        // Undone, the whole credential is undecided again, not still kept in
        // one of its places.
        state.undo(ids[0]);
        assert_eq!(reasons(&state), [None; 3]);
    }

    #[test]
    fn what_was_said_of_the_value_comes_before_what_was_said_of_the_place() {
        let mut state = Review::default();
        let npm = |secret| {
            (
                "dev.npm.inline-credentials",
                "~/.npmrc",
                Some("registry.example.invalid"),
                Some(secret),
            )
        };
        let note = (
            "secret.service-token",
            "~/notes.md",
            Some("npm access token"),
            Some("digest-b"),
        );
        state.ingest(&found(&[npm("digest-a"), note]));
        // One credential is kept where it is. Another is said to be dead.
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        state
            .decide(state.items[1].id, Reason::TestOrRevoked, 100, "then".into())
            .unwrap();
        let reason = |state: &Review| state.decision(&state.items[0], 200).map(|d| d.reason);
        assert_eq!(reason(&state), Some(Reason::Kept));
        // The kept place is then given the dead one, so both decisions cover
        // it. It is not called real and kept: of this very value the person
        // said otherwise.
        checked(&mut state, &found(&[npm("digest-b"), note]));
        assert_eq!(reason(&state), Some(Reason::TestOrRevoked));
        // With another value there, the place is kept as it was.
        checked(&mut state, &found(&[npm("digest-c"), note]));
        assert_eq!(reason(&state), Some(Reason::Kept));
        assert_eq!(state.items.len(), 2);
    }

    #[test]
    fn only_the_changed_credential_alerts_again() {
        let mut state = Review::default();
        let a = (
            "secret.env-assignment",
            "~/app/.env",
            Some("DB_PASSWORD"),
            Some("digest-a"),
        );
        let b = (
            "secret.env-assignment",
            "~/app/.env",
            Some("API_TOKEN"),
            Some("digest-b"),
        );
        state.ingest(&found(&[a, b]));
        seen(&mut state);
        // One variable changes. The file's own digest changes for both.
        let b2 = (
            "secret.env-assignment",
            "~/app/.env",
            Some("API_TOKEN"),
            Some("digest-c"),
        );
        let mut r = found(&[a, b2]);
        for f in &mut r.findings {
            f.fingerprint = Some("file-digest-after-edit".into());
        }
        assert!(state.ingest(&r));
        let alerting: Vec<_> = state
            .items
            .iter()
            .filter(|i| state.alerting(i, 0))
            .map(|i| i.subject.as_deref().unwrap())
            .collect();
        assert_eq!(alerting, ["API_TOKEN"]);
    }

    #[test]
    fn a_changing_count_and_another_copy_are_not_news() {
        let mut state = Review::default();
        let mut logins = found(&[(
            "browser.chromium.saved-logins",
            "~/Library/Chrome/Default/Login Data",
            None,
            None,
        )]);
        logins.findings[0].fingerprint = None;
        logins.findings[0].detail = Some("3 saved logins".into());
        state.ingest(&logins);
        seen(&mut state);
        logins.findings[0].detail = Some("4 saved logins".into());
        assert!(!state.ingest(&logins));
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items[0].detail.as_deref(), Some("4 saved logins"));

        // A token already on the list turns up in a second file.
        let first = (
            "secret.service-token",
            "~/app/.env",
            Some("Synthetic token"),
            Some("digest-a"),
        );
        let second = (
            "secret.agent-record",
            "~/.claude/p/s.jsonl",
            Some("Synthetic token"),
            Some("digest-a"),
        );
        state.ingest(&found(&[first]));
        seen(&mut state);
        assert!(!state.ingest(&found(&[first, second])));
        assert_eq!(state.items.len(), 3);
        assert!(!state.pending(0));
    }

    #[test]
    fn a_kept_credential_found_elsewhere_alerts() {
        let mut state = Review::default();
        let env = (
            "secret.env-assignment",
            "~/app/.env",
            Some("API_TOKEN"),
            Some("digest-a"),
        );
        assert!(state.ingest(&found(&[env])));
        // Its notification was delivered, and the person keeps it there.
        seen(&mut state);
        let id = state.items[0].id;
        state.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        assert!(!state.pending(200));
        // "Kept" is about that one place. The same value somewhere else is news.
        let copy = (
            "secret.agent-record",
            "~/.claude/p/s.jsonl",
            Some("Synthetic token"),
            Some("digest-a"),
        );
        assert!(state.ingest(&found(&[env, copy])));
        assert!(state.decision(&state.items[1], 200).is_none());
        assert!(state.pending(200), "the copy elsewhere did not alert");
    }

    #[test]
    fn two_secrets_of_one_kind_in_one_file_are_two_quiet_items() {
        const R: &str = "secret.agent-record";
        const P: &str = "~/.claude/projects/p/s.jsonl";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        let two = || found(&[at("digest-a"), at("digest-b")]);
        let mut state = Review::default();
        assert!(state.ingest(&two()));
        assert_eq!(state.items.len(), 2);
        seen(&mut state);
        // The same file, checked again and unchanged, is not news.
        assert!(!state.ingest(&two()), "an unchanged file alerted again");
        assert!(!state.pending(1001));
        // Nor in the other order, nor with one value on two lines.
        let again = found(&[at("digest-b"), at("digest-a"), at("digest-a")]);
        assert!(!state.ingest(&again));
        assert_eq!(state.items.len(), 2);
        // A value changed in place is the same item, changed. That is news,
        // and what was decided about the place still covers it.
        let (id, drawn) = (state.items[1].id, state.items[1].revision);
        assert!(checked(
            &mut state,
            &found(&[at("digest-c"), at("digest-a")])
        ));
        assert_eq!(state.items.len(), 2);
        assert_eq!(state.items[0].secret.as_deref(), Some("digest-a"));
        assert_eq!(state.items[1].secret.as_deref(), Some("digest-c"));
        // It keeps its id, and is no longer what was drawn under it.
        assert_eq!(state.items[1].id, id);
        assert!(state.as_shown(id, drawn).is_err());
        assert!(state.as_shown(id, state.items[1].revision).is_ok());
        // One of the two is taken out of the file. The report still has the
        // other, so the file was read, but that is what it held then: the
        // one the report no longer has is fixed once the file is read again.
        let one = found(&[at("digest-a")]);
        state.ingest(&one);
        state.resolve(&one, |_| None);
        assert!(state.items.iter().all(|i| !i.resolved));
        assert!(!checked(&mut state, &one));
        assert!(!state.items[0].resolved && state.items[1].resolved);
    }

    /// A report says what its scan read, and can be saved after a later
    /// check of the same file. What it leaves out was marked fixed on its
    /// word, and a value it brought took the item of one still in the file.
    #[test]
    fn a_report_alone_neither_fixes_a_value_nor_replaces_one() {
        const R: &str = "secret.service-token";
        const P: &str = "~/notes.txt";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        let there = |digests: &[&str]| -> Option<Still> {
            let value = |d: &&str| (Some("Synthetic token".to_string()), Some(d.to_string()));
            Some(digests.iter().map(value).collect())
        };
        let open = |state: &Review| -> Vec<String> {
            let open = state.items.iter().filter(|i| !i.resolved);
            open.map(|i| i.secret.clone().unwrap()).collect()
        };
        let mut state = Review::default();
        state.ingest(&found(&[at("digest-a")]));
        let id = state.items[0].id;
        state
            .decide(id, Reason::TestOrRevoked, 100, "then".into())
            .unwrap();
        // A second value is added and found. A report from before that, with
        // the first alone, is saved afterwards: the file still holds both.
        let (older, newer) = (
            found(&[at("digest-a")]),
            found(&[at("digest-a"), at("digest-b")]),
        );
        state.merge(&newer, |_| there(&["digest-a", "digest-b"]));
        state.merge(&older, |_| there(&["digest-a", "digest-b"]));
        assert_eq!(open(&state), ["digest-a", "digest-b"]);
        // Nor is it fixed where the file cannot be read again, where the
        // read cannot tell what one of that kind holds, or where it returns
        // as many hits as the scanner keeps.
        let unknown: Still = vec![(Some("Synthetic token".into()), None)];
        let many: Still = (0..HITS_PER_FILE)
            .map(|n| (Some(format!("subject-{n}")), Some(format!("digest-{n}"))))
            .chain(there(&["digest-a"]).unwrap())
            .collect();
        for still in [None, Some(unknown), Some(many)] {
            state.merge(&older, |_| still.clone());
            assert_eq!(open(&state), ["digest-a", "digest-b"]);
        }
        // The first value is replaced by a third, and the report that says
        // so is saved after one that had read the file before. The older
        // report does not put its value back over the one in the file, where
        // what was said of the first would have covered the third.
        let rotated = found(&[at("digest-c"), at("digest-b")]);
        assert!(state.merge(&rotated, |_| there(&["digest-c", "digest-b"])));
        assert_eq!(open(&state), ["digest-c", "digest-b"]);
        assert_eq!(
            state.items[0].id, id,
            "a value changed in place is one item"
        );
        state.merge(&newer, |_| there(&["digest-c", "digest-b"]));
        let third = state.items.iter().find(|i| i.id == id).unwrap();
        assert_eq!(third.secret.as_deref(), Some("digest-c"));
        assert!(!third.resolved && state.decision(third, 200).is_none());
        // What the older report did find is listed, on its word, until the
        // file is next checked.
        assert_eq!(open(&state), ["digest-c", "digest-b", "digest-a"]);
        assert!(!checked(&mut state, &rotated));
        assert_eq!(open(&state), ["digest-c", "digest-b"]);
        // Without a fresh read a new value is a new item, and the one it
        // might have replaced stays open.
        state.ingest(&found(&[at("digest-d")]));
        assert_eq!(open(&state), ["digest-c", "digest-b", "digest-d"]);
    }

    #[test]
    fn a_press_is_for_the_item_as_it_was_drawn() {
        let mut state = Review::default();
        let r = found(&[(
            "dev.npm.inline-credentials",
            "~/.npmrc",
            Some("registry.example.invalid"),
            None,
        )]);
        state.ingest(&r);
        let (id, drawn) = (state.items[0].id, state.items[0].revision);
        assert!(state.as_shown(id, drawn).is_ok());
        // An item that is gone is each action's own to refuse.
        assert!(state.as_shown(id + 1, drawn).is_ok());
        // With no single value, what the file holds is what can change. So
        // is whether others can read it, which "kept" agrees to.
        for change in [
            |f: &mut Finding| f.fingerprint = Some("file-digest-after-edit".into()),
            |f: &mut Finding| f.shared = true,
        ] {
            let mut changed = found(&[("dev.npm.inline-credentials", "~/.npmrc", None, None)]);
            changed.findings[0].subject = r.findings[0].subject.clone();
            change(&mut changed.findings[0]);
            let mut state = state.clone();
            assert!(state.ingest(&changed));
            assert_eq!(state.items.len(), 1);
            assert_eq!(state.as_shown(id, drawn).unwrap_err(), CHANGED);
            assert!(state.as_shown(id, state.items[0].revision).is_ok());
        }
    }

    #[test]
    fn an_item_that_stood_for_two_secrets_splits_and_is_news_once() {
        const R: &str = "secret.agent-record";
        const P: &str = "~/.claude/projects/p/s.jsonl";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        // As stored before: one item, holding whichever value came last.
        let mut state = Review::default();
        state.ingest(&found(&[at("digest-b")]));
        seen(&mut state);
        let two = || found(&[at("digest-a"), at("digest-b")]);
        assert!(state.ingest(&two()));
        assert_eq!(state.items.len(), 2);
        assert_eq!(state.items[0].secret.as_deref(), Some("digest-b"));
        seen(&mut state);
        assert!(!state.ingest(&two()));
    }

    #[test]
    fn a_value_missing_from_a_report_that_cannot_tell_is_not_fixed() {
        const R: &str = "secret.agent-record";
        const P: &str = "~/.claude/projects/p/s.jsonl";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        let mut state = Review::default();
        state.ingest(&found(&[at("digest-a"), at("digest-b")]));
        // The file was not read to its end: the report says so.
        let mut cut = found(&[at("digest-a")]);
        cut.not_checked.push(crate::report::NotChecked {
            path: P.into(),
            reason: "scan-limit",
        });
        state.resolve(&cut, |_| panic!("the report has this place"));
        assert!(state.items.iter().all(|i| !i.resolved));
        // The scanner keeps only so many hits for one file.
        let digests: Vec<String> = (0..HITS_PER_FILE).map(|n| format!("digest-{n}")).collect();
        let many: Vec<_> = digests.iter().map(|d| at(d.as_str())).collect();
        state.resolve(&found(&many), |_| panic!("the report has this place"));
        assert!(state.items.iter().all(|i| !i.resolved));
    }

    /// The scanner keeps only so many hits for one file, of every kind
    /// together. A read that returned that many, all of another kind, was
    /// taken to show that nothing of an item's kind was left: a token at
    /// the end of a file, after enough tokens of another type, was fixed
    /// while it was still there.
    #[test]
    fn a_read_that_kept_as_many_hits_as_it_may_does_not_say_what_is_gone() {
        const R: &str = "secret.service-token";
        const P: &str = "~/notes.txt";
        let other = |n: usize| (Some("Other type".to_string()), Some(format!("digest-{n}")));
        let others = |count: usize| -> Still { (0..count).map(other).collect() };
        let listed = || {
            let mut state = Review::default();
            state.ingest(&found(&[(R, P, Some("Synthetic token"), Some("digest-a"))]));
            state
        };
        // What the scan that read the file reports of it, as many of the
        // other type as `still` has: its value was replaced, the file holds
        // only the other type, or the scan did not come by the file at all.
        let reports = |still: &Still| {
            let digests: Vec<&str> = still.iter().filter_map(|(_, d)| d.as_deref()).collect();
            let there = digests.iter().map(|d| (R, P, Some("Other type"), Some(*d)));
            [
                found(&[(R, P, Some("Synthetic token"), Some("digest-b"))]),
                found(&there.collect::<Vec<_>>()),
                found(&[]),
            ]
        };
        // Whether the item is fixed, for each of those reports.
        let fixed = |count: usize| {
            let still = others(count);
            reports(&still).map(|report| {
                let mut state = listed();
                state.resolve(&report, |_| Some(still.clone()));
                state.items[0].resolved
            })
        };
        // As many as are kept, or more: the item's value may be among those
        // left out, so nothing is known of it.
        for count in [HITS_PER_FILE, 2 * HITS_PER_FILE] {
            assert_eq!(fixed(count), [false; 3], "a read that kept {count} hits");
        }
        // One fewer is all there is in the file, and an absent or empty
        // file holds nothing: the value is gone.
        for count in [HITS_PER_FILE - 1, 0] {
            assert_eq!(fixed(count), [true; 3], "a read of all {count} hits");
        }
    }

    /// A check whose report has nothing at an item's place asked only
    /// whether anything of the item's kind was still there. A value replaced
    /// in place, with the new one listed beside it, then stayed open at
    /// every later check: something of its kind was there.
    #[test]
    fn a_value_replaced_in_a_file_the_report_does_not_have_is_fixed_on_a_fresh_read() {
        const R: &str = "secret.service-token";
        const P: &str = "~/notes.txt";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        let there = |digests: &[&str]| -> Option<Still> {
            let value = |d: &&str| (Some("Synthetic token".to_string()), Some(d.to_string()));
            Some(digests.iter().map(value).collect())
        };
        let open = |state: &Review| -> Vec<String> {
            let open = state.items.iter().filter(|i| !i.resolved);
            open.map(|i| i.secret.clone().unwrap()).collect()
        };
        // Both are listed and open: the old value could not be read again
        // when the new one was found.
        let mut state = Review::default();
        state.ingest(&found(&[at("digest-a")]));
        let id = state.items[0].id;
        state.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        state.ingest(&found(&[at("digest-b")]));
        assert_eq!(open(&state), ["digest-a", "digest-b"]);
        // A check that did not come by the file. Nothing is fixed where the
        // file cannot be read again, where the read cannot tell what one of
        // that kind holds, where it returns as many hits as the scanner
        // keeps, or while the value is still there.
        let elsewhere = found(&[]);
        let unknown: Still = vec![(Some("Synthetic token".into()), None)];
        let many: Still = (0..HITS_PER_FILE)
            .map(|n| (Some("Synthetic token".into()), Some(format!("digest-{n}"))))
            .collect();
        for still in [
            None,
            Some(unknown.clone()),
            Some(many),
            there(&["digest-a", "digest-b"]),
        ] {
            state.merge(&elsewhere, |_| still.clone());
            assert_eq!(open(&state), ["digest-a", "digest-b"]);
        }
        // Read again, the file holds the new value alone: the old one is
        // fixed, and the one that is there stays open.
        assert!(!state.merge(&elsewhere, |_| there(&["digest-b"])));
        assert_eq!(open(&state), ["digest-b"]);
        assert_eq!(state.items.len(), 2);
        // What was agreed about the place still stands for what is there.
        let kept = state.decision(&state.items[1], 200).map(|d| d.reason);
        assert_eq!(kept, Some(Reason::Kept));
        // That one is taken out too.
        state.merge(&elsewhere, |_| there(&[]));
        assert!(open(&state).is_empty());
        // An item stored with no value to go by cannot be told from what is
        // there now, whatever value that has.
        let mut old = Review::default();
        old.ingest(&found(&[(R, P, Some("Synthetic token"), None)]));
        for still in [there(&["digest-b"]), Some(unknown)] {
            old.resolve(&elsewhere, |_| still.clone());
            assert!(!old.items[0].resolved);
        }
        old.resolve(&elsewhere, |_| there(&[]));
        assert!(old.items[0].resolved);
    }

    #[test]
    fn first_seen_is_when_the_value_was_found() {
        const R: &str = "secret.service-token";
        const P: &str = "~/notes.txt";
        let at = |digest| (R, P, Some("Synthetic token"), Some(digest));
        let when = |findings: &[_], time: &str| {
            let mut r = found(findings);
            r.generated_at = time.into();
            r
        };
        let first = |state: &Review| state.items[0].first_seen.clone().unwrap();
        let mut state = Review::default();
        checked(&mut state, &when(&[at("digest-a")], "2026-10-01T00:00:00Z"));
        // Found again, it is still the value first seen then.
        checked(&mut state, &when(&[at("digest-a")], "2026-10-02T00:00:00Z"));
        assert_eq!(first(&state), "2026-10-01T00:00:00Z");
        // Removed, then put back: the same value, first seen then too.
        state.resolve(&found(&[]), |_| Some(Vec::new()));
        assert!(state.items[0].resolved);
        checked(&mut state, &when(&[at("digest-a")], "2026-10-04T00:00:00Z"));
        assert_eq!(first(&state), "2026-10-01T00:00:00Z");
        // Replaced in place by another value, which takes the item: that
        // value was first seen when it was found.
        checked(&mut state, &when(&[at("digest-b")], "2026-10-05T00:00:00Z"));
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items[0].secret.as_deref(), Some("digest-b"));
        assert_eq!(first(&state), "2026-10-05T00:00:00Z");
    }

    #[test]
    fn a_full_list_drops_fixed_items_first_and_says_when_it_cannot() {
        let mut state = Review::default();
        let paths: Vec<_> = (0..MAX_ITEMS)
            .map(|n| format!("~/synthetic-{n}.csv"))
            .collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert_eq!(state.items.len(), MAX_ITEMS);
        for item in state.items.iter_mut().take(10) {
            item.resolved = true;
        }
        // Room is made from what is already fixed.
        assert!(state.ingest(&report(&[("review", "~/one-more.csv")])));
        assert_eq!(state.items.len(), MAX_ITEMS - 9);
        assert!(!state.full);
        // With every item still open, the next finding is left out, visibly.
        let extra: Vec<_> = (0..20).map(|n| format!("~/extra-{n}.csv")).collect();
        let pairs: Vec<_> = extra.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert_eq!(state.items.len(), MAX_ITEMS);
        assert!(state.full);
    }

    #[test]
    fn a_list_too_large_to_store_counts_as_full_before_the_save_would_fail() {
        // Long names, as a hostile folder can have: fewer than the item limit
        // of these already pass what the store accepts in one file.
        let mut state = Review::default();
        let paths: Vec<_> = (0..MAX_ITEMS - 1)
            .map(|n| format!("~/{}/synthetic-{n}.csv", "d".repeat(2100)))
            .collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert!(state.full);
        assert!(state.items.len() > 1000 && state.items.len() < MAX_ITEMS - 1);
        assert!(serde_json::to_vec(&state).unwrap().len() <= STORE_BYTES);
        // A finding already on the list is still kept up to date.
        let before = state.items.len();
        assert!(!state.ingest(&report(&[("review", paths[0].as_str())])));
        assert_eq!(state.items.len(), before);
        // Room is made from what is already fixed, as it is at the item limit.
        for item in state.items.iter_mut().take(10) {
            item.resolved = true;
        }
        // Larger than any room the estimate left over, so it cannot simply fit.
        let another = format!("~/{}/one-more.csv", "d".repeat(9000));
        assert!(state.ingest(&report(&[("review", another.as_str())])));
        // It fits, but over a thousand findings of the first report are
        // still not on the list.
        assert!(state.full);
        assert_eq!(state.items.len(), before - 9);
    }

    #[test]
    fn a_list_has_room_again_only_when_an_open_item_leaves_it() {
        // At the limit by number.
        let mut state = Review::default();
        let paths: Vec<_> = (0..MAX_ITEMS)
            .map(|n| format!("~/synthetic-{n}.csv"))
            .collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert!(!state.full && !state.has_room());
        state.items[0].resolved = true;
        assert!(state.has_room());
        // At the limit by size, with far fewer items.
        let mut state = Review::default();
        let paths: Vec<_> = (0..120)
            .map(|n| format!("~/{}/synthetic-{n}.csv", "d".repeat(60_000)))
            .collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert!(state.full && state.items.len() < 120);
        assert!(!state.has_room());
        state.items[0].resolved = true;
        assert!(state.has_room());
    }

    #[test]
    fn a_later_report_that_fits_does_not_clear_what_an_earlier_one_left_out() {
        // Names as long as nested folders can make them: a few hundred of
        // these fill the room for items.
        let deep = vec!["d".repeat(255); 60].join("/");
        let paths: Vec<_> = (0..420)
            .map(|n| format!("~/{deep}/synthetic-{n}.csv"))
            .collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        let mut state = Review::default();
        state.ingest(&report(&pairs));
        let listed = state.items.len();
        assert!(state.full && listed < paths.len());
        // The background agent reports one slice of its pass or one batch of
        // changed files at a time. This one has a single new finding, small
        // enough for the room that is left.
        assert!(state.ingest(&report(&[("review", "~/small.csv")])));
        assert_eq!(state.items.len(), listed + 1);
        assert!(
            state.full,
            "findings of the first report are still not on the list"
        );
    }

    #[test]
    fn nothing_is_rechecked_in_a_skipped_folder() {
        let mut state = Review::default();
        state.ingest(&report(&[
            ("review", "~/corpus/a.csv"),
            ("review", "~/docs/b.csv"),
        ]));
        state.skipped.push(Skip {
            path: "~/corpus".into(),
            added: "then".into(),
        });
        assert!(state.skips("~/corpus/deep/x") && !state.skips("~/corpus-other/x"));
        let rechecked = std::cell::RefCell::new(Vec::new());
        state.resolve(&report(&[]), |item| {
            rechecked.borrow_mut().push(item.path.clone());
            Some(vec![])
        });
        assert_eq!(*rechecked.borrow(), ["~/docs/b.csv"]);
        assert!(!state.items[0].resolved && state.items[1].resolved);
    }

    /// The store is a file anything running as the person can edit. A skip
    /// the app could not have added must not keep a scan out of the home.
    #[test]
    fn a_skip_the_app_could_not_have_added_is_not_honoured() {
        let mut state = Review::default();
        let skip = |path: &str| Skip {
            path: path.into(),
            added: "then".into(),
        };
        let edited = [
            "/",
            "~",
            "~/.",
            "~/..",
            "~/a/../..",
            "~/caf\u{e9}",
            "Volumes",
        ];
        state.skipped = edited.into_iter().map(skip).collect();
        state.skipped.push(skip("~/kept"));
        let honoured: Vec<&str> = state.honoured_skips().map(|s| s.path.as_str()).collect();
        assert_eq!(honoured, ["~/kept"]);
        assert!(state.skips("~/kept/deep/x"));
        for elsewhere in ["~/other/x", "~/a/x", "/Volumes/Backup/x", "~/caf\u{e9}/x"] {
            assert!(!state.skips(elsewhere), "{elsewhere}");
        }
        // No more are honoured than the app lets a person add.
        state.skipped = (0..MAX_SKIPS + 5)
            .map(|n| skip(&format!("~/f{n}")))
            .collect();
        assert_eq!(state.honoured_skips().count(), MAX_SKIPS);
        assert!(!state.skips(&format!("~/f{}/x", MAX_SKIPS + 4)));
    }

    #[test]
    fn nothing_is_rechecked_under_a_place_the_scan_could_not_read() {
        let found = [
            ("review", "/Volumes/Backup/dir/a.csv"),
            ("review", "/Volumes/Backup-2/b.csv"),
            ("review", "~/docs/c.csv"),
        ];
        // A scan of the home folder and a drive, with nothing found again.
        let scan = |gaps: &[(&str, &'static str)]| {
            let mut r = complete(report(&[]));
            let roots = &mut r.coverage.as_mut().unwrap().roots;
            roots.push("/Volumes/Backup".into());
            for (path, reason) in gaps {
                let path = path.to_string();
                r.not_checked.push(NotChecked { path, reason });
            }
            r
        };
        let rechecked = |r: &Report| {
            let mut state = Review::default();
            state.ingest(&report(&found));
            let asked = std::cell::RefCell::new(Vec::new());
            state.resolve(r, |item| {
                asked.borrow_mut().push(item.path.clone());
                Some(vec![])
            });
            let open: Vec<bool> = state.items.iter().map(|i| !i.resolved).collect();
            (asked.into_inner(), open)
        };
        let all = found.map(|(_, path)| path.to_string());
        // The drive is not connected, so the scan could not read it. A file
        // on it is not there either, and that says nothing about the file.
        for reason in ["unreadable", "permission-denied"] {
            assert_eq!(
                rechecked(&scan(&[("/Volumes/Backup", reason)])),
                (all[1..].to_vec(), vec![true, false, false]),
                "{reason}"
            );
        }
        // The home folder that could not be read is such a place too.
        assert_eq!(
            rechecked(&scan(&[("~/", "unreadable")])),
            (all[..2].to_vec(), vec![false, false, true])
        );
        // A place the scan was stopped in, or that holds a cloud-only file,
        // was not read to its end, and its files can still be looked at. So
        // can a file under a folder that is not one of the scan's places.
        for gap in [
            ("~/", "scan-limit"),
            ("/Volumes/Backup", "scan-limit"),
            ("/Volumes/Backup", "cloud-only-file"),
            ("/Volumes/Backup/dir", "unreadable"),
            ("~/docs", "permission-denied"),
        ] {
            assert_eq!(
                rechecked(&scan(&[gap])),
                (all.to_vec(), vec![false; 3]),
                "{gap:?}"
            );
        }
    }

    #[test]
    fn where_a_file_s_volume_was_mounted_is_kept_with_its_item() {
        let mut r = report(&[("review", "/Volumes/Backup/a.csv"), ("review", "~/b.csv")]);
        (r.findings[0].mount, r.findings[1].mount) = (Some(3), Some(0));
        let mut state = Review::default();
        state.ingest(&r);
        let kept = |state: &Review| -> Vec<_> { state.items.iter().map(|i| i.mount).collect() };
        assert_eq!(kept(&state), [Some(3), Some(0)]);
        // State written before this was kept has none, and is still read.
        let mut stored = serde_json::to_value(&state).unwrap();
        for item in stored["items"].as_array_mut().unwrap() {
            assert!(item.as_object_mut().unwrap().remove("mount").is_some());
        }
        let mut old: Review = serde_json::from_value(stored).unwrap();
        assert_eq!(kept(&old), [None, None]);
        // The next scan to find the file says where it is. A finding that
        // cannot tell leaves what was known.
        old.ingest(&r);
        assert_eq!(kept(&old), [Some(3), Some(0)]);
        (r.findings[0].mount, r.findings[1].mount) = (None, Some(4));
        old.ingest(&r);
        assert_eq!(kept(&old), [Some(3), Some(4)]);
    }

    #[test]
    fn groups_new_findings_and_suppresses_repeats() {
        let mut review = Review::default();
        let r = report(&[("review", "~/one.csv"), ("review", "~/two.csv")]);
        assert!(review.ingest(&r));
        assert_eq!(review.items.len(), 2);
        assert!(!review.ingest(&r));
        assert!(review.ingest(&report(&[("review", "~/three.csv")])));
        assert_eq!(review.items.len(), 3);
    }

    #[test]
    fn normal_credentials_and_gaps_do_not_alert() {
        let mut review = Review::default();
        assert!(!review.ingest(&report(&[("inventory", "~/.aws/credentials")])));
        assert!(!review.ingest(&report(&[])));
        assert!(review.items.is_empty());
    }

    #[test]
    fn missing_matches_do_not_resolve_or_repeat() {
        let mut review = Review::default();
        let r = report(&[("review", "~/one.csv")]);
        review.ingest(&r);
        assert!(!review.ingest(&report(&[])));
        assert!(!review.ingest(&r));
        assert!(!review.items[0].resolved);
    }

    /// An item an older build snoozed is open here, and that build can still
    /// read what this one saves.
    #[test]
    fn a_reminder_from_an_older_build_is_read_as_open() {
        let mut review = Review::default();
        review.ingest(&report(&[("review", "~/one.csv")]));
        let mut saved = serde_json::to_value(&review).unwrap();
        saved["items"][0]["deferred"] = true.into();
        saved["items"][0]["snoozed_until"] = u64::MAX.into();
        let loaded: Review = serde_json::from_value(saved).unwrap();
        assert!(!loaded.items[0].deferred);
        assert!(loaded.alerting(&loaded.items[0], 1000));
        let again = serde_json::to_value(&loaded).unwrap();
        assert_eq!(again["items"][0]["deferred"], false);
        assert!(again["items"][0].get("snoozed_until").is_none());
    }

    #[test]
    fn foreground_is_inline_and_denied_permission_retains_review() {
        let mut review = Review::default();
        let new = review.ingest(&report(&[("review", "~/one.csv")]));
        assert_eq!(delivery(new, true, true, true), Delivery::Inline);
        assert_eq!(delivery(new, true, true, false), Delivery::Inline);
        assert_eq!(delivery(new, true, false, false), Delivery::None);
        assert_eq!(delivery(new, true, false, true), Delivery::Native);
        assert_eq!(delivery(new, false, false, true), Delivery::None);
        assert_eq!(delivery(false, true, false, true), Delivery::None);
        assert_eq!(review.items.len(), 1);
        assert!(!review.items[0].resolved);
    }

    #[test]
    fn restart_retains_pending_and_decisions_with_private_atomic_storage() {
        let root = std::env::temp_dir().join(format!(
            "credential-review-test-{}-{}",
            std::process::id(),
            crate::report::utc_now().replace(':', "")
        ));
        std::fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        let mut review = store.load().unwrap();
        let r = report(&[("review", "~/one.csv")]);
        review.ingest(&r);
        store.save(&review).unwrap();
        let id = review.items[0].id;
        review.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        store.save(&review).unwrap();
        let state = root.join(STATE_DIR).join("state.json");
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o600);
        drop(store);
        let store = Store::open(&root).unwrap();
        let mut loaded = store.load().unwrap();
        assert!(loaded.decision(&loaded.items[0], 100).is_some());
        assert!(!loaded.ingest(&r));
        std::fs::remove_file(&state).unwrap();
        symlink("/dev/null", &state).unwrap();
        assert!(store.load().is_err());
        std::fs::remove_file(state).unwrap();
        drop(store);
        let dir = root.join(STATE_DIR);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Store::open(&root).is_err());
        remove_store(&root);
    }

    /// The store's folder and the folders made on the way to it, which must
    /// be empty, then the synthetic home.
    fn remove_store(root: &Path) {
        for dir in [STATE_DIR, "Library/Application Support", "Library", ""] {
            std::fs::remove_dir(root.join(dir)).unwrap();
        }
    }

    fn synthetic_home(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("credential-review-{name}-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn state_is_kept_where_macos_apps_keep_their_data() {
        let root = synthetic_home("location");
        let store = Store::open(&root).unwrap();
        let consent = |state: &mut Review| {
            state.monitoring = true;
            Ok(())
        };
        store.update(consent).unwrap();
        let dir = root.join("Library/Application Support/dev.loosekeys.desktop");
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert!(dir.join("state.json").is_file());
        assert!(std::fs::symlink_metadata(root.join(".loose-keys-review")).is_err());
        assert!(crate::scan::EXCLUDED.contains(&STATE_DIR));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn state_in_the_old_folder_is_moved_once() {
        let root = synthetic_home("moved");
        let old = root.join(".loose-keys-review");
        std::fs::create_dir(&old).unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();
        let saved = Review {
            monitoring: true,
            ..Review::default()
        };
        std::fs::write(old.join("state.json"), serde_json::to_vec(&saved).unwrap()).unwrap();
        std::fs::set_permissions(
            old.join("state.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = Store::open(&root).unwrap();
        assert!(store.read().unwrap().monitoring);
        assert!(std::fs::symlink_metadata(&old).is_err());
        drop(store);
        // Opened again, there is nothing left to move.
        assert!(Store::open(&root).unwrap().read().unwrap().monitoring);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn state_in_the_old_folder_never_replaces_newer_state() {
        let root = synthetic_home("newer");
        let pause = |state: &mut Review| {
            state.paused = true;
            Ok(())
        };
        Store::open(&root).unwrap().update(pause).unwrap();
        let old = root.join(".loose-keys-review");
        std::fs::create_dir(&old).unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stale = Review {
            monitoring: true,
            ..Review::default()
        };
        std::fs::write(old.join("state.json"), serde_json::to_vec(&stale).unwrap()).unwrap();
        std::fs::set_permissions(
            old.join("state.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let state = Store::open(&root).unwrap().read().unwrap();
        assert!(state.paused && !state.monitoring);
        assert!(old.join("state.json").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_link_on_the_way_to_the_state_is_not_followed() {
        for (name, link) in [
            ("library", "Library"),
            ("support", "Library/Application Support"),
            ("folder", STATE_DIR),
        ] {
            let root = synthetic_home(&format!("link-{name}"));
            let elsewhere = root.join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
            let at = root.join(link);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            symlink(&elsewhere, &at).unwrap();
            assert!(Store::open(&root).is_err(), "{link}");
            assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0, "{link}");
            std::fs::remove_dir_all(root).unwrap();
        }
        // A link where the old folder was is left alone, and is no reason
        // not to open the store.
        let root = synthetic_home("link-old");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(elsewhere.join("state.json"), b"{}").unwrap();
        symlink(&elsewhere, root.join(".loose-keys-review")).unwrap();
        assert!(Store::open(&root).is_ok());
        assert!(elsewhere.join("state.json").is_file());
        assert!(!root.join(STATE_DIR).join("state.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn app_and_agent_share_one_store_without_losing_updates() {
        let root = std::env::temp_dir().join(format!(
            "credential-review-shared-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let (app, agent) = (Store::open(&root).unwrap(), Store::open(&root).unwrap());
        // The agent records a finding; the app, holding an older copy, sets
        // it aside and changes a setting; the agent then records another.
        agent
            .update(|s| Ok(s.ingest(&report(&[("review", "~/one.csv")]))))
            .unwrap();
        let stale = app.read().unwrap();
        agent
            .update(|s| Ok(s.ingest(&report(&[("review", "~/two.csv")]))))
            .unwrap();
        let (first, drawn) = (stale.items[0].id, stale.items[0].revision);
        app.update(|s| {
            s.as_shown(first, drawn)?;
            s.decide(first, Reason::Kept, 100, "then".into())
        })
        .unwrap();
        app.update(|s| {
            s.monitoring = true;
            Ok(())
        })
        .unwrap();
        let (state, ()) = agent
            .update(|s| {
                s.agent.changes += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(state.items.len(), 2);
        assert!(state.decision(&state.items[0], 100).is_some());
        assert!(state.decision(&state.items[1], 100).is_none());
        assert!(state.monitoring && state.agent.changes == 1);
        // The first update creates the fingerprint key, and it never changes.
        assert_eq!(state.key.len(), 32);
        assert_eq!(app.read().unwrap().key, state.key);
        // A failed change saves nothing.
        assert!(app
            .update(|s| {
                s.monitoring = false;
                Err::<(), _>("refused".to_string())
            })
            .is_err());
        assert!(agent.read().unwrap().monitoring);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn complete(mut r: Report) -> Report {
        r.status = "complete";
        r.not_checked.clear();
        r.coverage = Some(crate::report::Coverage {
            roots: vec!["~/".into()],
            excluded_directories: crate::scan::EXCLUDED,
            excluded_by_user: Vec::new(),
            limitations: crate::report::LIMITATIONS,
        });
        r
    }

    #[test]
    fn material_change_resolution_reappearance_and_bounded_retry() {
        let mut r = complete(report(&[("review", "~/one.csv")]));
        r.findings[0].fingerprint = Some("keyed-synthetic-a".into());
        let mut state = Review::default();
        assert!(state.ingest(&r));
        assert!(state.pending(1));
        state.attempted(1);
        assert!(!state.pending(60));
        assert!(state.pending(61));
        state.notified_revision = state.revision;
        assert!(!state.ingest(&r));
        assert!(!state.pending(1000));
        r.findings[0].fingerprint = Some("keyed-synthetic-b".into());
        assert!(state.ingest(&r));
        assert!(state.pending(1000));
        for t in [1000, 1060, 1360] {
            assert!(state.pending(t));
            state.attempted(t);
        }
        assert!(!state.pending(u64::MAX));
        assert!(!state.ingest(&report(&[])));
        state.resolve(&report(&[]), |_| None);
        assert!(
            !state.items[0].resolved,
            "an unchecked file must retain its finding"
        );
        // A partial scan still resolves an item whose own file was rechecked.
        state.resolve(&report(&[]), |_| Some(vec![]));
        assert!(state.items[0].resolved);
        assert_eq!(state.items[0].resolved_at.as_deref(), Some("synthetic"));
        assert!(state.ingest(&r));
        assert!(!state.items[0].resolved);
        assert_eq!(state.attempts, 0);
        assert!(state.pending(2000));
    }

    #[test]
    fn digest_pending_attempts_and_consent_survive_restart_without_raw_material() {
        let root =
            std::env::temp_dir().join(format!("credential-monitor-restart-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        let mut r = report(&[("review", "~/one.csv")]);
        r.findings[0].fingerprint = Some("keyed-synthetic-digest".into());
        let mut state = Review {
            monitoring: true,
            paused: true,
            key: vec![7; 32],
            ..Review::default()
        };
        state.ingest(&r);
        state.attempted(10);
        store.save(&state).unwrap();
        drop(store);
        let store = Store::open(&root).unwrap();
        let mut loaded = store.load().unwrap();
        assert!(loaded.monitoring && loaded.paused);
        assert_eq!(loaded.attempts, 1);
        assert!(!loaded.ingest(&r));
        assert!(
            loaded.pending(1000),
            "submission without a durable acknowledgement stays pending after restart"
        );
        loaded.notified_revision = loaded.revision;
        store.save(&loaded).unwrap();
        assert!(!store.load().unwrap().pending(10000));
        let export = crate::report::to_ascii_json(&r);
        assert!(!export.contains("keyed-synthetic-digest"));
        std::fs::remove_file(root.join(STATE_DIR).join("state.json")).unwrap();
        drop(store);
        remove_store(&root);
    }

    #[test]
    fn access_warning_refreshes_in_both_directions_and_survives_reload() {
        let root =
            std::env::temp_dir().join(format!("credential-review-warning-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        let mut state = Review::default();
        let mut r = report(&[("review", "~/synthetic.csv")]);
        state.key = vec![7; 32];
        r.findings[0].fingerprint = Some("synthetic-private".into());
        r.findings[0].reason = None;
        assert!(state.ingest(&r));
        for (digest, reason) in [
            (
                "synthetic-shared",
                Some("Group or other users can read this file."),
            ),
            ("synthetic-private-again", None),
        ] {
            state.notified_revision = state.revision;
            r.findings[0].fingerprint = Some(digest.into());
            r.findings[0].reason = reason.map(str::to_string);
            r.findings[0].line = Some(8);
            r.findings[0].title = "Current title";
            r.findings[0].explanation = "Current explanation";
            r.findings[0].next_step = Some("Current next step");
            assert!(state.ingest(&r));
            assert_eq!(state.items[0].reason, r.findings[0].reason);
            assert_eq!(state.items[0].line, Some(8));
            assert_eq!(state.items[0].title, "Current title");
            assert_eq!(state.items[0].explanation, "Current explanation");
            assert_eq!(
                state.items[0].next_step.as_deref(),
                Some("Current next step")
            );
            assert!(state.pending(0));
            store.save(&state).unwrap();
            state = store.load().unwrap();
            assert_eq!(state.items[0].reason, r.findings[0].reason);
            assert_eq!(state.items[0].fingerprint, r.findings[0].fingerprint);
            assert!(!state.ingest(&r));
        }
        std::fs::remove_file(root.join(STATE_DIR).join("state.json")).unwrap();
        drop(store);
        remove_store(&root);
    }

    #[test]
    fn old_state_establishes_a_baseline_without_a_repeat_alert() {
        let mut r = report(&[("review", "~/one.csv")]);
        let mut state = Review::default();
        state.ingest(&r);
        state.notified_revision = state.revision;
        r.findings[0].fingerprint = Some("keyed-synthetic".into());
        assert!(!state.ingest(&r));
        assert!(!state.pending(0));
        assert_eq!(state.items[0].fingerprint, r.findings[0].fingerprint);
    }

    #[test]
    fn line_moves_do_not_alert_and_unchecked_or_excluded_locations_do_not_resolve() {
        let mut r = complete(report(&[("review", "~/one.csv")]));
        r.findings[0].fingerprint = Some("synthetic-keyed".into());
        r.findings[0].line = Some(2);
        let mut state = Review::default();
        state.ingest(&r);
        state.notified_revision = state.revision;
        r.findings[0].line = Some(9);
        assert!(!state.ingest(&r));
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items[0].line, Some(9));
        state.resolve(&complete(report(&[])), |_| None);
        assert!(!state.items[0].resolved);
        // Still found on recheck, although the scan did not report it.
        state.resolve(&complete(report(&[])), |_| Some(vec![(None, None)]));
        assert!(!state.items[0].resolved);
    }

    #[test]
    fn review_history_is_bounded_before_serialization() {
        let paths: Vec<_> = (0..4100).map(|n| format!("~/synthetic-{n}.csv")).collect();
        let input: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        let mut state = Review::default();
        state.ingest(&report(&input));
        assert_eq!(state.items.len(), 4096);
        state.items.push(state.items[0].clone());
        let root =
            std::env::temp_dir().join(format!("credential-review-cap-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        assert!(store.save(&state).is_err());
        assert!(!root.join(STATE_DIR).join("state.json").exists());
        drop(store);
        remove_store(&root);
    }

    #[test]
    fn interrupted_private_temp_is_recovered_but_links_are_refused() {
        let root = std::env::temp_dir().join(format!(
            "credential-review-interrupted-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        let temp = root.join(STATE_DIR).join("state.tmp");
        fsutil::write_export(&temp, "interrupted synthetic state", false).unwrap();
        store.save(&Review::default()).unwrap();
        assert!(!temp.exists());
        let state = root.join(STATE_DIR).join("state.json");
        std::fs::hard_link(&state, &temp).unwrap();
        assert!(store.save(&Review::default()).is_err());
        std::fs::remove_file(&temp).unwrap();
        symlink(&state, &temp).unwrap();
        assert!(store.save(&Review::default()).is_err());
        std::fs::remove_file(temp).unwrap();
        assert!(store.load().is_ok());
        std::fs::remove_file(state).unwrap();
        drop(store);
        remove_store(&root);
    }

    #[test]
    fn an_expected_place_is_set_aside_and_does_not_alert() {
        let mut state = Review::default();
        let key = (
            "key.ssh.private",
            "~/.safe-chain/certs/ca-key.pem",
            None,
            None,
        );
        state.ingest(&found(&[key]));
        assert!(state.pending(100));
        state.set_expected(vec![Expected {
            rule: key.0.into(),
            path: key.1.into(),
        }]);
        let d = state
            .decision(&state.items[0], 100)
            .expect("expected applies");
        assert_eq!(d.reason, Reason::Expected);
        assert!(!state.pending(100), "the helper stays quiet");
        // Another rule at the same path is not covered.
        let other = ("secret.service-token", key.1, None, Some("digest-a"));
        state.ingest(&found(&[key, other]));
        assert!(state.decision(&state.items[1], 100).is_none());
        // The person's own decision is what is shown.
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        assert_eq!(
            state.decision(&state.items[0], 100).unwrap().reason,
            Reason::Kept
        );
    }

    #[test]
    fn returning_an_expected_item_keeps_it_open_until_the_list_drops_it() {
        let mut state = Review::default();
        let key = (
            "key.ssh.private",
            "~/.safe-chain/certs/ca-key.pem",
            None,
            None,
        );
        let pair = Expected {
            rule: key.0.into(),
            path: key.1.into(),
        };
        state.ingest(&found(&[key]));
        state.set_expected(vec![pair.clone()]);
        state.undo(state.items[0].id);
        assert!(state.decision(&state.items[0], 100).is_none());
        assert_eq!(state.returned, vec![pair.clone()]);
        // The list sent again does not set it aside again.
        state.set_expected(vec![pair.clone()]);
        assert!(state.decision(&state.items[0], 100).is_none());
        // Kept, then returned: open, not expected again.
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        assert!(state.returned.is_empty());
        state.set_expected(vec![pair.clone()]);
        state.undo(state.items[0].id);
        assert!(state.decision(&state.items[0], 100).is_none());
        // The organization drops it: the return is forgotten.
        state.set_expected(Vec::new());
        assert!(state.returned.is_empty() && state.expected.is_empty());
    }

    #[test]
    fn an_expected_list_is_checked_capped_and_deduplicated() {
        let mut state = Review::default();
        let good = |n: usize| Expected {
            rule: "key.ssh.private".into(),
            path: format!("~/k{n}"),
        };
        let bad = |rule: &str, path: String| Expected {
            rule: rule.into(),
            path,
        };
        let mut list = vec![
            bad("no.such-rule", "~/a".into()),
            bad("key.ssh.private", "/etc/a".into()),
            bad("key.ssh.private", "~/../a".into()),
            bad("key.ssh.private", "~".into()),
            bad("key.ssh.private", "~/caf\u{e9}/key".into()),
            bad("key.ssh.private", format!("~/{}", "x".repeat(4096))),
            good(0),
            good(0),
        ];
        list.extend((1..40).map(good));
        state.set_expected(list);
        assert_eq!(state.expected.len(), MAX_EXPECTED);
        assert!(state
            .expected
            .iter()
            .all(|d| d.reason == Reason::Expected && d.decided == "organization"));
        assert_eq!(
            state.expected.iter().filter(|d| d.path == "~/k0").count(),
            1
        );
        assert!(state.expected.iter().all(|d| d.path.starts_with("~/k")));
        assert_eq!(
            state.decide(0, Reason::Expected, 100, "then".into()),
            Err("That reason is set by your organization's settings.".into())
        );
    }

    #[test]
    fn state_without_the_expected_fields_loads_as_empty_lists() {
        let mut saved = serde_json::to_value(Review::default()).unwrap();
        let map = saved.as_object_mut().unwrap();
        map.remove("expected");
        map.remove("returned");
        let old: Review = serde_json::from_value(saved).unwrap();
        assert!(old.expected.is_empty() && old.returned.is_empty());
    }

    /// Kept, then Move to Worth Reviewing, then the list sent again, as the
    /// window does each time the app comes to the front: still open.
    #[test]
    fn a_returned_item_stays_open_after_the_person_kept_it_once() {
        let mut state = Review::default();
        let key = (
            "key.ssh.private",
            "~/.safe-chain/certs/ca-key.pem",
            None,
            None,
        );
        let pair = Expected {
            rule: key.0.into(),
            path: key.1.into(),
        };
        state.ingest(&found(&[key]));
        state.set_expected(vec![pair.clone()]);
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        state.undo(state.items[0].id);
        assert!(state.decision(&state.items[0], 100).is_none());
        state.set_expected(vec![pair]);
        assert!(
            state.decision(&state.items[0], 100).is_none(),
            "expected again after the list is sent again"
        );
    }

    #[test]
    fn a_copy_of_an_expected_credential_elsewhere_alerts() {
        let mut state = Review::default();
        let key = (
            "key.ssh.private",
            "~/.safe-chain/certs/ca-key.pem",
            None,
            Some("digest-a"),
        );
        state.set_expected(vec![Expected {
            rule: key.0.into(),
            path: key.1.into(),
        }]);
        state.ingest(&found(&[key]));
        seen(&mut state);
        let copy = (
            "key.ssh.private",
            "~/Desktop/ca-key.pem",
            None,
            Some("digest-a"),
        );
        state.ingest(&found(&[key, copy]));
        assert!(state.decision(&state.items[1], 200).is_none());
        assert!(state.pending(200), "the copy elsewhere must alert");
    }

    #[test]
    fn a_decision_about_the_value_does_not_return_an_expected_place() {
        let mut state = Review::default();
        let a = (
            "key.ssh.private",
            "~/.safe-chain/certs/ca-key.pem",
            None,
            Some("digest-a"),
        );
        let b = (
            "key.ssh.private",
            "~/Desktop/ca-key.pem",
            None,
            Some("digest-a"),
        );
        state.set_expected(vec![Expected {
            rule: a.0.into(),
            path: a.1.into(),
        }]);
        state.ingest(&found(&[a, b]));
        state
            .decide(state.items[1].id, Reason::Testing, 100, "then".into())
            .unwrap();
        assert!(state.returned.is_empty(), "{:?}", state.returned);
        assert_eq!(state.expected.len(), 1);
    }
}
