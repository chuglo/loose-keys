//! Stored sign-ins: what apps keep so the person stays signed in. They are
//! saved apart from what is worth reviewing, in a part of the state builds
//! before it ignore and drop when they save. None is ever news: a stored
//! sign-in never alerts and never counts toward what does. One can be set
//! aside only as kept here on purpose, which is about the file and so
//! outlasts a refreshed token, and no decision of one kind covers the other.

use super::*;

/// How many stored sign-ins are kept, within `MAX_ITEMS`.
pub const MAX_STORED: usize = 512;
/// Their room as they are stored, within `ITEM_BYTES`, so that what is
/// worth reviewing always keeps seven eighths of it.
const STORED_BYTES: usize = ITEM_BYTES / 8;
/// How many decisions about stored sign-ins are kept, and their room as
/// they are stored, within `MAX_ITEMS` and `DECISION_BYTES`.
const MAX_STORED_DECISIONS: usize = 512;
const STORED_DECISION_BYTES: usize = DECISION_BYTES / 4;

/// Said to any reason but Kept for a stored sign-in.
const NOT_FOR_STORED: &str = "That reason doesn't apply to a stored sign-in.";
const STORED_DECISIONS_FULL: &str =
    "Too many stored sign-ins are set aside. Move some back to Stored Sign-ins.";

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Stored {
    /// Items of the same kind as those worth reviewing, numbered from the
    /// same counter, and with the same keyed fields kept on this side.
    #[serde(default)]
    pub items: Vec<Item>,
    /// The person's decisions about them. Only a Kept is honoured: the file
    /// is one other programs can edit.
    #[serde(default)]
    pub decisions: Vec<Decision>,
    /// Their own counter, never compared with `notified_revision`.
    #[serde(default)]
    pub revision: u64,
    /// A stored sign-in has been left out for lack of room, and no scan the
    /// person ran to its end has since found room for it.
    #[serde(default)]
    pub full: bool,
    /// When a manual scan or the helper's full pass last ended, which every
    /// stored sign-in was looked for in.
    #[serde(default)]
    pub checked_at: Option<String>,
}

impl Review {
    /// The decision that sets this stored sign-in aside, if one applies now:
    /// the person's Kept, or the organization's entry for its file.
    pub fn decision_stored(&self, item: &Item, now: u64) -> Option<&Decision> {
        let mine = self.stored.decisions.iter();
        mine.chain(&self.expected).find(|d| match d.reason {
            Reason::Expected => d.rule == item.rule && d.path == item.path,
            Reason::Kept => kept_covers(d, item, now),
            _ => false,
        })
    }

    /// `decide` for a stored sign-in: Kept only, and with every other copy
    /// of its value in its file decided on by the caller, as for a finding.
    pub(super) fn decide_stored(
        &mut self,
        item: Item,
        reason: Reason,
        now: u64,
        stamp: String,
    ) -> Result<(), String> {
        if reason != Reason::Kept {
            return Err(NOT_FOR_STORED.into());
        }
        forget(&mut self.stored.decisions, &item);
        let decision = Decision::about(item, reason, now, stamp);
        // With the comma before it in the stored list.
        let size = stored_size(&decision) + 1;
        let (others, other_bytes) = (self.decisions.len(), contents(&self.decisions));
        let room = |count: usize, bytes: usize| {
            count < MAX_STORED_DECISIONS
                && bytes + size <= STORED_DECISION_BYTES
                && count + others < MAX_ITEMS
                && bytes + other_bytes + size <= DECISION_BYTES
        };
        let decisions = &mut self.stored.decisions;
        if !room(decisions.len(), stored_size(decisions)) {
            make_room(decisions, &self.stored.items, now, room);
        }
        if !room(decisions.len(), stored_size(decisions)) {
            return Err(STORED_DECISIONS_FULL.into());
        }
        decisions.push(decision);
        Ok(())
    }

    /// `resolve` for stored sign-ins, against the report's stored sign-ins.
    /// One no longer found stays, marked so, and is not shown. It goes when
    /// its room is needed.
    pub fn resolve_stored(&mut self, report: &Report, recheck: impl Fn(&Item) -> Option<Still>) {
        let skipped = self.not_read(&self.stored.items);
        resolve_in(
            &mut self.stored.items,
            &skipped,
            report,
            "inventory",
            recheck,
        );
    }

    /// Take in the stored sign-ins a check found, matched to the listed ones
    /// as findings worth reviewing are. None is news. An item's revision
    /// rises when what it is changes: found again, another value, another
    /// kind of token, or another answer to whether others can read it. Not
    /// for a file written again with the same kind of sign-in in it, so a
    /// refreshed token neither makes a press fail nor ends a Kept.
    pub fn ingest_stored(&mut self, report: &Report) {
        self.number();
        let findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.kind == "inventory")
            .collect();
        let mut claimed = claimed_by_value(&self.stored.items, &findings);
        let mut bytes: Option<usize> = None;
        let mut made_room = false;
        let others = room_taken(&self.items);
        for f in findings {
            let stored = &mut self.stored;
            if let Some(at) = matching(&stored.items, f, &claimed) {
                let item = &mut stored.items[at];
                claimed.insert(item.id);
                let changed = item.resolved
                    || item.secret != f.secret
                    || item.token_type.as_deref() != f.token_type
                    || item.shared != f.shared;
                if changed {
                    stored.revision = stored.revision.saturating_add(1);
                    item.revision = stored.revision;
                }
                fill(item, f, &report.generated_at);
                continue;
            }
            let mut item = Item::new(f, &report.generated_at);
            // Its two numbers are not known yet; allow for their digits.
            let size = stored_size(&item) + 48;
            let mut used = *bytes.get_or_insert_with(|| stored_size(&stored.items));
            let fits = |count: usize, used: usize| {
                count < MAX_STORED
                    && used + size <= STORED_BYTES
                    && count + others.0 < MAX_ITEMS
                    && used + others.1 + size <= ITEM_BYTES
            };
            if !fits(stored.items.len(), used) && !made_room {
                stored.items.retain(|i| !i.resolved);
                used = stored_size(&stored.items);
                made_room = true;
            }
            if !fits(stored.items.len(), used) {
                // As `ingest` sets `full`: here only, for a report of
                // everything to settle.
                stored.full = true;
                bytes = Some(used);
                continue;
            }
            stored.revision = stored.revision.saturating_add(1);
            item.revision = stored.revision;
            self.next_id = self.next_id.saturating_add(1);
            item.id = self.next_id;
            claimed.insert(item.id);
            self.stored.items.push(item);
            bytes = Some(used + size);
        }
    }

    /// As `has_room`, for a stored sign-in within its share.
    pub fn stored_has_room(&self) -> bool {
        let sizes = open_sizes(&self.stored.items);
        // Fixed findings worth reviewing stay listed: `ingest_stored` never
        // takes their room.
        let (others, other_bytes) = room_taken(&self.items);
        let largest = sizes.iter().copied().max().unwrap_or(0) + 48;
        let used = list_bytes(&sizes);
        sizes.len() < MAX_STORED
            && used + largest <= STORED_BYTES
            && sizes.len() + others < MAX_ITEMS
            && used + other_bytes + largest <= ITEM_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{checked, found, report, seen, synthetic_home};
    use super::*;
    use crate::report::NotChecked;
    use std::cell::RefCell;

    const LOGIN: &str = "dev.cli.stored-login";
    const HUB: &str = "~/.config/hub";

    /// A stored sign-in at `path`, with the digest of its value if it has one.
    fn signin(path: &str, secret: Option<&str>) -> Finding {
        Finding {
            rule: LOGIN,
            category: "developer-cloud",
            kind: "inventory",
            severity: "medium",
            title: "Synthetic sign-in",
            explanation: "Synthetic reason.",
            path: path.into(),
            secret: secret.map(str::to_string),
            fingerprint: Some(format!("file-digest-of-{path}")),
            ..Finding::default()
        }
    }

    fn signins(found: &[(&str, Option<&str>)]) -> Report {
        let mut r = report(&[]);
        r.findings = found
            .iter()
            .map(|(path, secret)| signin(path, *secret))
            .collect();
        r
    }

    /// A key file only its owner can read, a stored sign-in, or with
    /// `shared`, one others can read, which is worth reviewing.
    fn key(shared: bool) -> Report {
        let mut r = report(&[]);
        r.findings = vec![Finding {
            rule: "key.ssh.private",
            category: "private-key",
            kind: if shared { "review" } else { "inventory" },
            severity: "low",
            title: "Possible private key",
            explanation: "Synthetic reason.",
            path: "~/.ssh/id_synthetic".into(),
            fingerprint: Some(format!("key-digest-shared-{shared}")),
            shared,
            ..Finding::default()
        }];
        r
    }

    /// What reading a key file again finds when others can or cannot read
    /// it now: something of the kind asked about, or nothing.
    fn key_now(shared: bool) -> impl Fn(&Item, Want) -> Option<Still> {
        move |_, want| {
            Some(if (want == Want::Review) == shared {
                vec![(None, None)]
            } else {
                vec![]
            })
        }
    }

    #[test]
    fn stored_sign_ins_are_saved_without_alerting() {
        let mut state = Review::default();
        let token = (
            "secret.service-token",
            "~/a/.env",
            Some("Test token"),
            Some("digest-a"),
        );
        assert!(checked(&mut state, &found(&[token])));
        seen(&mut state);
        state.attempted(100);
        let alerts = |s: &Review| (s.revision, s.notified_revision, s.attempts, s.retry_at);
        let before = alerts(&state);
        // Saved, apart from what is worth reviewing, and nothing is news.
        assert!(!checked(&mut state, &signins(&[(HUB, None)])));
        assert_eq!(state.stored.items.len(), 1);
        assert_eq!(state.stored.items[0].revision, state.stored.revision);
        assert!(state.stored.items[0].id != 0);
        assert!(state.items.iter().all(|i| i.rule != LOGIN));
        // Places that could not be read do not alert either.
        assert!(!checked(&mut state, &report(&[])));
        assert_eq!(alerts(&state), before);
        assert!(!state.pending(1000));
    }

    #[test]
    fn a_worth_reviewing_copy_of_a_stored_value_alerts() {
        let mut state = Review::default();
        checked(&mut state, &signins(&[(HUB, Some("digest-a"))]));
        seen(&mut state);
        let copy = (
            "secret.service-token",
            "~/notes.md",
            Some("Test token"),
            Some("digest-a"),
        );
        assert!(checked(&mut state, &found(&[copy])));
        assert!(state.items[0].revision > state.notified_revision);
        assert!(state.pending(1000));
    }

    #[test]
    fn a_stored_sign_in_left_out_of_a_slice_stays_while_its_file_holds_it() {
        let mut state = Review::default();
        checked(&mut state, &signins(&[(HUB, None)]));
        let asked = RefCell::new(Vec::new());
        let never_reviewed = |item: &Item, want: Want, still: Option<Still>| {
            assert_eq!(want, Want::Stored, "a stored sign-in was read for review");
            asked.borrow_mut().push(item.path.clone());
            still
        };
        // Still there, or not known: it stays.
        state.merge(&report(&[]), |i, w| {
            never_reviewed(i, w, Some(vec![(None, None)]))
        });
        state.merge(&report(&[]), |i, w| never_reviewed(i, w, None));
        assert!(!state.stored.items[0].resolved);
        // Gone from its file: it is no longer found.
        state.merge(&report(&[]), |i, w| never_reviewed(i, w, Some(vec![])));
        assert!(state.stored.items[0].resolved);
        assert_eq!(asked.borrow().len(), 3);

        // Under a place the scan could not read, in a folder the person
        // stopped checking, or in a file the report may have left values
        // out of, nothing is read again.
        let unread = "/Volumes/Synthetic";
        let corpus = "~/corpus/sign-in.json";
        let mut state = Review::default();
        let many: Vec<String> = (0..HITS_PER_FILE).map(|n| format!("digest-{n}")).collect();
        let mut first = signins(&[(&format!("{unread}/.config/hub"), None), (corpus, None)]);
        first.findings.push(signin(HUB, Some("digest-old")));
        checked(&mut state, &first);
        assert_eq!(state.stored.items.len(), 3);
        state.skipped.push(Skip {
            path: "~/corpus".into(),
            added: "then".into(),
        });
        let mut later = signins(
            &many
                .iter()
                .map(|d| (HUB, Some(d.as_str())))
                .collect::<Vec<_>>(),
        );
        later.coverage.roots = vec![unread.into()];
        later.not_checked.push(NotChecked {
            path: unread.into(),
            reason: "unreadable",
        });
        state.resolve_stored(&later, |item| panic!("{} was read again", item.path));
        assert!(state.stored.items.iter().all(|i| !i.resolved));
    }

    #[test]
    fn stored_sign_ins_take_only_their_share_of_the_list() {
        let paths: Vec<String> = (0..=MAX_STORED)
            .map(|n| format!("~/.kube/cache/oidc-login/{n}"))
            .collect();
        let pairs: Vec<(&str, Option<&str>)> = paths.iter().map(|p| (p.as_str(), None)).collect();
        let mut state = Review::default();
        state.ingest_stored(&signins(&pairs));
        assert_eq!(state.stored.items.len(), MAX_STORED);
        assert!(state.stored.full && !state.full);
        assert!(!state.stored_has_room() && state.has_room());
        // What is worth reviewing still fits.
        assert!(state.ingest(&report(&[("review", "~/one.csv")])));
        assert_eq!(state.items.len(), 1);
        // One no longer found makes room for another.
        state.stored.items[0].resolved = true;
        assert!(state.stored_has_room());
        state.ingest_stored(&signins(&[("~/.config/hub", None)]));
        assert_eq!(state.stored.items.len(), MAX_STORED);
        assert!(state.stored.items.iter().any(|i| i.path == HUB));

        // By size as well as by number.
        let long: Vec<String> = (0..40)
            .map(|n| format!("~/{}/sign-in-{n}.json", "d".repeat(60_000)))
            .collect();
        let pairs: Vec<(&str, Option<&str>)> = long.iter().map(|p| (p.as_str(), None)).collect();
        let mut state = Review::default();
        state.ingest_stored(&signins(&pairs));
        assert!(state.stored.full && !state.full);
        assert!(state.stored.items.len() < 20);
        assert!(stored_size(&state.stored.items) <= STORED_BYTES);
        assert!(state.ingest(&report(&[("review", "~/one.csv")])));

        // And the reverse: a full Worth Reviewing leaves the stored sign-ins
        // listed, and says nothing of their room.
        let mut state = Review::default();
        state.ingest_stored(&signins(&[(HUB, None)]));
        let paths: Vec<_> = (0..MAX_ITEMS).map(|n| format!("~/s-{n}.csv")).collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert_eq!(state.items.len(), MAX_ITEMS - 1);
        assert!(state.full && !state.stored.full);
        assert_eq!(state.stored.items.len(), 1);
        // One no longer found, which is not shown, gives its room to a
        // finding worth reviewing.
        state.stored.items[0].resolved = true;
        assert!(state.ingest(&report(&[("review", "~/one-more.csv")])));
        assert!(state.stored.items.is_empty());
        assert_eq!(state.items.len(), MAX_ITEMS);
    }

    /// Fixed findings worth reviewing stay listed, and a stored sign-in
    /// never takes their room, so they count against it.
    #[test]
    fn fixed_findings_worth_reviewing_hold_the_room_a_sign_in_needs() {
        let mut state = Review::default();
        let paths: Vec<_> = (0..MAX_ITEMS).map(|n| format!("~/s-{n}.csv")).collect();
        let pairs: Vec<_> = paths.iter().map(|p| ("review", p.as_str())).collect();
        state.ingest(&report(&pairs));
        assert_eq!(state.items.len(), MAX_ITEMS);
        for item in state.items.iter_mut().take(MAX_STORED) {
            item.resolved = true;
        }
        state.ingest_stored(&signins(&[(HUB, None)]));
        assert!(state.stored.items.is_empty() && state.stored.full);
        assert!(!state.stored_has_room());
    }

    #[test]
    fn a_report_lists_review_findings_before_stored_sign_ins() {
        let mut state = Review::default();
        let token = (
            "secret.service-token",
            "~/a/.env",
            Some("Test token"),
            Some("digest-a"),
        );
        let mut both = found(&[token]);
        both.findings.push(signin(HUB, None));
        checked(&mut state, &both);
        let asked = RefCell::new(Vec::new());
        state.merge(&report(&[]), |item, want| {
            asked.borrow_mut().push((want, item.path.clone()));
            None
        });
        assert_eq!(
            *asked.borrow(),
            [
                (Want::Review, "~/a/.env".into()),
                (Want::Stored, HUB.into())
            ]
        );
    }

    #[test]
    fn a_file_made_readable_alerts_as_a_new_finding() {
        let mut state = Review::default();
        assert!(!state.merge(&key(false), key_now(false)));
        assert_eq!((state.items.len(), state.stored.items.len()), (0, 1));
        seen(&mut state);
        assert!(state.merge(&key(true), key_now(true)));
        assert!(state.stored.items[0].resolved);
        assert_eq!(state.items.len(), 1);
        assert!(state.pending(1000));
    }

    #[test]
    fn a_finding_made_private_becomes_a_quiet_stored_sign_in() {
        let mut state = Review::default();
        assert!(state.merge(&key(true), key_now(true)));
        seen(&mut state);
        assert!(!state.merge(&key(false), key_now(false)));
        assert!(state.items[0].resolved);
        assert_eq!(state.stored.items.len(), 1);
        assert!(!state.stored.items[0].resolved);
        assert!(!state.pending(1000));
    }

    #[test]
    fn only_keeping_it_here_sets_aside_a_stored_sign_in() {
        let mut state = Review::default();
        checked(&mut state, &signins(&[(HUB, None)]));
        let (id, revision) = (state.stored.items[0].id, state.stored.items[0].revision);
        let set_aside = |s: &Review, now| s.decision_stored(&s.stored.items[0], now).is_some();
        for reason in [
            Reason::NotACredential,
            Reason::Testing,
            Reason::NoLongerWorks,
            Reason::TestOrRevoked,
        ] {
            assert_eq!(
                state.decide(id, reason, 100, "then".into()),
                Err(NOT_FOR_STORED.into())
            );
        }
        assert!(state.decisions.is_empty() && state.stored.decisions.is_empty());
        // A press on the row as it was drawn, and no other.
        assert_eq!(state.as_shown(id, revision + 1), Err(CHANGED.into()));
        assert_eq!(state.as_shown(id, revision), Ok(()));
        state.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        assert!(set_aside(&state, 200));
        assert!(state.decisions.is_empty());
        state.undo(id);
        assert!(!set_aside(&state, 200));
        // It comes back after six months, without an alert.
        state.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        seen(&mut state);
        assert!(!set_aside(&state, 100 + RECONFIRM));
        assert!(!state.pending(100 + RECONFIRM));
        // The organization's list sets it aside too, until moved back.
        state.undo(id);
        let entry = Expected {
            rule: LOGIN.into(),
            path: HUB.into(),
        };
        state.set_expected(vec![entry.clone()]);
        assert!(set_aside(&state, 200));
        state.undo(id);
        assert!(!set_aside(&state, 200));
        assert_eq!(state.returned, [entry]);

        // Room for the decisions runs out before the room for the items.
        let mut state = Review::default();
        let paths: Vec<String> = (0..200)
            .map(|n| format!("~/{}/sign-in-{n}.json", "d".repeat(1000)))
            .collect();
        let pairs: Vec<(&str, Option<&str>)> = paths.iter().map(|p| (p.as_str(), None)).collect();
        state.ingest_stored(&signins(&pairs));
        assert_eq!(state.stored.items.len(), 200);
        let ids: Vec<u64> = state.stored.items.iter().map(|i| i.id).collect();
        let refused = ids
            .iter()
            .map(|id| state.decide(*id, Reason::Kept, 100, "then".into()))
            .find(Result::is_err);
        assert_eq!(refused, Some(Err(STORED_DECISIONS_FULL.into())));
        assert!(stored_size(&state.stored.decisions) <= STORED_DECISION_BYTES);
        assert!(state.stored.decisions.len() <= MAX_STORED_DECISIONS);
    }

    #[test]
    fn kept_on_a_stored_sign_in_outlasts_a_token_refresh() {
        let mut state = Review::default();
        checked(&mut state, &signins(&[(HUB, None)]));
        let (id, revision) = (state.stored.items[0].id, state.stored.items[0].revision);
        state.decide(id, Reason::Kept, 100, "then".into()).unwrap();
        // The file is written again with a new token in it.
        let mut refreshed = signins(&[(HUB, None)]);
        refreshed.findings[0].fingerprint = Some("file-digest-after-refresh".into());
        assert!(!checked(&mut state, &refreshed));
        let item = &state.stored.items[0];
        assert_eq!(
            item.fingerprint.as_deref(),
            Some("file-digest-after-refresh")
        );
        assert_eq!(item.revision, revision);
        assert_eq!(state.as_shown(id, revision), Ok(()));
        assert!(state.decision_stored(item, 200).is_some());
        // Another kind of sign-in in it is not what was agreed to.
        refreshed.findings[0].token_type = Some("Another token");
        assert!(!checked(&mut state, &refreshed));
        let item = &state.stored.items[0];
        assert!(item.revision > revision);
        assert!(state.as_shown(id, revision).is_err());
        assert!(state.decision_stored(item, 200).is_none());
    }

    #[test]
    fn decisions_never_cross_kinds() {
        // Kept on a stored sign-in does not cover a finding worth reviewing
        // at the same place, alike in every other way.
        let mut state = Review::default();
        checked(&mut state, &signins(&[(HUB, None)]));
        let stored = state.stored.items[0].id;
        state
            .decide(stored, Reason::Kept, 100, "then".into())
            .unwrap();
        seen(&mut state);
        let mut worth = signins(&[(HUB, None)]);
        worth.findings[0].kind = "review";
        assert!(checked(&mut state, &worth));
        assert!(state.decision(&state.items[0], 200).is_none());
        assert!(state.pending(200));
        // Nor does Kept on that finding cover the stored sign-in.
        let mut state = Review::default();
        checked(&mut state, &worth);
        state
            .decide(state.items[0].id, Reason::Kept, 100, "then".into())
            .unwrap();
        checked(&mut state, &signins(&[(HUB, None)]));
        assert!(state.decision_stored(&state.stored.items[0], 200).is_none());
        // A reason about a value worth reviewing does not cover a stored copy.
        let mut state = Review::default();
        let token = (
            "secret.service-token",
            "~/notes.md",
            Some("Test token"),
            Some("digest-a"),
        );
        checked(&mut state, &found(&[token]));
        state
            .decide(state.items[0].id, Reason::Testing, 100, "then".into())
            .unwrap();
        checked(&mut state, &signins(&[(HUB, Some("digest-a"))]));
        assert!(state.decision_stored(&state.stored.items[0], 200).is_none());
        // A stored copy's decision cannot come to cover the value either:
        // one about the value is refused for it.
        let id = state.stored.items[0].id;
        assert!(state
            .decide(id, Reason::NotACredential, 100, "then".into())
            .is_err());
    }

    /// The organization's entry for a file covers both kinds in it. One kind
    /// moved back stays open when the other is set aside and the list is
    /// sent again, as the window does each time the app comes to the front.
    #[test]
    fn setting_one_kind_aside_keeps_the_other_returned() {
        let entry = Expected {
            rule: LOGIN.into(),
            path: HUB.into(),
        };
        let mut both = signins(&[(HUB, None)]);
        let mut worth = signin(HUB, Some("digest-live"));
        worth.kind = "review";
        both.findings.push(worth);
        for stored_returned in [false, true] {
            let mut state = Review::default();
            checked(&mut state, &both);
            state.set_expected(vec![entry.clone()]);
            let (stored, finding) = (state.stored.items[0].id, state.items[0].id);
            let (back, aside) = if stored_returned {
                (stored, finding)
            } else {
                (finding, stored)
            };
            state.undo(back);
            state
                .decide(aside, Reason::Kept, 100, "then".into())
                .unwrap();
            state.set_expected(vec![entry.clone()]);
            let open = if stored_returned {
                state.decision_stored(&state.stored.items[0], 200)
            } else {
                state.decision(&state.items[0], 200)
            };
            assert!(open.is_none(), "set aside again, stored: {stored_returned}");
        }
    }

    #[test]
    fn an_older_build_saving_drops_stored_sign_ins_without_alerting() {
        let mut state = Review::default();
        let token = (
            "secret.service-token",
            "~/a/.env",
            Some("Test token"),
            Some("digest-a"),
        );
        checked(&mut state, &found(&[token]));
        checked(&mut state, &signins(&[(HUB, None), ("~/.netrc", None)]));
        state.stored.checked_at = Some("then".into());
        let kept = state.stored.items[0].id;
        state
            .decide(kept, Reason::Kept, 100, "then".into())
            .unwrap();
        seen(&mut state);
        // As a build without them saves the state: without the section.
        let mut saved = serde_json::to_value(&state).unwrap();
        saved.as_object_mut().unwrap().remove("stored");
        let mut older: Review = serde_json::from_value(saved).unwrap();
        assert!(older.stored.items.is_empty() && older.stored.decisions.is_empty());
        assert!(older.stored.checked_at.is_none() && !older.stored.full);
        assert!(older.items.iter().all(|i| i.rule != LOGIN));
        assert!(!older.pending(1000));
        // Such a build numbers a finding of its own from the counter it kept.
        let more = (
            "secret.service-token",
            "~/b/.env",
            Some("Test token"),
            Some("digest-b"),
        );
        older.ingest(&found(&[more]));
        // The next scan lists the sign-ins again, quietly, under ids no item
        // has had.
        seen(&mut older);
        assert!(!checked(&mut older, &signins(&[(HUB, None)])));
        let mut ids: Vec<u64> = older.items.iter().map(|i| i.id).collect();
        ids.extend(older.stored.items.iter().map(|i| i.id));
        assert!(older.stored.items.iter().all(|i| i.id > state.next_id));
        let distinct: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len());
        assert!(older.ids_hold());
        assert!(older.decision_stored(&older.stored.items[0], 200).is_none());
    }

    #[test]
    fn load_refuses_clashing_ids_and_too_many_stored_sign_ins() {
        refused(
            "stored-ids-clash",
            "The review list file is damaged or in an unknown format.",
            |state| {
                state.stored.items[0].id = state.items[0].id;
            },
        );
        refused(
            "stored-too-many",
            "The review list is too large for automatic scanning.",
            |state| {
                let paths: Vec<String> = (0..MAX_STORED).map(|n| format!("~/s-{n}")).collect();
                let pairs: Vec<(&str, Option<&str>)> =
                    paths.iter().map(|p| (p.as_str(), None)).collect();
                let mut more = Review::default();
                more.ingest_stored(&signins(&pairs));
                for mut item in more.stored.items {
                    state.next_id += 1;
                    item.id = state.next_id;
                    state.stored.items.push(item);
                }
            },
        );
    }

    /// A state that `damage` leaves as no build of this app saves it is
    /// refused when saved, and when read back from a file made that way.
    fn refused(name: &str, error: &str, damage: impl FnOnce(&mut Review)) {
        let root = synthetic_home(name);
        let store = Store::open(&root).unwrap();
        let mut state = Review::default();
        checked(&mut state, &report(&[("review", "~/one.csv")]));
        checked(&mut state, &signins(&[(HUB, None)]));
        store.save(&state).unwrap();
        assert!(store.read().is_ok());
        damage(&mut state);
        assert!(store.save(&state).is_err(), "{name}: saved");
        let path = root.join(STATE_DIR).join("state.json");
        std::fs::remove_file(&path).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        fsutil::write_export(&path, &json, false).unwrap();
        assert_eq!(store.read().err().as_deref(), Some(error), "{name}");
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
