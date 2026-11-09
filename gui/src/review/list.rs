//! What one list of items does, shared by what is worth reviewing and by
//! stored sign-ins: matching a report's findings to listed items, reading
//! files again to tell what is gone, and the room items and decisions take.

use super::*;

/// Whether a decision is about this item's place: its rule, file and what
/// it concerns there.
pub(super) fn same_place(d: &Decision, item: &Item) -> bool {
    d.rule == item.rule && d.path == item.path && d.identity() == item.identity()
}

/// Whether a Kept covers this item now. It is about the place: a rotated
/// value of the same kind stays quiet, but not anything worse than what
/// was agreed to, and not past six months.
pub(super) fn kept_covers(d: &Decision, item: &Item, now: u64) -> bool {
    same_place(d, item)
        && d.token_type == item.token_type
        && (d.shared || !item.shared)
        && rank(&item.severity) >= rank(&d.severity)
        && now < d.decided_at.saturating_add(RECONFIRM)
}

impl Decision {
    /// A decision about `item` for `reason`: about its value where it has
    /// one, for any reason but Kept, which is about its place.
    pub(super) fn about(item: Item, reason: Reason, now: u64, stamp: String) -> Self {
        Decision {
            reason,
            secret: item.secret.filter(|_| reason != Reason::Kept),
            rule: item.rule,
            path: item.path,
            scope: item.scope,
            subject: item.subject,
            fingerprint: item.fingerprint,
            token_type: item.token_type,
            shared: item.shared,
            severity: item.severity,
            decided: stamp,
            decided_at: now,
        }
    }
}

/// The other places in `items` the same credential is stored, plus this one.
pub(super) fn copies(items: &[Item], id: u64) -> Vec<usize> {
    let Some(at) = items.iter().position(|i| i.id == id) else {
        return Vec::new();
    };
    let secret = &items[at].secret;
    (0..items.len())
        .filter(|n| *n == at || (secret.is_some() && items[*n].secret == *secret))
        .collect()
}

/// Remove the person's decisions in `decisions` that set this item aside.
/// The organization's list is left as it is.
pub(super) fn forget(decisions: &mut Vec<Decision>, item: &Item) {
    decisions.retain(|d| match &d.secret {
        Some(secret) => item.secret.as_ref() != Some(secret),
        None => !same_place(d, item),
    });
}

/// Room for one more decision in `decisions`, made from those no item in
/// `items` uses, until `room` says the list, at its count and stored size,
/// has it. Each list makes room from its own decisions only. A decision
/// stays when what it was about leaves the list, where the person can no
/// longer move it back. Such a decision only sets aside a credential found
/// again, so dropping one can make that ask for attention again, never hide
/// it. A Kept that has run out sets nothing aside, so those go first; then
/// the oldest. A decision a listed item uses stays, even a Kept that has
/// run out: `ingest` reads that one to tell whether a copy of a credential
/// is news.
pub(super) fn make_room(
    decisions: &mut Vec<Decision>,
    items: &[Item],
    now: u64,
    room: impl Fn(usize, usize) -> bool,
) {
    let secrets: std::collections::HashSet<&String> =
        items.iter().filter_map(|i| i.secret.as_ref()).collect();
    let places: std::collections::HashSet<_> = items
        .iter()
        .map(|i| (&i.rule, &i.path, i.identity()))
        .collect();
    // As `forget` matches them: by value where there is one, else by place.
    let used = |d: &Decision| match &d.secret {
        Some(secret) => secrets.contains(secret),
        None => places.contains(&(&d.rule, &d.path, d.identity())),
    };
    let run_out =
        |d: &Decision| d.reason == Reason::Kept && now >= d.decided_at.saturating_add(RECONFIRM);
    decisions.retain(|d| used(d) || !run_out(d));
    let mut bytes = stored_size(decisions);
    while !room(decisions.len(), bytes) {
        let Some(oldest) = decisions.iter().position(|d| !used(d)) else {
            break;
        };
        let gone = decisions.remove(oldest);
        bytes = bytes.saturating_sub(stored_size(&gone) + 1);
    }
}

/// What a list adds to another of its kind in the stored state: its items
/// and the comma before each, without its own brackets.
pub(super) fn contents<T: Serialize>(list: &[T]) -> usize {
    match list {
        [] => 0,
        _ => stored_size(&list).saturating_sub(1),
    }
}

/// How many items a list holds and what they add to the room the lists
/// share, as `contents` counts it.
pub(super) fn room_taken(items: &[Item]) -> (usize, usize) {
    (items.len(), contents(items))
}

/// The stored size of each item still open.
pub(super) fn open_sizes(items: &[Item]) -> Vec<usize> {
    items
        .iter()
        .filter(|i| !i.resolved)
        .map(stored_size)
        .collect()
}

/// As a stored list: each item, a comma between two, and the brackets.
pub(super) fn list_bytes(sizes: &[usize]) -> usize {
    sizes.iter().sum::<usize>() + sizes.len() + 1
}

/// As `room_taken`, for the open items only: the fixed ones are dropped
/// when their room is needed.
pub(super) fn open_room(items: &[Item]) -> (usize, usize) {
    let sizes = open_sizes(items);
    (sizes.len(), sizes.iter().sum::<usize>() + sizes.len())
}

/// The items in `items` that hold a value some finding has at their place.
///
/// One place can hold several credentials of one kind: two tokens in one
/// session record are two findings with the same rule, path and subject.
/// Each is its own item, known by its value. A finding goes to the item
/// that holds its value. Failing that, it takes an item at its place that no
/// finding of this report claims and whose value is gone, which is a value
/// changed in place. Failing that, it is a new item. The items claimed by
/// value are settled first, so that a new value met earlier in the report
/// does not take the item of one that is still there.
pub(super) fn claimed_by_value(
    items: &[Item],
    findings: &[&Finding],
) -> std::collections::HashSet<u64> {
    items
        .iter()
        .filter(|i| {
            i.secret.is_some()
                && findings
                    .iter()
                    .any(|f| at_place(i, f) && f.secret == i.secret)
        })
        .map(|i| i.id)
        .collect()
}

pub(super) fn at_place(i: &Item, f: &Finding) -> bool {
    i.rule == f.rule && i.path == f.path && i.identity() == f.identity()
}

/// Which item of `items` a finding goes to, as `claimed_by_value` says.
///
/// That a report leaves a value out does not show the value is gone: the
/// report says what its scan read, and an older scan can be saved after a
/// newer one. So the item taken is one already marked fixed, which
/// `resolve` does on a fresh read (`merge` asks it first), or one stored
/// with no value to lose. An open item keeps its value, and what was
/// decided about another value cannot come to cover it.
pub(super) fn matching(
    items: &[Item],
    f: &Finding,
    claimed: &std::collections::HashSet<u64>,
) -> Option<usize> {
    items
        .iter()
        .position(|i| f.secret.is_some() && at_place(i, f) && i.secret == f.secret)
        // A finding with no value to go by takes the item at its place.
        .or_else(|| {
            items.iter().position(|i| {
                let free = !claimed.contains(&i.id) && (i.resolved || i.secret.is_none());
                at_place(i, f) && (f.secret.is_none() || free)
            })
        })
}

/// Bring a listed item up to date with the finding that went to it.
pub(super) fn fill(item: &mut Item, f: &Finding, generated_at: &str) {
    // Another value taking the item was first seen now.
    if matches!((&item.secret, &f.secret), (Some(old), Some(now)) if old != now) {
        item.first_seen = Some(generated_at.to_string());
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
    item.subject = f.subject.clone();
    item.title = f.title.into();
    item.explanation = f.explanation.into();
    item.reason = f.reason.clone();
    item.next_step = f.next_step.map(str::to_string);
    item.severity = f.severity.into();
    item.steps = f.steps.iter().map(|s| s.to_string()).collect();
    item.link = f.link.map(str::to_string);
}

impl Item {
    /// A new item for a finding. Its revision and id are given once it is
    /// known to fit.
    pub(super) fn new(f: &Finding, generated_at: &str) -> Self {
        Item {
            fingerprint: f.fingerprint.clone(),
            resolved: false,
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
            scope: f.scope.clone(),
            subject: f.subject.clone(),
            first_seen: Some(generated_at.to_string()),
            resolved_at: None,
            deferred: false,
            id: 0,
            secret: f.secret.clone(),
            detail: f.detail.clone(),
            token_type: f.token_type.map(str::to_string),
            shared: f.shared,
            mount: f.mount,
        }
    }
}

/// `Review::resolve` over one list, for the findings of its `kind`.
/// `skipped` says, for each item, whether a scan leaves its file unread.
pub(super) fn resolve_in(
    items: &mut [Item],
    skipped: &[bool],
    report: &Report,
    kind: &str,
    recheck: impl Fn(&Item) -> Option<Still>,
) {
    // The values the report holds at each place, and how much it holds
    // for each file.
    let mut seen: std::collections::HashMap<_, Vec<Option<&str>>> = Default::default();
    let mut hits: std::collections::HashMap<&str, usize> = Default::default();
    for f in report.findings.iter().filter(|f| f.kind == kind) {
        seen.entry((f.rule, f.path.as_str(), f.identity()))
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
        .roots
        .iter()
        .filter(|root| {
            report
                .not_checked
                .iter()
                .any(|g| g.path == **root && matches!(g.reason, "unreadable" | "permission-denied"))
        })
        .map(String::as_str)
        .collect();
    for (i, skipped) in items.iter_mut().zip(skipped) {
        if i.resolved || *skipped {
            continue;
        }
        if let Some(values) = seen.get(&(i.rule.as_str(), i.path.as_str(), i.identity())) {
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
