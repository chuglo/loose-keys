use super::*;

#[test]
fn a_public_aws_id_decision_does_not_cover_an_access_secret() {
    let aws_id = ["AK", "IA", "ABCDEFGHIJ", "KLMNOP"].concat();
    let notes = Notes::new("aws-secret-versus-id", &aws_id);
    let mut state = review::Review::default();
    notes.save(&mut state, &notes.scan());
    let id = state.items[0].id;
    state
        .decide(id, review::Reason::NotACredential, now(), "then".into())
        .unwrap();
    std::fs::create_dir(notes.0.join(".aws")).unwrap();
    let path = notes.0.join(".aws/credentials");
    std::fs::write(
        &path,
        format!(
            "[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = synthetic-only-A\n"
        ),
    )
    .unwrap();
    assert!(notes.save(&mut state, &notes.scan()));
    let pair = |state: &review::Review| {
        state
            .items
            .iter()
            .position(|i| i.rule == "dev.aws.inline-credentials" && !i.resolved)
            .unwrap()
    };
    let credential = &state.items[pair(&state)];
    assert!(state.decision(credential, now()).is_none());
    assert!(state.alerting(credential, now()));
    assert!(state.decision(&state.items[0], now()).is_some());
    let group = state.copies_in_its_file(credential.id);
    assert_eq!(
        group.len(),
        1,
        "the generic hit and the profile are one credential"
    );
    state
        .decide(credential.id, review::Reason::Testing, now(), "then".into())
        .unwrap();
    std::fs::write(
        &path,
        format!(
            "[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = synthetic-only-B\n"
        ),
    )
    .unwrap();
    assert!(notes.save(&mut state, &notes.scan()));
    let rotated = &state.items[pair(&state)];
    assert!(state.decision(rotated, now()).is_none());
    assert!(state.alerting(rotated, now()));
    std::fs::write(&path, format!("[default]\naws_access_key_id = {aws_id}\n")).unwrap();
    notes.save(&mut state, &notes.scan());
    assert!(state
        .items
        .iter()
        .all(|i| i.rule != "dev.aws.inline-credentials" || i.resolved));
}

#[test]
fn an_aws_secret_decision_follows_the_value_without_covering_its_public_id() {
    let aws_id = ["AK", "IA", "ABCDEFGHIJ", "KLMNOP"].concat();
    let notes = Notes::new("aws-id-versus-secret", "");
    let aws = notes.0.join(".aws");
    std::fs::create_dir(&aws).unwrap();
    let pair = aws.join("credentials");
    let secret = "synthetic-aws-secret-only";
    let id_only = format!("[default]\naws_access_key_id = {aws_id}\n");
    std::fs::write(
        &pair,
        format!("{id_only}aws_secret_access_key = {secret}\n"),
    )
    .unwrap();
    let assignment = notes.0.join(".env");
    std::fs::write(&assignment, format!("AWS_SECRET_ACCESS_KEY={secret}\n")).unwrap();
    let mut state = review::Review::default();
    notes.save(&mut state, &notes.scan());
    let profile = state
        .items
        .iter()
        .find(|i| i.rule == "dev.aws.inline-credentials")
        .unwrap();
    state
        .decide(profile.id, review::Reason::Testing, now(), "then".into())
        .unwrap();
    let env = state.items.iter().find(|i| i.path == "~/.env").unwrap();
    assert!(
        state.decision(env, now()).is_some(),
        "the same secret has the same decision"
    );

    std::fs::write(&pair, id_only).unwrap();
    notes.save(&mut state, &notes.scan());
    let public = state
        .items
        .iter()
        .find(|i| i.path == "~/.aws/credentials" && !i.resolved)
        .unwrap();
    assert_eq!(public.token_type.as_deref(), Some("AWS access key"));
    assert!(state.decision(public, now()).is_none());
    assert!(state.alerting(public, now()));
}

#[test]
fn a_late_observation_does_not_reopen_a_fixed_item() {
    let a = token('A');
    let notes = Notes::new("late-observation", &a);
    let mut state = review::Review::default();
    let started_at = state.check_generation;
    let older = notes.scan();
    notes.save(&mut state, &older);
    notes.write("");
    notes.save(&mut state, &notes.scan());
    assert_eq!(tokens(&state), [('A', false)]);
    notes.save_observed(&mut state, &older, started_at);
    assert_eq!(tokens(&state), [('A', false)]);
    notes.write(&a);
    assert!(notes.save(&mut state, &notes.scan()));
    assert_eq!(tokens(&state), [('A', true)]);
}

#[test]
fn an_overlapping_scan_does_not_restore_a_pruned_finding() {
    let notes = Notes::new("late-pruned-observation", &token('A'));
    let mut state = review::Review::default();
    let older = notes.scan();
    let started_at = state.check_generation;
    notes.save(&mut state, &older);
    notes.write("");
    notes.save(&mut state, &notes.scan());
    assert_eq!(tokens(&state), [('A', false)]);
    state.items.clear();
    notes.save_observed(&mut state, &older, started_at);
    assert!(state.items.is_empty());
}

/// A scan leaves a wallet's folder unopened, and so does a recheck. What an
/// earlier build listed in it is then not read again, which says nothing
/// about whether it is still there.
#[test]
fn an_item_in_a_folder_left_unopened_is_not_fixed() {
    let phrase = concat!(
        "velvet winner thank year wave sausage ",
        "worth useful legal winner thank yellow\n"
    );
    let notes = Notes::new("unopened-wallet-phrase", phrase);
    let mut older = notes.scan();
    let wallet = "Library/Application Support/Exodus/exodus.wallet";
    let finding = older
        .findings
        .iter_mut()
        .find(|f| f.rule == "wallet.recovery-phrase")
        .expect("the phrase is found where the scan reads it");
    // Where an earlier build read and listed it.
    finding.path = format!("~/{wallet}/notes.txt");
    std::fs::create_dir_all(notes.0.join(wallet)).unwrap();
    std::fs::rename(
        notes.0.join("notes.txt"),
        notes.0.join(wallet).join("notes.txt"),
    )
    .unwrap();
    let mut state = review::Review::default();
    notes.save(&mut state, &older);
    let phrase = |state: &review::Review| {
        state
            .items
            .iter()
            .filter(|i| i.rule == "wallet.recovery-phrase")
            .map(|i| !i.resolved)
            .collect::<Vec<_>>()
    };
    assert_eq!(phrase(&state), [true]);
    notes.save(&mut state, &notes.scan());
    assert_eq!(
        phrase(&state),
        [true],
        "the unchanged file was marked fixed"
    );
}
