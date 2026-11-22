use super::*;

fn give_access(path: &Path, entry: &str) {
    let out = std::process::Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .output()
        .unwrap();
    assert!(out.status.success(), "chmod: {:?}", out.stderr);
}

#[test]
fn review_store_accepts_inherited_deny_only_access_lists() {
    let home = synthetic_home("deny-only-acl");
    let parent = home.join("Library/Application Support");
    std::fs::create_dir_all(&parent).unwrap();
    give_access(
        &parent,
        "group:everyone deny writeextattr,file_inherit,directory_inherit",
    );
    let store = Store::open(&home).unwrap();
    store.update(|_| Ok(())).unwrap();
    assert!(store.read().is_ok());
    store
        .update(|state| {
            state.monitoring = true;
            Ok(())
        })
        .unwrap();
    assert!(Store::open(&home).unwrap().read().unwrap().monitoring);
    // An export still refuses a file that would inherit any ACL.
    assert!(fsutil::write_export(&parent.join("export.json"), "{}", false).is_err());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn review_store_refuses_inherited_access_before_writing_state() {
    let home = synthetic_home("inherited-access");
    std::fs::create_dir_all(home.join("Library/Application Support")).unwrap();
    give_access(
        &home.join("Library/Application Support"),
        "group:everyone deny writeextattr,file_inherit,directory_inherit",
    );
    give_access(
        &home.join("Library/Application Support"),
        "group:everyone allow read,search,file_inherit,directory_inherit",
    );
    let saved = Store::open(&home).and_then(|store| store.update(|_| Ok(())));
    assert!(saved.is_err());
    assert!(std::fs::symlink_metadata(home.join(STATE_DIR).join("state.json")).is_err());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn review_store_refuses_an_access_list_on_existing_state() {
    let home = synthetic_home("file-access");
    let store = Store::open(&home).unwrap();
    store.update(|_| Ok(())).unwrap();
    let state = home.join(STATE_DIR).join("state.json");
    let before = std::fs::read(&state).unwrap();
    give_access(&state, "group:everyone allow read");
    assert!(store.read().is_err());
    assert!(store.update(|_| Ok(())).is_err());
    assert_eq!(std::fs::read(state).unwrap(), before);
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn review_store_preserves_good_state_when_its_temporary_file_has_an_access_list() {
    let home = synthetic_home("temp-access");
    let store = Store::open(&home).unwrap();
    store.update(|_| Ok(())).unwrap();
    let state = home.join(STATE_DIR).join("state.json");
    let before = std::fs::read(&state).unwrap();
    let temp = home.join(STATE_DIR).join("state.tmp");
    fsutil::write_export(&temp, "synthetic interrupted data", false).unwrap();
    give_access(&temp, "group:everyone allow read");
    assert!(store
        .update(|review| {
            review.monitoring = true;
            Ok(())
        })
        .is_err());
    assert_eq!(std::fs::read(&state).unwrap(), before);
    assert!(std::fs::symlink_metadata(temp).is_ok());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn review_store_leaves_legacy_state_with_an_access_list_in_place() {
    let home = synthetic_home("legacy-access");
    let old = home.join(".loose-keys-review");
    std::fs::create_dir(&old).unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = old.join("state.json");
    std::fs::write(&file, br#"{"items":[],"monitoring":true}"#).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    give_access(&file, "group:everyone allow read");
    assert!(Store::open(&home).is_err());
    assert!(std::fs::symlink_metadata(file).is_ok());
    assert!(std::fs::symlink_metadata(home.join(STATE_DIR).join("state.json")).is_err());
    std::fs::remove_dir_all(home).unwrap();
}
