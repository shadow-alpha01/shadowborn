use shadowborn_core::{Config, Secret, State};
use shadowborn_platform::*;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
fn state() -> State {
    State {
        schema_version: 1,
        config: Config::parse(include_str!("../../../config/server.example.toml")).unwrap(),
        server_private_key: Secret::new(format!("{}A=", "B".repeat(42))).unwrap(),
        server_public_key: format!("{}A=", "C".repeat(42)),
        peers: vec![],
    }
}
#[test]
fn lock_conflicts_atomic_compare_and_no_extra_history() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = Store::open(dir.path(), false).unwrap();
    assert!(Store::open(dir.path(), false).is_err());
    let first = state();
    store.save(None, &first).unwrap();
    assert!(store.save(None, &first).is_err());
    let mut next = first.clone();
    next.config.server.ssh_port = 2222;
    store.save(Some(&first), &next).unwrap();
    assert!(store.save(Some(&first), &first).is_err());
    assert_eq!(store.load().unwrap(), next);
    let mut names = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, vec!["lock", "state.json"]);
    assert_eq!(
        fs::metadata(dir.path().join("state.json")).unwrap().mode() & 0o777,
        0o600
    );
}
#[test]
fn symlinks_hardlinks_and_unsafe_permissions_rejected() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.path().join("secret");
    write_new_secret(&file, b"fixture").unwrap();
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert!(read_secret(&link).is_err());
    let hard = dir.path().join("hard");
    fs::hard_link(&file, &hard).unwrap();
    assert!(read_secret(&hard).is_err());
    fs::remove_file(hard).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_secret(&file).is_err());
    assert!(write_new_secret(&file, b"replace").is_err());
    assert_eq!(fs::read(file).unwrap(), b"fixture");
}
#[test]
fn bundles_do_not_overwrite_and_are_private() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = dir.path().join("bundle");
    export_bundle(&output, &state()).unwrap();
    assert!(export_bundle(&output, &state()).is_err());
    for file in fs::read_dir(output).unwrap() {
        assert_eq!(file.unwrap().metadata().unwrap().mode() & 0o777, 0o600);
    }
}
#[test]
fn unknown_command_and_state_schema_cannot_echo_secrets() {
    assert!(run("sh", &["-c", "exit 0"], &[]).is_err());
    let error = Store::decode(br#"{"private_key":"SENSITIVE_FIXTURE"}"#).unwrap_err();
    assert!(!error.to_string().contains("SENSITIVE_FIXTURE"));
}

#[test]
fn traversal_is_rejected_before_any_directory_is_created() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let inner = dir.path().join("inner");
    fs::create_dir(&inner).unwrap();
    let escaped = dir.path().join("escaped");
    assert!(create_private(&inner.join("../escaped")).is_err());
    assert!(!escaped.exists());
    assert!(create_private(std::path::Path::new("relative-private-test")).is_err());
}
