//! Patched dependency floors without relaxing the pinned LiveSync client contract.

#[test]
fn bundled_sqlite_contains_the_mismatched_wal_page_size_fix() {
    // RUSTSEC-2026-0459 / CVE-2026-119375 is fixed in SQLite 3.54.0.
    // Check the library actually linked into every test binary, not just Cargo.toml.
    assert!(
        rusqlite::version_number() >= 3_054_000,
        "bundled SQLite {} predates the WAL page-size fix",
        rusqlite::version()
    );
}

#[test]
fn compatibility_client_keeps_its_protocol_pin_and_patched_glob_dependency() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("compat/package.json")).unwrap();
    let lock: serde_json::Value =
        serde_json::from_str(include_str!("compat/package-lock.json")).unwrap();
    assert_eq!(
        manifest["devDependencies"]["@vrtmrz/livesync-commonlib"], "0.1.44",
        "a transitive security update must not silently change the client contract"
    );
    assert_eq!(
        lock["packages"]["node_modules/@vrtmrz/livesync-commonlib"]["version"],
        "0.1.44"
    );
    assert_eq!(manifest["overrides"]["minimatch"], "11.0.1");
    assert_eq!(
        lock["packages"]["node_modules/minimatch"]["version"], "11.0.1",
        "GHSA-g3hv-75wg-m249 must be fixed in the installed compatibility graph"
    );
}

#[test]
fn rustix_lock_no_longer_contains_the_unsound_xattr_buffer_release() {
    let lock: toml::Value = toml::from_str(include_str!("../Cargo.lock")).unwrap();
    let packages = lock["package"].as_array().unwrap();
    let rustix: Vec<_> = packages
        .iter()
        .filter(|package| package["name"].as_str() == Some("rustix"))
        .collect();
    assert!(!rustix.is_empty());
    for package in rustix {
        let version: Vec<u64> = package["version"]
            .as_str()
            .unwrap()
            .split('.')
            .map(|part| part.parse().unwrap())
            .collect();
        assert!(
            version.as_slice() >= [1, 1, 6].as_slice(),
            "RUSTSEC-2026-0486 requires rustix >=1.1.6"
        );
    }
}
