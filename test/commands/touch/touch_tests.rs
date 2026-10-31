// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! touch unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/touch/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::test_tempdir::TempDir;
use std::os::unix::fs::symlink;
use std::time::Duration;

#[test]
fn accepts_directory_metadata() {
    let directory = TempDir::new().unwrap();
    let info = inspect_path(directory.path()).unwrap();

    assert_eq!(info.source, EvidenceSource::Metadata);
    assert_eq!(info.actor, "unknown");
}

#[test]
fn accepts_path_with_spaces() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("file with spaces");
    fs::write(&path, "hello").unwrap();
    let info = inspect_path(&path).unwrap();

    assert_eq!(info.path, path);
}

#[test]
fn missing_path_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing");

    assert_eq!(
        inspect_path(&missing).unwrap_err().to_string(),
        format!("path not found: {}", missing.display())
    );
}

#[test]
fn broken_symlink_reports_as_symlink_with_target() {
    // Previously broken symlinks returned Err; now they're reported as
    // symlinks with their target (which may or may not exist).
    let directory = TempDir::new().unwrap();
    let link = directory.path().join("broken");
    symlink(directory.path().join("missing"), &link).unwrap();

    let info = inspect_path(&link).unwrap();
    assert_eq!(info.path, link);
    let meta = info.meta.expect("meta should be set");
    assert!(meta.is_symlink);
    assert_eq!(meta.file_type, "symlink");
    assert!(
        meta.symlink_target
            .as_ref()
            .map(|t| t.contains("missing"))
            .unwrap_or(false)
    );
}

#[test]
fn inspect_does_not_change_mtime() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("file");
    fs::write(&path, "hello").unwrap();
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    let _ = inspect_path(&path).unwrap();
    let after = fs::metadata(&path).unwrap().modified().unwrap();

    assert_eq!(before, after);
}

#[test]
fn timestamp_format_is_stable_shape() {
    let formatted = format_system_time(UNIX_EPOCH + Duration::from_secs(1_700_000_000));

    // The civil clock's contract (src/clock.rs): the tree's
    // long-standing zero-padded core plus the explicit UTC
    // marker. Ground truth: 1_700_000_000 = 2023-11-14 22:13:20
    // UTC (verified via date -u -d @1700000000).
    assert_eq!(formatted, "2023-11-14 22:13:20 (UTC)");
    assert_eq!(formatted.len(), 25);
    assert_eq!(&formatted[4..5], "-");
    assert_eq!(&formatted[7..8], "-");
    assert_eq!(&formatted[10..11], " ");
    assert_eq!(&formatted[13..14], ":");
    assert_eq!(&formatted[16..17], ":");
}

#[test]
fn parses_passwd_contents() {
    let users = crate::system::parse_passwd_users(
        "root:x:0:0::/root:/bin/sh\nrezky:x:1000:1000::/home/rezky:/bin/zsh\n",
    )
    .unwrap();

    assert_eq!(users.get(&0).map(String::as_str), Some("root"));
    assert_eq!(users.get(&1000).map(String::as_str), Some("rezky"));
}
