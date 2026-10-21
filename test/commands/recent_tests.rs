// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! recent unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/recent.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use std::fs::File;
use tempfile::TempDir;

#[test]
fn parses_minutes_hours_and_days() {
    assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
    assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7_200));
    assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
}

#[test]
fn rejects_invalid_duration() {
    assert!(parse_duration("soon").is_err());
    assert!(parse_duration("10x").is_err());
    assert!(parse_duration("m").is_err());
}

#[test]
fn huge_amounts_saturate_instead_of_overflowing() {
    // night-total-lts-1: the pre-fix arithmetic (amount * 60 * 60 and
    // friends) panicked in debug and wrapped in release - the hour
    // arm at 5124095576030432h wrapped to exactly zero seconds. The
    // saturating law: an absurd age ask is "older than everything",
    // never a wrapped-to-small window that filters the wrong file
    // set. Every arm saturates at the same u64::MAX seconds.
    assert_eq!(
        parse_duration("18446744073709551615m").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    assert_eq!(
        parse_duration("18446744073709551615h").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    assert_eq!(
        parse_duration("18446744073709551615d").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    // The exact wrap-to-zero input from the audit (2^64 seconds =
    // 5124095576030432 * 3600): pre-fix this parsed as zero seconds.
    assert_eq!(
        parse_duration("5124095576030432h").unwrap(),
        Duration::from_secs(u64::MAX)
    );
}

#[test]
fn sorts_newest_first() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut files = vec![
        RecentFile {
            path: PathBuf::from("old"),
            modified: now - Duration::from_secs(20),
            changed: now - Duration::from_secs(20),
            size: 100,
            uid: 1000,
            perms: 0o644,
        },
        RecentFile {
            path: PathBuf::from("new"),
            modified: now,
            changed: now,
            size: 100,
            uid: 1000,
            perms: 0o644,
        },
        RecentFile {
            path: PathBuf::from("middle"),
            modified: now - Duration::from_secs(10),
            changed: now - Duration::from_secs(10),
            size: 100,
            uid: 1000,
            perms: 0o644,
        },
    ];

    sort_newest_first(&mut files);

    assert_eq!(files[0].path, PathBuf::from("new"));
    assert_eq!(files[1].path, PathBuf::from("middle"));
    assert_eq!(files[2].path, PathBuf::from("old"));
}

#[test]
fn limit_zero_selects_no_files() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let files = vec![RecentFile {
        path: PathBuf::from("file"),
        modified: now,
        changed: now,
        size: 100,
        uid: 1000,
        perms: 0o644,
    }];

    assert!(select_recent_files(files, 0, None, now).is_empty());
}

#[test]
fn invalid_since_fails_before_scanning() {
    let directory = TempDir::new().unwrap();

    assert!(run(directory.path(), 20, Some("bad")).is_err());
}

#[test]
fn scan_skips_ignored_directories() {
    let directory = TempDir::new().unwrap();
    File::create(directory.path().join("visible")).unwrap();

    for ignored in IGNORED_DIRECTORIES {
        let ignored_directory = directory.path().join(ignored);
        fs::create_dir(&ignored_directory).unwrap();
        File::create(ignored_directory.join("hidden")).unwrap();
    }

    let files = scan_recent_files(directory.path()).unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, directory.path().join("visible"));
}
