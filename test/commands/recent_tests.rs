// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! recent unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/recent.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::test_tempdir::TempDir;
use std::fs::File;

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
fn rejects_multibyte_units_without_panicking() {
    // night-dragon-lts-1: the pre-fix parser split the input at
    // len() - 1 BYTES, and str::split_at panics when that index
    // lands inside a multibyte character - a `--since 5分` age ask
    // crashed the CLI with a byte-index panic instead of the clean
    // usage error. Every multibyte-final input must be a rejection.
    for bad in ["é", "日", "5分", "2日", "🦀", "1d分"] {
        assert!(parse_duration(bad).is_err(), "must reject {bad:?}");
    }
    assert!(parse_duration("分d").is_err());
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

    assert!(run(directory.path(), 20, Some("bad"), false).is_err());
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

// The JSON lane (night-badass-9): the same selection, typed.

#[test]
fn json_files_carry_the_typed_rows() {
    let base = PathBuf::from("/tmp/recent-json");
    let files = vec![RecentFile {
        path: base.join("src/main.rs"),
        modified: SystemTime::UNIX_EPOCH + Duration::from_secs(1_761_270_000),
        changed: SystemTime::UNIX_EPOCH + Duration::from_secs(1_761_270_000),
        size: 4123,
        uid: 1000,
        perms: 0o644,
    }];
    let users = std::collections::HashMap::from([(1000u32, "rezky".to_owned())]);
    let out = super::files_json(&base, &files, &users);
    // The relative path the text renders, the unix-second timestamps,
    // and the resolved owner - all typed, one line.
    assert!(out.starts_with("{\"path\":\"/tmp/recent-json\""));
    assert!(out.contains("\"path\":\"src/main.rs\""));
    assert!(out.contains("\"mtime_unix_secs\":1761270000"));
    assert!(out.contains("\"changed_unix_secs\":1761270000"));
    assert!(out.contains("\"size_bytes\":4123"));
    assert!(out.contains("\"uid\":1000"));
    assert!(out.contains("\"owner\":\"rezky\""));
    assert!(out.contains("\"perms\":\"0644\""));
    assert!(!out.contains('\n'));
}

#[test]
fn json_files_empty_selection_is_an_empty_array() {
    let base = PathBuf::from(".");
    let users = std::collections::HashMap::new();
    let out = super::files_json(&base, &[], &users);
    // The honest empty: the selection ran and found nothing - the
    // same verdict the text's "no modified files found" renders.
    assert_eq!(out, "{\"path\":\".\",\"files\":[]}");
}

#[test]
fn json_owner_falls_back_to_the_uid_word() {
    let base = PathBuf::from(".");
    let files = vec![RecentFile {
        path: PathBuf::from("orphan"),
        modified: SystemTime::UNIX_EPOCH,
        changed: SystemTime::UNIX_EPOCH,
        size: 1,
        uid: 65534,
        perms: 0o600,
    }];
    let users = std::collections::HashMap::new();
    let out = super::files_json(&base, &files, &users);
    // The text lane's own fallback: an unnamed uid rides the raw uid
    // string the renderer prints.
    assert!(out.contains("\"owner\":\"65534\""));
}
