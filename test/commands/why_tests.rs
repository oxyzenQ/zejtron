// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! why parser and error-path pins (the synthesis pins moved to
//! why/ledger_tests.rs with night-improve-3's Evidence Ledger). Lives
//! under the single test/ tree and is #[path]-wired from
//! src/commands/why.rs, so `super::` reaches the module exactly like
//! the inline tests did.

use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

#[test]
fn target_detection_valid_port() {
    assert_eq!(parse_target("53").unwrap(), Target::Port(53));
    assert_eq!(parse_target("65535").unwrap(), Target::Port(65535));
}

#[test]
fn target_detection_invalid_port() {
    assert_eq!(
        parse_target("0").unwrap_err().to_string(),
        "invalid port: 0"
    );
    assert_eq!(
        parse_target("65536").unwrap_err().to_string(),
        "invalid port: 65536"
    );
}

#[test]
fn target_detection_path() {
    assert_eq!(
        parse_target("/tmp/file with spaces").unwrap(),
        Target::Path(PathBuf::from("/tmp/file with spaces"))
    );
    assert_eq!(
        parse_target("abc").unwrap(),
        Target::Path(PathBuf::from("abc"))
    );
}

#[test]
fn missing_path_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing");

    let (window, window_label) = crate::commands::lane::resolve_window(None).unwrap();
    assert_eq!(
        ledger::build_path_report(&missing, window, window_label, false, false)
            .unwrap_err()
            .to_string(),
        format!("path not found: {}", missing.display())
    );
}

#[test]
fn broken_symlink_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let link = directory.path().join("broken");
    symlink(directory.path().join("missing"), &link).unwrap();

    let (window, window_label) = crate::commands::lane::resolve_window(None).unwrap();
    assert_eq!(
        ledger::build_path_report(&link, window, window_label, false, false)
            .unwrap_err()
            .to_string(),
        format!("path not found: {}", link.display())
    );
}

#[test]
fn path_with_spaces_works() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("file with spaces");
    fs::write(&path, "hello").unwrap();

    // Through the ledger (the lane state is environment-dependent;
    // the subject line holds whichever lane served).
    let (window, window_label) = crate::commands::lane::resolve_window(None).unwrap();
    let output = ledger::build_path_report(&path, window, window_label, false, false).unwrap();

    assert!(output.contains(&path.display().to_string()));
}
