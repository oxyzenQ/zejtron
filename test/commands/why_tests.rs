// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! why unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/why.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::commands::touch::{EvidenceSource, ProcessEvidence};
use std::os::unix::fs::symlink;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;

fn holder(pid: u32, name: &str, evidence: Vec<Evidence>) -> Holder {
    Holder {
        pid,
        name: name.to_owned(),
        user: "rezky".to_owned(),
        cwd: Some(PathBuf::from("/home/rezky/project")),
        evidence,
    }
}

fn quiet_stats() -> ScanStats {
    ScanStats::default()
}

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
fn renders_port_reason_with_holder() {
    let output = format_port_holder_reason(3000, &[holder(1234, "node", vec![])], &quiet_stats());

    assert!(output.contains(":3000"));
    assert!(output.contains("reason: port is open because a process owns this socket"));
    assert!(output.contains("holder: node pid=1234 user=rezky"));
    assert!(output.contains("cwd /home/rezky/project"));
    assert!(output.contains("evidence: socket inode matched from /proc"));
    assert!(output.contains("1 reason"));
}

#[test]
fn renders_port_no_visible_holder_with_unreadable_note() {
    let output = format_no_visible_port_reason(53);

    assert!(output.contains(":53"));
    assert!(output.contains("reason: no visible holder found"));
    assert!(output.contains("process details may be incomplete"));
    assert!(output.contains("try sudo for complete explanation"));
}

#[test]
fn renders_no_port_reason() {
    assert_eq!(
        format!("No reason found for port {}.", 3000),
        "No reason found for port 3000."
    );
}

#[test]
fn renders_path_reason_with_holder_evidence() {
    let output = format_path_holder_reason(
        "/tmp/example",
        &[holder(
            1234,
            "nano",
            vec![Evidence::Fd(12, holds::FdMode::Read)],
        )],
        &quiet_stats(),
    );

    assert!(output.contains("reason: path is open because a process references it"));
    assert!(output.contains("holder: nano pid=1234 user=rezky"));
    assert!(output.contains("fd 12"));
    assert!(output.contains("evidence: /proc/<pid>/fd link matched this path"));
    assert!(output.contains("1 reason"));
}

#[test]
fn renders_path_metadata_fallback() {
    let output = format_path_touch_reason(&TouchInfo {
        path: PathBuf::from("/tmp/example"),
        modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        source: EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: None,
    });

    assert!(output.contains("reason: path exists and has modification evidence"));
    assert!(output.contains("source: filesystem metadata"));
    assert!(output.contains("actor: unknown"));
    assert!(output.contains("not who changed it"));
    assert!(!output.contains("try sudo for complete explanation"));
}

#[test]
fn renders_path_journal_evidence() {
    let output = format_path_touch_reason(&TouchInfo {
        path: PathBuf::from("/tmp/example"),
        modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        source: EvidenceSource::Journal,
        actor: "rezky".to_owned(),
        process: Some(ProcessEvidence {
            name: "sudo".to_owned(),
            pid: Some(230261),
        }),
        meta: None,
    });

    assert!(output.contains("reason: path has recent modification evidence"));
    assert!(output.contains("source: journal evidence"));
    assert!(output.contains("process: sudo pid=230261"));
    assert!(output.contains("best-effort"));
}

#[test]
fn missing_path_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing");

    assert_eq!(
        explain_path(&missing).unwrap_err().to_string(),
        format!("path not found: {}", missing.display())
    );
}

#[test]
fn broken_symlink_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let link = directory.path().join("broken");
    symlink(directory.path().join("missing"), &link).unwrap();

    assert_eq!(
        explain_path(&link).unwrap_err().to_string(),
        format!("path not found: {}", link.display())
    );
}

#[test]
fn path_with_spaces_works() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("file with spaces");
    fs::write(&path, "hello").unwrap();

    let output = explain_path(&path).unwrap();

    assert!(output.contains(&path.display().to_string()));
}

#[test]
fn wording_does_not_overclaim() {
    let output = format_path_touch_reason(&TouchInfo {
        path: PathBuf::from("/tmp/example"),
        modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        source: EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: None,
    });

    assert!(!output.contains("definitely"));
    assert!(!output.contains("malicious"));
}

#[test]
fn permission_note_is_not_added_to_metadata_explanation() {
    let output = format_path_touch_reason(&TouchInfo {
        path: PathBuf::from("/tmp/example"),
        modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        source: EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: None,
    });

    assert!(!output.contains("try sudo for complete explanation"));
}

#[test]
fn permission_note_is_added_once_for_holder_explanation() {
    let stats = ScanStats {
        unreadable_processes: 1,
        unreadable_fds: 2,
        unreadable_maps: 3,
    };
    let output = format_path_holder_reason(
        "/tmp/example",
        &[holder(
            1234,
            "nano",
            vec![Evidence::Fd(12, holds::FdMode::Read)],
        )],
        &stats,
    );

    assert_eq!(
        output
            .matches("note: some processes were not readable; try sudo for complete explanation")
            .count(),
        1
    );
}

#[test]
fn stable_summary_count_for_multiple_holders() {
    let output = format_path_holder_reason(
        "/tmp/example",
        &[
            holder(1111, "nano", vec![Evidence::Fd(4, holds::FdMode::Read)]),
            holder(
                2222,
                "vim",
                vec![Evidence::Mmap(holds::MmapPerms {
                    read: true,
                    write: false,
                    execute: false,
                    private: true,
                })],
            ),
        ],
        &quiet_stats(),
    );

    assert!(output.contains("2 reasons"));
    assert!(output.contains("/proc/<pid>/fd link or maps entry matched this path"));
}
