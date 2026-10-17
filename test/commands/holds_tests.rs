// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! holds unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/holds.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::procfs::{classify_proc_error, parse_proc_net_line, parse_socket_inode};
use super::*;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

fn holder(pid: u32, name: &str, evidence: Vec<Evidence>) -> Holder {
    Holder {
        pid,
        name: name.to_owned(),
        user: "rezky".to_owned(),
        cwd: None,
        evidence,
    }
}

#[test]
fn target_detection_valid_port() {
    assert_eq!(parse_target("3000").unwrap(), Target::Port(3000));
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
}

#[test]
fn renders_one_port_holder() {
    let mut row = holder(1234, "bun", vec![Evidence::Fd(8, FdMode::Read)]);
    row.cwd = Some(PathBuf::from("/home/rezky/project"));

    assert_eq!(
        format_port_report(3000, &[row], &ScanStats::default()),
        ":3000\n└── bun pid=1234 user=rezky\n    ├── cwd /home/rezky/project\n    └── fd 8 (r)\n\n1 holder"
    );
}

#[test]
fn renders_multiple_port_holders() {
    let mut first = holder(1234, "bun", vec![Evidence::Fd(8, FdMode::Read)]);
    first.cwd = Some(PathBuf::from("/home/rezky/project"));
    let mut second = holder(2222, "node", vec![Evidence::Fd(9, FdMode::Read)]);
    second.cwd = Some(PathBuf::from("/home/rezky/other"));

    assert_eq!(
        format_port_report(3000, &[first, second], &ScanStats::default()),
        ":3000\n├── bun pid=1234 user=rezky\n│   ├── cwd /home/rezky/project\n│   └── fd 8 (r)\n└── node pid=2222 user=rezky\n    ├── cwd /home/rezky/other\n    └── fd 9 (r)\n\n2 holders"
    );
}

#[test]
fn renders_no_port_holders() {
    assert_eq!(
        format_port_report(3000, &[], &ScanStats::default()),
        "No holders found for port 3000."
    );
}

#[test]
fn renders_path_holder() {
    assert_eq!(
        format_path_report(
            "/tmp/file with spaces",
            &[holder(1234, "cat", vec![Evidence::Fd(12, FdMode::Read)])],
            &ScanStats::default()
        ),
        "/tmp/file with spaces\n└── cat pid=1234 user=rezky\n    └── fd 12 (r)\n\n1 holder"
    );
}

#[test]
fn renders_path_holder_with_multiple_evidence() {
    assert_eq!(
        format_path_report(
            "/tmp/lib.so",
            &[holder(
                1234,
                "app",
                vec![
                    Evidence::Fd(4, FdMode::Read),
                    Evidence::Mmap(MmapPerms {
                        read: true,
                        write: false,
                        execute: false,
                        private: true
                    })
                ]
            )],
            &ScanStats::default()
        ),
        "/tmp/lib.so\n└── app pid=1234 user=rezky\n    ├── fd 4 (r)\n    └── mmap r--p\n\n1 holder"
    );
}

#[test]
fn renders_no_path_holders() {
    assert_eq!(
        format_path_report("/tmp/empty", &[], &ScanStats::default()),
        "No holders found for '/tmp/empty'."
    );
}

#[test]
fn missing_path_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let missing = directory.path().join("missing file");

    assert_eq!(
        scan_path_holders(&missing).unwrap_err().to_string(),
        format!("{}: no such file or directory", missing.display())
    );
}

#[test]
fn broken_symlink_error_is_clean() {
    let directory = TempDir::new().unwrap();
    let link = directory.path().join("broken link");
    symlink(directory.path().join("missing target"), &link).unwrap();

    assert_eq!(
        scan_path_holders(&link).unwrap_err().to_string(),
        format!("{}: no such file or directory", link.display())
    );
}

#[test]
fn vanished_holder_is_skipped() {
    assert!(read_holder(u32::MAX, vec![Evidence::Fd(1, FdMode::Read)]).is_none());
}

#[test]
fn unreadable_note_appears_only_when_relevant() {
    assert!(!format_port_report(53, &[], &ScanStats::default()).contains("note:"));
    assert!(
        format_port_report(
            53,
            &[],
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 0,
                unreadable_maps: 0,
            },
        )
        .contains("note: some processes were not readable")
    );
}

#[test]
fn stable_summary_counts() {
    let holders = vec![
        holder(1, "one", vec![Evidence::Fd(1, FdMode::Read)]),
        holder(2, "two", vec![Evidence::Fd(2, FdMode::Read)]),
    ];

    assert!(format_path_report("/tmp/x", &holders, &ScanStats::default()).contains("2 holders"));
}

#[test]
fn proc_net_line_parses_local_port_and_inode() {
    let line = "0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0";
    assert_eq!(
        parse_proc_net_line(line, Protocol::Tcp),
        Some(SocketEntry {
            protocol: Protocol::Tcp,
            port: 3000,
            inode: 12345,
        })
    );
}

#[test]
fn parse_socket_inode_from_fd_link() {
    assert_eq!(parse_socket_inode(Path::new("socket:[12345]")), Some(12345));
    assert_eq!(parse_socket_inode(Path::new("pipe:[12345]")), None);
}

#[test]
fn classifies_vanished_proc_errors() {
    match classify_proc_error::<()>(io::Error::new(io::ErrorKind::NotFound, "gone")) {
        ProcRead::Gone => {}
        _ => panic!("expected gone"),
    }
}
