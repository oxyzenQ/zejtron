// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! holds parser and error-path pins (the render pins moved to
//! holds/ledger_tests.rs with night-improve-3's Evidence Ledger).
//! Lives under the single test/ tree and is #[path]-wired from
//! src/commands/holds.rs, so `super::` reaches the module exactly
//! like the inline tests did.

use super::procfs::{classify_proc_error, parse_proc_net_line, parse_socket_inode};
use super::*;
use crate::test_tempdir::TempDir;
use std::os::unix::fs::symlink;

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
    assert!(
        read_holder(
            u32::MAX,
            vec![Evidence::Fd(1, FdMode::Read)],
            &std::collections::HashMap::new()
        )
        .is_none()
    );
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
