// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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

#[test]
fn the_keyed_walk_survives_a_mid_scan_deletion() {
    // night-dragon-lts-4: the why lane keys its holder walk to the
    // identity the opening stat captured, so a file deleted after
    // the scan began still answers for its holders. The fd this
    // very process keeps open is the deleted-but-open evidence the
    // report must keep rendering - a second stat of the vanished
    // path must not kill the walk (the pre-fix flow statted the
    // path again inside the holder walk and errored the whole
    // report out at exactly the moment the leak evidence appeared).
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("gone");
    std::fs::write(&path, "payload").unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    let held = std::fs::File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let (holders, _stats) = scan_path_holders_for_file_id(FileId::from_metadata(&meta)).unwrap();
    let found = holders
        .iter()
        .any(|holder| holder.pid == std::process::id());
    assert!(
        found,
        "the deleted-but-open fd is still holder evidence: {holders:?}"
    );
    drop(held);
}

#[test]
fn the_keyed_walk_ignores_a_replacement_object() {
    // The other half of the one-identity law: when the path is
    // replaced, the keyed walk must not silently adopt the
    // replacement - a holder of the NEW inode is not a holder of
    // the object this scan asked about. The replacement here is a
    // different file nobody holds; the anchor's own holder (this
    // process) is the only evidence that may render.
    let directory = TempDir::new().unwrap();
    let anchor_path = directory.path().join("anchor");
    std::fs::write(&anchor_path, "the queried object").unwrap();
    let meta = std::fs::metadata(&anchor_path).unwrap();
    let held = std::fs::File::open(&anchor_path).unwrap();
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, "the impostor").unwrap();
    let (holders, _stats) = scan_path_holders_for_file_id(FileId::from_metadata(&meta)).unwrap();
    assert!(
        holders
            .iter()
            .any(|holder| holder.pid == std::process::id()),
        "the anchor's own holder renders: {holders:?}"
    );
    drop(held);
    // The replacement carries the anchor's content nowhere: a walk
    // keyed to the anchor CANNOT see it, and a walk keyed to the
    // replacement CANNOT see the anchor's holder - the blend the
    // one-identity law forbids, from the other side.
    let replacement_meta = std::fs::metadata(&replacement).unwrap();
    let (impostor_holders, _) =
        scan_path_holders_for_file_id(FileId::from_metadata(&replacement_meta)).unwrap();
    assert!(
        !impostor_holders.iter().any(|h| h.pid == std::process::id()),
        "a holder of the anchor is not a holder of the impostor: {impostor_holders:?}"
    );
}
