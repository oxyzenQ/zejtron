// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! checks unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/doctor/checks.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::test_tempdir::TempDir;

#[test]
fn missing_systemctl_is_warn_not_fail() {
    let check = check_systemctl("zejtron-missing-systemctl-test-command");

    assert_eq!(check.status, CheckStatus::Warn);
    assert_eq!(check.check, "systemctl");
}

#[test]
fn missing_journalctl_is_warn_not_fail() {
    let check = check_journalctl("zejtron-missing-journalctl-test-command");

    assert_eq!(check.status, CheckStatus::Warn);
    assert_eq!(check.check, "journalctl");
}

#[test]
fn procfs_missing_is_fail() {
    let directory = TempDir::new().unwrap();
    let check = check_procfs(&directory.path().join("missing-proc"));

    assert_eq!(check.status, CheckStatus::Fail);
    assert_eq!(check.check, "procfs");
}

#[test]
fn proc_net_parse_count_formatting() {
    let directory = TempDir::new().unwrap();
    fs::write(
        directory.path().join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46743 2 0000000000000000 100 0 0 10 0\n",
    )
    .unwrap();

    let check = check_proc_net(directory.path());

    assert_eq!(check.status, CheckStatus::Warn);
    assert_eq!(check.check, "proc_net");
    assert!(check.message.contains("1 sockets parsed"));
}

#[test]
fn proc_net_idle_netns_is_ok_not_fail() {
    let directory = TempDir::new().unwrap();
    // The Container E2E shape: every net file readable, zero socket
    // rows (a fresh netns). The surface works; the verdict is OK.
    let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    for name in ["tcp", "udp", "tcp6", "udp6"] {
        fs::write(directory.path().join(name), header).unwrap();
    }

    let check = check_proc_net(directory.path());

    assert_eq!(check.status, CheckStatus::Ok);
    assert_eq!(check.check, "proc_net");
    assert!(check.message.contains("0 sockets parsed"));
}

#[test]
fn proc_net_no_readable_file_is_fail() {
    let directory = TempDir::new().unwrap();
    // The broken-procfs shape: not one /proc/net file readable.
    let check = check_proc_net(directory.path());

    assert_eq!(check.status, CheckStatus::Fail);
    assert_eq!(check.check, "proc_net");
}
