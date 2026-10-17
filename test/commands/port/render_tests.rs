// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! render unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/port/render.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::super::model::Protocol;
use super::*;
use std::path::PathBuf;

fn socket_with_inode(
    protocol: Protocol,
    port: u16,
    state: Option<&str>,
    inode: u64,
) -> SocketEntry {
    socket_at(protocol, "127.0.0.1", port, state, inode)
}

fn socket_at(
    protocol: Protocol,
    address: &str,
    port: u16,
    state: Option<&str>,
    inode: u64,
) -> SocketEntry {
    SocketEntry {
        protocol,
        address: address.to_owned(),
        port,
        state: state.map(ToOwned::to_owned),
        inode,
        remote_address: "0.0.0.0".to_owned(),
        remote_port: 0,
    }
}

fn options() -> PortOptions {
    PortOptions {
        port: None,
        tcp: false,
        udp: false,
        listen: false,
        all: false,
        numeric: false,
        group: false,
        no_pid: false,
    }
}

fn process(pid: u32, name: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_owned(),
        user: "rezky".to_owned(),
        cwd: None,
        cmdline: None,
        fd: None,
    }
}

#[test]
fn report_summary_uses_rendered_socket_count_after_filtering() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 443, Some("ESTABLISHED"), 200),
    ];
    let selected = super::super::filter_sockets(&sockets, &options());
    let mut owners = OwnerMap::new();
    owners.insert(200, vec![process(7, "curl")]);

    let report = format_report(&selected, &owners, &ScanStats::default(), &options());

    assert!(report.contains("1 port · 0 owners"));
    assert!(!report.contains("443"));
}

#[test]
fn owner_summary_counts_unique_known_rendered_processes() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Udp, 53, None, 200),
        socket_with_inode(Protocol::Udp, 5353, None, 300),
    ];
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process(7, "daemon")]);
    owners.insert(200, vec![process(7, "daemon")]);

    let report = format_report(&sockets, &owners, &ScanStats::default(), &options());

    assert!(report.contains("3 ports · 1 owner"));
}

#[test]
fn cwd_is_only_rendered_for_specific_port_reports() {
    let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
    let mut process = process(1234, "node");
    process.cwd = Some(PathBuf::from("/home/rezky/project"));
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process]);

    let list_report = format_report(&sockets, &owners, &ScanStats::default(), &options());
    let detail_report = format_report(
        &sockets,
        &owners,
        &ScanStats::default(),
        &PortOptions {
            port: Some(3000),
            ..options()
        },
    );

    assert!(!list_report.contains("cwd /home/rezky/project"));
    assert!(detail_report.contains("cwd /home/rezky/project"));
}

#[test]
fn report_respects_no_pid_owner_formatting() {
    let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process(1234, "node")]);

    let report = format_report(
        &sockets,
        &owners,
        &ScanStats::default(),
        &PortOptions {
            no_pid: true,
            ..options()
        },
    );

    assert!(report.contains("node user=rezky"));
    assert!(!report.contains("pid=1234"));
}

#[test]
fn grouped_report_combines_repeated_sockets() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
    ];

    let report = format_report(
        &sockets,
        &OwnerMap::new(),
        &ScanStats::default(),
        &PortOptions {
            group: true,
            ..options()
        },
    );

    assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
    assert!(report.contains("1 group · 2 sockets · 0 owners"));
    assert_eq!(report.matches("unknown").count(), 1);
}

#[test]
fn grouped_report_keeps_different_owners_separate() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
    ];
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process(10, "unbound")]);
    owners.insert(200, vec![process(20, "dnsmasq")]);

    let report = format_report(
        &sockets,
        &owners,
        &ScanStats::default(),
        &PortOptions {
            group: true,
            ..options()
        },
    );

    assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
    assert!(!report.contains("×2"));
    assert!(report.contains("2 groups · 2 sockets · 2 owners"));
}

#[test]
fn grouped_report_keeps_socket_identity_separate() {
    let sockets = vec![
        socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("LISTEN"), 100),
        socket_at(Protocol::Tcp, "127.0.0.2", 53, Some("LISTEN"), 200),
        socket_at(Protocol::Tcp, "127.0.0.1", 54, Some("LISTEN"), 300),
        socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("ESTABLISHED"), 400),
        socket_at(Protocol::Udp, "127.0.0.1", 53, None, 500),
    ];

    let report = format_report(
        &sockets,
        &OwnerMap::new(),
        &ScanStats::default(),
        &PortOptions {
            group: true,
            all: true,
            ..options()
        },
    );

    assert!(report.contains("5 groups · 5 sockets · 0 owners"));
    assert!(!report.contains('×'));
}

#[test]
fn grouped_summary_counts_groups_sockets_and_unique_owners() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        socket_with_inode(Protocol::Udp, 5353, None, 300),
    ];
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process(10, "unbound")]);
    owners.insert(200, vec![process(10, "unbound")]);

    let report = format_report(
        &sockets,
        &owners,
        &ScanStats::default(),
        &PortOptions {
            group: true,
            ..options()
        },
    );

    assert!(report.contains("2 groups · 3 sockets · 1 owner"));
}

#[test]
fn grouped_report_respects_no_pid_owner_formatting() {
    let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
    let mut owners = OwnerMap::new();
    owners.insert(100, vec![process(1234, "node")]);

    let report = format_report(
        &sockets,
        &owners,
        &ScanStats::default(),
        &PortOptions {
            group: true,
            no_pid: true,
            ..options()
        },
    );

    assert!(report.contains("node user=rezky"));
    assert!(!report.contains("pid=1234"));
}

#[test]
fn grouped_specific_port_keeps_detail_header() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
    ];

    let report = format_report(
        &sockets,
        &OwnerMap::new(),
        &ScanStats::default(),
        &PortOptions {
            port: Some(53),
            group: true,
            ..options()
        },
    );

    assert!(report.starts_with(":53\n"));
    assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
    assert!(report.contains("1 group · 2 sockets · 0 owners"));
}

#[test]
fn no_match_specific_port_omits_unreadable_note() {
    let report = format_report(
        &[],
        &OwnerMap::new(),
        &ScanStats {
            unreadable_processes: 1,
            unreadable_fds: 1,
        },
        &PortOptions {
            port: Some(22),
            ..options()
        },
    );

    assert_eq!(report, "No sockets found for port 22.");
}

#[test]
fn grouped_no_match_specific_port_omits_unreadable_note() {
    let report = format_report(
        &[],
        &OwnerMap::new(),
        &ScanStats {
            unreadable_processes: 1,
            unreadable_fds: 1,
        },
        &PortOptions {
            port: Some(22),
            group: true,
            ..options()
        },
    );

    assert_eq!(report, "No sockets found for port 22.");
}

#[test]
fn rendered_sockets_keep_unreadable_note() {
    let sockets = vec![socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100)];

    let report = format_report(
        &sockets,
        &OwnerMap::new(),
        &ScanStats {
            unreadable_processes: 1,
            unreadable_fds: 0,
        },
        &PortOptions {
            group: true,
            ..options()
        },
    );

    assert!(report.contains("tcp 127.0.0.1:53 LISTEN"));
    assert!(
        report.contains(
            "note: some processes were not readable; try sudo for complete owner details"
        )
    );
}

#[test]
fn raw_report_does_not_group_by_default() {
    let sockets = vec![
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
        socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
    ];

    let report = format_report(
        &sockets,
        &OwnerMap::new(),
        &ScanStats::default(),
        &options(),
    );

    assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
    assert!(report.contains("2 ports · 0 owners"));
    assert!(!report.contains('×'));
}
