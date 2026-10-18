// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! port unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/port/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

fn socket(protocol: Protocol, port: u16, state: Option<&str>) -> SocketEntry {
    socket_with_inode(protocol, port, state, u64::from(port))
}

fn socket_with_inode(
    protocol: Protocol,
    port: u16,
    state: Option<&str>,
    inode: u64,
) -> SocketEntry {
    SocketEntry {
        protocol,
        address: "127.0.0.1".to_owned(),
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
        window: std::time::Duration::from_secs(60),
        events_only: false,
        snapshot_only: false,
    }
}

#[test]
fn validates_port_range() {
    assert_eq!(validate_port("1").unwrap(), 1);
    assert_eq!(validate_port("65535").unwrap(), 65_535);
    assert!(validate_port("0").is_err());
    assert!(validate_port("65536").is_err());
    assert!(validate_port("abc").is_err());
}

#[test]
fn filters_by_protocol() {
    let sockets = vec![
        socket(Protocol::Tcp, 80, Some("LISTEN")),
        socket(Protocol::Udp, 53, None),
    ];
    let tcp = PortOptions {
        tcp: true,
        ..options()
    };
    let udp = PortOptions {
        udp: true,
        tcp: false,
        ..tcp
    };

    assert_eq!(filter_sockets(&sockets, &tcp).len(), 1);
    assert_eq!(filter_sockets(&sockets, &tcp)[0].protocol, Protocol::Tcp);
    assert_eq!(filter_sockets(&sockets, &udp).len(), 1);
    assert_eq!(filter_sockets(&sockets, &udp)[0].protocol, Protocol::Udp);
}

#[test]
fn tcp_and_udp_flags_include_both_protocols() {
    let sockets = vec![
        socket(Protocol::Tcp, 80, Some("LISTEN")),
        socket(Protocol::Udp, 53, None),
    ];
    let selected = filter_sockets(
        &sockets,
        &PortOptions {
            tcp: true,
            udp: true,
            ..options()
        },
    );

    assert_eq!(selected.len(), 2);
    assert!(
        selected
            .iter()
            .any(|socket| socket.protocol == Protocol::Tcp)
    );
    assert!(
        selected
            .iter()
            .any(|socket| socket.protocol == Protocol::Udp)
    );
}

#[test]
fn default_and_listen_filter_match() {
    let sockets = vec![
        socket(Protocol::Tcp, 80, Some("LISTEN")),
        socket(Protocol::Tcp, 443, Some("ESTABLISHED")),
        socket(Protocol::Udp, 53, None),
        socket(Protocol::Udp, 0, None),
    ];
    let default = filter_sockets(&sockets, &options());
    let listen = filter_sockets(
        &sockets,
        &PortOptions {
            listen: true,
            ..options()
        },
    );

    assert_eq!(default, listen);
    assert_eq!(default.len(), 2);
    assert!(default.iter().any(|socket| socket.port == 80));
    assert!(default.iter().any(|socket| socket.port == 53));
    assert!(!default.iter().any(|socket| socket.port == 443));
    assert!(!default.iter().any(|socket| socket.port == 0));
}

#[test]
fn all_includes_non_listening_tcp() {
    let sockets = vec![
        socket(Protocol::Tcp, 80, Some("LISTEN")),
        socket(Protocol::Tcp, 443, Some("ESTABLISHED")),
    ];
    let selected = filter_sockets(
        &sockets,
        &PortOptions {
            all: true,
            ..options()
        },
    );

    assert_eq!(selected.len(), 2);
    assert!(selected.iter().any(|socket| socket.port == 443));
}

#[test]
fn filters_by_specific_port() {
    let sockets = vec![
        socket(Protocol::Tcp, 80, Some("LISTEN")),
        socket(Protocol::Udp, 53, None),
    ];
    let options = PortOptions {
        port: Some(53),
        ..options()
    };

    let selected = filter_sockets(&sockets, &options);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].port, 53);
}

#[test]
fn specific_port_filter_combines_with_protocol_and_all_filters() {
    let sockets = vec![
        socket(Protocol::Tcp, 3000, Some("ESTABLISHED")),
        socket(Protocol::Udp, 3000, None),
        socket(Protocol::Tcp, 8080, Some("LISTEN")),
    ];
    let listening_tcp = filter_sockets(
        &sockets,
        &PortOptions {
            port: Some(3000),
            tcp: true,
            ..options()
        },
    );
    let all_tcp = filter_sockets(
        &sockets,
        &PortOptions {
            port: Some(3000),
            tcp: true,
            all: true,
            ..options()
        },
    );

    assert!(listening_tcp.is_empty());
    assert_eq!(all_tcp.len(), 1);
    assert_eq!(all_tcp[0].protocol, Protocol::Tcp);
    assert_eq!(all_tcp[0].port, 3000);
}

#[test]
fn listen_and_all_conflict() {
    assert!(
        parse_options(
            None,
            PortFlags {
                listen: true,
                all: true,
                ..PortFlags::default()
            },
        )
        .is_err()
    );
}

#[test]
fn formats_owner_without_pid() {
    let process = model::ProcessInfo {
        pid: 1234,
        name: "node".to_owned(),
        user: "rezky".to_owned(),
        cwd: None,
        cmdline: None,
        fd: None,
    };
    assert_eq!(format_owner(&process, true), "node user=rezky");
}

#[test]
fn formats_unknown_owner() {
    assert_eq!(format_unknown_owner(), "unknown");
}

#[test]
fn unreadable_note_logic() {
    assert!(!should_show_unreadable_note(&model::ScanStats::default()));
    assert!(should_show_unreadable_note(&model::ScanStats {
        unreadable_processes: 1,
        unreadable_fds: 0,
    }));
    assert!(should_show_unreadable_note(&model::ScanStats {
        unreadable_processes: 0,
        unreadable_fds: 1,
    }));
}
