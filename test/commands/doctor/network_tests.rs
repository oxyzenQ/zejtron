// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The network symptom's pins (night-improve-48): the interface
//! parser, the socket-state census, and the render shape, pinned
//! with synthetic /proc bytes - the report is the contract, not
//! this host's own tables.

use super::*;
use std::collections::BTreeMap;

fn iface(name: &str, rx_bytes: u64, rx_packets: u64, tx_bytes: u64, tx_packets: u64) -> IfRow {
    IfRow {
        name: name.to_owned(),
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    }
}

#[test]
fn the_net_dev_line_parses_the_kernel_shape() {
    let (name, row) = parse_net_dev_line("  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0")
        .expect("data line parses");
    assert_eq!(name, "eth0");
    assert_eq!(row.name, "eth0");
    assert_eq!(row.rx_bytes, 1000);
    assert_eq!(row.rx_packets, 10);
    assert_eq!(row.tx_bytes, 2000);
    assert_eq!(row.tx_packets, 20);
}

#[test]
fn the_net_dev_parser_refuses_headers_and_short_lines() {
    assert!(
        parse_net_dev_line("Inter-|   Receive                                       |  Transmit")
            .is_none()
    );
    assert!(parse_net_dev_line(" face |bytes packets errs drop").is_none());
    assert!(parse_net_dev_line("eth0: 1 2 3").is_none());
    assert!(parse_net_dev_line("no colon").is_none());
}

#[test]
fn the_interface_deltas_rank_by_total_then_name() {
    let mut a = BTreeMap::new();
    a.insert("lo".to_owned(), iface("lo", 100, 1, 100, 1));
    a.insert("eth0".to_owned(), iface("eth0", 500, 5, 500, 5));
    a.insert("wlan0".to_owned(), iface("wlan0", 70, 7, 70, 7));
    let mut b = BTreeMap::new();
    b.insert("lo".to_owned(), iface("lo", 100, 1, 100, 1));
    b.insert(
        "eth0".to_owned(),
        iface("eth0", 1_500_000, 150, 300_000, 30),
    );
    b.insert(
        "wlan0".to_owned(),
        iface("wlan0", 1_700_000, 170, 60_000, 6),
    );

    let rows = interface_deltas(&a, &b);
    let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, vec!["eth0", "wlan0"], "combined bytes descending");
    assert_eq!(rows[0].rx_bytes, 1_500_000 - 500);
    assert_eq!(rows[0].rx_packets, 145);
    assert_eq!(rows[0].tx_bytes, 300_000 - 500);
    // lo moved nothing in the window and is not a row.
    assert!(!names.contains(&"lo"), "{names:?}");
}

#[test]
fn the_socket_census_counts_the_named_states() {
    let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 1234 1
   1: 0100007F:0035 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 1235 1
   2: 0100007F:0035 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 1236 1
   3: 0100007F:0035 00000000:0000 08 00000000:00000000 00:00000000 00000000     0        0 1237 1
   4: 0100007F:0035 00000000:0000 04 00000000:00000000 00:00000000 00000000     0        0 1238 1
";
    let mut states = SocketStates::default();
    census_sockets(table, &mut states);
    assert_eq!(states.total, 5);
    assert_eq!(states.established, 1);
    assert_eq!(states.time_wait, 2);
    assert_eq!(states.close_wait, 1);
}

#[test]
fn the_census_skips_the_header_line_by_shape_not_by_count() {
    // A header-shaped line carries no state column and is skipped
    // by the field count itself, never by a magic line number.
    let mut states = SocketStates::default();
    census_sockets("sl local_address rem_address st", &mut states);
    assert_eq!(states.total, 0);
}

fn synthetic() -> NetworkSample {
    NetworkSample {
        sampled_at: "2026-10-22 10:00:00 (UTC)".to_owned(),
        interfaces: vec![
            iface("eth0", 1_500_000, 150, 300_000, 30),
            iface("wlan0", 1_700_000, 170, 60_000, 6),
        ],
        sockets: SocketStates {
            total: 500,
            established: 400,
            time_wait: 45,
            close_wait: 12,
        },
        holders: vec![HolderRow {
            pid: 999,
            comm: "python3".to_owned(),
            sockets: 23,
        }],
        fd_permission_refused: 5,
        exit_lane: ExitLane::NotAttached,
    }
}

#[test]
fn the_report_carries_the_locked_shape() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains("Evidence report: symptom - network"),
        "{report}"
    );
    assert!(report.contains("Interfaces (window 1.0s):"), "{report}");
    assert!(
        report.contains("eth0  RX 1.4 MiB (150 packets)  TX 292 KiB (30 packets)  [measured]"),
        "{report}"
    );
    assert!(report.contains("Socket states:"), "{report}");
    assert!(
        report.contains("ESTABLISHED 400  TIME_WAIT 45  CLOSE_WAIT 12  (of 500 sockets)"),
        "{report}"
    );
    assert!(report.contains("Top socket holders:"), "{report}");
    assert!(
        report.contains("PID 999 (python3)  23 sockets open  [measured]"),
        "{report}"
    );
}

#[test]
fn the_verdict_names_the_busiest_interface_and_the_permission_boundary() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains("The busiest interface is eth0 (RX 1.4 MiB, TX 292 KiB in the window)."),
        "{report}"
    );
    assert!(
        report.contains(
            "5 processes' fd tables unreadable (permission) - the holder list names \
             only the holders visible to this user"
        ),
        "{report}"
    );
    // 45 TIME_WAIT is under the boundary - the risk line must not
    // fire.
    assert!(!report.contains("port exhaustion"), "{report}");
}

#[test]
fn the_port_exhaustion_boundary_fires_above_the_named_number() {
    let mut churn = synthetic();
    churn.sockets.time_wait = 1500;
    let report = render(&churn, false);
    assert!(
        report.contains(
            "The TIME_WAIT count (1500) is above 1024 - local port exhaustion pressure \
             is the named risk"
        ),
        "{report}"
    );
}

#[test]
fn the_empty_window_is_a_named_finding() {
    let mut quiet = synthetic();
    quiet.interfaces.clear();
    let report = render(&quiet, false);
    assert!(
        report.contains("No interface moved a byte or a packet in the window."),
        "{report}"
    );
}

#[test]
fn the_raw_drill_down_names_the_interface_table() {
    let plain = render(&synthetic(), false);
    assert!(!plain.contains("Raw /proc reads"), "{plain}");
    let raw = render(&synthetic(), true);
    assert!(raw.contains("Raw /proc reads (drill-down):"), "{raw}");
    assert!(raw.contains("/proc/net/dev:"), "{raw}");
}
