// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
// NON_LATIN_FIXTURE: the multibyte rejection pins deliberately
// exercise CJK, kana-style seconds, accented units, and a
// four-byte CJK Extension B ideograph - the exact inputs the
// pre-fix parser panicked on.
//
//! The port window pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/commands/port/window.rs. The grammar half (parse, clamp,
//! label, refusal) and the fallback contract are pinned in every
//! lane; the live rendering half is pinned under the ebpf feature
//! with synthetic events - the format is the contract, not the
//! host's traffic.

use super::*;
use crate::commands::port::model::Protocol;
use std::collections::HashMap;

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
        window: WINDOW_DEFAULT,
        events_only: false,
        snapshot_only: false,
    }
}

#[test]
fn window_grammar_accepts_s_m_h() {
    assert_eq!(parse_window("60s").unwrap(), Duration::from_secs(60));
    assert_eq!(parse_window("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_window("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_window("90s").unwrap(), Duration::from_secs(90));
}

#[test]
fn window_grammar_rejects_the_shapes_it_does_not_speak() {
    // Days are the file-age grammar (recent's); bare numbers, empty
    // strings, and floats are nobody's grammar.
    for bad in ["", "5", "s", "60x", "5d", "1.5m", "-60s", "60S"] {
        assert!(parse_window(bad).is_err(), "must reject {bad:?}");
    }
}

#[test]
fn window_grammar_rejects_multibyte_units_without_panicking() {
    // night-dragon-lts-1: the pre-fix parser split the input at
    // len() - 1 BYTES, and str::split_at panics when that index
    // lands inside a multibyte character - `--since 5分` (or a
    // bare `é`) crashed the CLI with a byte-index panic instead of
    // the clean usage error. Every multibyte-final input must be a
    // rejection, never a panic. The four-byte CJK Extension B
    // ideograph (U+20000) rides beside the two- and three-byte
    // shapes: it exercises the widest char the boundary can land
    // inside without carrying an emoji-class codepoint (the owner
    // law bans those from every text file, fixtures included).
    for bad in ["é", "日", "5分", "60秒", "\u{20000}", "5s分"] {
        assert!(parse_window(bad).is_err(), "must reject {bad:?}");
    }
    // An ASCII unit after a multibyte amount stays a rejection too
    // (the amount is not a number).
    assert!(parse_window("分s").is_err());
}

#[test]
fn huge_amounts_saturate_instead_of_overflowing() {
    // night-total-lts-1: the pre-fix arithmetic (amount * 3600)
    // panicked in debug and wrapped in release - 5124095576030432h
    // wrapped to exactly zero seconds, which the clamp then shaped
    // into the 1s floor: an absurd ask produced the SMALLEST window.
    // The saturating law: an absurd window ask is "the maximum",
    // which clamp_window shapes into the honest 1h ceiling.
    assert_eq!(
        parse_window("18446744073709551615m").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    assert_eq!(
        parse_window("18446744073709551615h").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    // The exact wrap-to-zero input from the audit (2^64 seconds =
    // 5124095576030432 * 3600): pre-fix this parsed as zero seconds.
    assert_eq!(
        parse_window("5124095576030432h").unwrap(),
        Duration::from_secs(u64::MAX)
    );
    // And the clamp shapes the saturated ask into the ceiling.
    assert_eq!(
        clamp_window(parse_window("5124095576030432h").unwrap()),
        Duration::from_secs(3600)
    );
}

#[test]
fn window_clamps_into_the_evidence_shaped_range() {
    // The pinned clamps: 0s -> 1s, 2h -> 1h - and the in-range
    // values pass through untouched.
    assert_eq!(clamp_window(Duration::from_secs(0)), Duration::from_secs(1));
    assert_eq!(
        clamp_window(Duration::from_secs(7200)),
        Duration::from_secs(3600)
    );
    assert_eq!(
        clamp_window(Duration::from_secs(90)),
        Duration::from_secs(90)
    );
    assert_eq!(
        clamp_window(Duration::from_secs(2700)),
        Duration::from_secs(2700)
    );
}

#[test]
fn window_labels_are_compact_and_stable() {
    assert_eq!(window_label(Duration::from_secs(60)), "60s");
    assert_eq!(window_label(Duration::from_secs(300)), "5m");
    assert_eq!(window_label(Duration::from_secs(3600)), "1h");
    assert_eq!(window_label(Duration::from_secs(90)), "90s");
    assert_eq!(window_label(Duration::from_secs(1)), "1s");
}

#[test]
fn the_refusal_line_names_the_doctor() {
    // One shape for every not-live reason; the doctor carries the
    // exact verdict.
    assert_eq!(
        unavailability_line(Duration::from_secs(60)),
        "Changes in the last 60s: unavailable (this binary/run cannot capture \
         events - see zejtron doctor [eBPF])"
    );
    assert_eq!(
        unavailability_line(Duration::from_secs(3600)),
        "Changes in the last 1h: unavailable (this binary/run cannot capture \
         events - see zejtron doctor [eBPF])"
    );
}

#[test]
fn parse_options_carries_the_window_grammar() {
    use crate::commands::port::PortFlags;

    // Absent --since: the 60s default.
    let parsed = super::super::parse_options(None, PortFlags::default()).unwrap();
    assert_eq!(parsed.window, WINDOW_DEFAULT);

    // Present --since: parsed AND clamped (0s -> 1s, 2h -> 1h).
    let clamped_low = super::super::parse_options(
        None,
        PortFlags {
            since: Some("0s".to_owned()),
            ..PortFlags::default()
        },
    )
    .unwrap();
    assert_eq!(clamped_low.window, Duration::from_secs(1));

    let clamped_high = super::super::parse_options(
        None,
        PortFlags {
            since: Some("2h".to_owned()),
            ..PortFlags::default()
        },
    )
    .unwrap();
    assert_eq!(clamped_high.window, Duration::from_secs(3600));

    let invalid = super::super::parse_options(
        None,
        PortFlags {
            since: Some("5d".to_owned()),
            ..PortFlags::default()
        },
    );
    assert!(invalid.is_err());
}

#[test]
fn events_only_and_snapshot_only_conflict_is_refused() {
    use crate::commands::port::PortFlags;

    let conflict = super::super::parse_options(
        None,
        PortFlags {
            events_only: true,
            snapshot_only: true,
            ..PortFlags::default()
        },
    );
    assert!(conflict.is_err());
}

#[test]
fn snapshot_only_is_the_phase_one_renderer_whatever_the_lane() {
    // The escape hatch: --snapshot-only renders the phase-1 tree,
    // byte-identical, in every build - the host's pin state cannot
    // change what this flag means.
    let sockets = vec![SocketEntry {
        protocol: Protocol::Tcp,
        address: "0.0.0.0".to_owned(),
        port: 22,
        remote_address: "0.0.0.0".to_owned(),
        remote_port: 0,
        state: Some("LISTEN".to_owned()),
        inode: 100,
    }];
    let owners: OwnerMap = HashMap::new();
    let stats = ScanStats::default();
    let options = PortOptions {
        snapshot_only: true,
        ..options()
    };

    assert_eq!(
        format_port_output(&sockets, &owners, &stats, &options),
        format_report(&sockets, &owners, &stats, &options)
    );
}

// ── The live rendering pins ──────────────────

mod live {
    use super::*;
    use crate::ebpf::events::{
        AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, SockEvent, TCP_CLOSE, TCP_LISTEN,
    };

    fn live_event(
        pid: u32,
        sport: u16,
        protocol: u8,
        family: u16,
        oldstate: u8,
        newstate: u8,
    ) -> SockEvent {
        SockEvent {
            timestamp_ns: 0,
            skaddr: 0xffff_8880_0000_0000,
            family,
            protocol,
            oldstate,
            newstate,
            _pad: 0,
            sport,
            dport: 0,
            _pad2: 0,
            pid,
        }
    }

    fn self_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn snapshot_rows_are_flat_provenance_tcp_first() {
        let sockets = vec![
            SocketEntry {
                protocol: Protocol::Udp,
                address: "0.0.0.0".to_owned(),
                port: 5353,
                remote_address: "0.0.0.0".to_owned(),
                remote_port: 0,
                state: None,
                inode: 2,
            },
            SocketEntry {
                protocol: Protocol::Tcp,
                address: "0.0.0.0".to_owned(),
                port: 22,
                remote_address: "0.0.0.0".to_owned(),
                remote_port: 0,
                state: Some("LISTEN".to_owned()),
                inode: 1,
            },
        ];
        let mut owners: OwnerMap = HashMap::new();
        owners.insert(
            1,
            vec![ProcessInfo {
                pid: 1234,
                name: "sshd".to_owned(),
                user: "root".to_owned(),
                cwd: None,
                cmdline: None,
                fd: Some(3),
            }],
        );
        let rows = snapshot_rows(&sockets, &owners, &options());
        assert_eq!(rows.len(), 2);
        // TCP block first, then UDP - the spec's grouping.
        assert_eq!(
            rows[0],
            "[snapshot]  TCP  0.0.0.0:22  LISTEN  PID 1234  (sshd)"
        );
        assert_eq!(rows[1], "[snapshot]  UDP  0.0.0.0:5353  owner unknown");
    }

    #[test]
    fn window_events_filter_by_clock_protocol_and_port() {
        // The live filter chain: window cutoff, protocol selection,
        // port selection - pinned against the same CLOCK_MONOTONIC
        // the filter reads (night-dragon-lts-1: the helper used to
        // re-implement the /proc/uptime read, which is CLOCK_BOOTTIME
        // - a different domain from the bpf_ktime_get_ns stamps
        // whenever the host has ever suspended).
        let now_ns = monotonic_now_ns();
        let recent = now_ns.saturating_sub(10_000_000_000); // 10s ago
        let stale = now_ns.saturating_sub(120_000_000_000); // 120s ago

        let events = vec![
            live_event(1, 8080, IPPROTO_TCP, AF_INET, TCP_CLOSE, TCP_LISTEN), // ts 0: stale
            SockEvent {
                timestamp_ns: stale,
                ..live_event(1, 8080, IPPROTO_TCP, AF_INET, TCP_CLOSE, TCP_LISTEN)
            },
            SockEvent {
                timestamp_ns: recent,
                ..live_event(1, 8080, IPPROTO_TCP, AF_INET, TCP_CLOSE, TCP_LISTEN)
            }, // in window, TCP, port match
            SockEvent {
                timestamp_ns: recent,
                ..live_event(1, 9090, IPPROTO_TCP, AF_INET, TCP_CLOSE, TCP_LISTEN)
            }, // in window, wrong port
            SockEvent {
                timestamp_ns: recent,
                ..live_event(1, 5353, IPPROTO_UDP, AF_INET, TCP_CLOSE, TCP_CLOSE)
            }, // in window, UDP
            SockEvent {
                timestamp_ns: recent,
                ..live_event(1, 8080, IPPROTO_TCP, AF_INET, 2, 1)
            }, // in window, ESTABLISHED churn (dropped by the mirror)
        ];

        let all = PortOptions {
            window: Duration::from_secs(60),
            ..options()
        };
        let selected = window_events(&events, &all);
        let sports: Vec<u16> = selected.iter().map(|e| e.sport).collect();
        // No port probe: every in-window port-surface transition,
        // whatever the port - the churn event (ESTABLISHED) is the
        // only thing the mirror drops.
        assert_eq!(sports, vec![8080, 9090, 5353]);

        let tcp_only = PortOptions {
            tcp: true,
            window: Duration::from_secs(60),
            ..options()
        };
        let selected = window_events(&events, &tcp_only);
        assert_eq!(
            selected.iter().map(|e| e.sport).collect::<Vec<_>>(),
            vec![8080, 9090]
        );

        let port_probe = PortOptions {
            port: Some(5353),
            window: Duration::from_secs(60),
            ..options()
        };
        let selected = window_events(&events, &port_probe);
        assert_eq!(
            selected.iter().map(|e| e.sport).collect::<Vec<_>>(),
            vec![5353]
        );
    }

    fn monotonic_now_ns() -> u64 {
        crate::info::clock::monotonic_now_ns().unwrap()
    }
}
