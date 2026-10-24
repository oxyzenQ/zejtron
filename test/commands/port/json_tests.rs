// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The port surface's JSON lane pins (night-badass-9). Lives under
//! the single test/ tree and is #[path]-wired from
//! src/commands/port/json.rs. The schema is the contract: the two
//! truths (snapshot table, event window), the lane honesty (the
//! unavailable window names its reason, never a fabricated event
//! list), and the absence law (nulls, not empty strings).

use super::*;

use crate::commands::port::model::Protocol;
use crate::ebpf::events::{AF_INET, IPPROTO_TCP, IPPROTO_UDP, TCP_CLOSE, TCP_LISTEN};
use std::collections::HashMap;
use std::time::Duration;

fn options(snapshot_only: bool) -> PortOptions {
    PortOptions {
        port: Some(9999),
        tcp: false,
        udp: false,
        listen: false,
        all: false,
        numeric: false,
        group: false,
        no_pid: false,
        window: Duration::from_secs(60),
        events_only: false,
        snapshot_only,
    }
}

fn socket() -> SocketEntry {
    SocketEntry {
        protocol: Protocol::Tcp,
        address: "0.0.0.0".to_owned(),
        port: 9999,
        remote_address: "0.0.0.0".to_owned(),
        remote_port: 0,
        state: Some("LISTEN".to_owned()),
        inode: 42,
    }
}

fn owners() -> OwnerMap {
    HashMap::from([(
        42u64,
        vec![super::super::model::ProcessInfo {
            pid: 2829,
            name: "python3".to_owned(),
            user: "root".to_owned(),
            cwd: None,
            cmdline: None,
            fd: Some(3),
        }],
    )])
}

fn live_event(pid: u32, oldstate: u8, newstate: u8) -> SockEvent {
    SockEvent {
        timestamp_ns: 0,
        skaddr: 0xffff_8880_0000_0000,
        family: AF_INET,
        protocol: IPPROTO_TCP,
        oldstate,
        newstate,
        _pad: 0,
        sport: 9999,
        dport: 0,
        _pad2: 0,
        pid,
    }
}

fn live_udp_event(pid: u32) -> SockEvent {
    SockEvent {
        protocol: IPPROTO_UDP,
        ..live_event(pid, TCP_CLOSE, TCP_CLOSE)
    }
}

#[test]
fn json_snapshot_shape_pins_the_two_truths() {
    let stats = ScanStats::default();
    let opts = options(true);
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None);
    // The subject pins the asked port; the mode is the honest
    // snapshot; the ports array carries the owner typed.
    assert!(out.starts_with("{\"subject\":\":9999\""));
    assert!(out.contains("\"mode\":\"snapshot\""));
    assert!(out.contains("\"window\":\"60s\""));
    assert!(out.contains(
        "\"ports\":[{\"protocol\":\"tcp\",\"local_addr\":\"0.0.0.0:9999\",\"state\":\"LISTEN\""
    ));
    assert!(out.contains("\"owners\":[{\"pid\":2829,\"process\":\"python3\",\"user\":\"root\"}]"));
    // The snapshot-only escape hatch names its own reason.
    assert!(out.contains("\"changes\":{\"available\":false,\"reason\":\"snapshot-only\""));
    assert!(out.contains("\"events\":[]"));
    assert!(out.contains("\"scan\":{\"unreadable_processes\":0,\"unreadable_fds\":0}"));
    assert!(!out.contains('\n'));
}

#[test]
fn json_snapshot_without_a_port_filter_has_a_null_subject() {
    let stats = ScanStats::default();
    let mut opts = options(true);
    opts.port = None;
    let out = super::port_report_json(&[], &HashMap::new(), &stats, &opts, None);
    assert!(out.starts_with("{\"subject\":null"));
}

#[test]
fn json_live_shape_carries_the_event_kinds() {
    let stats = ScanStats::default();
    let opts = options(false);
    let events = vec![
        live_event(std::process::id(), TCP_CLOSE, TCP_LISTEN),
        // The UDP closed transition: the third truth the window
        // grammar names.
        live_udp_event(std::process::id()),
        // A pid the kernel no longer shows: the unaccounted gap.
        live_event(4_000_000, TCP_CLOSE, TCP_LISTEN),
    ];
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, Some(&events));
    assert!(out.contains("\"mode\":\"live\""));
    assert!(out.contains("\"changes\":{\"available\":true,\"reason\":null"));
    // The transition vocabulary, as the jq-friendly kind tokens.
    assert!(out.contains("\"kind\":\"listened\""));
    assert!(out.contains("\"kind\":\"closed\""));
    assert!(out.contains("\"protocol\":\"tcp4\""));
    assert!(out.contains("\"protocol\":\"udp4\""));
    assert!(out.contains("\"port\":9999"));
    assert!(out.contains("\"unaccounted\":1"));
}

#[test]
fn json_lane_absence_names_the_reason_not_a_fake_window() {
    let stats = ScanStats::default();
    let opts = options(false);
    // The default shape with no captured window: the same snapshot
    // honesty as --snapshot-only, with the lane's own reason.
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None);
    assert!(out.contains("\"mode\":\"snapshot\""));
    assert!(out.contains("\"changes\":{\"available\":false,\"reason\":\"lane-not-attached\""));
}
