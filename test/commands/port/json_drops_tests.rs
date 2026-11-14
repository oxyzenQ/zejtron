// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The changes block's typed boundary pins (night-frontier-Z2 moved
//! the drop-truth test here - a pure move under the 600-LOC cap, the
//! builder moves' precedent) and the wall-clock skew field it gained
//! in the same frontier: both boundaries ride the changes block as
//! always-present typed fields, null when the measurement did not
//! answer, never a guessed zero.

use std::collections::HashMap;

use super::super::lane_state::LaneUnavailable;
use super::*;

/// The local options fixture (the sibling file's own helper shape,
/// duplicated so the two test modules stay independently readable):
/// no port filter, TCP-only default, not snapshot-only - a served
/// window's shape.
fn options(snapshot_only: bool) -> PortOptions {
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
        snapshot_only,
        events_only: false,
    }
}

// ── night-frontier-Z1, the drop truth typed ─────────────────────────

#[test]
fn the_changes_block_carries_the_drop_truth_typed() {
    // The typed lane's explicit zero is the machine-honest shape its
    // text lane renders as silence: number when the census answered,
    // null when it did not - the field never disappears, so a
    // consumer diffs the shape, not the field list.
    let json = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        Some(&[]),
        None,
        None,
        None,
        Some(5),
        None,
    );
    assert!(json.contains("\"ring_drops\":5"), "{json}");
    let zero = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        Some(&[]),
        None,
        None,
        None,
        Some(0),
        None,
    );
    assert!(zero.contains("\"ring_drops\":0"), "{zero}");
    let unknown = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        Some(&[]),
        None,
        None,
        None,
        None,
        None,
    );
    assert!(unknown.contains("\"ring_drops\":null"), "{unknown}");
    // A lane-down shape consults no camera: null, not a guess.
    let down = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        None,
        None,
        None,
        None,
        None,
        Some(LaneUnavailable::NotAttached),
    );
    assert!(down.contains("\"ring_drops\":null"), "{down}");
}

// ── night-frontier-Z2, the wall-clock skew typed ────────────────────

#[test]
fn the_changes_block_carries_the_wall_skew_typed() {
    // The skew field rides the same always-present law: a NUMBER when
    // the measurement answered, null when the capture had no pre
    // anchor. The exact value rides the pure compare's own pins
    // (test/info/clock_tests.rs) - a live render offset cannot be
    // named by a fixture, and pretending otherwise would be a flaky
    // pin, not a law.
    let json = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        Some(&[]),
        None,
        None,
        Some(0),
        None,
        None,
    );
    let marker = "\"wall_skew_ns\":";
    let start = json.find(marker).expect("the field always rides") + marker.len();
    let value = &json[start..start + 1];
    assert!(
        value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '-'),
        "a pre anchor renders a signed number, got: {value}"
    );
    let none = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &ScanStats::default(),
        &options(false),
        Some(&[]),
        None,
        None,
        None,
        None,
        None,
    );
    assert!(none.contains("\"wall_skew_ns\":null"), "{none}");
}
