// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The port JSON lane's window-boundary pins (the one-shot window
//! semantics residual). Split from json_tests.rs at the 600-LOC cap
//! (the no-mercy law) - the boundary pins are their own topic: the
//! changes block names WHICH window it describes. Two sequential
//! runs watch two different windows, and the automation lane gets
//! the same answer the text header gives the human reader. The
//! bounds are the capture's own CLOCK_MONOTONIC stamps, fed here as
//! fixtures (hermetic: no ring, no live window); the rendered times
//! ride the live wall offset, so the pins are structural (the
//! `HH:MM:SS UTC` shape) and arithmetic (the span between the
//! stamps), never by wall-clock value. Wired from
//! src/commands/port/json.rs beside the schema pins it extends.

use super::*;

use crate::commands::port::model::Protocol;
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

/// The stamps one capture observed: start T, end T + window + the
/// collection overhead - the real capture's own shape (the wait
/// runs the window long, the drains cost the overhead).
fn fixture_bounds(window_secs: u64, overhead_ns: u64) -> (u64, u64) {
    let start = 30_000_123_456_789;
    (start, start + window_secs * 1_000_000_000 + overhead_ns)
}

/// The value token of one changes-block boundary field.
fn window_field(out: &str, field: &str) -> String {
    let marker = format!("\"{field}\":");
    let start = out
        .find(&marker)
        .unwrap_or_else(|| panic!("{field} present: {out}"));
    let rest = &out[start + marker.len()..];
    let end = rest.find(',').unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// The seconds-of-day a `HH:MM:SS UTC` token names - the parse the
/// span pin computes over.
fn seconds_of_day(token: &str) -> u64 {
    let bare = token.trim_matches('"');
    let clock = bare
        .strip_suffix(" UTC")
        .unwrap_or_else(|| panic!("the UTC marker rides the token: {bare}"));
    assert_eq!(clock.len(), 8, "HH:MM:SS shape: {clock}");
    assert_eq!(&clock[2..3], ":", "{clock}");
    assert_eq!(&clock[5..6], ":", "{clock}");
    let parts: Vec<u64> = clock.split(':').map(|p| p.parse().unwrap()).collect();
    parts[0] * 3600 + parts[1] * 60 + parts[2]
}

#[test]
fn json_changes_block_names_its_window() {
    // available:true + observed bounds: both fields present, both
    // string-typed, both `HH:MM:SS UTC` - and the span between them
    // is the window the capture actually watched (end - start ~= the
    // duration, the tolerance covering the fixture's own overhead
    // and the whole-second truncation).
    let stats = ScanStats::default();
    let opts = options(false);
    let bounds = fixture_bounds(60, 137_000_000);
    let out = super::port_report_json_with_exits(
        &[socket()],
        &owners(),
        &stats,
        &opts,
        Some(&[]),
        None,
        Some(bounds),
        None,
        None,
    );
    assert!(out.contains("\"changes\":{\"available\":true"), "{out}");
    let start = window_field(&out, "window_start_utc");
    let end = window_field(&out, "window_end_utc");
    for token in [&start, &end] {
        assert!(
            token.starts_with('"') && token.ends_with('"'),
            "string-typed: {token}"
        );
        seconds_of_day(token);
    }
    let span = (seconds_of_day(&end) + 86_400 - seconds_of_day(&start)) % 86_400;
    assert!((58..=62).contains(&span), "end - start ~= 60s: {span}");
    // One line, one block: the boundaries ride inside the changes
    // block the automation lane reads.
    assert!(!out.contains('\n'), "{out}");
}

#[test]
fn json_two_sequential_runs_name_two_different_windows() {
    // The live evidence this residual closes, hermetic: two
    // sequential runs of the same command capture two different
    // windows - the blocks must not render a static range. The
    // second run's start IS the first run's end (the same shape the
    // owner's two back-to-back invocations produce).
    let stats = ScanStats::default();
    let opts = options(false);
    let first = fixture_bounds(60, 0);
    let second = (first.1, first.1 + 60 * 1_000_000_000 + 42_000_000);
    let one = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &stats,
        &opts,
        Some(&[]),
        None,
        Some(first),
        None,
        None,
    );
    let two = super::port_report_json_with_exits(
        &[],
        &HashMap::new(),
        &stats,
        &opts,
        Some(&[]),
        None,
        Some(second),
        None,
        None,
    );
    assert_ne!(
        window_field(&one, "window_start_utc"),
        window_field(&two, "window_start_utc"),
        "the ranges are real, not static strings"
    );
    assert_ne!(
        window_field(&one, "window_end_utc"),
        window_field(&two, "window_end_utc"),
    );
}

#[test]
fn json_unavailable_changes_block_keeps_both_fields_null() {
    // The lane never ran: both boundary fields are null - never
    // omitted, never invented (the schema law).
    let stats = ScanStats::default();
    let opts = options(false);
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None, None, None);
    assert!(
        out.contains(
            "\"changes\":{\"available\":false,\"reason\":\"lane-not-attached\",\
             \"hint\":\"attach first: sudo zejtron doctor --attach\",\
             \"window_start_utc\":null,\"window_end_utc\":null"
        ),
        "{out}"
    );
}

#[test]
fn json_window_that_ran_without_a_clock_keeps_both_fields_null() {
    // The honest absence law: a served window whose clock read
    // failed cannot name its boundaries - the fields stay null (the
    // events still ride), the lane never guesses a range.
    let stats = ScanStats::default();
    let opts = options(false);
    let out = super::port_report_json_with_exits(
        &[socket()],
        &owners(),
        &stats,
        &opts,
        Some(&[]),
        None,
        None,
        None,
        None,
    );
    assert!(
        out.contains(
            "\"changes\":{\"available\":true,\"reason\":null,\"hint\":null,\
             \"window_start_utc\":null,\"window_end_utc\":null"
        ),
        "{out}"
    );
}

/// The lane-honesty pins (the misleading-reason residual): the
/// changes block names the ACTUAL cause and the next action that
/// heals it - a lane this euid cannot read is not a lane that is
/// not attached. Split here with the boundary pins (the 600-LOC
/// cap); the classification ladder's own unit pins live in
/// window_tests.rs - this module pins the JSON contract only.
mod lane_honesty {
    use super::*;

    fn report_with_lane(lane: Option<LaneUnavailable>) -> String {
        let stats = ScanStats::default();
        let opts = options(false);
        super::port_report_json_with_exits(
            &[socket()],
            &owners(),
            &stats,
            &opts,
            None,
            None,
            None,
            None,
            lane,
        )
    }

    #[test]
    fn json_the_unreadable_lane_names_sudo_not_attach() {
        // The live evidence, typed: pins present, euid != 0 - the
        // reason is the permission wall and the hint is the sudo
        // command, never the attach instruction that cannot heal it.
        let out = report_with_lane(Some(LaneUnavailable::Unreadable));
        assert!(
            out.contains(
                "\"reason\":\"lane-unreadable\",\"hint\":\"pins exist but \
                 are root-owned: run with sudo\""
            ),
            "{out}"
        );
        assert!(!out.contains("lane-not-attached"), "{out}");
    }

    #[test]
    fn json_the_missing_lane_names_attach_first() {
        let out = report_with_lane(Some(LaneUnavailable::NotAttached));
        assert!(
            out.contains(
                "\"reason\":\"lane-not-attached\",\"hint\":\"attach first: \
                 sudo zejtron doctor --attach\""
            ),
            "{out}"
        );
    }

    #[test]
    fn json_the_mid_window_detach_names_the_retry() {
        // The window ran and its lane was torn down mid-flight: the
        // block reports the detach, the events stay empty (never a
        // suspect window served as whole), the hint says re-attach.
        let out = report_with_lane(Some(LaneUnavailable::DetachedMidWindow));
        assert!(
            out.contains(
                "\"reason\":\"lane-detached-mid-window\",\"hint\":\"the lane \
                 was detached mid-window: re-attach and retry\""
            ),
            "{out}"
        );
        assert!(out.contains("\"available\":false"), "{out}");
        assert!(out.contains("\"events\":[]"), "{out}");
        assert!(
            out.contains("\"window_start_utc\":null,\"window_end_utc\":null"),
            "{out}"
        );
    }

    #[test]
    fn json_the_working_lane_carries_null_reason_and_null_hint() {
        // The contract's silence half: reason null, hint null - the
        // absence IS the "lane worked" verdict.
        let stats = ScanStats::default();
        let opts = options(false);
        let out = super::port_report_json_with_exits(
            &[socket()],
            &owners(),
            &stats,
            &opts,
            Some(&[]),
            None,
            None,
            None,
            None,
        );
        assert!(
            out.contains("\"changes\":{\"available\":true,\"reason\":null,\"hint\":null"),
            "{out}"
        );
    }

    #[test]
    fn json_snapshot_only_stays_a_named_shape_without_a_hint() {
        // The operator's own request is not a failure: the reason
        // token rides (it always has), no next action is invented.
        let stats = ScanStats::default();
        let opts = options(true);
        let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None, None, None);
        assert!(
            out.contains(
                "\"changes\":{\"available\":false,\"reason\":\"snapshot-only\",\"hint\":null"
            ),
            "{out}"
        );
    }

    #[test]
    fn json_the_reason_and_hint_are_strings_or_nulls_never_absent() {
        // The schema law: the pair is ALWAYS present in the changes
        // block - strings when the lane is down, nulls when it is
        // not. Pinned through every shape the block can take.
        for out in [
            report_with_lane(None),
            report_with_lane(Some(LaneUnavailable::Unreadable)),
        ] {
            let changes = out
                .split("\"changes\":{")
                .nth(1)
                .and_then(|rest| rest.find(",\"events\":").map(|end| &rest[..end]))
                .expect("the changes block");
            assert!(changes.contains("\"reason\":"), "{changes}");
            assert!(changes.contains("\"hint\":"), "{changes}");
        }
    }
}
