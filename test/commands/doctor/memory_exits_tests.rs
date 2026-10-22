// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The post-mortem exit lane's pins (night-improve-47): the comm
//! rendering contract, the window arithmetic against the live
//! monotonic clock (guarded - an unreadable clock skips, it never
//! guesses), and the section render's three lane states with
//! synthetic rows only - the shape is the contract, not the host's
//! own exits.

use super::*;

fn exit(ts_ns: u64, pid: u32, comm: &[u8; 16]) -> ProcExitEvent {
    ProcExitEvent {
        timestamp_ns: ts_ns,
        pid,
        _pad: 0,
        comm: *comm,
    }
}

fn comm_bytes(name: &str) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let name = name.as_bytes();
    let len = name.len().min(16);
    bytes[..len].copy_from_slice(&name[..len]);
    bytes
}

#[test]
fn window_is_five_seconds_and_the_cap_rides_the_ledger() {
    // The spec's own window: five seconds, the freshest slice the
    // doctor names. The row cap is the ledger's TOP_N, pinned here
    // so the two constants cannot drift apart silently.
    assert_eq!(EXIT_WINDOW_SECS, 5);
    assert_eq!(super::super::ledger::TOP_N, 10);
}

#[test]
fn the_lane_defaults_to_not_attached() {
    // The honest default: a sample nobody filled reads as the
    // clean-host shape, in tests and on hosts alike.
    assert_eq!(ExitLane::default(), ExitLane::NotAttached);
}

#[test]
fn comm_renders_up_to_the_first_nul() {
    // The helper's contract: NUL-terminated, zeroed past the end.
    assert_eq!(comm_string(&comm_bytes("python3")), "python3");
    assert_eq!(comm_string(&comm_bytes("sh")), "sh");
}

#[test]
fn an_all_nul_comm_is_unknown_never_empty() {
    let mut empty = [0u8; 16];
    empty[0] = 0;
    assert_eq!(comm_string(&empty), "unknown");
    // Whitespace-only reduces to nothing and degrades the same way -
    // an absent fact stays absent, never a blank cell.
    let spaces = comm_bytes("   ");
    assert_eq!(comm_string(&spaces), "unknown");
}

#[test]
fn a_sixteen_byte_comm_renders_whole_and_lossy() {
    // No NUL in the record: the whole 16 bytes are the name (a
    // 17-byte ask truncates to the record's own width - TASK_COMM_LEN
    // is the bound both sides carry). Invalid UTF-8 degrades through
    // the lossy path - the bytes the kernel wrote are rendered as
    // close to themselves as text allows.
    let full = comm_bytes("sixteen-bytes-nam");
    assert_eq!(comm_string(&full), "sixteen-bytes-na");
    let mut hostile = [0xffu8; 16];
    hostile[0] = b'x';
    assert!(comm_string(&hostile).starts_with('x'), "lossy, not empty");
}

#[test]
fn the_window_keeps_the_fresh_slice_and_sorts_ascending() {
    // Against the live monotonic clock: the ancient stamps fall
    // outside the five-second window, the fresh ones stay, and the
    // survivors render oldest-first. An unreadable clock (no
    // /proc/uptime) skips the filter assertion entirely - the
    // honest degradation keeps every drained record.
    let Some(now) = crate::info::clock::monotonic_now_ns() else {
        return;
    };
    let events = vec![
        exit(
            now.saturating_sub(1_000_000_000),
            222,
            &comm_bytes("second"),
        ),
        exit(100, 999, &comm_bytes("ancient")),
        exit(
            now.saturating_sub(4_000_000_000),
            111,
            &comm_bytes("fourth-second"),
        ),
    ];
    let rows = window_rows(events, EXIT_WINDOW_SECS);
    let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
    assert_eq!(pids, vec![111, 222], "fresh only, ascending by time");
}

#[test]
fn the_not_attached_lane_renders_no_section() {
    // The absent lane rides the mode line and the Unaccounted block,
    // never a fake empty section - an absent lane and an empty
    // window are different truths.
    let mut lines: Vec<String> = Vec::new();
    render_section(&ExitLane::NotAttached, &mut lines, "5s");
    assert!(lines.is_empty(), "no section lines: {lines:?}");
}

#[test]
fn the_drained_lane_renders_the_spec_row_shape() {
    let mut lines: Vec<String> = Vec::new();
    let lane = ExitLane::Drained(vec![
        ExitRow {
            pid: 1234,
            comm: "python3".to_owned(),
            timestamp_ns: 1,
        },
        ExitRow {
            pid: 5678,
            comm: "make".to_owned(),
            timestamp_ns: 2,
        },
    ]);
    render_section(&lane, &mut lines, "5s");
    assert_eq!(
        lines[0], "Recently exited (eBPF, last 5s):",
        "the header names the source and the window"
    );
    assert!(
        lines[1].ends_with("  PID 1234 (python3)  exited  [observed]"),
        "the spec's own row shape: {lines:?}"
    );
    assert!(
        lines[2].ends_with("  PID 5678 (make)  exited  [observed]"),
        "rows ascend in the order they happened: {lines:?}"
    );
}

#[test]
fn the_drained_lane_renders_the_empty_window_finding() {
    let mut lines: Vec<String> = Vec::new();
    render_section(&ExitLane::Drained(Vec::new()), &mut lines, "5s");
    assert_eq!(lines[0], "Recently exited (eBPF, last 5s):");
    assert_eq!(lines[1], "  (none observed)");
}

#[test]
fn the_drained_lane_caps_rows_at_the_ledger_top_n() {
    let rows: Vec<ExitRow> = (0..12)
        .map(|i| ExitRow {
            pid: i,
            comm: "x".to_owned(),
            timestamp_ns: i as u64,
        })
        .collect();
    let mut lines: Vec<String> = Vec::new();
    render_section(&ExitLane::Drained(rows), &mut lines, "5s");
    // header + 10 rows + the overflow note + the blank separator.
    assert_eq!(lines.len(), 13, "capped rows plus the note: {lines:?}");
    assert!(
        lines[11].contains("(2 more exits in the window, not rendered)"),
        "{lines:?}"
    );
}

#[test]
fn the_drain_failed_lane_names_the_error_verbatim() {
    let mut lines: Vec<String> = Vec::new();
    render_section(
        &ExitLane::DrainFailed("pinned proc_events map test-refused".to_owned()),
        &mut lines,
        "5s",
    );
    assert_eq!(lines[0], "Recently exited (eBPF, last 5s):");
    assert!(
        lines[1].contains("the exit ring could not be read (pinned proc_events map test-refused)"),
        "the error rides the report verbatim: {lines:?}"
    );
}
