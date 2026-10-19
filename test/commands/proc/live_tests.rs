// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The lifecycle stream's render pins (night-improve-4, Part C):
//! SYNTHETIC ProcEvents in, the locked report shape out - the
//! contract, not the host's own task churn. The rows carry
//! [observed] (the kernel recorded each event the moment it
//! happened), the Unaccounted block names the stream's boundaries,
//! and the verdict names facts, never actions.

use super::*;
use crate::ebpf::events::{PROC_OP_EXEC, PROC_OP_EXIT, PROC_OP_FORK, ProcEvent};

fn event(op: u8, pid: u32, ppid: u32, comm: &str, timestamp_ns: u64) -> ProcEvent {
    let mut comm_bytes = [0u8; 16];
    let name = comm.as_bytes();
    let len = name.len().min(16);
    comm_bytes[..len].copy_from_slice(&name[..len]);
    ProcEvent {
        timestamp_ns,
        op,
        _pad: [0; 3],
        pid,
        ppid,
        uid: 1000,
        comm: comm_bytes,
    }
}

#[test]
fn op_labels_name_the_three_truths_and_refuse_the_rest() {
    assert_eq!(op_label(PROC_OP_EXEC), Some("exec'd"));
    assert_eq!(op_label(PROC_OP_FORK), Some("started"));
    assert_eq!(op_label(PROC_OP_EXIT), Some("exited"));
    assert_eq!(op_label(0), None);
    assert_eq!(op_label(4), None);
}

#[test]
fn the_memory_hog_list_matches_by_prefix_only() {
    assert!(is_memory_hog_comm("python3"));
    assert!(is_memory_hog_comm("java"));
    assert!(is_memory_hog_comm("chromium-browse"));
    assert!(is_memory_hog_comm("pythonista-long")); // prefix still matches
    assert!(!is_memory_hog_comm("bash"));
    assert!(!is_memory_hog_comm(""));
}

#[test]
fn the_report_carries_the_locked_header_and_mode() {
    let report = render(&[], Duration::from_secs(30));
    let mut lines = report.lines();
    assert_eq!(lines.next(), Some("Evidence report: process lifecycle"));
    assert_eq!(lines.next(), Some("Mode: live (window 30s)"));
}

#[test]
fn an_empty_window_says_so_and_names_the_boundaries() {
    let report = render(&[], Duration::from_secs(45));
    assert!(report.contains("(no events in the window)"), "{report}");
    assert!(
        report.contains("Processes that existed before attach (no birth event recorded)"),
        "{report}"
    );
    assert!(
        report.contains("Processes owned by other users with hidepid=2 (namespace boundary)"),
        "{report}"
    );
    assert!(report.contains("Unaccounted:"), "{report}");
    assert!(report.contains("Verdict:"), "{report}");
}

#[test]
fn the_rows_carry_observed_provenance_and_utc() {
    let events = vec![
        event(PROC_OP_FORK, 1234, 5678, "python3", 0),
        event(PROC_OP_EXIT, 1234, 0, "python3", 51_000_000_000),
    ];
    let report = render(&events, Duration::from_secs(60));
    let mut lines = report.lines();
    assert_eq!(lines.next(), Some("Evidence report: process lifecycle"));
    assert_eq!(lines.next(), Some("Mode: live (window 60s)"));
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), Some("Process events:"));
    let first = lines.next().expect("the first row");
    assert!(
        first.ends_with("PID 1234 (python3)  started  [observed]  ppid 5678"),
        "{first}"
    );
    // The rows declare the column's clock: HH:MM:SS UTC.
    assert!(first.contains(" UTC"), "{first}");
    let second = lines.next().expect("the second row");
    assert!(
        second.ends_with("PID 1234 (python3)  exited  [observed]  runtime 51s"),
        "{second}"
    );
    // The exit row carries no ppid (0 = the walk refused or the
    // tracepoint did not name one) - the absent token stays absent.
    assert!(!second.contains("ppid"), "{second}");
}

#[test]
fn an_exit_without_a_birth_in_window_omits_the_runtime() {
    // The task was born before attach: no birth event in the window,
    // so the runtime is unknown - omitted, never guessed.
    let events = vec![event(PROC_OP_EXIT, 77, 0, "sshd", 0)];
    let report = render(&events, Duration::from_secs(30));
    let row = report
        .lines()
        .find(|l| l.contains("PID 77"))
        .expect("the exit row");
    assert!(row.contains("exited"), "{row}");
    assert!(!row.contains("runtime"), "{row}");
}

#[test]
fn the_verdict_counts_and_names_a_memory_hog_conditionally() {
    let events = vec![
        event(PROC_OP_FORK, 10, 1, "systemd", 0),
        event(PROC_OP_EXEC, 10, 0, "python3", 1_000_000_000),
    ];
    let report = render(&events, Duration::from_secs(30));
    assert!(report.contains("2 lifecycle event(s) in 30s."), "{report}");
    assert!(
        report.contains("PID 10 (python3) is named - investigate its lifetime against"),
        "{report}"
    );

    // A window with no memory-hungry exec carries only the count.
    let quiet = vec![event(PROC_OP_FORK, 10, 1, "systemd", 0)];
    let report = render(&quiet, Duration::from_secs(30));
    assert!(report.contains("1 lifecycle event(s) in 30s."), "{report}");
    assert!(!report.contains("is named - investigate"), "{report}");
}

#[test]
fn the_render_is_deterministic_byte_for_byte() {
    let events = vec![
        event(PROC_OP_FORK, 1234, 5678, "python3", 0),
        event(PROC_OP_EXIT, 1234, 0, "python3", 51_000_000_000),
    ];
    assert_eq!(
        render(&events, Duration::from_secs(30)),
        render(&events, Duration::from_secs(30))
    );
}
