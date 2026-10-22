// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The disk symptom's pins (night-improve-48): the I/O delta table
//! and the render shape, pinned with synthetic samples - the
//! report is the contract, not this host's own I/O.

use super::*;
use std::collections::BTreeMap;

fn stat(comm: &str) -> delta::PidStat {
    delta::PidStat {
        comm: comm.to_owned(),
        state: 'S',
        cpu_ticks: 10,
    }
}

fn io(read: u64, write: u64) -> delta::PidIo {
    delta::PidIo {
        read_bytes: read,
        write_bytes: write,
    }
}

#[test]
fn the_delta_table_ranks_by_combined_bytes_and_keeps_both_halves() {
    let mut a = BTreeMap::new();
    a.insert(1, io(1000, 0));
    a.insert(2, io(0, 2000));
    let mut b = BTreeMap::new();
    b.insert(1, io(512 * 1024 * 1024 + 1000, 0));
    b.insert(2, io(0, 2000));
    let mut stats = BTreeMap::new();
    stats.insert(1, stat("dd"));
    stats.insert(2, stat("quiet"));
    let (rows, started, vanished) = delta_rows(&a, &b, &stats);
    assert_eq!(rows.len(), 1, "zero deltas are not rows");
    assert_eq!(rows[0].pid, 1);
    assert_eq!(rows[0].comm, "dd");
    assert_eq!(rows[0].read_delta, 512 * 1024 * 1024);
    assert_eq!(rows[0].write_delta, 0);
    assert_eq!(started, 0);
    assert_eq!(vanished, 0);
}

#[test]
fn the_delta_table_sorts_by_total_then_pid_and_counts_the_boundaries() {
    let mut a = BTreeMap::new();
    a.insert(10, io(10, 10));
    a.insert(20, io(0, 0));
    a.insert(30, io(5, 5));
    let mut b = BTreeMap::new();
    b.insert(20, io(0, 900));
    b.insert(30, io(300, 300));
    b.insert(40, io(5, 5));
    let stats = BTreeMap::new();
    let (rows, started, vanished) = delta_rows(&a, &b, &stats);
    // pid 20 wrote 900 (no baseline A? it HAD one: (0,0) - delta
    // (0,900) counts), pid 30 moved 600, pid 10 vanished, pid 40
    // started with no baseline.
    let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
    assert_eq!(pids, vec![20, 30], "combined bytes descending");
    assert_eq!(started, 1);
    assert_eq!(vanished, 1);
    assert_eq!(rows[0].comm, "unknown", "a vanished comm is not guessed");
}

fn synthetic() -> DiskSample {
    DiskSample {
        sampled_at: "2026-10-22 10:00:00 (UTC)".to_owned(),
        iowait_pct: Some(23.4),
        total_ticks_delta: 1000,
        top: vec![DiskRow {
            pid: 4242,
            comm: "dd".to_owned(),
            read_delta: 512 * 1024 * 1024,
            write_delta: 300,
        }],
        started_in_window: 1,
        vanished_between_reads: 0,
        io_permission_refused: 7,
        exit_lane: ExitLane::NotAttached,
    }
}

#[test]
fn the_report_carries_the_locked_shape() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains("Evidence report: symptom - disk"),
        "{report}"
    );
    assert!(
        report.contains("Mode: snapshot delta (1.0s sample; eBPF not attached)"),
        "{report}"
    );
    assert!(report.contains("I/O wait (window 1.0s):"), "{report}");
    assert!(
        report.contains("iowait: 23.4% of total CPU ticks (delta 1000 ticks)"),
        "{report}"
    );
    assert!(report.contains("Top disk I/O (window 1.0s):"), "{report}");
    assert!(
        report.contains("PID 4242 (dd)  read 512.0 MiB, wrote 300 B  [measured]"),
        "{report}"
    );
}

#[test]
fn the_permission_boundary_is_named_never_dropped() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains(
            "7 processes' /proc/<pid>/io unreadable (permission - root or the owning \
             user only): their I/O share is not carried"
        ),
        "{report}"
    );
    assert!(
        report.contains("1 processes started inside the window"),
        "{report}"
    );
}

#[test]
fn the_verdict_names_the_hog_and_the_iowait_finding() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains(
            "The largest disk I/O consumer is dd (read 512.0 MiB, wrote 300 B in the \
             window)."
        ),
        "{report}"
    );
    assert!(
        report.contains(
            "The I/O wait (23.4% of the window's CPU ticks) is high; the top I/O consumer \
             above is dd (PID 4242)."
        ),
        "{report}"
    );
}

#[test]
fn a_quiet_iowait_never_fires_the_finding() {
    let mut quiet = synthetic();
    quiet.iowait_pct = Some(3.0);
    let report = render(&quiet, false);
    assert!(
        report.contains("iowait: 3.0% of total CPU ticks"),
        "{report}"
    );
    assert!(!report.contains("is high;"), "{report}");
}

#[test]
fn the_empty_window_is_a_named_finding() {
    let mut quiet = synthetic();
    quiet.top.clear();
    let report = render(&quiet, false);
    assert!(
        report.contains("No process moved block-backed I/O in the window."),
        "{report}"
    );
}

#[test]
fn the_raw_drill_down_names_the_top_files() {
    let plain = render(&synthetic(), false);
    assert!(!plain.contains("Raw /proc reads"), "{plain}");
    let raw = render(&synthetic(), true);
    assert!(raw.contains("Raw /proc reads (drill-down):"), "{raw}");
    assert!(
        raw.contains("/proc/<pid>/io (top 10 by window delta, verbatim):"),
        "{raw}"
    );
}
