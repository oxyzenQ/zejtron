// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The cpu symptom's pins (night-improve-48): the delta table, the
//! render shape, and the stuck-I/O verdict, all pinned with
//! synthetic samples - the report is the contract, not this host's
//! own load.

use super::*;
use std::collections::BTreeMap;

fn stat(comm: &str, state: char, ticks: u64) -> delta::PidStat {
    delta::PidStat {
        comm: comm.to_owned(),
        state,
        cpu_ticks: ticks,
    }
}

fn sample_a() -> BTreeMap<u32, delta::PidStat> {
    let mut map = BTreeMap::new();
    map.insert(1, stat("yes", 'R', 100));
    map.insert(2, stat("old", 'S', 50));
    map
}

fn sample_b() -> BTreeMap<u32, delta::PidStat> {
    let mut map = BTreeMap::new();
    map.insert(1, stat("yes", 'R', 472));
    map.insert(2, stat("old", 'S', 50));
    map.insert(3, stat("newborn", 'S', 5));
    map
}

#[test]
fn the_delta_table_ranks_descending_and_counts_the_boundaries() {
    let (rows, started, vanished) = delta_rows(&sample_a(), &sample_b(), 1000);
    // pid 1 burned 372 ticks (47.2% of 1000); pid 2 burned none and
    // is not a row; pid 3 has no baseline and counts as started;
    // nobody vanished in this shape (pid 2 lived through both).
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pid, 1);
    assert_eq!(rows[0].comm, "yes");
    assert_eq!(rows[0].ticks, 372);
    assert!((rows[0].pct - 37.2).abs() < 0.01);
    assert_eq!(started, 1);
    assert_eq!(vanished, 0);
}

#[test]
fn the_delta_table_sorts_by_ticks_then_pid_and_skips_zero_deltas() {
    let mut a = BTreeMap::new();
    a.insert(10, stat("idle", 'S', 40));
    a.insert(20, stat("busy", 'R', 10));
    a.insert(30, stat("busier", 'R', 0));
    let mut b = BTreeMap::new();
    b.insert(10, stat("idle", 'S', 40));
    b.insert(20, stat("busy", 'R', 60));
    b.insert(30, stat("busier", 'R', 200));
    let (rows, started, vanished) = delta_rows(&a, &b, 250);
    let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
    assert_eq!(pids, vec![30, 20], "descending by ticks");
    assert_eq!(vanished, 0);
    assert_eq!(started, 0);
}

#[test]
fn the_delta_table_survives_a_zero_tick_host() {
    // A zero total delta (a machine that burned nothing) yields
    // rows with 0% rather than a division panic - the honest shape.
    let (rows, _, _) = delta_rows(&sample_a(), &sample_b(), 0);
    assert_eq!(rows[0].pct, 0.0);
}

fn synthetic() -> CpuSample {
    CpuSample {
        sampled_at: "2026-10-22 10:00:00 (UTC)".to_owned(),
        ncpu: 2,
        loadavg_1min: Some(1.50),
        busy_pct: Some(47.2),
        total_ticks_delta: 2000,
        top: vec![CpuRow {
            pid: 1234,
            comm: "yes".to_owned(),
            pct: 47.2,
            ticks: 944,
        }],
        running: 4,
        stuck: vec![StuckRow {
            pid: 77,
            comm: "kworker".to_owned(),
        }],
        stuck_overflow: 0,
        started_in_window: 2,
        vanished_between_reads: 1,
        exit_lane: ExitLane::NotAttached,
        raw_stat_a: "cpu  1 2 3 4 5 6 7 8".to_owned(),
        raw_stat_b: "cpu  2 4 6 8 10 12 14 16".to_owned(),
        raw_loadavg: "1.50 1.00 0.50 1/500 12345".to_owned(),
    }
}

#[test]
fn the_report_carries_the_locked_header_mode_and_sections() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains("Evidence report: symptom - cpu"),
        "{report}"
    );
    assert!(
        report.contains("Mode: snapshot delta (1.0s sample; eBPF not attached)"),
        "{report}"
    );
    assert!(
        report.contains("Sampled: 2026-10-22 10:00:00 (UTC)"),
        "{report}"
    );
    assert!(report.contains("CPU (window 1.0s):"), "{report}");
    assert!(
        report.contains("Busy: 47.2% of total ticks (delta 2000 ticks across 2 cores)"),
        "{report}"
    );
    assert!(
        report.contains("Load average (1m): 1.50 across 2 cores"),
        "{report}"
    );
    assert!(
        report.contains("Top CPU consumers (window 1.0s):"),
        "{report}"
    );
    assert!(
        report.contains("PID 1234 (yes)  47.2% of total CPU  (944 ticks)  [measured]"),
        "the spec's own row shape: {report}"
    );
    assert!(report.contains("Load / stuck:"), "{report}");
    assert!(
        report.contains("4 processes in R state (running)  [measured]"),
        "{report}"
    );
    assert!(
        report.contains("PID 77 (kworker)  state D (uninterruptible sleep)  [measured]"),
        "{report}"
    );
}

#[test]
fn the_report_names_the_boundaries_and_the_verdict() {
    let report = render(&synthetic(), false);
    assert!(report.contains("Unaccounted:"), "{report}");
    assert!(
        report.contains(
            "processes that started and exited within the 1.0s sampling window: \
             not attributed (zejtron samples, it does not watch)"
        ),
        "{report}"
    );
    assert!(
        report.contains("2 processes started inside the window"),
        "{report}"
    );
    assert!(
        report.contains("1 processes vanished between the reads"),
        "{report}"
    );
    assert!(
        report.contains("The largest CPU consumer is yes (47.2% of total CPU in the window)."),
        "{report}"
    );
}

#[test]
fn the_raw_drill_down_appends_the_sampled_bytes() {
    let plain = render(&synthetic(), false);
    assert!(!plain.contains("Raw /proc reads"), "{plain}");
    let raw = render(&synthetic(), true);
    assert!(raw.contains("Raw /proc reads (drill-down):"), "{raw}");
    assert!(raw.contains("/proc/stat aggregate, sample A:"), "{raw}");
    assert!(raw.contains("cpu  1 2 3 4 5 6 7 8"), "{raw}");
    assert!(raw.contains("/proc/loadavg:"), "{raw}");
}

#[test]
fn the_stuck_signature_fires_only_on_load_high_and_cpu_quiet() {
    let mut hot = synthetic();
    hot.loadavg_1min = Some(8.50);
    hot.busy_pct = Some(3.0);
    let report = render(&hot, false);
    assert!(
        report.contains(
            "the load is processes waiting on I/O, not CPU work. The Load/stuck \
             section above names the D-state processes."
        ),
        "{report}"
    );

    // A busy CPU at the same load is CPU work, not stuck I/O - the
    // sentence must not fire.
    let mut busy = hot;
    busy.busy_pct = Some(90.0);
    let report = render(&busy, false);
    assert!(
        !report.contains("not CPU work"),
        "a busy CPU is CPU work: {report}"
    );

    // A quiet load never fires the sentence.
    let quiet = synthetic();
    let report = render(&quiet, false);
    assert!(!report.contains("not CPU work"), "{report}");
}

#[test]
fn the_empty_window_is_a_named_finding() {
    let mut quiet = synthetic();
    quiet.top.clear();
    let report = render(&quiet, false);
    assert!(report.contains("(none observed)"), "{report}");
    assert!(
        report.contains("No process burned a measurable CPU tick in the window."),
        "{report}"
    );
}

/// night-dragon-maintenance-T1, the non-finite loadavg filter:
/// Rust's f64 FromStr accepts "NaN", "inf", and "infinity" as
/// successfully parsed values, and an unfiltered parse would ride
/// the JSON lane as an invalid NaN token (the incident class the
/// write_pct guard holds at emission; this filter holds it at the
/// source). A non-finite load average is not a fact - it is None.
#[test]
fn parse_loadavg_rejects_non_finite_and_garbage_tokens() {
    // The kernel's real shape parses.
    assert_eq!(parse_loadavg("0.52 0.58 0.65 1/487 12345"), Some(0.52));
    // The tokens Rust's f64 parser would accept but a load average
    // can never honestly be.
    assert_eq!(parse_loadavg("NaN 0.58 0.65 1/487 12345"), None);
    assert_eq!(parse_loadavg("inf 0.58 0.65 1/487 12345"), None);
    assert_eq!(parse_loadavg("infinity 0.58 0.65 1/487 12345"), None);
    // Garbage and emptiness stay None (the pre-guard behavior).
    assert_eq!(parse_loadavg("not-a-number at all"), None);
    assert_eq!(parse_loadavg(""), None);
}
