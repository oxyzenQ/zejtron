// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory symptom's Evidence Ledger pins (night-improve-4,
//! Part B): the report is rendered from SYNTHETIC samples only -
//! the shape is the contract, not the host's own RAM. The four
//! provenance tiers stay four ([measured] rows, [unaccounted]
//! residual); the verdict names facts, never actions; the
//! permission boundaries are named on every report.

use super::super::exits::ExitRow;
use super::*;
use crate::commands::doctor::memory::{
    DeletedOpenFile, ExitLane, MemInfo, MemfdFile, MemorySample, ProcessPss, SlabRow, TmpfsFile,
};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

fn sample() -> MemorySample {
    let mut sample = MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 16 * (GIB / KIB),
            free_kib: 8 * (GIB / KIB),
            available_kib: 12 * (GIB / KIB),
            cached_kib: 2 * (GIB / KIB),
            buffers_kib: 200 * MIB / KIB,
            shmem_kib: 400 * MIB / KIB,
            s_reclaimable_kib: 300 * MIB / KIB,
            s_unreclaim_kib: 100 * MIB / KIB,
        }),
        ..Default::default()
    };
    sample.pss = vec![
        ProcessPss {
            pid: 1234,
            name: "firefox".to_owned(),
            pss_kib: 2457 * MIB / KIB,
            anon_kib: 1843 * MIB / KIB,
            file_kib: 102 * MIB / KIB,
            shmem_kib: 512 * MIB / KIB,
            rss_kib: 3 * GIB / KIB,
        },
        ProcessPss {
            pid: 2345,
            name: "systemd".to_owned(),
            pss_kib: 50 * MIB / KIB,
            anon_kib: 30 * MIB / KIB,
            file_kib: 10 * MIB / KIB,
            shmem_kib: 10 * MIB / KIB,
            rss_kib: 60 * MIB / KIB,
        },
    ];
    sample.tmpfs_files = vec![TmpfsFile {
        path: "/dev/shm/pg.sock.lock".to_owned(),
        size_bytes: 100 * MIB,
        holders: vec![3456],
    }];
    sample.tmpfs_mounts = vec!["/dev/shm".to_owned()];
    sample.deleted = vec![DeletedOpenFile {
        pid: 1234,
        name: "firefox".to_owned(),
        path: "/tmp/xyz (deleted)".to_owned(),
        size_bytes: Some(512 * MIB),
        identity: Some((9, 1)),
    }];
    sample.memfds = vec![MemfdFile {
        pid: 2345,
        name: "systemd".to_owned(),
        target: "memfd:journal".to_owned(),
        size_bytes: Some(300 * MIB),
        identity: Some((9, 2)),
    }];
    sample.slab_readable = true;
    sample.slab = vec![SlabRow {
        cache: "dentry".to_owned(),
        size_kib: 300 * MIB / KIB,
    }];
    sample
}

#[test]
fn size_labels_are_adaptive_and_deterministic() {
    assert_eq!(fmt_bytes(2 * GIB + 400 * MIB), "2.4 GiB");
    assert_eq!(fmt_bytes(512 * MIB), "512.0 MiB");
    assert_eq!(fmt_bytes(192 * KIB), "192 KiB");
    assert_eq!(fmt_bytes(12), "12 B");
    assert_eq!(fmt_bytes(0), "0 B");
}

#[test]
fn the_report_carries_the_locked_header_and_mode() {
    let report = render(&sample(), false);
    let mut lines = report.lines();
    assert_eq!(lines.next(), Some("Evidence report: memory / ram"));
    assert_eq!(
        lines.next(),
        Some("Mode: snapshot (eBPF not attached - recent exits are invisible)")
    );
}

#[test]
fn the_mode_line_names_the_exit_lane_state() {
    // Three truths, one line each (night-improve-47): the drained
    // lane claims the post-mortem only when it ran, the failed
    // drain names itself, and the not-attached host says what stays
    // invisible.
    let mut drained = sample();
    drained.exit_lane = ExitLane::Drained(Vec::new());
    assert!(
        render(&drained, false)
            .contains("Mode: snapshot + post-mortem (eBPF exit lane drained, last 5s)"),
        "the drained lane's mode line"
    );
    let mut failed = sample();
    failed.exit_lane = ExitLane::DrainFailed("test refusal".to_owned());
    assert!(
        render(&failed, false)
            .contains("Mode: snapshot + post-mortem (the exit drain failed - named below)"),
        "the failed drain's mode line"
    );
}

#[test]
fn the_unaccounted_block_names_the_exit_boundary_by_lane_state() {
    // night-improve-47 reworks night-improve-34's static lifecycle
    // line into the lane's three truths: the spec's own sentence
    // when not attached, the window boundary when drained, the
    // verbatim error when the drain failed.
    let report = render(&sample(), false);
    assert!(
        report.contains(
            "eBPF is not attached - processes that exited before this snapshot are invisible"
        ),
        "the not-attached sentence: {report}"
    );

    let mut drained = sample();
    drained.exit_lane = ExitLane::Drained(vec![ExitRow {
        pid: 1234,
        comm: "python3".to_owned(),
        timestamp_ns: 1,
    }]);
    let report = render(&drained, false);
    assert!(
        report.contains("Recently exited (eBPF, last 5s):"),
        "the section rides when the lane ran: {report}"
    );
    assert!(
        report.contains("PID 1234 (python3)  exited  [observed]"),
        "the spec's own row: {report}"
    );
    assert!(
        report.contains("processes that exited before the 5-second eBPF window: not named"),
        "the drained boundary: {report}"
    );

    let mut failed = sample();
    failed.exit_lane = ExitLane::DrainFailed("test refusal".to_owned());
    let report = render(&failed, false);
    assert!(
        report.contains("the eBPF exit drain failed (test refusal)"),
        "the failed drain names its error: {report}"
    );
}

#[test]
fn the_not_attached_report_has_no_exits_section() {
    // The absent lane rides the mode line and the Unaccounted block
    // only - never a fake empty section (an absent lane and an
    // empty window are different truths).
    let report = render(&sample(), false);
    assert!(
        !report.contains("Recently exited"),
        "no section when the lane is off: {report}"
    );
}

#[test]
fn the_report_renders_every_section_with_provenance() {
    let report = render(&sample(), false);
    assert!(report.contains("Memory total: 16.0 GiB"), "{report}");
    assert!(
        report.contains("Memory used:  4.0 GiB  (25% of total)"),
        "{report}"
    );
    assert!(report.contains("Memory avail: 12.0 GiB"), "{report}");

    assert!(report.contains("Per-process PSS (top 10):"), "{report}");
    assert!(
        report.contains("PSS 2.4 GiB  (anon 1.8 GiB, shmem 512.0 MiB, file 102.0 MiB)  [measured]"),
        "{report}"
    );
    assert!(report.contains("PID 1234 (firefox)"), "{report}");

    assert!(report.contains("Tmpfs (files in RAM, top 10):"), "{report}");
    assert!(
        report.contains("held by PID 3456 (") && report.contains("[measured]"),
        "{report}"
    );

    assert!(report.contains("Deleted-but-open files:"), "{report}");
    assert!(report.contains("/tmp/xyz (deleted)"), "{report}");

    assert!(report.contains("Memfd files:"), "{report}");
    assert!(report.contains("memfd:journal"), "{report}");

    assert!(report.contains("Page cache (reclaimable):"), "{report}");
    assert!(report.contains("Buffers:"), "{report}");
    assert!(report.contains("Shmem:"), "{report}");

    assert!(report.contains("Slab:"), "{report}");
    assert!(report.contains("dentry"), "{report}");

    assert!(report.contains("Unaccounted:"), "{report}");
    assert!(
        report.contains("[unaccounted]"),
        "the residual carries the fourth tier: {report}"
    );
    assert!(report.contains("Verdict:"), "{report}");
}

#[test]
fn the_render_is_deterministic_byte_for_byte() {
    // Same rows in, same bytes out - twice, including the sort
    // order the caller is responsible for.
    assert_eq!(render(&sample(), false), render(&sample(), false));
}

#[test]
fn verdict_names_the_largest_consumer() {
    let report = render(&sample(), false);
    assert!(
        report.contains("The largest single consumer is firefox (2.4 GiB PSS)."),
        "{report}"
    );
}

#[test]
fn verdict_names_an_unheld_tmpfs_file_conditionally_not_imperatively() {
    // The anomaly threshold: an unheld tmpfs file above 500 MiB
    // gets the conditional sentence - verify first, the user
    // decides. Never an instruction to remove.
    let mut big = sample();
    big.tmpfs_files.insert(
        0,
        TmpfsFile {
            path: "/tmp/core.dump".to_owned(),
            size_bytes: 3 * GIB,
            holders: Vec::new(),
        },
    );
    let report = render(&big, false);
    assert!(
        report.contains("The tmpfs file /tmp/core.dump holds 3.0 GiB"),
        "{report}"
    );
    assert!(
        report.contains("verify with `zejtron touch /tmp/core.dump` first"),
        "{report}"
    );
    assert!(
        !report.contains("No anomalous consumer detected."),
        "{report}"
    );

    // The same file WITH holders is not the finding.
    let mut held = big;
    held.tmpfs_files[0].holders = vec![99];
    let report = render(&held, false);
    assert!(
        !report.contains("The tmpfs file /tmp/core.dump"),
        "{report}"
    );
}

#[test]
fn verdict_names_deleted_but_open_totals_without_removal_language() {
    // Deleted-but-open memory can never be called removable: the
    // holder process is the only way it frees. The sentence names
    // the fact and the boundary, nothing else.
    let report = render(&sample(), false);
    assert!(
        report.contains("512.0 MiB is held by deleted files still open in live processes."),
        "{report}"
    );
    assert!(
        report.contains("cannot be removed without closing the holder"),
        "{report}"
    );
}

#[test]
fn verdict_flags_a_residual_above_the_heuristic_threshold() {
    // A 16 GiB host with nothing readable attributed and no kernel
    // buckets to blame: the residual is the full 4 GiB used = 25% -
    // above the 15% threshold, named with the --raw pointer.
    let mut thin = sample();
    thin.pss.clear();
    thin.deleted.clear();
    let mem = thin.meminfo.as_mut().expect("sample carries meminfo");
    mem.cached_kib = 0;
    mem.buffers_kib = 0;
    mem.shmem_kib = 0;
    mem.s_reclaimable_kib = 0;
    mem.s_unreclaim_kib = 0;
    let report = render(&thin, false);
    assert!(
        report.contains("is above the 15% heuristic threshold"),
        "{report}"
    );
    assert!(
        report.contains("zejtron doctor --symptom ram --raw"),
        "{report}"
    );
}

#[test]
fn verdict_says_no_anomaly_when_nothing_fires() {
    // Everything attributable, every finding under threshold.
    let mut quiet = sample();
    quiet.deleted.clear();
    let report = render(&quiet, false);
    assert!(
        report.contains("No anomalous consumer detected."),
        "{report}"
    );
}

#[test]
fn permission_boundaries_are_named_when_they_fired() {
    let mut gated = sample();
    gated.pss_permission_refused = 7;
    gated.fd_permission_refused = 3;
    let report = render(&gated, false);
    assert!(
        report.contains("7 processes with an unreadable smaps_rollup (permission)"),
        "{report}"
    );
    assert!(
        report.contains("3 processes with unreadable fd tables (permission)"),
        "{report}"
    );
}

#[test]
fn unreadable_meminfo_degrades_to_the_named_absence() {
    let mut blind = sample();
    blind.meminfo = None;
    let report = render(&blind, false);
    assert!(
        report.contains("Memory total: unknown (/proc/meminfo unreadable)"),
        "{report}"
    );
    assert!(
        report.contains("the residual is unknown (/proc/meminfo unreadable)  [unaccounted]"),
        "{report}"
    );
}

#[test]
fn unreadable_slabinfo_names_the_absence_but_keeps_the_totals() {
    let mut no_slab = sample();
    no_slab.slab_readable = false;
    no_slab.slab.clear();
    let report = render(&no_slab, false);
    assert!(
        report.contains(
            "unavailable (/proc/slabinfo is not readable by this user; the \
             reclaimable/unreclaimable totals above still carry the slab total)"
        ),
        "{report}"
    );
}

#[test]
fn raw_appends_the_drill_down_marker() {
    // The raw block is a distinct trailing section; with synthetic
    // pids the smaps_rollup re-read rides the real /proc and may or
    // may not resolve - both shapes name the pid header.
    let report = render(&sample(), true);
    assert!(report.contains("Raw /proc reads (drill-down):"), "{report}");
    assert!(report.contains("== PID 1234 (firefox) =="), "{report}");
    assert!(report.contains("/proc/meminfo:"), "{report}");
    // The plain render carries none of it.
    let plain = render(&sample(), false);
    assert!(!plain.contains("Raw /proc reads (drill-down):"), "{plain}");
}
