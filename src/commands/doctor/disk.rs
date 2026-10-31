// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The disk symptom (night-improve-48): "who is chewing my I/O?"
//! answered by a 1.0-second delta sample of the kernel's own I/O
//! tables. Two /proc/<pid>/io walks (read_bytes and write_bytes -
//! the block-backed pair, NOT rchar/wchar, which count cache hits
//! and terminal writes), one /proc/stat pair for the iowait share,
//! one sleep, one Evidence Ledger, exit.
//!
//! /proc/<pid>/io is permission-gated (root or the owning user), so
//! on a multi-user host the unreadable share is a NAMED absence:
//! every refusal is counted into the Unaccounted block, never
//! silently dropped - the honest boundary, not a hole.

use super::delta::{self, SAMPLE_WINDOW_DESC};
use super::memory::exits::ExitLane;
use super::memory::pid_dirs;
use std::time::SystemTime;

/// The row cap - the ledger's own TOP_N.
const TOP_N: usize = 10;

/// One ranked I/O consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiskRow {
    pub pid: u32,
    pub comm: String,
    pub read_delta: u64,
    pub write_delta: u64,
}

impl DiskRow {
    fn total(&self) -> u64 {
        self.read_delta.saturating_add(self.write_delta)
    }
}

/// The whole disk sample: everything the report rode on.
#[derive(Debug, Clone, Default)]
pub(crate) struct DiskSample {
    pub sampled_at: String,
    /// The iowait share of the window (iowait tick delta over total
    /// tick delta, percent). None when no ticks burned.
    pub iowait_pct: Option<f64>,
    pub total_ticks_delta: u64,
    /// Top I/O consumers, descending by combined bytes, capped.
    pub top: Vec<DiskRow>,
    /// Processes that appeared between the samples (no baseline).
    pub started_in_window: usize,
    /// Processes whose io vanished between the reads (exit races).
    pub vanished_between_reads: usize,
    /// Other users' /proc/<pid>/io this invocation may not read.
    pub io_permission_refused: usize,
    pub exit_lane: ExitLane,
}

/// The per-process I/O delta table: every pid present in both
/// samples with a strictly positive byte delta. The sort is the
/// deterministic contract: combined bytes descending, pid ascending.
fn delta_rows(
    a: &std::collections::BTreeMap<u32, delta::PidIo>,
    b: &std::collections::BTreeMap<u32, delta::PidIo>,
    stats: &std::collections::BTreeMap<u32, delta::PidStat>,
) -> (Vec<DiskRow>, usize, usize) {
    let mut rows = Vec::new();
    let mut started = 0usize;
    let mut vanished = 0usize;
    for (pid, io_b) in b {
        let Some(io_a) = a.get(pid) else {
            started += 1;
            continue;
        };
        let read_delta = io_b.read_bytes.saturating_sub(io_a.read_bytes);
        let write_delta = io_b.write_bytes.saturating_sub(io_a.write_bytes);
        if read_delta == 0 && write_delta == 0 {
            continue;
        }
        let comm = stats
            .get(pid)
            .map(|stat| stat.comm.clone())
            .unwrap_or_else(|| "unknown".to_owned());
        rows.push(DiskRow {
            pid: *pid,
            comm,
            read_delta,
            write_delta,
        });
    }
    for pid in a.keys() {
        if !b.contains_key(pid) {
            vanished += 1;
        }
    }
    rows.sort_by(|left, right| {
        right
            .total()
            .cmp(&left.total())
            .then(left.pid.cmp(&right.pid))
    });
    (rows, started, vanished)
}

/// Collect the disk sample: two io/stat walks, two /proc/stat
/// reads, one sleep - the wait IS the measurement.
pub(crate) fn collect() -> DiskSample {
    let pids = pid_dirs(std::path::Path::new("/proc"));
    let stat_a = read_stat_ticks();
    let pid_a = delta::read_pid_sample(&pids);
    delta::sample_gap();
    let stat_b = read_stat_ticks();
    let pid_b = delta::read_pid_sample(&pids);
    from_pair(
        stat_a,
        stat_b,
        &pid_a,
        &pid_b,
        delta::collect_exits_overlay(),
    )
}

/// The aggregate /proc/stat tick read this lane rides on - the
/// first line only, parsed. Split out of [`collect`] (night-dragon-
/// lts-2) so the shape is one named read, not an inline chain.
fn read_stat_ticks() -> delta::CpuTicks {
    delta::parse_cpu_line(
        &std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|contents| contents.lines().next().map(str::to_owned))
            .unwrap_or_default(),
    )
    .unwrap_or_default()
}

/// The disk sample from a shared pair of instants (night-dragon-lts-2):
/// the delta arithmetic, verbatim, lifted out of [`collect`] so the
/// umbrella symptom (`slow`) can compute this lane from the SAME
/// t0/t1 pair its cpu and network numbers ride on - one window,
/// simultaneous evidence, one sleep for the whole report family.
/// [`collect`] remains this lane's own reader; nothing here reads
/// the host, so a synthetic pair pins every number the render carries.
pub(crate) fn from_pair(
    stat_a: delta::CpuTicks,
    stat_b: delta::CpuTicks,
    pid_a: &delta::PidSample,
    pid_b: &delta::PidSample,
    exit_lane: ExitLane,
) -> DiskSample {
    let total_delta = stat_b.total().saturating_sub(stat_a.total());
    let iowait_delta = stat_b.iowait.saturating_sub(stat_a.iowait);
    let iowait_pct = (total_delta != 0).then(|| (iowait_delta as f64) * 100.0 / total_delta as f64);
    let (mut rows, started, vanished) = delta_rows(&pid_a.io, &pid_b.io, &pid_b.stat);
    rows.truncate(TOP_N);

    DiskSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        iowait_pct,
        total_ticks_delta: total_delta,
        top: rows,
        started_in_window: started,
        vanished_between_reads: vanished,
        io_permission_refused: pid_b.io_permission_refused,
        exit_lane,
    }
}

/// The report: collect, render, one String, exit.
pub(crate) fn report(raw: bool) -> String {
    render(&collect(), raw)
}

/// The pure render - separated from [`collect`] so the shape is
/// unit-pinnable with synthetic samples, the memory ledger's own
/// discipline: the report is the contract, not the host.
pub(crate) fn render(sample: &DiskSample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} symptom - disk",
        crate::output::ok_out("Evidence report:")
    ));
    lines.push(crate::output::grey_out(delta::mode_line(
        &sample.exit_lane,
        true,
    )));
    lines.push(crate::output::grey_out(&format!(
        "Sampled: {} (window 1.0s)",
        sample.sampled_at
    )));
    lines.push(String::new());
    render_iowait(sample, &mut lines);
    render_top(sample, &mut lines);
    delta::render_exits_overlay(&sample.exit_lane, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

fn render_iowait(sample: &DiskSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("I/O wait (window 1.0s):"));
    let share = match sample.iowait_pct {
        Some(pct) => format!("{pct:.1}% of total CPU ticks"),
        None => "unknown (no ticks burned in the window)".to_owned(),
    };
    lines.push(format!(
        "  {} {} (delta {} ticks)  {}",
        crate::output::ok_out("iowait:"),
        share,
        sample.total_ticks_delta,
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_top(sample: &DiskSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Top disk I/O (window 1.0s):"));
    if sample.top.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    for row in &sample.top {
        lines.push(format!(
            "  PID {} ({})  read {}, wrote {}  {}",
            row.pid,
            row.comm,
            crate::output::grey_out(&fmt_bytes(row.read_delta)),
            crate::output::grey_out(&fmt_bytes(row.write_delta)),
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &DiskSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    lines.push(delta::sampling_unaccounted(
        &sample.exit_lane,
        SAMPLE_WINDOW_DESC,
    ));
    if sample.io_permission_refused > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.io_permission_refused,
            crate::output::grey_out(
                "processes' /proc/<pid>/io unreadable (permission - root or the owning \
                 user only): their I/O share is not carried"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    if sample.started_in_window > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.started_in_window,
            crate::output::grey_out(
                "processes started inside the window: no baseline to delta against, not ranked"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    if sample.vanished_between_reads > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.vanished_between_reads,
            crate::output::grey_out(
                "processes vanished between the reads: their window share is not carried"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &DiskSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    for line in verdict_lines(sample) {
        lines.push(format!("  {line}"));
    }
}

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane
/// (night-badass-5).
pub(crate) fn verdict_lines(sample: &DiskSample) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    match sample.top.first() {
        Some(top) => lines.push(format!(
            "The largest disk I/O consumer is {} (read {}, wrote {} in the window).",
            top.comm,
            fmt_bytes(top.read_delta),
            fmt_bytes(top.write_delta)
        )),
        None => lines.push("No process moved block-backed I/O in the window.".to_owned()),
    }
    // The iowait finding: a high iowait share with a named top
    // consumer is two facts the reader ties - the verdict states
    // both, never the instruction htop would give. The is_finite
    // gate (night-dragon-maintenance-T1) is the write_pct guard's
    // prose twin: an infinite share is nonsense data, not a high
    // measurement, and must not fire the sentence as "inf%".
    if let (Some(pct), Some(top)) = (sample.iowait_pct, sample.top.first())
        && pct.is_finite()
        && pct > 20.0
    {
        lines.push(format!(
            "The I/O wait ({pct:.1}% of the window's CPU ticks) is high; the top I/O \
                 consumer above is {comm} (PID {pid}).",
            comm = top.comm,
            pid = top.pid
        ));
    }
    lines
}

/// The drill-down: the top consumers' verbatim /proc/<pid>/io at
/// render time (the ram report's own re-read pattern - a process
/// that died with the window names its absence honestly).
fn render_raw(sample: &DiskSample, lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push(crate::output::ok_out("Raw /proc reads (drill-down):"));
    lines.push(crate::output::grey_out(
        "  /proc/<pid>/io (top 10 by window delta, verbatim):",
    ));
    for row in &sample.top {
        lines.push(crate::output::grey_out(&format!(
            "    == PID {} ({}) ==",
            row.pid, row.comm
        )));
        match std::fs::read_to_string(format!("/proc/{}/io", row.pid)) {
            Ok(contents) => {
                for line in contents.lines() {
                    lines.push(format!("      {line}"));
                }
            }
            Err(e) => lines.push(crate::output::grey_out(&format!(
                "      unreadable at render time ({e})"
            ))),
        }
    }
}

/// The adaptive size label - the memory ledger's own, one source
/// for the whole symptom family (KiB/MiB/GiB, one unit, no
/// scientific notation).
fn fmt_bytes(bytes: u64) -> String {
    super::memory::ledger::fmt_bytes(bytes)
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/disk_tests.rs"]
mod tests;
