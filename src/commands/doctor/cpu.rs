// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The cpu symptom (night-improve-48): "why is my load high, who is
//! burning the processor?" answered by a 1.0-second delta sample of
//! the kernel's own tick tables. Two /proc/stat reads, two
//! per-process stat walks, one sleep, one Evidence Ledger, exit -
//! the delta snapshot, not a monitor.
//!
//! The percentages are tick RATIOS (pid tick delta over total tick
//! delta), so the arithmetic is honest on every HZ and needs no
//! clock-frequency guess: a row that says 47.2% says "47.2 percent
//! of all CPU ticks the host burned in this window".
//!
//! The Load/stuck section is the part htop cannot give without
//! being left running: processes in state D (uninterruptible sleep,
//! usually I/O) and R (running), named from the second sample,
//! because a high load average with a quiet CPU is the stuck-I/O
//! signature the verdict names.

use super::delta::{self, SAMPLE_WINDOW_DESC};
use super::memory::exits::ExitLane;
use super::memory::pid_dirs;
use crate::output::noun_for;
use std::collections::BTreeMap;
use std::time::SystemTime;

/// The row cap - the ledger's own TOP_N, one row budget for the
/// whole report family.
const TOP_N: usize = 10;

/// One ranked CPU consumer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CpuRow {
    pub pid: u32,
    pub comm: String,
    /// Percent of total CPU ticks burned in the window.
    pub pct: f64,
    /// The raw tick delta (utime + stime) - the number behind the
    /// percentage, printed beside it.
    pub ticks: u64,
}

/// One stuck process: state D at the second sample's instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StuckRow {
    pub pid: u32,
    pub comm: String,
}

/// The whole cpu sample: everything the report rode on.
#[derive(Debug, Clone, Default)]
pub(crate) struct CpuSample {
    /// The collect moment, UTC-formatted once (render determinism).
    pub sampled_at: String,
    pub ncpu: usize,
    /// The 1-minute load average, when /proc/loadavg parsed.
    pub loadavg_1min: Option<f64>,
    /// Busy percent of the window (busy tick delta / total tick
    /// delta). None when the host burned no ticks in the window.
    pub busy_pct: Option<f64>,
    pub total_ticks_delta: u64,
    /// Top consumers, descending by ticks then ascending by pid,
    /// capped at TOP_N.
    pub top: Vec<CpuRow>,
    /// Running-state count at the second sample.
    pub running: usize,
    /// D-state processes at the second sample (capped at TOP_N).
    pub stuck: Vec<StuckRow>,
    /// D-state processes beyond the render cap.
    pub stuck_overflow: usize,
    /// Processes that appeared between the samples: alive, but with
    /// no baseline to delta against - named, not ranked.
    pub started_in_window: usize,
    /// Processes whose stat vanished between the reads (exit races).
    pub vanished_between_reads: usize,
    pub exit_lane: ExitLane,
    /// The verbatim aggregate /proc/stat lines (the --raw
    /// drill-down) and the loadavg line.
    pub raw_stat_a: String,
    pub raw_stat_b: String,
    pub raw_loadavg: String,
}

/// The per-process tick delta table: every pid present in both
/// samples with a strictly positive delta, plus the boundary
/// counts the Unaccounted block names. The sort is the
/// deterministic contract: ticks descending, pid ascending.
fn delta_rows(
    a: &BTreeMap<u32, delta::PidStat>,
    b: &BTreeMap<u32, delta::PidStat>,
    total_delta: u64,
) -> (Vec<CpuRow>, usize, usize) {
    let mut rows = Vec::new();
    let mut started = 0usize;
    let mut vanished = 0usize;
    for (pid, stat_b) in b {
        let Some(stat_a) = a.get(pid) else {
            started += 1;
            continue;
        };
        let ticks = stat_b.cpu_ticks.saturating_sub(stat_a.cpu_ticks);
        if ticks == 0 {
            continue;
        }
        let pct = if total_delta == 0 {
            0.0
        } else {
            (ticks as f64) * 100.0 / (total_delta as f64)
        };
        rows.push(CpuRow {
            pid: *pid,
            comm: stat_b.comm.clone(),
            pct,
            ticks,
        });
    }
    for pid in a.keys() {
        if !b.contains_key(pid) {
            vanished += 1;
        }
    }
    rows.sort_by(|left, right| right.ticks.cmp(&left.ticks).then(left.pid.cmp(&right.pid)));
    (rows, started, vanished)
}

/// Read the aggregate /proc/stat facts: the tick line (parsed and
/// verbatim - the --raw drill-down prints the sampled bytes, not a
/// later re-read) and the core count (the "cpuN" lines). None when
/// the file is unreadable - the honest degradation, never a guess.
/// pub(crate) since night-dragon-lts-2: the umbrella symptom reads
/// the same pair its own lane rides on, one source of parse truth.
pub(crate) fn read_cpu_facts() -> Option<(delta::CpuTicks, usize, String)> {
    let contents = std::fs::read_to_string("/proc/stat").ok()?;
    let mut first: Option<(delta::CpuTicks, &str)> = None;
    let mut ncpu = 0usize;
    for line in contents.lines() {
        if let Some(ticks) = delta::parse_cpu_line(line) {
            if first.is_none() {
                first = Some((ticks, line));
            }
        } else if line.starts_with("cpu") && line.len() > 3 && line.as_bytes()[3].is_ascii_digit() {
            ncpu += 1;
        }
    }
    let (ticks, raw) = first?;
    Some((ticks, ncpu.max(1), raw.to_owned()))
}

/// Collect the cpu sample: two stat reads, two pid walks, one sleep
/// - the wait IS the measurement, and it happens exactly once.
pub(crate) fn collect() -> CpuSample {
    let pids = pid_dirs(std::path::Path::new("/proc"));
    let (ticks_a, ncpu, raw_stat_a) = read_cpu_facts().unwrap_or_default();
    let pid_a = delta::read_pid_sample(&pids);
    let raw_loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    delta::sample_gap();
    let (ticks_b, _, raw_stat_b) = read_cpu_facts().unwrap_or_default();
    let pid_b = delta::read_pid_sample(&pids);
    from_pair(CpuPair {
        ncpu,
        loadavg: &raw_loadavg,
        ticks_a,
        ticks_b,
        pid_a: &pid_a,
        pid_b: &pid_b,
        stat_a: &raw_stat_a,
        stat_b: &raw_stat_b,
        exit_lane: delta::collect_exits_overlay(),
    })
}

/// The shared-window inputs to [`from_pair`] (night-dragon-lts-2):
/// the two instants every cpu number computes from - the ticks
/// (parsed), the per-process samples, the verbatim aggregate lines
/// the --raw drill-down re-prints, the loadavg bytes, the core
/// count, and the exit lane one drain filled. Bundled so the
/// umbrella symptom (`slow`) hands over the SAME pair every delta
/// lane rides on without an arity ladder.
pub(crate) struct CpuPair<'a> {
    pub ncpu: usize,
    pub loadavg: &'a str,
    pub ticks_a: delta::CpuTicks,
    pub ticks_b: delta::CpuTicks,
    pub pid_a: &'a delta::PidSample,
    pub pid_b: &'a delta::PidSample,
    pub stat_a: &'a str,
    pub stat_b: &'a str,
    pub exit_lane: ExitLane,
}

/// The cpu sample from a shared pair of instants (night-dragon-lts-2):
/// the delta arithmetic, verbatim, lifted out of [`collect`] so the
/// umbrella symptom (`slow`) can compute this lane from the SAME
/// t0/t1 pair its disk and network numbers ride on - one window,
/// simultaneous evidence, one sleep for the whole report family.
/// [`collect`] remains this lane's own reader; nothing here reads the
/// host, so a synthetic pair pins every number the render carries.
pub(crate) fn from_pair(pair: CpuPair<'_>) -> CpuSample {
    let CpuPair {
        ncpu,
        loadavg: raw_loadavg,
        ticks_a,
        ticks_b,
        pid_a,
        pid_b,
        stat_a: raw_stat_a,
        stat_b: raw_stat_b,
        exit_lane,
    } = pair;
    let total_delta = ticks_b.total().saturating_sub(ticks_a.total());
    let busy_delta = ticks_b.busy().saturating_sub(ticks_a.busy());
    let busy_pct = (total_delta != 0).then(|| (busy_delta as f64) * 100.0 / total_delta as f64);
    let (mut rows, started, vanished) = delta_rows(&pid_a.stat, &pid_b.stat, total_delta);
    rows.truncate(TOP_N);

    let mut stuck: Vec<StuckRow> = pid_b
        .stat
        .iter()
        .filter(|(_, stat)| stat.state == 'D')
        .map(|(pid, stat)| StuckRow {
            pid: *pid,
            comm: stat.comm.clone(),
        })
        .collect();
    stuck.sort_by_key(|row| row.pid);
    let stuck_overflow = stuck.len().saturating_sub(TOP_N);
    stuck.truncate(TOP_N);
    let running = pid_b.stat.values().filter(|stat| stat.state == 'R').count();

    CpuSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        ncpu,
        loadavg_1min: parse_loadavg(raw_loadavg),
        busy_pct,
        total_ticks_delta: total_delta,
        top: rows,
        running,
        stuck,
        stuck_overflow,
        started_in_window: started,
        vanished_between_reads: vanished,
        exit_lane,
        raw_stat_a: raw_stat_a.to_owned(),
        raw_stat_b: raw_stat_b.to_owned(),
        raw_loadavg: raw_loadavg.to_owned(),
    }
}

/// The 1-minute load average from the first /proc/loadavg field.
fn parse_loadavg(contents: &str) -> Option<f64> {
    // The is_finite filter (night-dragon-maintenance-T1): Rust's
    // f64 FromStr accepts "NaN", "inf", and "infinity" as
    // successfully parsed values, and a non-finite load average is
    // not a fact - it would ride the JSON lane as an invalid
    // `NaN` token without the filter. /proc/loadavg's kernel
    // format is fixed decimal, so the filter is defense in depth
    // against every future reader of a less trustworthy source.
    contents
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

/// The report: collect, render, one String, exit - the command's
/// whole lifetime.
pub(crate) fn report(raw: bool) -> String {
    render(&collect(), raw)
}

/// The pure render - separated from [`collect`] so the shape is
/// unit-pinnable with synthetic samples, the memory ledger's own
/// discipline: the report is the contract, not the host.
pub(crate) fn render(sample: &CpuSample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} symptom - cpu",
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
    render_cpu_facts(sample, &mut lines);
    render_top(sample, &mut lines);
    render_load_stuck(sample, &mut lines);
    delta::render_exits_overlay(&sample.exit_lane, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

fn render_cpu_facts(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("CPU (window 1.0s):"));
    let busy = match sample.busy_pct {
        Some(pct) => format!("{pct:.1}% of total ticks"),
        None => "unknown (no ticks burned in the window)".to_owned(),
    };
    lines.push(format!(
        "  {} {} (delta {} ticks across {} cores)  {}",
        crate::output::ok_out("Busy:"),
        busy,
        sample.total_ticks_delta,
        sample.ncpu,
        crate::output::ok_out("[measured]")
    ));
    let load = match sample.loadavg_1min {
        Some(value) => format!("{value:.2}"),
        None => "unknown".to_owned(),
    };
    lines.push(format!(
        "  {} {} across {} cores  {}",
        crate::output::ok_out("Load average (1m):"),
        load,
        sample.ncpu,
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_top(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Top CPU consumers (window 1.0s):"));
    if sample.top.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    for row in &sample.top {
        lines.push(format!(
            "  PID {} ({})  {:.1}% of total CPU  ({} ticks)  {}",
            row.pid,
            row.comm,
            row.pct,
            row.ticks,
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_load_stuck(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Load / stuck:"));
    lines.push(format!(
        "  {} {} in R state (running)  {}",
        sample.running,
        noun_for(sample.running, "process", "processes"),
        crate::output::ok_out("[measured]")
    ));
    for row in &sample.stuck {
        lines.push(format!(
            "  PID {} ({})  state D (uninterruptible sleep)  {}",
            row.pid,
            row.comm,
            crate::output::ok_out("[measured]")
        ));
    }
    if sample.stuck_overflow > 0 {
        lines.push(crate::output::grey_out(&format!(
            "  ({} more D-state processes, not rendered)",
            sample.stuck_overflow
        )));
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    lines.push(delta::sampling_unaccounted(
        &sample.exit_lane,
        SAMPLE_WINDOW_DESC,
    ));
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

fn render_verdict(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    for line in verdict_lines(sample) {
        lines.push(format!("  {line}"));
    }
}

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane
/// (night-badass-5): the fact sentences both surfaces name.
pub(crate) fn verdict_lines(sample: &CpuSample) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    match sample.top.first() {
        // night-dragon-maintenance-T1: a non-finite share (the
        // class write_pct guards on the JSON number lane) must not
        // reach the prose as "NaN%"/"inf%" - the honest sentence
        // states the raw ticks, the number that is always real.
        // The real collector cannot produce a non-finite pct
        // (delta_rows guards the division); this is the same
        // defense-in-depth the emission guard carries.
        Some(top) if !top.pct.is_finite() => lines.push(format!(
            "The largest CPU consumer is {} ({} CPU ticks in the window).",
            top.comm, top.ticks
        )),
        Some(top) => lines.push(format!(
            "The largest CPU consumer is {} ({:.1}% of total CPU in the window).",
            top.comm, top.pct
        )),
        None => lines.push("No process burned a measurable CPU tick in the window.".to_owned()),
    }
    // The stuck finding: load above the core count while the CPU is
    // quiet is the waiting-on-I/O signature. Two measured facts, one
    // conditional sentence - a fact the user verifies, never an
    // instruction.
    let stuck_signature = match (sample.loadavg_1min, sample.busy_pct) {
        (Some(load), Some(busy)) => load > sample.ncpu as f64 && busy < 20.0,
        _ => false,
    };
    if stuck_signature {
        lines.push(format!(
            "The load average ({:.2}) is above the core count ({}) while the CPU is quiet \
             ({:.1}% busy) - the load is processes waiting on I/O, not CPU work. The \
             Load/stuck section above names the D-state processes.",
            sample.loadavg_1min.unwrap_or(0.0),
            sample.ncpu,
            sample.busy_pct.unwrap_or(0.0),
        ));
    }
    lines
}

/// The drill-down: the verbatim sampled bytes (kept from the two
/// reads, never a later re-read - the sample IS the evidence).
fn render_raw(sample: &CpuSample, lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push(crate::output::ok_out("Raw /proc reads (drill-down):"));
    lines.push(crate::output::grey_out("  /proc/stat aggregate, sample A:"));
    lines.push(format!("    {}", sample.raw_stat_a));
    lines.push(crate::output::grey_out("  /proc/stat aggregate, sample B:"));
    lines.push(format!("    {}", sample.raw_stat_b));
    lines.push(crate::output::grey_out("  /proc/loadavg:"));
    lines.push(format!("    {}", sample.raw_loadavg));
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/cpu_tests.rs"]
mod tests;
