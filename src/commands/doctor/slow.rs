// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The umbrella symptom (night-dragon-lts-2): "why is my machine
//! slow?" - the one question every operator asks first, answered by
//! composing the four machine-slow lanes (cpu, disk, memory,
//! network) over ONE shared 1.0-second window. Not a fifth source
//! of kernel facts: the same tables the dedicated lanes read, read
//! once, slept between once, and cross-examined together - a
//! verdict that says "iowait high while the CPU is quiet" is only
//! honest when both numbers come from the same window, and a host
//! that pays three sleeps for three sequential windows gets three
//! answers about three different seconds.
//!
//! The depth this lane adds over its parts is the CROSS-LANE
//! signature set, each a named boundary, never a mood:
//!
//! - swap pressure: pages moved in/out of swap inside the window
//!   (/proc/vmstat pswpin/pswpout deltas - the RATE, not the
//!   total: a host with a full swap cache from last week and zero
//!   movement today is not slow because of swap);
//! - stuck I/O: D-state processes, or load above the core count
//!   while the CPU is quiet (the cpu lane's own signature);
//! - I/O wait: the disk lane's own 20%-of-ticks boundary;
//! - memory pressure: under 10% of MemTotal still available;
//! - CPU saturation: 80% of the window's ticks busy;
//! - runnable queue: more processes in R than cores;
//! - socket churn: the network lane's own TIME_WAIT boundary, plus
//!   the CLOSE_WAIT pile (sockets the remote closed and no local
//!   process did).
//!
//! The gpu lane rides outside this triage and the report says so
//! in the Unaccounted block - a fact not carried is named, never
//! silently dropped. The drill-down is the funnel: each compact
//! lane line names its headline numbers, the dedicated
//! `--symptom <lane>` reports carry the per-process tables.

use super::cpu::{self, CpuPair, CpuSample};
use super::delta::{self, SAMPLE_WINDOW_DESC};
use super::disk::{self, DiskSample};
use super::memory::{self, MemInfo, exits::ExitLane, pid_dirs};
use super::network::{self, NetworkSample};
use std::time::SystemTime;

// The verdict ladder's split home (night-dragon-lts-2, the LOC
// cap's no-mercy law): the severity classes, their named
// boundaries, and the ranking live in slow/verdict.rs beside this
// file - the memory lane's own submodule discipline. Re-exported
// so every consumer's `super::...` path resolves exactly as a
// single-file lane would.
pub(crate) mod verdict;
pub(crate) use verdict::{rank_findings, verdict_lines};

/// The whole umbrella sample: the four lanes computed from one
/// shared pair of instants, plus the memory headline facts.
#[derive(Debug, Clone)]
pub(crate) struct SlowSample {
    /// The collect moment, UTC-formatted once (render determinism).
    pub sampled_at: String,
    pub cpu: CpuSample,
    pub disk: DiskSample,
    pub network: NetworkSample,
    /// /proc/meminfo's headline facts; None when unreadable - the
    /// memory lane renders unknown, never a guess.
    pub meminfo: Option<MemInfo>,
    pub swap_total_kib: Option<u64>,
    pub swap_free_kib: Option<u64>,
    /// Pages moved in/out of swap inside the window (the rate, the
    /// only swap fact that says "slow now").
    pub swap_in_pages: u64,
    pub swap_out_pages: u64,
    pub exit_lane: ExitLane,
    /// The verbatim /proc/meminfo bytes and the two /proc/vmstat
    /// swap lines per instant (the --raw drill-down re-prints the
    /// sampled bytes, never a later re-read).
    pub raw_meminfo: String,
    pub raw_vmstat_a: String,
    pub raw_vmstat_b: String,
}

/// The two swap counters /proc/vmstat carries, in pages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VmstatSwap {
    pub pswpin: u64,
    pub pswpout: u64,
    /// The verbatim sampled lines ("pswpin N\npswpout N"), empty
    /// when the file was unreadable - the honest absence.
    pub raw: String,
}

/// Parse the pswpin/pswpout pair out of /proc/vmstat. Absent
/// fields count zero (a kernel that does not carry the counter has
/// never swapped on this boot); an unreadable file is the caller's
/// `None` to name.
pub(crate) fn parse_vmstat_swap(contents: &str) -> VmstatSwap {
    let mut swap = VmstatSwap::default();
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("pswpin ") {
            swap.pswpin = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("pswpout ") {
            swap.pswpout = rest.trim().parse().unwrap_or(0);
        }
    }
    swap
}

/// Read /proc/vmstat's swap pair - parsed and verbatim.
fn read_vmstat_swap() -> VmstatSwap {
    match std::fs::read_to_string("/proc/vmstat") {
        Ok(contents) => {
            let mut swap = parse_vmstat_swap(&contents);
            swap.raw = contents
                .lines()
                .filter(|line| line.starts_with("pswpin ") || line.starts_with("pswpout "))
                .collect::<Vec<_>>()
                .join("\n");
            swap
        }
        Err(_) => VmstatSwap::default(),
    }
}

/// Collect the umbrella sample: one t0 read of every table the four
/// lanes ride on, one sleep, one t1 read, one post-window walk, one
/// exit drain - the whole family pays for exactly one window.
pub(crate) fn collect() -> SlowSample {
    let pids = pid_dirs(std::path::Path::new("/proc"));
    let (ticks_a, ncpu, raw_stat_a) = cpu::read_cpu_facts().unwrap_or_default();
    let pid_a = delta::read_pid_sample(&pids);
    let dev_a = network::read_net_dev();
    let raw_loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let vmstat_a = read_vmstat_swap();
    delta::sample_gap();
    let (ticks_b, _, raw_stat_b) = cpu::read_cpu_facts().unwrap_or_default();
    let pid_b = delta::read_pid_sample(&pids);
    let dev_b = network::read_net_dev();
    let vmstat_b = read_vmstat_swap();
    let (sockets, holders, refused) = network::collect_now_facts();
    let exit_lane = delta::collect_exits_overlay();
    let raw_meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let meminfo = memory::parse_meminfo(&raw_meminfo);
    let swap_total_kib = memory::meminfo_field(&raw_meminfo, "SwapTotal");
    let swap_free_kib = memory::meminfo_field(&raw_meminfo, "SwapFree");

    let cpu_sample = cpu::from_pair(CpuPair {
        ncpu,
        loadavg: &raw_loadavg,
        ticks_a,
        ticks_b,
        pid_a: &pid_a,
        pid_b: &pid_b,
        stat_a: &raw_stat_a,
        stat_b: &raw_stat_b,
        exit_lane: exit_lane.clone(),
    });
    let disk_sample = disk::from_pair(ticks_a, ticks_b, &pid_a, &pid_b, exit_lane.clone());
    let network_sample =
        network::from_pair(&dev_a, &dev_b, sockets, holders, refused, exit_lane.clone());

    SlowSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        cpu: cpu_sample,
        disk: disk_sample,
        network: network_sample,
        meminfo,
        swap_total_kib,
        swap_free_kib,
        swap_in_pages: vmstat_b.pswpin.saturating_sub(vmstat_a.pswpin),
        swap_out_pages: vmstat_b.pswpout.saturating_sub(vmstat_a.pswpout),
        exit_lane,
        raw_meminfo,
        raw_vmstat_a: vmstat_a.raw,
        raw_vmstat_b: vmstat_b.raw,
    }
}

/// The report: collect, render, one String, exit - the command's
/// whole lifetime.
pub(crate) fn report(raw: bool) -> String {
    render(&collect(), raw)
}

/// The pure render - separated from [`collect`] so the triage shape
/// is unit-pinnable with synthetic samples, the family's own
/// discipline: the report is the contract, not the host.
pub(crate) fn render(sample: &SlowSample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} symptom - slow",
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
    render_cpu_lane(sample, &mut lines);
    render_memory_lane(sample, &mut lines);
    render_disk_lane(sample, &mut lines);
    render_network_lane(sample, &mut lines);
    delta::render_exits_overlay(&sample.exit_lane, &mut lines);
    render_findings(sample, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

fn render_cpu_lane(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("CPU (window 1.0s):"));
    let busy = match sample.cpu.busy_pct {
        Some(pct) => format!("{pct:.1}% of total ticks"),
        None => "unknown (no ticks burned in the window)".to_owned(),
    };
    let load = match sample.cpu.loadavg_1min {
        Some(value) => format!("{value:.2}"),
        None => "unknown".to_owned(),
    };
    lines.push(format!(
        "  busy {}  load {} across {} cores  {} running  {} in D state  {}",
        busy,
        load,
        sample.cpu.ncpu,
        sample.cpu.running,
        sample.cpu.stuck.len(),
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_memory_lane(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Memory:"));
    let headline = match &sample.meminfo {
        Some(mem) => {
            let used = mem.total_kib.saturating_sub(mem.available_kib);
            let pct = if mem.total_kib == 0 {
                0.0
            } else {
                (used as f64) * 100.0 / (mem.total_kib as f64)
            };
            format!(
                "{} used of {} ({pct:.0}% used)  {} available",
                super::memory::ledger::fmt_bytes(used * 1024),
                super::memory::ledger::fmt_bytes(mem.total_kib * 1024),
                super::memory::ledger::fmt_bytes(mem.available_kib * 1024),
            )
        }
        None => "unknown (/proc/meminfo unreadable)".to_owned(),
    };
    lines.push(format!(
        "  {}  swap in {} pages, out {} pages in window  {}",
        headline,
        sample.swap_in_pages,
        sample.swap_out_pages,
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_disk_lane(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Disk (window 1.0s):"));
    let iowait = match sample.disk.iowait_pct {
        Some(pct) => format!("{pct:.1}% of total ticks"),
        None => "unknown (no ticks burned in the window)".to_owned(),
    };
    let top = match sample.disk.top.first() {
        Some(row) => format!(
            "top I/O {} (PID {}, read {}, wrote {})",
            row.comm,
            row.pid,
            super::memory::ledger::fmt_bytes(row.read_delta),
            super::memory::ledger::fmt_bytes(row.write_delta)
        ),
        None => "top I/O none observed".to_owned(),
    };
    lines.push(format!(
        "  iowait {}  {}  {}",
        iowait,
        top,
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_network_lane(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Network (window 1.0s):"));
    let busiest = match sample.network.interfaces.first() {
        Some(row) => format!(
            "{} RX {} TX {}",
            row.name,
            super::memory::ledger::fmt_bytes(row.rx_bytes),
            super::memory::ledger::fmt_bytes(row.tx_bytes)
        ),
        None => "no interface moved a byte or a packet".to_owned(),
    };
    let more = sample.network.interfaces.len().saturating_sub(1);
    let more_note = if more > 0 {
        format!("  (+{more} more with traffic)")
    } else {
        String::new()
    };
    lines.push(format!(
        "  {}  {} ESTABLISHED  {} TIME_WAIT  {} CLOSE_WAIT{more_note}  {}",
        busiest,
        sample.network.sockets.established,
        sample.network.sockets.time_wait,
        sample.network.sockets.close_wait,
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_findings(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Findings (ranked by severity):"));
    let findings = rank_findings(sample);
    if findings.is_empty() {
        lines.push(format!(
            "  {}  {}",
            crate::output::grey_out("(none - no lane crossed its named boundary)"),
            crate::output::ok_out("[measured]")
        ));
        lines.push(String::new());
        return;
    }
    for (index, finding) in findings.iter().enumerate() {
        lines.push(format!(
            "  {}. {}  {}",
            index + 1,
            finding.text,
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    lines.push(delta::sampling_unaccounted(
        &sample.exit_lane,
        SAMPLE_WINDOW_DESC,
    ));
    if sample.meminfo.is_none() {
        lines.push(format!(
            "  {}  {}",
            crate::output::grey_out("/proc/meminfo unreadable: the memory share is not carried"),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    if sample.disk.io_permission_refused > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.disk.io_permission_refused,
            crate::output::grey_out(
                "processes' /proc/<pid>/io unreadable (permission - root or the owning \
                 user only): their I/O share is not carried"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    if sample.network.fd_permission_refused > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.network.fd_permission_refused,
            crate::output::grey_out(
                "processes' fd tables unreadable (permission) - the holder list names \
                 only the holders visible to this user"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    lines.push(format!(
        "  {}  {}",
        crate::output::grey_out(
            "the gpu lane rides outside this triage - 'zejtron doctor --symptom gpu' \
             is its dedicated report"
        ),
        crate::output::grey_out("[unaccounted]")
    ));
    lines.push(String::new());
}

fn render_verdict(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    for line in verdict_lines(sample) {
        lines.push(format!("  {line}"));
    }
}

/// The drill-down: the shared pair's verbatim bytes - the aggregate
/// /proc/stat lines, the loadavg line, the meminfo headline block,
/// and the vmstat swap lines - the sampled evidence, never a later
/// re-read.
fn render_raw(sample: &SlowSample, lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push(crate::output::ok_out("Raw /proc reads (drill-down):"));
    lines.push(crate::output::grey_out("  /proc/stat aggregate, sample A:"));
    lines.push(format!("    {}", sample.cpu.raw_stat_a));
    lines.push(crate::output::grey_out("  /proc/stat aggregate, sample B:"));
    lines.push(format!("    {}", sample.cpu.raw_stat_b));
    lines.push(crate::output::grey_out("  /proc/loadavg:"));
    lines.push(format!("    {}", sample.cpu.raw_loadavg));
    lines.push(crate::output::grey_out("  /proc/meminfo (headline block):"));
    for line in sample.raw_meminfo.lines().take(5) {
        lines.push(format!("    {line}"));
    }
    lines.push(crate::output::grey_out(
        "  /proc/vmstat swap lines, sample A:",
    ));
    if sample.raw_vmstat_a.is_empty() {
        lines.push(crate::output::grey_out("    (unreadable at sample time)"));
    } else {
        for line in sample.raw_vmstat_a.lines() {
            lines.push(format!("    {line}"));
        }
    }
    lines.push(crate::output::grey_out(
        "  /proc/vmstat swap lines, sample B:",
    ));
    if sample.raw_vmstat_b.is_empty() {
        lines.push(crate::output::grey_out("    (unreadable at sample time)"));
    } else {
        for line in sample.raw_vmstat_b.lines() {
            lines.push(format!("    {line}"));
        }
    }
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/slow_tests.rs"]
mod tests;
