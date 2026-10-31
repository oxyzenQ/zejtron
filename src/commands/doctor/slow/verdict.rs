// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The umbrella symptom's verdict ladder (night-dragon-lts-2): the
//! severity classes, their named boundaries, and the ranking that
//! turns one shared window into one answer. Split out of slow.rs at
//! birth (the 600-line LOC cap, the no-mercy law) - a pure move,
//! the memory lane's own submodule discipline.
//!
//! The order is the contract - swap pressure outranks stuck I/O,
//! which outranks iowait, memory pressure, CPU saturation, the
//! runnable queue, and socket churn - because that is the order in
//! which the causes cripple a host. Every boundary is a named
//! number, never a mood.

use super::SlowSample;
use crate::commands::doctor::memory::ledger::fmt_bytes;
use crate::commands::doctor::network::{CLOSE_WAIT_PILE, PORT_EXHAUSTION_RISK};

/// The swap-rate boundary: any page moved in or out of swap inside
/// the window is swap pressure. One page is the floor because the
/// counter's unit IS the fact - a host that is not swapping moves
/// zero pages, always.
pub(crate) const SWAP_PRESSURE_PAGES: u64 = 1;

/// The available-memory boundary: below this share of MemTotal the
/// kernel is inside its reclaim slope and every allocation starts
/// paying for the page cache - the named edge before the swap cliff.
pub(crate) const MEMORY_PRESSURE_PCT: f64 = 10.0;

/// The CPU saturation boundary: the share of the window's ticks a
/// saturated host burns. Below it there are idle ticks for more
/// work; at it, queues grow.
pub(crate) const CPU_SATURATION_PCT: f64 = 80.0;

/// One triage finding: a severity class and the sentence that
/// carries its numbers. The class ranks; the text explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    /// The severity class - the ranking ladder's own name.
    pub class: &'static str,
    /// The sentence with the numbers behind the finding.
    pub text: String,
}

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane:
/// the top-ranked finding restated with its cross-lane context, or
/// the quiet-host sentence that restates the four headlines so the
/// "nothing" is a number-backed answer, never a shrug.
pub(crate) fn verdict_lines(sample: &SlowSample) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    match rank_findings(sample).first() {
        Some(top) => lines.push(top.text.clone()),
        None => {
            let busy = sample
                .cpu
                .busy_pct
                .map(|pct| format!("{pct:.1}%"))
                .unwrap_or_else(|| "unknown".to_owned());
            let iowait = sample
                .disk
                .iowait_pct
                .map(|pct| format!("{pct:.1}%"))
                .unwrap_or_else(|| "unknown".to_owned());
            let avail = sample
                .meminfo
                .as_ref()
                .map(|mem| fmt_bytes(mem.available_kib * 1024))
                .unwrap_or_else(|| "unknown".to_owned());
            lines.push(format!(
                "Nothing measurable is dragging this host in the 1.0s window: CPU {} \
                 busy, iowait {}, swap {}/{} pages, {} available.",
                busy, iowait, sample.swap_in_pages, sample.swap_out_pages, avail
            ));
            lines.push(
                "A stall that comes and goes does not live inside one 1.0s window - the \
                 per-lane reports and the event windows (why, holds, port --since) watch \
                 longer spans."
                    .to_owned(),
            );
        }
    }
    lines
}

/// The severity ladder: every finding the window's numbers support,
/// ranked. The order is the contract - swap pressure outranks stuck
/// I/O, which outranks iowait, memory pressure, CPU saturation, the
/// runnable queue, and socket churn - because that is the order in
/// which the causes cripple a host.
pub(crate) fn rank_findings(sample: &SlowSample) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    // 1. Swap pressure: the rate is the fact.
    if sample.swap_in_pages >= SWAP_PRESSURE_PAGES || sample.swap_out_pages >= SWAP_PRESSURE_PAGES {
        findings.push(Finding {
            class: "swap_pressure",
            text: format!(
                "The host is swapping: {} pages in, {} pages out inside the window - \
                 memory pressure is the drag; 'zejtron doctor --symptom ram' names the \
                 per-process memory.",
                sample.swap_in_pages, sample.swap_out_pages
            ),
        });
    }
    // 2. Stuck I/O: D-state processes, or the load-vs-quiet signature.
    let stuck_signature = match (sample.cpu.loadavg_1min, sample.cpu.busy_pct) {
        (Some(load), Some(busy)) => load > sample.cpu.ncpu as f64 && busy < 20.0,
        _ => false,
    };
    if !sample.cpu.stuck.is_empty() {
        let names: Vec<String> = sample
            .cpu
            .stuck
            .iter()
            .map(|row| format!("{} (PID {})", row.comm, row.pid))
            .collect();
        findings.push(Finding {
            class: "stuck_io",
            text: format!(
                "{} process{} in D state (uninterruptible sleep, waiting on I/O): {} - \
                 the load is stuck-I/O, not CPU work.",
                sample.cpu.stuck.len(),
                if sample.cpu.stuck.len() == 1 {
                    ""
                } else {
                    "es"
                },
                names.join(", ")
            ),
        });
    } else if stuck_signature {
        findings.push(Finding {
            class: "stuck_io",
            text: format!(
                "The load average ({:.2}) is above the core count ({}) while the CPU is \
                 quiet ({:.1}% busy) - processes are waiting on I/O, not CPU work.",
                sample.cpu.loadavg_1min.unwrap_or(0.0),
                sample.cpu.ncpu,
                sample.cpu.busy_pct.unwrap_or(0.0),
            ),
        });
    }
    // 3. I/O wait: the disk lane's own boundary.
    if let Some(pct) = sample.disk.iowait_pct
        && pct.is_finite()
        && pct > 20.0
    {
        findings.push(Finding {
            class: "io_wait",
            text: format!(
                "The I/O wait is high: {pct:.1}% of the window's CPU ticks - the disk \
                 lane is the drag; the top I/O consumer is {}.",
                sample
                    .disk
                    .top
                    .first()
                    .map(|row| format!("{} (PID {})", row.comm, row.pid))
                    .unwrap_or_else(|| "not attributable in this window".to_owned())
            ),
        });
    }
    // 4. Memory pressure: the available share below its floor.
    if let Some(mem) = &sample.meminfo
        && mem.total_kib > 0
    {
        let avail_pct = (mem.available_kib as f64) * 100.0 / (mem.total_kib as f64);
        if avail_pct < MEMORY_PRESSURE_PCT {
            findings.push(Finding {
                class: "memory_pressure",
                text: format!(
                    "Only {:.1}% of memory is still available ({} of {}) - the host is \
                     at the reclaim edge; 'zejtron doctor --symptom ram' names the holders.",
                    avail_pct,
                    fmt_bytes(mem.available_kib * 1024),
                    fmt_bytes(mem.total_kib * 1024),
                ),
            });
        }
    }
    // 5. CPU saturation.
    if let Some(busy) = sample.cpu.busy_pct
        && busy.is_finite()
        && busy >= CPU_SATURATION_PCT
    {
        findings.push(Finding {
            class: "cpu_saturation",
            text: format!(
                "The CPU is saturated: {busy:.1}% of the window's ticks busy - the \
                 largest consumer is {}.",
                sample
                    .cpu
                    .top
                    .first()
                    .map(|row| format!("{} ({:.1}% of total CPU)", row.comm, row.pct))
                    .unwrap_or_else(|| "not attributable in this window".to_owned())
            ),
        });
    }
    // 6. Runnable queue over-subscription.
    if sample.cpu.running > sample.cpu.ncpu {
        findings.push(Finding {
            class: "runnable_queue",
            text: format!(
                "{} {} are running on {} {} - the runnable queue is \
                 over-subscribed.",
                sample.cpu.running,
                crate::output::noun_for(sample.cpu.running, "process", "processes"),
                sample.cpu.ncpu,
                crate::output::noun_for(sample.cpu.ncpu, "core", "cores"),
            ),
        });
    }
    // 7. Socket churn: the network lane's boundaries.
    if sample.network.sockets.time_wait > PORT_EXHAUSTION_RISK {
        findings.push(Finding {
            class: "socket_churn",
            text: format!(
                "TIME_WAIT sockets ({}) are above the {} boundary - connection churn \
                 is the network-side shape.",
                sample.network.sockets.time_wait, PORT_EXHAUSTION_RISK
            ),
        });
    }
    if sample.network.sockets.close_wait >= CLOSE_WAIT_PILE {
        findings.push(Finding {
            class: "socket_churn",
            text: format!(
                "{} sockets sit in CLOSE_WAIT (above the {} boundary) - a local \
                 process is not closing its sockets; the holders above name the \
                 busiest owners.",
                sample.network.sockets.close_wait, CLOSE_WAIT_PILE
            ),
        });
    }
    findings
}
