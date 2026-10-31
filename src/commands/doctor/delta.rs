// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The delta symptoms' shared engine (night-improve-48): the
//! machinery `--symptom cpu`, `disk`, and `network` all ride on.
//! The contract is the spec's own: read the kernel's tables, sleep
//! exactly 1.0 seconds, read them again, and hand the caller two
//! samples - then print and exit. That is a delta snapshot, not a
//! monitor: no loop, no daemon, one window, one report.
//!
//! What lives here because three surfaces need it identically:
//!
//! - the /proc/stat aggregate tick parser (cpu's busy share and
//!   disk's iowait share both ride it);
//! - the /proc/<pid>/stat parser (the comm/state/tick triple - the
//!   comm is field 2, taken between the outermost parens so a
//!   process named "yes R" parses, the state is field 3, and the
//!   utime+stime pair is fields 14/15);
//! - the /proc/<pid>/io parser (the block-backed byte pair);
//! - the sampling gap itself - `SAMPLE_WINDOW`, stated once;
//! - the eBPF exits overlay glue the spec grants the delta symptoms:
//!   when the probe is attached, the last two seconds of recorded
//!   exits name the processes that died inside the sampling window,
//!   [observed]; the shared mode-line and sampling-boundary
//!   builders keep the three ledgers from drifting apart.
//!
//! GPU rides the overlay too (a pure snapshot - it names its own
//! window honestly) but none of the delta machinery: its file is
//! self-contained, and the shared builders take its facts from the
//! same source.

use std::collections::BTreeMap;
use std::time::Duration;

use super::memory::exits::ExitLane;

/// The sampling window: exactly 1.0 seconds, the spec's own number.
/// The wait IS the measurement - every delta row's denominator -
/// and it happens once per run, never in a loop.
pub(crate) const SAMPLE_WINDOW: Duration = Duration::from_secs(1);

/// The overlay window: when the probe is attached, the delta symptoms
/// drain the eBPF exit ring for the last two seconds - wide enough
/// to cover the sampling window plus the drain's own skew, narrow
/// enough that every [observed] row is one of the freshest facts on
/// the host. The label rides beside the number so the header and
/// the boundary text cannot drift apart.
pub(crate) const OVERLAY_WINDOW_SECS: u64 = 2;
pub(crate) const OVERLAY_WINDOW_LABEL: &str = "2s";

/// One /proc/stat aggregate snapshot: the CPU tick counters, in
/// USER_HZ units. The percentages the symptoms print are tick
/// RATIOS - pid ticks over total ticks - so the clock frequency
/// never enters the arithmetic (a ratio is honest on any HZ).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CpuTicks {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTicks {
    /// Every tick the aggregate line carries (guest time is already
    /// accounted inside user on Linux; it is not double-counted).
    pub(crate) fn total(self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    /// The busy share: everything except idle and iowait.
    pub(crate) fn busy(self) -> u64 {
        self.user + self.nice + self.system + self.irq + self.softirq + self.steal
    }
}

/// Parse the /proc/stat aggregate line: `cpu  user nice system idle
/// iowait irq softirq steal ...`. The leading "cpu" token is the
/// signature; eight numeric fields is the floor kernel's shape, and
/// later-appended fields (guest, guest_nice) ride after them and
/// are not read.
pub(crate) fn parse_cpu_line(line: &str) -> Option<CpuTicks> {
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut ticks = CpuTicks::default();
    for slot in [
        &mut ticks.user,
        &mut ticks.nice,
        &mut ticks.system,
        &mut ticks.idle,
        &mut ticks.iowait,
        &mut ticks.irq,
        &mut ticks.softirq,
        &mut ticks.steal,
    ] {
        *slot = fields.next()?.parse().ok()?;
    }
    Some(ticks)
}

/// One process's per-window facts from /proc/<pid>/stat: the comm
/// (field 2, taken between the FIRST '(' and the LAST ')' so a
/// comm containing spaces or parens parses whole), the state
/// (field 3, the single letter the Load/stuck section rides on),
/// and the CPU tick pair (utime + stime, fields 14/15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PidStat {
    pub comm: String,
    pub state: char,
    pub cpu_ticks: u64,
}

/// Parse one /proc/<pid>/stat file. `None` is every unparsable
/// shape (a vanished process racing the read, a truncated line) -
/// the caller counts the miss, never guesses.
pub(crate) fn parse_pid_stat(contents: &str) -> Option<PidStat> {
    let open = contents.find('(')?;
    let close = contents.rfind(')')?;
    if close <= open {
        return None;
    }
    // The comm is the process's own string (it can rename itself to
    // anything); the display sanitizer is applied at the parse
    // boundary so no ledger row can ever carry a control byte - the
    // zero-escape law, one source, every surface.
    let comm = crate::system::sanitize_display(&contents[open + 1..close]);
    // After the ')' the fields continue from field 3: state is the
    // first token, and utime/stime are the 12th and 13th tokens
    // after it (fields 14 and 15 counting from 1 on the whole line).
    let tail = contents[close + 1..].split_whitespace().collect::<Vec<_>>();
    if tail.len() < 13 {
        return None;
    }
    let state = tail[0].chars().next()?;
    let utime: u64 = tail[11].parse().ok()?;
    let stime: u64 = tail[12].parse().ok()?;
    Some(PidStat {
        comm,
        state,
        cpu_ticks: utime.saturating_add(stime),
    })
}

/// One process's /proc/<pid>/io snapshot: the block-backed byte
/// pair the disk symptom rides on (read_bytes and write_bytes -
/// NOT rchar/wchar, which count every syscall byte including
/// cache hits and terminal writes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PidIo {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// Parse one /proc/<pid>/io file. Absent fields stay zero (the
/// kernel writes both names on every modern host; a short file is a
/// race, not a guess).
pub(crate) fn parse_pid_io(contents: &str) -> PidIo {
    let mut io = PidIo::default();
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("read_bytes:") {
            io.read_bytes = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("write_bytes:") {
            io.write_bytes = rest.trim().parse().unwrap_or(0);
        }
    }
    io
}

/// One instant's per-process snapshot: every pid's stat facts and
/// (for the disk lane) the io facts, with the read boundaries
/// counted by class - a permission refusal and a vanished process
/// are different truths, and neither is ever silently dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PidSample {
    pub stat: BTreeMap<u32, PidStat>,
    pub io: BTreeMap<u32, PidIo>,
    pub stat_unreadable: usize,
    pub io_permission_refused: usize,
    pub io_vanished: usize,
}

/// Read the per-process snapshot at this instant: the stat pair for
/// every readable pid, the io pair for every readable pid, and the
/// refusal counts the Unaccounted blocks name. One walker, two
/// reads per pid, no loop.
pub(crate) fn read_pid_sample(pids: &[u32]) -> PidSample {
    let mut sample = PidSample::default();
    for pid in pids {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(contents) => {
                if let Some(stat) = parse_pid_stat(&contents) {
                    sample.stat.insert(*pid, stat);
                } else {
                    sample.stat_unreadable += 1;
                }
            }
            Err(_) => sample.stat_unreadable += 1,
        }
        match std::fs::read_to_string(format!("/proc/{pid}/io")) {
            Ok(contents) => {
                sample.io.insert(*pid, parse_pid_io(&contents));
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                sample.io_permission_refused += 1;
            }
            Err(_) => sample.io_vanished += 1,
        }
    }
    sample
}

/// The sampling gap: sleep exactly the window. The only wait in the
/// lane - the callers call it once between their two reads, and the
/// spec's law holds: no loop, no second window (the narration's
/// wake slices are one window's chunks, deadline-anchored, never a
/// re-armed window). The wait is narrated (night-hunter-6): the
/// countdown rides stderr's own lane, the ledger's stdout untouched.
pub(crate) fn sample_gap() {
    crate::output::spinner::wait(SAMPLE_WINDOW, "sampling");
}

/// The exits overlay for a delta symptom: the spec's grant - when
/// the probe is attached, drain the eBPF exit ring for the last two
/// seconds and name the processes that died inside the sampling
/// window, [observed]. Not attached is the honest [unaccounted]
/// boundary the builders below phrase.
pub(crate) fn collect_exits_overlay() -> ExitLane {
    super::memory::exits::collect_window(OVERLAY_WINDOW_SECS)
}

/// Render the overlay section - the same renderer ram seats, the
/// delta label instead of ram's.
pub(crate) fn render_exits_overlay(lane: &ExitLane, lines: &mut Vec<String>) {
    super::memory::exits::render_section(lane, lines, OVERLAY_WINDOW_LABEL);
}

/// The mode line for a delta symptom (gpu passes `false` for its
/// snapshot shape): the lane's own truth - a 1.0s delta sample, plus
/// the overlay state. One builder, four surfaces, no drift.
pub(crate) fn mode_line(lane: &ExitLane, delta: bool) -> &'static str {
    match (delta, lane) {
        (true, ExitLane::NotAttached) => "Mode: snapshot delta (1.0s sample; eBPF not attached)",
        (true, ExitLane::Drained(..)) => {
            "Mode: snapshot delta + post-mortem (1.0s sample; eBPF exits drained, last 2s)"
        }
        (true, ExitLane::DrainFailed(_)) => {
            "Mode: snapshot delta + post-mortem (1.0s sample; the exit drain failed - named below)"
        }
        (false, ExitLane::NotAttached) => "Mode: snapshot (eBPF not attached)",
        (false, ExitLane::Drained(..)) => {
            "Mode: snapshot + post-mortem (eBPF exits drained, last 2s)"
        }
        (false, ExitLane::DrainFailed(_)) => {
            "Mode: snapshot + post-mortem (the exit drain failed - named below)"
        }
    }
}

/// The sampling-boundary unaccounted line, shared by all four new
/// symptoms (the spec's own sentence for the not-attached shape;
/// gpu passes its snapshot phrasing through the same builder). The
/// text rides grey with the [unaccounted] tag - the weakest
/// evidence, named exactly.
pub(crate) fn sampling_unaccounted(lane: &ExitLane, window_desc: &str) -> String {
    let body = match lane {
        ExitLane::NotAttached => format!(
            "processes that started and exited within {window_desc}: not attributed \
             (zejtron samples, it does not watch)"
        ),
        ExitLane::Drained(..) => format!(
            "processes that started and exited within {window_desc}: named [observed] \
             in the exits section above (the eBPF drain holds the last {OVERLAY_WINDOW_LABEL})"
        ),
        ExitLane::DrainFailed(e) => format!(
            "processes that started and exited within {window_desc}: not attributed \
             (the eBPF exit drain failed: {e})"
        ),
    };
    format!(
        "  {}  {}",
        crate::output::grey_out(&body),
        crate::output::grey_out("[unaccounted]")
    )
}

/// The delta symptoms' sampling description - the phrase the three
/// delta ledgers share (gpu carries its own).
pub(crate) const SAMPLE_WINDOW_DESC: &str = "the 1.0s sampling window";

#[cfg(test)]
#[path = "../../../test/commands/doctor/delta_tests.rs"]
mod tests;
