// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory symptom's post-mortem exit lane (night-improve-47):
//! the eBPF half of `doctor --symptom ram`. The /proc snapshot in
//! the parent module cannot see a process that exited even a second
//! before the read - its memory is unaccounted by physics, not by
//! policy. When the probe is attached, the kernel-side exit probe
//! (ebpf/src/exits.rs) has been recording every process exit into
//! the proc_events ring; this module drains that ring once, keeps
//! the last EXIT_WINDOW_SECS seconds, and hands the rows to the
//! ledger - the Lazy Camera's post-mortem, not a stream: read once,
//! print, exit. No daemon, no persistent reader, nothing written to
//! disk (docs/EBPF_LIFECYCLE.md owns the doctrine).
//!
//! The lane states are three, and the ledger names each: not
//! attached (no drain - the Unaccounted block says what is
//! invisible), drained (the exits the window holds, possibly none -
//! an empty window is a finding), and drain-failed (the probe is
//! attached but the ring would not open - the error rides the
//! report verbatim, never a silent empty section).

use crate::ebpf::{self, events::ProcExitEvent};

/// The post-mortem window: the last five seconds of process exits
/// the doctor drains and names. Five, because the question this
/// symptom answers is "what just ate my RAM" - a window wide enough
/// to catch the culprit that exited while the operator reached for
/// the terminal, narrow enough that every row is one of the freshest
/// facts on the host.
pub(crate) const EXIT_WINDOW_SECS: u64 = 5;

/// The post-mortem window's compact label - the render header's own
/// token, kept beside the number so the two cannot drift apart
/// (night-improve-48 parameterizes the renderer: the delta symptoms
/// pass their own pair, ram passes this one).
pub(crate) const EXIT_WINDOW_LABEL: &str = "5s";

/// One rendered exit row's facts: the record's pid and comm, and
/// the monotonic stamp the ledger renders as a time of day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExitRow {
    pub pid: u32,
    pub comm: String,
    pub timestamp_ns: u64,
}

/// The exit lane's state, the three truths the ledger renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExitLane {
    /// No attached probe: no drain is possible or honest - the
    /// Unaccounted block names what stays invisible.
    NotAttached,
    /// The drain succeeded: the exits inside the window, possibly
    /// none (an empty window is a finding, not a missing section).
    Drained(Vec<ExitRow>),
    /// The probe is attached but the ring would not open: the error
    /// text rides the report verbatim.
    DrainFailed(String),
}

impl Default for ExitLane {
    /// The honest default: a sample nobody filled reads as the
    /// not-attached host (the synthetic-test default and the
    /// clean-host shape agree).
    fn default() -> Self {
        Self::NotAttached
    }
}

/// The process's comm, rendered: the bytes up to the first NUL (the
/// helper's contract), lossy over invalid UTF-8, "unknown" when
/// nothing but NULs rode the record - an absent fact stays absent.
pub(crate) fn comm_string(bytes: &[u8; 16]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if text.is_empty() {
        "unknown".to_owned()
    } else {
        text
    }
}

/// Collect the exit lane: the pin state first (a partial chain is
/// not a live chain - `doctor --attach` heals it), then the drain,
/// then the window cutoff. The read side needs no capabilities,
/// only the bpffs walk. CLOCK_MONOTONIC end to end - the records
/// are bpf_ktime_get_ns stamps and "now" is /proc/uptime, the same
/// pair the port window uses (one source since night-improve-47:
/// the civil clock module owns both companions).
pub(crate) fn collect_window(window_secs: u64) -> ExitLane {
    if !ebpf::all_pins_present() {
        return ExitLane::NotAttached;
    }
    match ebpf::ringbuf::drain_proc_exits() {
        Err(e) => ExitLane::DrainFailed(e),
        Ok(events) => ExitLane::Drained(window_rows(events, window_secs)),
    }
}

/// Filter the drained exits to the window, ascending by time - the
/// deterministic ordering law, the caller's contract. A ring read
/// consumes, so this is every exit the ring held; the cutoff keeps
/// the window's freshest slice. An unreadable clock keeps the
/// drained records rather than guessing a cutoff - the ring is
/// bounded and the section header names the window either way.
/// night-improve-48 grows the parameter: ram asks for its five
/// seconds, the delta symptoms ask for two (the window the spec
/// names for the sampling-blind overlay).
fn window_rows(events: Vec<ProcExitEvent>, window_secs: u64) -> Vec<ExitRow> {
    let cutoff_ns = crate::info::clock::monotonic_now_ns()
        .map(|now| now.saturating_sub(window_secs * 1_000_000_000));
    let mut rows: Vec<ExitRow> = events
        .into_iter()
        .filter(|event| match cutoff_ns {
            Some(cutoff) => event.timestamp_ns >= cutoff,
            None => true,
        })
        .map(|event| ExitRow {
            pid: event.pid,
            comm: comm_string(&event.comm),
            timestamp_ns: event.timestamp_ns,
        })
        .collect();
    rows.sort_by_key(|row| row.timestamp_ns);
    rows
}

/// The exit section's render, seated between the slab section and
/// the Unaccounted block. Rendered only when the probe is attached -
/// the not-attached truth rides the mode line and the Unaccounted
/// block (spec law: the absent lane is named where the boundary is
/// named). Rows are the doctrine's own shape:
/// `<HH:MM:SS UTC>  PID <pid> (<comm>)  exited  [observed]` - the
/// time rides grey (a timestamp), the pid and comm stay unwrapped
/// (the values), and the [observed] tag rides green (the kernel
/// itself recorded the exit as it happened - the strongest tier a
/// report can carry). The row cap is the ledger's own TOP_N; the
/// window label is the caller's contract (night-improve-48 - ram
/// passes its own pair, the delta symptoms pass theirs).
pub(crate) fn render_section(lane: &ExitLane, lines: &mut Vec<String>, window_label: &str) {
    let header = format!("Recently exited (eBPF, last {window_label}):");
    let rows = match lane {
        ExitLane::NotAttached => return,
        ExitLane::Drained(rows) => rows,
        ExitLane::DrainFailed(e) => {
            lines.push(crate::output::ok_out(&header));
            lines.push(format!(
                "  {}",
                crate::output::grey_out(&format!(
                    "the exit ring could not be read ({e}) - recent exits are not named"
                ))
            ));
            lines.push(String::new());
            return;
        }
    };
    lines.push(crate::output::ok_out(&header));
    if rows.is_empty() {
        // The empty-window line rides grey (the "no events" class):
        // the lane RAN and the window is a finding.
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    for row in rows.iter().take(super::ledger::TOP_N) {
        lines.push(format!(
            "  {}  PID {} ({})  exited  {}",
            crate::output::grey_out(&crate::info::clock::time_of_day_from_monotonic_ns(
                row.timestamp_ns
            )),
            row.pid,
            row.comm,
            crate::output::ok_out("[observed]"),
        ));
    }
    if rows.len() > super::ledger::TOP_N {
        lines.push(crate::output::grey_out(&format!(
            "  ({} more exits in the window, not rendered)",
            rows.len() - super::ledger::TOP_N
        )));
    }
    lines.push(String::new());
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_exits_tests.rs"]
mod tests;
