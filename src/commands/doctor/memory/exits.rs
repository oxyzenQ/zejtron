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
use crate::output::noun_for;

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
    /// none (an empty window is a finding, not a missing section),
    /// and the count of the observer's own invocations the lane
    /// excluded from those rows (named, never silently dropped -
    /// night-dragon-lts-4).
    Drained(Vec<ExitRow>, usize),
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

/// This invocation's own comm (the observer): every previous
/// zejtron run that exited inside the window is the tool measuring
/// itself - a watch-loop's invocations, a monitoring cron's one per
/// second. Those exits are real kernel events but facts about the
/// observer, not the host: the lane excludes them from the rows and
/// names the exclusion count, never a silent drop. The kernel
/// truncates comm to 15 characters (TASK_COMM_LEN minus the NUL),
/// and the comparison truncates the same way or a long binary name
/// never matches its own exits.
///
/// The kernel's own record first (night-dragon-lts-4): /proc/self/comm
/// is the exact string bpf_get_current_comm() will attach to this
/// process's own exit event, so the comparison matches by
/// construction where a path-derived guess does not - a watch loop
/// invoking through a symlink alias (current_exe resolves the link,
/// comm rides the alias name) and a watch loop holding the binary
/// across a rebuild (current_exe grows the kernel's " (deleted)"
/// marker, comm keeps the bare name) are the two shapes this lane
/// exists for, and both break the basename guess.
fn own_comm() -> String {
    if let Ok(record) = std::fs::read_to_string("/proc/self/comm") {
        let shaped = shape_comm_record(&record);
        if !shaped.is_empty() {
            return shaped;
        }
    }
    let name = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        // The deleted-binary shape: /proc/self/exe names the unlinked
        // file as "<name> (deleted)" - the marker is the kernel's
        // annotation, not part of any comm.
        .map(|name| {
            name.strip_suffix(" (deleted)")
                .map(str::to_owned)
                .unwrap_or(name)
        })
        .unwrap_or_else(|| "zejtron".to_owned());
    name.chars().take(15).collect()
}

/// Shape one /proc/self/comm record into the comparison form: trim
/// the trailing newline (and any NUL a record ever carried), cap at
/// the kernel's own 15-character comm bound. An unreadable or empty
/// record is the caller's signal to fall through to the exe path -
/// never a guess rendered as the kernel's word.
fn shape_comm_record(record: &str) -> String {
    record
        .trim_end_matches(['\n', '\0'])
        .chars()
        .take(15)
        .collect()
}

/// Collect the exit lane: the pin state first (a partial chain is
/// not a live chain - `doctor --attach` heals it), then the drain,
/// then the window cutoff. The read side needs no capabilities,
/// only the bpffs walk. CLOCK_MONOTONIC end to end - the records
/// are bpf_ktime_get_ns stamps and "now" is clock_gettime on the
/// same clock (night-dragon-lts-1; one source since
/// night-improve-47: the civil clock module owns both companions).
pub(crate) fn collect_window(window_secs: u64) -> ExitLane {
    if !ebpf::all_pins_present() {
        return ExitLane::NotAttached;
    }
    match ebpf::ringbuf::drain_proc_exits() {
        Err(e) => ExitLane::DrainFailed(e),
        Ok(events) => {
            let (rows, observer_excluded) = window_rows(events, window_secs);
            ExitLane::Drained(rows, observer_excluded)
        }
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
/// names for the sampling-blind overlay). night-dragon-lts-4 adds
/// the observer cut: this tool's own invocations leave the rows and
/// ride the named exclusion count instead - the pre-fix lane
/// rendered "PID 12345 (zejtron) exited" inside a zejtron report,
/// the observer accusing itself.
fn window_rows(events: Vec<ProcExitEvent>, window_secs: u64) -> (Vec<ExitRow>, usize) {
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
    let own = own_comm();
    let before = rows.len();
    rows.retain(|row| row.comm != own);
    let observer_excluded = before - rows.len();
    rows.sort_by_key(|row| row.timestamp_ns);
    (rows, observer_excluded)
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
    let (rows, observer_excluded) = match lane {
        ExitLane::NotAttached => return,
        ExitLane::Drained(rows, observer_excluded) => (rows, observer_excluded),
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
        let more = rows.len() - super::ledger::TOP_N;
        lines.push(crate::output::grey_out(&format!(
            "  ({more} more {} in the window, not rendered)",
            noun_for(more, "exit", "exits")
        )));
    }
    // The observer boundary (night-dragon-lts-4): this tool's own
    // invocations are real kernel events but facts about the
    // observer, not the host - excluded from the rows above and
    // named here, never dropped in silence.
    if *observer_excluded > 0 {
        lines.push(crate::output::grey_out(&format!(
            "  {} {} of this tool excluded (the observer's own invocations, not host facts)",
            observer_excluded,
            noun_for(*observer_excluded, "exit", "exits")
        )));
    }
    lines.push(String::new());
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_exits_tests.rs"]
mod tests;
