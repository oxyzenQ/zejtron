// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The process lifecycle stream (night-improve-4, Part C): the
//! `proc --live` surface. Part B names what still holds the RAM;
//! this names what held it briefly and left - the exec, fork, and
//! exit events the kernel recorded in the proc_events ring while
//! the command watched, rendered as an Evidence Ledger report.
//!
//! The grammar follows the same collection-over-duration discipline
//! the port window and the file taps speak: `--since N` waits N
//! seconds, draining the pinned ring continuously - the wait IS the
//! collection. Without eBPF, or without a live chain, the honest
//! unavailability line is the answer; no event is ever fabricated.
//!
//! The evidence rows are \[observed] (the kernel recorded each event
//! the moment it happened); the Unaccounted block names what the
//! stream cannot see: tasks born before attach, hidepid boundaries,
//! and the thread residual (every thread birth and death also fires
//! the sched_process_fork/_exit tracepoints - the stream records
//! task-level truth, and says so).

use std::time::Duration;

// The record contract and the ring readers compile into feature
// builds only (the default build has no reader for the ring); the
// grammar half below - the window, the clamp, the refusal line -
// compiles in every build, because the refusal is the default
// build's whole answer.
#[cfg(feature = "ebpf")]
use crate::ebpf::events::{PROC_OP_EXEC, PROC_OP_EXIT, PROC_OP_FORK, ProcEvent};
#[cfg(feature = "ebpf")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Decode a record's comm into a display name: bytes up to the first
/// NUL, lossy on non-UTF8. Empty renders `unknown` - a comm the
/// kernel never wrote stays absent, never guessed. Lives here (the
/// host renderer) rather than in events.rs: the record contract file
/// also compiles no_std into the bpfel object, where a String cannot
/// exist - the same split device_token_from_kernel and
/// device_token_from_stat already carry.
#[cfg(feature = "ebpf")]
pub(crate) fn comm_label(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    if name.is_empty() {
        "unknown".to_owned()
    } else {
        name.into_owned()
    }
}

/// The default window when `--live` runs without `--since`.
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(30);

/// The window floor: a zero or sub-second window is not a window.
pub const WINDOW_FLOOR: Duration = Duration::from_secs(1);

/// The window ceiling: ten minutes. A longer window than that is a
/// log-shaped problem, not an evidence-shaped one.
pub const WINDOW_CEILING: Duration = Duration::from_secs(600);

/// The drain slice: how often the collection wakes to empty the
/// ring while it waits (the same slice the port window uses - one
/// shape, both pumps).
#[cfg(feature = "ebpf")]
const POLL_SLICE: Duration = Duration::from_millis(100);

/// The unavailability line: the explicit request this run cannot
/// serve. One shape for every reason (featureless binary, no root,
/// chain not attached) - the doctor's \[eBPF\] section names the
/// exact one. The same sentence shape port's window prints, named
/// for process events.
pub fn unavailability_line(window: Duration) -> String {
    format!(
        "Process events in the last {}: unavailable (this binary/run cannot capture \
         process events - see zejtron doctor [eBPF])",
        window_label(window)
    )
}

/// The window as a compact label (the same grammar port's window
/// speaks: `30s`, `5m`).
pub fn window_label(window: Duration) -> String {
    let secs = window.as_secs();
    if secs != 0 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs > 60 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Clamp the window into [1s, 600s]: `0s` becomes `1s`, `1h`
/// becomes `600s`. The clamp is the contract, so every lane agrees
/// on what a lifecycle window means.
pub fn clamp_window(window: Duration) -> Duration {
    window.clamp(WINDOW_FLOOR, WINDOW_CEILING)
}

/// The lifecycle report for this run: the capture when the chain is
/// live, the named unavailability when it is not. The featureless
/// binary has no reader for the ring - the refusal IS the answer,
/// never a fake empty window.
pub fn report(window: Duration) -> String {
    #[cfg(feature = "ebpf")]
    if let Some(events) = capture(window) {
        return render(&events, window);
    }
    unavailability_line(window)
}

/// Capture the window: the pin state first (a partial chain is not
/// a live chain - `doctor --attach` heals it), then the collection -
/// the wait IS the collection, the ring held open and drained slice
/// by slice, the rolling cap bounding the Vec. `None` is every
/// not-live shape; the caller renders the refusal.
#[cfg(feature = "ebpf")]
fn capture(window: Duration) -> Option<Vec<ProcEvent>> {
    if !crate::ebpf::all_pins_present() {
        return None;
    }
    let mut ring = crate::ebpf::ringbuf::open_proc_ring().ok()?;
    let mut collected: Vec<ProcEvent> = Vec::new();
    let deadline = Instant::now() + window;
    loop {
        crate::ebpf::ringbuf::drain_proc_events_from(&mut ring, &mut collected);
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        std::thread::sleep(POLL_SLICE.min(deadline - now));
    }
    collected.sort_by_key(|event| event.timestamp_ns);
    Some(collected)
}

/// The op label for one lifecycle row: the three truths the
/// tracepoints record.
#[cfg(feature = "ebpf")]
pub fn op_label(op: u8) -> Option<&'static str> {
    match op {
        PROC_OP_EXEC => Some("exec'd"),
        PROC_OP_FORK => Some("started"),
        PROC_OP_EXIT => Some("exited"),
        _ => None,
    }
}

/// The programs the verdict names when one of them exec'd in the
/// window: the common memory-hungry interpreters, compilers, and
/// browsers. A prefix match on the record's comm. The list is fixed
/// and named here - the verdict reads the list, it does not guess.
#[cfg(feature = "ebpf")]
const MEMORY_HOG_PATTERNS: [&str; 12] = [
    "python", "java", "node", "ruby", "php", "chrome", "chromium", "firefox", "gcc", "cc1",
    "rustc", "clang",
];

/// True when the comm matches one of the named patterns.
#[cfg(feature = "ebpf")]
pub fn is_memory_hog_comm(comm: &str) -> bool {
    MEMORY_HOG_PATTERNS
        .iter()
        .any(|pattern| comm.starts_with(pattern))
}

/// One event's wall-clock time of day as `HH:MM:SS UTC` - the
/// monotonic stamp plus the wall-now/monotonic-now offset (the same
/// arithmetic port's window renders; duplicated by hand: those
/// helpers are port-surface privates and port's output is locked,
/// the cross-reference is the contract). Every row carries the UTC
/// marker - the locked shape for this surface shows it per row.
#[cfg(feature = "ebpf")]
fn event_time_of_day(event: &ProcEvent) -> String {
    let Some(offset) = wall_offset_ns() else {
        return "unknown".to_owned();
    };
    let secs = ((event.timestamp_ns as i128 + offset) / 1_000_000_000) as i64;
    let time_of_day = secs.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
}

/// The monotonic "now", in nanoseconds, from /proc/uptime (the
/// kernel's own CLOCK_BOOTTIME clock at 10 ms resolution). `None`
/// when the file is unreadable - the honest degradation, never a
/// guess.
#[cfg(feature = "ebpf")]
fn monotonic_now_ns() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = uptime.split_whitespace().next()?;
    let seconds: f64 = first.parse().ok()?;
    Some((seconds * 1e9) as u64)
}

#[cfg(feature = "ebpf")]
fn wall_offset_ns() -> Option<i128> {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    let mono = monotonic_now_ns()? as i128;
    Some(wall - mono)
}

/// Render the full report. The locked shape: header, mode, the
/// process events, Unaccounted, Verdict.
#[cfg(feature = "ebpf")]
pub fn render(events: &[ProcEvent], window: Duration) -> String {
    let mut lines = Vec::new();
    lines.push("Evidence report: process lifecycle".to_owned());
    lines.push(format!("Mode: live (window {})", window_label(window)));
    lines.push(String::new());

    lines.push("Process events:".to_owned());
    if events.is_empty() {
        lines.push("  (no events in the window)".to_owned());
    } else {
        // The runtime pairing: an exit row names the runtime when
        // the same task's birth (fork or exec) was observed in this
        // window; otherwise the runtime is unknown - a fact the row
        // simply omits, never guesses.
        let mut births: Vec<(u32, u64)> = Vec::new();
        for event in events {
            let label = op_label(event.op).unwrap_or("unknown");
            let mut row = format!(
                "  {}  PID {} ({})  {}  [observed]",
                event_time_of_day(event),
                event.pid,
                comm_label(&event.comm),
                label
            );
            if event.op == PROC_OP_EXIT {
                if let Some((_, born)) = births.iter().rev().find(|(pid, _)| *pid == event.pid) {
                    let runtime = event
                        .timestamp_ns
                        .saturating_sub(*born)
                        .div_euclid(1_000_000_000);
                    row.push_str(&format!("  runtime {runtime}s"));
                }
            } else {
                births.push((event.pid, event.timestamp_ns));
            }
            if event.ppid != 0 {
                row.push_str(&format!("  ppid {}", event.ppid));
            }
            lines.push(row);
        }
    }
    lines.push(String::new());

    lines.push("Unaccounted:".to_owned());
    lines.push("  Processes that existed before attach (no birth event recorded)".to_owned());
    lines.push("  Processes owned by other users with hidepid=2 (namespace boundary)".to_owned());
    lines.push(
        "  Thread births and deaths ride the same tracepoints - this stream is \
         task-level truth, and thread churn shows as task events"
            .to_owned(),
    );
    lines.push(String::new());

    lines.push("Verdict:".to_owned());
    lines.push(format!(
        "  {} lifecycle event(s) in {}.",
        events.len(),
        window_label(window)
    ));
    // The one conditional finding: an exec (or a fork whose child is
    // named for a memory-hungry program) in the window - named as a
    // fact, pointed at Part B's surface for attribution. Never an
    // instruction.
    if let Some(event) = events
        .iter()
        .filter(|e| e.op == PROC_OP_EXEC || e.op == PROC_OP_FORK)
        .find(|e| is_memory_hog_comm(&comm_label(&e.comm)))
    {
        lines.push(format!(
            "  PID {} ({}) is named - investigate its lifetime against \
             `zejtron doctor --symptom ram` for attribution.",
            event.pid,
            comm_label(&event.comm)
        ));
    }

    lines.join("\n")
}

// The render pins ride the feature lane (the render itself only
// exists there); the grammar pins (window, clamp, refusal) ride
// every lane through proc_tests.rs.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../../test/commands/proc/live_tests.rs"]
mod tests;
