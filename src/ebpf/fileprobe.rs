// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The file window capture (night-improve-3, feature builds only):
//! the live lane's one-shot, shared by holds, touch, and why. The
//! whole lifecycle of a live window lives here, once: insert the
//! queried file into the tracked_inodes filter map, collect over the
//! window's duration (the sleep IS the collection — the kprobes are
//! recording into the ring the whole time), remove the key, drain
//! the ring once, keep only the events whose full identity matches
//! the query, sort ascending.
//!
//! The clock arithmetic is CLOCK_MONOTONIC end to end — the records
//! are bpf_ktime_get_ns stamps; the same /proc/uptime + wall offset
//! conversion port's window uses (duplicated here by hand: those
//! three helpers are port-surface privates and port's output is
//! locked; the cross-reference is the contract).
//!
//! The collection-over-duration semantic is the honest one and it
//! costs what it costs: `--since 30s` waits 30 seconds, because the
//! filter map only lets the queried file's events cross WHILE the
//! key is in the map — a window that ended before it began would
//! capture nothing. No daemon, no reader while sleeping: the ring
//! accumulates in the kernel and one drain at the end collects it.

use std::time::Duration;

use super::events::FileEvent;
use super::ringbuf;
use super::tracked::{track_file, untrack_file};

/// Capture one live window for one file. Every error propagates
/// loudly (the caller already checked the chain was live; a failure
/// mid-window means the chain died under the command — that is worth
/// an error, never a silent lane switch). The untrack on the error
/// paths is the fail protocol: no window ends with a leaked key
/// while this code can still run.
pub fn capture_file_window(
    inode: u64,
    device: u64,
    window: Duration,
) -> Result<Vec<FileEvent>, String> {
    track_file(inode, device)?;
    // The collection: the kprobes are live against the filter map
    // for exactly this long. std sleep, no reader thread — the ring
    // keeps the history and one drain takes it.
    std::thread::sleep(window);
    untrack_file(inode, device)?;
    let drained = ringbuf::drain_file_events()?;
    Ok(select_window(&drained, inode, device))
}

/// Keep only the events whose FULL identity (inode + device, both
/// 64 bits) matches the query, ascending by timestamp. The
/// kernel-side filter keyed on the low 32 bits of each — this is
/// the host-side mirror, the same double discipline the port
/// surface's is_port_surface_event rides: the ring contract says a
/// foreign event cannot cross, the renderer refuses to invent a row
/// for one anyway.
pub fn select_window(events: &[FileEvent], inode: u64, device: u64) -> Vec<FileEvent> {
    let mut selected: Vec<FileEvent> = events
        .iter()
        .filter(|event| event.inode == inode && event.device == device)
        .copied()
        .collect();
    selected.sort_by_key(|event| event.timestamp_ns);
    selected
}

/// The monotonic "now", in nanoseconds, from /proc/uptime (the
/// kernel's own CLOCK_BOOTTIME clock at 10 ms resolution). `None`
/// when the file is unreadable — the honest degradation.
pub fn monotonic_now_ns() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = uptime.split_whitespace().next()?;
    let seconds: f64 = first.parse().ok()?;
    Some((seconds * 1e9) as u64)
}

/// The wall-clock offset for rendering event timestamps: wall-now
/// minus monotonic-now, both read in the same breath.
pub fn wall_offset_ns() -> Option<i128> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    let mono = monotonic_now_ns()? as i128;
    Some(wall - mono)
}

/// One event's wall-clock unix seconds (truncated to the second,
/// the ledger's rendering granularity). `None` when the clocks are
/// unreadable — the row then renders `unknown`, never a fabricated
/// time.
pub fn event_unix_secs(event: &FileEvent) -> Option<i64> {
    let offset = wall_offset_ns()?;
    let nanos = event.timestamp_ns as i128 + offset;
    if nanos.is_negative() {
        return None;
    }
    Some((nanos / 1_000_000_000) as i64)
}

#[cfg(test)]
#[path = "../../test/ebpf/fileprobe_tests.rs"]
mod tests;
