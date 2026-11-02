// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
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
//! are bpf_ktime_get_ns stamps, and the offset that turns them into
//! wall time rides the crate's one clock source (crate::info::clock,
//! the shared helpers night-improve-47 moved there): the same
//! wall_offset_ns the port window and the doctor's exit rows render
//! through, so the three surfaces cannot drift again. The hand
//! copies this module carried until night-improve-60 read
//! /proc/uptime - the CLOCK_BOOTTIME domain, suspend-inclusive -
//! so every live file row's rendered time ran early by the host's
//! cumulative suspend on any host that ever suspended (the exact
//! defect night-dragon-lts-1 fixed for the port window; this
//! module's hand duplicate was left behind by that fix).
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
    // keeps the history and one drain takes it. The wait is
    // narrated (night-hunter-6): a grey countdown on stderr, the
    // ledger's stdout untouched.
    crate::output::spinner::wait(window, "watching for events");
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

/// One event's wall-clock unix seconds (truncated to the second,
/// the ledger's rendering granularity). `None` when the clocks are
/// unreadable — the row then renders `unknown`, never a fabricated
/// time. The offset is the crate's one source
/// (crate::info::clock::wall_offset_ns, CLOCK_MONOTONIC through
/// clock_gettime - the same domain the eBPF stamps ride), never a
/// /proc/uptime re-implementation: the two clocks differ by the
/// host's cumulative suspend time, and a BOOTTIME-based offset
/// renders every live row that much too early.
pub fn event_unix_secs(event: &FileEvent) -> Option<i64> {
    let offset = crate::info::clock::wall_offset_ns()?;
    let nanos = event.timestamp_ns as i128 + offset;
    if nanos.is_negative() {
        return None;
    }
    Some((nanos / 1_000_000_000) as i64)
}

#[cfg(test)]
#[path = "../../test/ebpf/fileprobe_tests.rs"]
mod tests;
