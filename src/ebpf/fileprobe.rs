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
///
/// The `Ok` payload carries the capture's PRE offset alongside the
/// events (night-frontier-Z2, the wall-offset skew law): the wall
/// offset sampled the instant the window BEGINS - the anchor the
/// renderer measures its own render-time offset against, so a wall
/// clock that moved under the window is named instead of serving
/// skewed civil times silently. `None` rides when the clocks were
/// unreadable at the start (the render already degrades to
/// `unknown UTC` on its own).
///
/// The third member is the capture's PRE sleep gap (night-frontier-
/// Z6, D3): the BOOTTIME-MONOTONIC divergence sampled in the same
/// breath as the pre offset - the kernel's own suspend accounting.
/// The renderer samples the gap again at render time; a material
/// delta is the span the host spent ASLEEP inside the window, the
/// proof of absence the Unaccounted block names (no event can exist
/// in a span the stamps' clock did not run through). `None` rides
/// when the clocks were unreadable at the start - the honest
/// absence, never a guessed zero.
/// One live file window's PRE breath (night-frontier-Z10, D7 grew
/// the shape from the Z2 tuple): the four measurements of ONE
/// instant - the wall offset the civil times ride, the BOOTTIME
/// gap the sleep truth pairs against, the CLOCK_MONOTONIC stamp the
/// watch truth compares the attach instant against, and the active
/// clocksource regime the stamps' precision rides. One breath, one
/// instant, four readings - the render breath re-pairs them all.
pub struct PreBreath {
    /// The wall offset at the window's open (night-frontier-Z2).
    pub offset: Option<i128>,
    /// The BOOTTIME-MONOTONIC gap at the window's open
    /// (night-frontier-Z6, D3).
    pub gap: Option<i128>,
    /// The CLOCK_MONOTONIC stamp of the window's open - the anchor
    /// the watch-truth compare rides (night-frontier-Z10, D7).
    pub monotonic_ns: Option<u64>,
    /// The kernel's active clocksource regime at the window's open
    /// (night-frontier-Z10, D7).
    pub clocksource: Option<String>,
}

/// One live file window's capture: the selected events and the PRE
/// breath (the four one-instant readings above).
pub struct FileWindowCapture {
    pub events: Vec<FileEvent>,
    pub pre: PreBreath,
}

pub fn capture_file_window(
    inode: u64,
    device: u64,
    window: Duration,
) -> Result<FileWindowCapture, String> {
    track_file(inode, device)?;
    // The pre sample: after the key is in (the window is about to
    // open) and before the wait - the earliest instant the capture's
    // own span can name. Four readings of one instant, each paired
    // with its own re-read at render time (the Z2/Z6 pairing shape;
    // the monotonic stamp and the clocksource regime are Z10's).
    let pre = PreBreath {
        offset: crate::info::clock::wall_offset_ns(),
        gap: crate::info::clock::boottime_gap_ns(),
        monotonic_ns: crate::info::clock::monotonic_now_ns(),
        clocksource: crate::info::clock::current_clocksource(),
    };
    // The collection: the kprobes are live against the filter map
    // for exactly this long. std sleep, no reader thread — the ring
    // keeps the history and one drain takes it. The wait is
    // narrated (night-hunter-6): a grey countdown on stderr, the
    // ledger's stdout untouched.
    crate::output::spinner::wait(window, "watching for events");
    untrack_file(inode, device)?;
    let drained = ringbuf::drain_file_events()?;
    Ok(FileWindowCapture {
        events: select_window(&drained, inode, device),
        pre,
    })
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
    // night-depth-hardening-1: the timestamp alone leaves ties (two
    // syscalls stamped in the same nanosecond, per-CPU ring
    // interleave) to drain order - not byte-stable across runs. The
    // tail is a total order over the record's own fields (op, then
    // the full inode/device identity, then the actor).
    selected.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then(left.op.cmp(&right.op))
            .then(left.inode.cmp(&right.inode))
            .then(left.device.cmp(&right.device))
            .then(left.pid.cmp(&right.pid))
    });
    selected
}

/// The offset-threaded form (night-frontier-Z2, the
/// one-offset-per-render-breath law): every row of a report renders
/// under the ONE offset its renderer sampled at its start, so a wall
/// clock step between two rows' reads can never make the rows
/// disagree. Same arithmetic as [`event_unix_secs`], same `None`
/// honesty.
pub fn event_unix_secs_with(event: &FileEvent, offset: Option<i128>) -> Option<i64> {
    let offset = offset?;
    let nanos = event.timestamp_ns as i128 + offset;
    if nanos.is_negative() {
        return None;
    }
    Some((nanos / 1_000_000_000) as i64)
}

#[cfg(test)]
#[path = "../../test/ebpf/fileprobe_tests.rs"]
mod tests;
