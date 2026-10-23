// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The ring readers (night-improve-2 opens the first, night-improve-3
//! the second, night-improve-47 the third; feature builds only): the
//! event-window pumps. std +
//! aya, nothing else — no thread, no poll loop, no daemon. The pump
//! runs for exactly one command: open the pinned ring, read the
//! records the kernel holds, hand back a bounded Vec (or feed one
//! across a whole wait, slice by slice). The kernel-side filters
//! already bound what crosses each ring (the port-surface transitions
//! in sock_events; the tracked inodes in file_events; the leader
//! check in proc_events); the rolling
//! cap here bounds the Vec even if a ring holds more history than
//! the window wants. (night-improve-34 removed the old lifecycle
//! pump with the lifecycle stream surface; night-improve-47 opens
//! the third reader as the post-mortem exit pump - a different
//! shape: the doctor drains once, filters to its window, prints,
//! and exits.)
//!
//! One semantic the caller must know (and the CHANGELOG names): a
//! ring buffer read CONSUMES. Advancing the reader advances the
//! consumer position the kernel keeps in the map itself, so each
//! drain sees the events accumulated since the previous drain (or
//! since attach, for the first). No daemon means no persistent
//! reader — that is the honest shape of a command-lifetime pump, and
//! each ring's own 256 KiB bounds what can accumulate between drains.
//!
//! The record length is checked before every parse (a short record
//! is skipped, never failed — the zylaxion bridge discipline), and
//! the parse itself is the one unavoidable pod-cast: the bytes in
//! each ring are a repr(C) record by contract (src/ebpf/events.rs,
//! pinned by test), written by the kernel side's `output` call.

use aya::maps::{Map, MapData, RingBuf};

use super::PIN_MAP_FILE_EVENTS;
use super::PIN_MAP_PROC_EVENTS;
use super::PIN_MAP_SOCK_EVENTS;
use super::events::{
    FILE_EVENT_BYTES, FileEvent, PROCEXIT_EVENT_BYTES, ProcExitEvent, SOCK_EVENT_BYTES, SockEvent,
};

/// The rolling cap: the pump never hands back more than this many
/// events, newest kept, oldest dropped. 4096 records is half the
/// sock ring's 8192-record capacity — a window-shaped bound, not a
/// log-shaped one. The file ring holds 6553 40-byte records at the
/// same 256 KiB; the same cap bounds both.
pub const ROLLING_CAP: usize = 4096;

/// Open one pinned ring buffer by its pin path. The shared half of
/// every drain: the map is opened through its pin (a missing pin is
/// a diagnosis, never a generic failure) and converted to a live
/// consumer. Reopening is safe across runs - the consumer position
/// lives in the kernel map itself, so each drain continues where the
/// previous one stopped (that is why a run shows the events since
/// the previous drain, or since attach for the first).
pub fn open_ring(pin: &str, label: &str) -> Result<RingBuf<MapData>, String> {
    let map_data = MapData::from_pin(pin).map_err(|e| {
        let base = format!("pinned {label} map {pin}: {e}");
        if super::pin_access_denied(&e) {
            // The ladder's degrade marker (night-hunter-5): the same
            // classification the tracked_inodes writer carries - a
            // permission refusal at the open is an unavailability,
            // not a command death.
            format!("{}: {base}", super::PIN_ACCESS_DENIED)
        } else {
            base
        }
    })?;
    RingBuf::try_from(Map::RingBuf(map_data))
        .map_err(|e| format!("the pinned {label} map is not a ring buffer: {e}"))
}

/// The sock_events ring, opened: the port surface's window-shaped
/// capture (night-improve-4) holds one ring for the whole wait and
/// drains it slice by slice.
pub fn open_sock_ring() -> Result<RingBuf<MapData>, String> {
    open_ring(PIN_MAP_SOCK_EVENTS, "sock_events")
}

/// Push one event into the rolling window: newest kept, oldest
/// dropped when the cap is full. Generic over the record type so
/// both rings share the one rolling discipline; separated from the
/// drains so the rolling behavior is pinnable with a synthetic Vec,
/// no ring required.
pub fn push_rolling<T>(window: &mut Vec<T>, event: T, cap: usize) {
    if window.len() == cap {
        window.remove(0);
    }
    window.push(event);
}

/// Drain the records currently available on an OPEN sock_events ring
/// into a rolling Vec, without reopening the map. The window-shaped
/// half (night-improve-4): a caller that collects over a duration
/// keeps one ring open and drains it slice by slice — the consumer
/// position advances with every call, so the Vec accumulates exactly
/// what crossed while the caller waited, and the rolling cap bounds
/// the Vec no matter how long the wait. The one-shot shape this
/// function replaced (open, drain once, drop) died with Fix 2: the
/// port window now collects over its duration, so every caller keeps
/// the ring for the whole wait.
pub fn drain_sock_events_from(ring: &mut RingBuf<MapData>, out: &mut Vec<SockEvent>) {
    while let Some(record) = ring.next() {
        if record.len() != SOCK_EVENT_BYTES {
            continue;
        }
        // The pod-cast: the bytes are a repr(C) SockEvent by the
        // contract both sides compile from one file, and the length
        // check above is the bounds proof. Reading a u64-aligned
        // struct from a byte slice the kernel wrote is the one
        // unsafe step aya's API leaves to the caller.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const SockEvent) };
        push_rolling(out, event, ROLLING_CAP);
    }
}

/// Drain every record the pinned file_events ring holds (the
/// Evidence Ledger's window) into a bounded, rolling Vec. The same
/// contract as [`drain_sock_events_from`], record for record.
pub fn drain_file_events() -> Result<Vec<FileEvent>, String> {
    let mut ring = open_ring(PIN_MAP_FILE_EVENTS, "file_events")?;
    let mut window: Vec<FileEvent> = Vec::new();
    while let Some(record) = ring.next() {
        if record.len() != FILE_EVENT_BYTES {
            continue;
        }
        // The pod-cast, the file record's turn: the same
        // contract-and-bounds proof as the sock reader's.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const FileEvent) };
        push_rolling(&mut window, event, ROLLING_CAP);
    }
    Ok(window)
}

/// Drain every record the pinned proc_events ring holds (the
/// post-mortem exit stream, night-improve-47) into a bounded,
/// rolling Vec. The same contract as [`drain_file_events`], record
/// for record; the caller owns the window cutoff - the doctor keeps
/// the last five seconds and the read consumes, the Lazy Camera
/// contract unchanged (docs/EBPF_LIFECYCLE.md).
pub fn drain_proc_exits() -> Result<Vec<ProcExitEvent>, String> {
    let mut ring = open_ring(PIN_MAP_PROC_EVENTS, "proc_events")?;
    let mut window: Vec<ProcExitEvent> = Vec::new();
    while let Some(record) = ring.next() {
        if record.len() != PROCEXIT_EVENT_BYTES {
            continue;
        }
        // The pod-cast, the exit record's turn: the same
        // contract-and-bounds proof as the file reader's.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const ProcExitEvent) };
        push_rolling(&mut window, event, ROLLING_CAP);
    }
    Ok(window)
}

#[cfg(test)]
#[path = "../../test/ebpf/ringbuf_tests.rs"]
mod tests;
