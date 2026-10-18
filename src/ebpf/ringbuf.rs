// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The ring readers (night-improve-2 opens the first, night-improve-3
//! the second; feature builds only): the event-window pumps. std +
//! aya, nothing else — no thread, no poll loop, no daemon. The pump
//! runs for exactly one drain: open the pinned ring, read every
//! record the kernel holds, hand back a bounded Vec. The
//! kernel-side filter already bounded what crosses each ring (the
//! port-surface transitions in sock_events; the tracked inodes in
//! file_events); the rolling cap here bounds the Vec even if a ring
//! holds more history than the window wants.
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
use super::PIN_MAP_SOCK_EVENTS;
use super::events::{FILE_EVENT_BYTES, FileEvent, SOCK_EVENT_BYTES, SockEvent};

/// The rolling cap: the pump never hands back more than this many
/// events, newest kept, oldest dropped. 4096 records is half the
/// sock ring's 8192-record capacity — a window-shaped bound, not a
/// log-shaped one. The file ring holds 6553 40-byte records at the
/// same 256 KiB; the same cap bounds both.
pub const ROLLING_CAP: usize = 4096;

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

/// Drain every record the pinned sock_events ring holds (the port
/// surface's window) into a bounded, rolling Vec (capacity
/// [`ROLLING_CAP`], newest kept). Errors name the pin path — a
/// missing pin reads as a diagnosis, not a generic failure. A record
/// whose length is not exactly [`SOCK_EVENT_BYTES`] is skipped,
/// never failed: a passive reader never fails the window.
pub fn drain_sock_events() -> Result<Vec<SockEvent>, String> {
    let map_data = MapData::from_pin(PIN_MAP_SOCK_EVENTS)
        .map_err(|e| format!("pinned sock_events map {PIN_MAP_SOCK_EVENTS}: {e}"))?;
    let owned = Map::RingBuf(map_data);
    let mut ring = RingBuf::try_from(owned)
        .map_err(|e| format!("the pinned sock_events map is not a ring buffer: {e}"))?;

    let mut window: Vec<SockEvent> = Vec::new();
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
        push_rolling(&mut window, event, ROLLING_CAP);
    }
    Ok(window)
}

/// Drain every record the pinned file_events ring holds (the
/// Evidence Ledger's window) into a bounded, rolling Vec. The same
/// contract as [`drain_sock_events`], record for record.
pub fn drain_file_events() -> Result<Vec<FileEvent>, String> {
    let map_data = MapData::from_pin(PIN_MAP_FILE_EVENTS)
        .map_err(|e| format!("pinned file_events map {PIN_MAP_FILE_EVENTS}: {e}"))?;
    let owned = Map::RingBuf(map_data);
    let mut ring = RingBuf::try_from(owned)
        .map_err(|e| format!("the pinned file_events map is not a ring buffer: {e}"))?;

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

#[cfg(test)]
#[path = "../../test/ebpf/ringbuf_tests.rs"]
mod tests;
