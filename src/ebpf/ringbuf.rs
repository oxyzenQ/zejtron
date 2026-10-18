// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The sock_events ring reader (night-improve-2, feature builds
//! only): the port surface's window pump. std + aya, nothing else -
//! no thread, no poll loop, no daemon. The pump runs for exactly one
//! drain: open the pinned ring, read every record the kernel holds,
//! hand back a bounded Vec. The kernel-side filter already bounded
//! what crosses the ring (LISTEN enter/leave and UDP close only);
//! the rolling cap here bounds the Vec even if the ring holds more
//! history than the window wants.
//!
//! One semantic the caller must know (and the CHANGELOG names): a
//! ring buffer read CONSUMES. Advancing the reader advances the
//! consumer position the kernel keeps in the map itself, so each
//! `port` shows the events accumulated since the previous drain (or
//! since attach, for the first). No daemon means no persistent
//! reader - that is the honest shape of a command-lifetime pump, and
//! the ring's own 256 KiB bounds what can accumulate between drains.
//!
//! The record length is checked before every parse (a short record
//! is skipped, never failed - the zylaxion bridge discipline), and
//! the parse itself is the one unavoidable pod-cast: the bytes in
//! the ring are a repr(C) SockEvent by contract (src/ebpf/events.rs,
//! pinned by test), written by the kernel side's `output` call.

use aya::maps::{Map, MapData, RingBuf};

use super::PIN_MAP_SOCK_EVENTS;
use super::events::{SOCK_EVENT_BYTES, SockEvent};

/// The rolling cap: the pump never hands back more than this many
/// events, newest kept, oldest dropped. 4096 records is half the
/// ring's 8192-record capacity - a window-shaped bound, not a
/// log-shaped one.
pub const ROLLING_CAP: usize = 4096;

/// Push one event into the rolling window: newest kept, oldest
/// dropped when the cap is full. Separated from the drain so the
/// rolling behavior is pinnable with a synthetic Vec, no ring
/// required.
pub fn push_rolling(window: &mut Vec<SockEvent>, event: SockEvent, cap: usize) {
    if window.len() == cap {
        window.remove(0);
    }
    window.push(event);
}

/// Drain every record the pinned ring holds into a bounded, rolling
/// Vec (capacity [`ROLLING_CAP`], newest kept). Errors name the pin
/// path - a missing pin reads as a diagnosis, not a generic failure.
/// A record whose length is not exactly [`SOCK_EVENT_BYTES`] is
/// skipped, never failed: a passive reader never fails the window.
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

#[cfg(test)]
#[path = "../../test/ebpf/ringbuf_tests.rs"]
mod tests;
