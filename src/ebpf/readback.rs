// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The counter readback (night-improve-1, feature builds only): the
//! last link of the chain. The kernel increments stats\[0\] on every
//! sched_process_exec; this module reads the number back out through
//! the pin - the same `MapData::from_pin` lane the zelynic lineage
//! proved on the owner host. No bpf() syscall is hand-rolled and no
//! capability is needed on the read side: a pinned map opens by path,
//! like any file, which is exactly why the map is pinned.
//!
//! The read is the proof the whole pass exists for: a number that
//! only the kernel could have written, arriving in userspace through
//! a path only the kernel could have planted. `doctor` renders it in
//! the \[eBPF\] section's Lane row; `doctor --attach` prints it right
//! after planting (the fresh N=0 shape).
//!
//! The attach moment rides the stats pin's own mtime: bpffs stamps a
//! pin at creation and nothing rewrites it afterward (a pin is never
//! written, only linked and unlinked), so the map pin's mtime IS the
//! attach moment, at the granularity the filesystem keeps. When the
//! filesystem reports no timestamp the moment degrades to "unknown"
//! - an absent fact stays absent, it is never guessed.

use std::time::SystemTime;

use aya::maps::{Array, Map, MapData};

use super::PIN_MAP_STATS;

/// The stats slot this module reads: stats\[0\], the count of
/// sched_process_exec events since attach. The index contract with
/// the kernel side (ebpf/src/main.rs's STATS_EVENTS) - both sides
/// keep the same slot in lockstep.
const STATS_EVENTS: u32 = 0;

/// Read the events counter through the pin: stats\[STATS_EVENTS\] as
/// the kernel holds it right now. Errors name the pin path (a missing
/// pin reads as a diagnosis, not a generic failure).
pub fn read_events_counter() -> Result<u64, String> {
    let map_data = MapData::from_pin(PIN_MAP_STATS)
        .map_err(|e| format!("pinned stats map {PIN_MAP_STATS}: {e}"))?;
    let map = Map::Array(map_data);
    let counter: Array<_, u64> = Array::try_from(&map)
        .map_err(|e| format!("the pinned stats map is not an array map: {e}"))?;
    let key: u32 = STATS_EVENTS;
    counter
        .get(&key, 0)
        .map_err(|e| format!("stats[{STATS_EVENTS}] read failed: {e}"))
}

/// The attach moment: the stats pin's mtime (creation time - a pin is
/// planted once and never rewritten). `None` when the pin is absent
/// or the filesystem reports no timestamp; the honest degradation,
/// never a guess.
pub fn attach_moment() -> Option<SystemTime> {
    std::fs::metadata(PIN_MAP_STATS)
        .ok()
        .and_then(|m| m.modified().ok())
}

#[cfg(test)]
#[path = "../../test/ebpf/readback_tests.rs"]
mod tests;
