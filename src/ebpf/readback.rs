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

use super::events::{
    OFF_SLOT_FDT_FD, OFF_SLOT_FDT_MAX_FDS, OFF_SLOT_FILES_FDT, OFF_SLOT_TASK_FILES,
};
use super::{PIN_MAP_OFFSETS, PIN_MAP_STATS};

/// The stats slots this module reads. The index contract with the
/// kernel side (ebpf/src/main.rs's STATS_EVENTS, STATS_ZJW_DROPS,
/// STATS_ZJW_WALKED, STATS_ZJW_STAGE_BASE, STATS_ZJW_STAGE_COUNT) -
/// both sides keep the slots in lockstep.
const STATS_EVENTS: u32 = 0;
const STATS_ZJW_DROPS: u32 = 1;
const STATS_ZJW_WALKED: u32 = 2;
const STATS_ZJW_STAGE_BASE: u32 = 3;
const STATS_ZJW_STAGE_COUNT: u32 = 14;

/// Read one stats slot through the pin: the same `MapData::from_pin`
/// lane the events counter rides - a pinned map opens by path, like
/// any file, which is exactly why the map is pinned.
fn read_stats_slot(slot: u32) -> Result<u64, String> {
    let map_data = MapData::from_pin(PIN_MAP_STATS)
        .map_err(|e| format!("pinned stats map {PIN_MAP_STATS}: {e}"))?;
    let map = Map::Array(map_data);
    let counter: Array<_, u64> = Array::try_from(&map)
        .map_err(|e| format!("the pinned stats map is not an array map: {e}"))?;
    counter
        .get(&slot, 0)
        .map_err(|e| format!("stats[{slot}] read failed: {e}"))
}

/// Read the events counter through the pin: stats[STATS_EVENTS] as
/// the kernel holds it right now. Errors name the pin path (a missing
/// pin reads as a diagnosis, not a generic failure).
pub fn read_events_counter() -> Result<u64, String> {
    read_stats_slot(STATS_EVENTS)
}

/// The write probe's kernel-side drop census (night-hunter-2): the
/// counters the pinned stats map carries for the fd-walk instrument.
pub struct WriteCensus {
    /// Total drops across every stage.
    pub drops: u64,
    /// Walks that crossed every hop (published, or missed the filter).
    pub walked: u64,
    /// The furthest stage that dropped - the blocker hop - with its
    /// own drop count. `None` when no stage slot is nonzero.
    pub furthest: Option<(u64, u64)>,
}

/// The furthest census stage with a nonzero count: the highest stage
/// number whose per-stage counter survived. Pure so the lockstep
/// derivation is testable without a pinned map.
fn furthest_stage(counts: &[u64; STATS_ZJW_STAGE_COUNT as usize]) -> Option<(u64, u64)> {
    (1..=STATS_ZJW_STAGE_COUNT)
        .rev()
        .map(|stage| (u64::from(stage), counts[(stage - 1) as usize]))
        .find(|(_, count)| *count > 0)
}

/// Read the write probe's drop census through the pin: the totals and
/// the furthest drop stage (the exact hop a silent verification died
/// at, instead of a mute refusal).
pub fn read_write_census() -> Result<WriteCensus, String> {
    let map_data = MapData::from_pin(PIN_MAP_STATS)
        .map_err(|e| format!("pinned stats map {PIN_MAP_STATS}: {e}"))?;
    let map = Map::Array(map_data);
    let stats: Array<_, u64> = Array::try_from(&map)
        .map_err(|e| format!("the pinned stats map is not an array map: {e}"))?;
    let slot = |index: u32| -> Result<u64, String> {
        stats
            .get(&index, 0)
            .map_err(|e| format!("stats[{index}] read failed: {e}"))
    };
    let drops = slot(STATS_ZJW_DROPS)?;
    let walked = slot(STATS_ZJW_WALKED)?;
    let mut counts = [0u64; STATS_ZJW_STAGE_COUNT as usize];
    for stage in 1..=STATS_ZJW_STAGE_COUNT {
        counts[(stage - 1) as usize] = slot(STATS_ZJW_STAGE_BASE + stage - 1)?;
    }
    Ok(WriteCensus {
        drops,
        walked,
        furthest: furthest_stage(&counts),
    })
}

/// The four fd-walk offsets exactly as the pinned offsets map holds
/// them right now (slots 8..11, the OFF_SLOT_* contract in
/// events.rs): the planted facts a failed write verification echoes
/// beside its census, so a slot the map never carried (the
/// night-hunter-3 plant bug: the fd-walk slots were never written)
/// is visible in the refusal itself, never guessed at. The same
/// `MapData::from_pin` lane as every readback - a pinned map opens
/// by path, no capability needed. Order: [files, fdt, max_fds, fd],
/// the walk order the probe rides.
pub fn read_fd_walk_offsets() -> Result<[u64; 4], String> {
    let map_data = MapData::from_pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("pinned offsets map {PIN_MAP_OFFSETS}: {e}"))?;
    let map = Map::Array(map_data);
    let offsets: Array<_, u64> = Array::try_from(&map)
        .map_err(|e| format!("the pinned offsets map is not an array map: {e}"))?;
    let slot = |index: u32| -> Result<u64, String> {
        offsets
            .get(&index, 0)
            .map_err(|e| format!("offsets[{index}] read failed: {e}"))
    };
    Ok([
        slot(OFF_SLOT_TASK_FILES)?,
        slot(OFF_SLOT_FILES_FDT)?,
        slot(OFF_SLOT_FDT_MAX_FDS)?,
        slot(OFF_SLOT_FDT_FD)?,
    ])
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
