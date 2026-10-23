// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The tracked_inodes writer (night-improve-3, feature builds only):
//! the command-lifetime half of the filter contract. A command that
//! wants a live window inserts the queried file's key
//! ((inode << 32) | device - the same packing the kprobes check)
//! before its window starts and removes it when the window ends, so
//! the kernel-side filter passes exactly the queried file's events
//! and nothing else's. No daemon: each call opens the pin, does one
//! operation, and lets go - the same from-pin discipline the
//! readback and the ring readers use.
//!
//! The lifecycle is the caller's discipline: track at window start,
//! untrack at window end, and untrack on every error path after a
//! successful track (the fail protocol). An interrupted command (a
//! SIGKILL mid-window) can leave a stale key; the map's 1024-entry
//! bound caps the leak, the events a stale key lets through only
//! waste ring space (the host drops any event whose full identity
//! does not match the query), and the whole map dies at the next
//! `doctor --detach` - the honest cleanup, named here.
//!
//! The two functions repeat the open-map-do dance on purpose: a
//! shared closure helper would have to name aya's inference-heavy
//! `HashMap<&mut MapData, _>` shape at every call site - eight
//! duplicated lines beat a generic that fights the reader.

use aya::maps::{HashMap, Map, MapData};

use super::PIN_MAP_TRACKED_INODES;
use super::events::pack_filter_key;

/// Insert the key for one file: presence in the map is the whole
/// meaning (the value is always 1; the kprobes never read it).
pub fn track_file(inode: u64, device: u64) -> Result<(), String> {
    let key = pack_filter_key(inode, device);
    let map_data = MapData::from_pin(PIN_MAP_TRACKED_INODES).map_err(|e| {
        format!(
            "cannot track inode {inode:#x}: pinned tracked_inodes map \
             {PIN_MAP_TRACKED_INODES}: {e} (is the probes attached? see zejtron doctor [eBPF])"
        )
    })?;
    let mut owned = Map::HashMap(map_data);
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(&mut owned)
        .map_err(|e| format!("the pinned tracked_inodes map is not a hash map: {e}"))?;
    map.insert(key, 1u8, 0)
        .map_err(|e| format!("the tracked_inodes insert failed: {e}"))
}

/// Remove the key for one file. Removing an absent key is a success
/// (idempotence - an untrack that races a detach is fine).
pub fn untrack_file(inode: u64, device: u64) -> Result<(), String> {
    let key = pack_filter_key(inode, device);
    let map_data = MapData::from_pin(PIN_MAP_TRACKED_INODES).map_err(|e| {
        format!(
            "cannot untrack inode {inode:#x}: pinned tracked_inodes map \
             {PIN_MAP_TRACKED_INODES}: {e} (is the probes attached? see zejtron doctor [eBPF])"
        )
    })?;
    let mut owned = Map::HashMap(map_data);
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(&mut owned)
        .map_err(|e| format!("the pinned tracked_inodes map is not a hash map: {e}"))?;
    map.remove(&key)
        .map_err(|e| format!("the tracked_inodes remove failed: {e}"))
}

#[cfg(test)]
#[path = "../../test/ebpf/tracked_tests.rs"]
mod tests;
