// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The tracked_inodes writer (night-improve-3):
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
//! A map that HAS filled refuses new questions (night-frontier-Z5,
//! the question census): the kernel answers E2BIG, the writer counts
//! the refusal in the pinned stats map's question-census slot, and
//! the error names the camera, the cumulative count, and the remedy -
//! the question map obeys the census law like every bounded resource
//! the camera owns: its refusals are counted, never silent. The
//! census dies with the map at the next detach (the whole estate
//! does), so the counts are comparable only within one attach
//! session.
//!
//! The two functions repeat the open-map-do dance on purpose: a
//! shared closure helper would have to name aya's inference-heavy
//! `HashMap<&mut MapData, _>` shape at every call site - eight
//! duplicated lines beat a generic that fights the reader.

use aya::maps::{HashMap, Map, MapData, MapError};

use super::PIN_MAP_TRACKED_INODES;
use super::events::pack_filter_key;

/// The kernel's own refusal shape for a full hash map: BPF_MAP_UPDATE
/// _ELEM answers E2BIG once max_entries are live. Pure, so the
/// classification is pinnable without a pinned map - and so a
/// permission refusal (EPERM at the syscall) can never be mistaken
/// for a capacity refusal: the census counts only questions the
/// kernel refused for CAPACITY, never for access.
fn is_map_full_error(error: &MapError) -> bool {
    let errno = match error {
        MapError::SyscallError(syscall) => syscall.io_error.raw_os_error(),
        MapError::IoError(err) => err.raw_os_error(),
        _ => None,
    };
    errno == Some(libc::E2BIG)
}

/// The refusal message for a question the camera could not take
/// (night-frontier-Z5, the question census): the cause, the camera's
/// own count, and the remedy - refusal-with-a-name, the shape every
/// camera boundary carries. `census` is `Ok(count)` when the bump
/// landed (the count INCLUDES this refusal) and `Err(reason)` when
/// the census is unreadable on this camera (a missing pin, an older
/// estate) - the message degrades honestly, naming why, and never
/// invents the number. Pure, so the wording is pinnable without a
/// pinned map.
fn refused_question_error(insert_error: &MapError, census: Result<u64, String>) -> String {
    let counted = match census {
        Ok(count) => format!("{count} refused since attach, this one included; "),
        Err(reason) => format!("the question census is unreadable on this camera ({reason}); "),
    };
    format!(
        "the camera refused this question: its question map has no capacity \
         left (the tracked_inodes insert failed: {insert_error}); {counted}\
         stale questions from killed commands clear at the next doctor --detach"
    )
}

/// Insert the key for one file: presence in the map is the whole
/// meaning (the value is always 1; the kprobes never read it).
pub fn track_file(inode: u64, device: u64) -> Result<(), String> {
    let key = pack_filter_key(inode, device);
    let map_data = MapData::from_pin(PIN_MAP_TRACKED_INODES).map_err(|e| {
        let base = format!("pinned tracked_inodes map {PIN_MAP_TRACKED_INODES}: {e}");
        if super::pin_access_denied(&e) {
            // The ladder's degrade marker (night-hunter-5): a
            // permission refusal at the open is an unavailability the
            // caller can step down from, not a command death.
            format!("{}: {base}", super::PIN_ACCESS_DENIED)
        } else {
            format!(
                "cannot track inode {inode:#x}: {base} \
                 (is the probes attached? see zejtron doctor [eBPF])"
            )
        }
    })?;
    let mut owned = Map::HashMap(map_data);
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(&mut owned)
        .map_err(|e| format!("the pinned tracked_inodes map is not a hash map: {e}"))?;
    map.insert(&key, &1u8, 0).map_err(|error| {
        if is_map_full_error(&error) {
            // night-frontier-Z5: the census lands BEFORE the message
            // reads it, so the count includes this refusal. The bump
            // is best-effort: a census failure degrades the message
            // (the count section names why), never masks the insert
            // error.
            let census = super::readback::count_question_refusal();
            refused_question_error(&error, census)
        } else {
            format!("the tracked_inodes insert failed: {error}")
        }
    })
}

/// Remove the key for one file. Removing an absent key is a success
/// (idempotence - an untrack that races a detach is fine).
pub fn untrack_file(inode: u64, device: u64) -> Result<(), String> {
    let key = pack_filter_key(inode, device);
    let map_data = MapData::from_pin(PIN_MAP_TRACKED_INODES).map_err(|e| {
        let base = format!("pinned tracked_inodes map {PIN_MAP_TRACKED_INODES}: {e}");
        if super::pin_access_denied(&e) {
            // The ladder's degrade marker (night-hunter-5): the same
            // classification track_file carries.
            format!("{}: {base}", super::PIN_ACCESS_DENIED)
        } else {
            format!(
                "cannot untrack inode {inode:#x}: {base} \
                 (is the probes attached? see zejtron doctor [eBPF])"
            )
        }
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
