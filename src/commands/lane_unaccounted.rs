// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The live lane's Unaccounted entry builders (night-frontier-Z2
//! moved them here - a PURE move under the 600-LOC cap, the
//! json/gpu.rs sibling precedent): the count-backed drop-truth entry
//! and the state-backed wall-clock skew entry the evidence ledgers
//! (holds, touch, why) render. One module, one concern - the
//! boundaries the live lane names - so the ledger grammar's additive
//! entries live beside each other, not beside the row loop.

use crate::evidence::UnaccountedEntry;

/// The file ring's drop-truth entry (night-frontier-Z1): one
/// Unaccounted entry for the file_events reserve failures, `None`
/// when the count is zero (the count-backed boundary class - an
/// entry that says "0 drops" on every run would read as noise, and
/// the boundary exists only when it fired). Pure, so the wording and
/// the threshold are pinnable without a pinned map.
pub(crate) fn file_ring_drop_entry(drops: u64) -> Option<UnaccountedEntry> {
    (drops > 0).then(|| {
        UnaccountedEntry::new(
            drops as usize,
            "ring drops",
            "file_events reserve failures since attach - events the kernel \
             saw but the ring could not hold; the window above may be \
             missing records the same way",
        )
    })
}

/// The wall-clock skew entry (night-frontier-Z2): one Unaccounted
/// entry for a wall-clock movement measured across the capture
/// (beyond the half-second bound), the signed movement named and the
/// rows' exposure said plainly. Pure, so the wording and the shape
/// are pinnable without two live clock reads.
pub(crate) fn wall_skew_entry(skew_ns: i128) -> UnaccountedEntry {
    UnaccountedEntry::new(
        1,
        "wall clock skew",
        format!(
            "the wall clock moved {skew_ns:+} ns across this capture \
             (beyond the 500 ms bound) - the civil times above render \
             under the post-capture offset and can sit that far from \
             the times the events happened at"
        ),
    )
}

#[cfg(test)]
#[path = "../../test/commands/lane_unaccounted_tests.rs"]
mod tests;
