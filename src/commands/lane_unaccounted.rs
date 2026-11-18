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

/// The sleep blackout entry (night-frontier-Z6, D3): the proof of
/// absence a moving BOOTTIME-MONOTONIC gap carries. A POSITIVE delta
/// is the blackout arm - the span the host spent asleep inside this
/// capture, where no event can exist because the stamps' clock does
/// not run there: the hole becomes evidence instead of an unexplained
/// gap. A NEGATIVE delta is the anomaly arm - the clock pairing
/// itself moved backwards (a paravirt resync), so the pairing cannot
/// measure a sleep honestly and the withheld measurement is named
/// instead of trusted. Pure, so the wording and the two arms are
/// pinnable without a live suspend.
pub(crate) fn sleep_blackout_entry(sleep_delta_ns: i128) -> UnaccountedEntry {
    if sleep_delta_ns > 0 {
        let span = crate::info::clock::format_sleep_span(sleep_delta_ns);
        UnaccountedEntry::new(
            1,
            "sleep blackout",
            format!(
                "the host spent {span} asleep inside this capture - \
                 CLOCK_BOOTTIME diverged from the stamps' CLOCK_MONOTONIC \
                 by the same span, and the stamps' clock does not run \
                 while the host sleeps: no event can exist in that span, \
                 and the rows above are the only evidence this window \
                 could have"
            ),
        )
    } else {
        let span = crate::info::clock::format_sleep_span(-sleep_delta_ns);
        UnaccountedEntry::new(
            1,
            "sleep clock anomaly",
            format!(
                "the sleep measurement moved backwards by {span} across \
                 this capture - the BOOTTIME-MONOTONIC pairing itself is \
                 untrustworthy here (a paravirt clock resync), so any \
                 blackout report for this window is withheld rather \
                 than guessed"
            ),
        )
    }
}

#[cfg(test)]
#[path = "../../test/commands/lane_unaccounted_tests.rs"]
mod tests;
