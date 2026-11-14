// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The memory ledger's boundary-line builders (night-frontier-Z2
//! moved them here - a PURE move under the 600-LOC cap, the
//! lane_unaccounted sibling precedent): the exit ring's drop-truth
//! line and the wall-clock skew line the ram Unaccounted block
//! renders. One module, one concern - the count-backed and
//! state-backed boundary lines - so the block's additive lines live
//! beside each other, not beside the section renderers.

use crate::output::noun_for;

/// The exit ring's drop-truth line (night-frontier-Z1): one
/// count-backed boundary line, `None` when the count is zero - the
/// boundary exists only when it fired. Pure, so the wording and the
/// threshold are pinnable without a pinned map (the lane's
/// file_ring_drop_entry precedent).
pub(crate) fn ring_drop_line(drops: u64) -> Option<String> {
    (drops > 0).then(|| {
        format!(
            "  {} {}",
            drops,
            crate::output::grey_out(&format!(
                "{} on the proc_events ring since attach - exits the camera \
                 saw but the ring could not hold; the window above may be \
                 missing exits the same way",
                noun_for(drops as usize, "ring drop", "ring drops")
            ))
        )
    })
}

/// The wall-clock skew line (night-frontier-Z2): one boundary line
/// for a wall clock that demonstrably moved between the collection
/// and the render, the signed movement named and the rows' exposure
/// said. The count-backed zero class does not apply: the movement
/// HAPPENED (the compare already gated it at the half-second bound),
/// so the line always renders. Pure, pinnable without two live
/// clock reads.
pub(crate) fn wall_skew_line(skew_ns: i128) -> Option<String> {
    Some(format!(
        "  {}{}",
        format_args!("{skew_ns:+} ns"),
        crate::output::grey_out(
            " of wall-clock skew measured since the exit collection began \
             (beyond the 500 ms bound) - the exit times above render under the \
             post-collection offset and can sit that far from the times the \
             exits happened at"
        )
    ))
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_boundary_tests.rs"]
mod tests;
