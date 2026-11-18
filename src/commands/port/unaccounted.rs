// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The port event section's Unaccounted line builders (night-frontier-
//! Z6 moved them here - a PURE move of night-frontier-Z1's
//! ring-drop line and Z2's wall-skew line out of events.rs under the
//! 600-LOC cap, the lane_unaccounted.rs sibling precedent), plus the
//! sleep blackout line the third clock's law adds (D3). One module,
//! one concern - the boundaries the port window names - so the
//! section grammar's additive lines live beside each other, not
//! beside the row loop.

/// The wall-clock skew line (night-frontier-Z2): one grey row for a
/// wall clock that demonstrably moved across the capture, the signed
/// movement named and the rows' exposure said. The count-backed zero
/// class does not apply: the movement HAPPENED (the compare already
/// gated it at the half-second bound), so the line always renders.
/// Pure, pinnable without two live clock reads.
pub(crate) fn wall_skew_line(skew_ns: i128) -> String {
    format!(
        "{}{skew_ns:+}{}",
        crate::output::grey_out("  "),
        crate::output::grey_out(
            " ns of wall-clock skew measured across this capture (beyond the\n  500 ms bound) - the times above render under the post-capture offset and\n  can sit that far from the times the events happened at"
        )
    )
}

/// The sock ring's drop-truth line (night-frontier-Z1): one grey
/// row for the reserve failures, `None` when the count is zero (the
/// count-backed boundary class - the boundary exists only when it
/// fired). Pure, so the wording and the threshold are pinnable
/// without a pinned map (the lane.rs file_ring_drop_entry
/// precedent).
pub(crate) fn ring_drop_line(drops: u64) -> Option<String> {
    (drops > 0).then(|| {
        format!(
            "{}{drops}{}",
            crate::output::grey_out("  "),
            crate::output::grey_out(
                " sock_events ring drops since attach (the camera saw\n  transitions the ring could not hold; the window above may be missing events the same way)"
            )
        )
    })
}

/// The sleep blackout line (night-frontier-Z6, D3): the proof of
/// absence a moving BOOTTIME-MONOTONIC gap carries, in the section's
/// grey-line grammar. A POSITIVE delta names the span the host spent
/// asleep inside this window - no event can exist there, the stamps'
/// clock does not run while the host sleeps. A NEGATIVE delta names
/// the anomaly arm - the clock pairing itself moved backwards (a
/// paravirt resync), and the withheld measurement is said instead of
/// trusted. Pure, so the wording and the two arms are pinnable
/// without a live suspend.
pub(crate) fn sleep_blackout_line(sleep_delta_ns: i128) -> String {
    if sleep_delta_ns > 0 {
        let span = crate::info::clock::format_sleep_span(sleep_delta_ns);
        format!(
            "{}{span}{}",
            crate::output::grey_out("  "),
            crate::output::grey_out(
                " of the window was spent asleep - CLOCK_BOOTTIME diverged\n  from the stamps' CLOCK_MONOTONIC by the same span, and the stamps' clock\n  does not run while the host sleeps: no event can exist in that span, and\n  the rows above are the only evidence this window could have"
            )
        )
    } else {
        let span = crate::info::clock::format_sleep_span(-sleep_delta_ns);
        format!(
            "{}{span}{}",
            crate::output::grey_out("  "),
            crate::output::grey_out(
                " of backwards movement in the sleep measurement - the\n  BOOTTIME-MONOTONIC pairing itself is untrustworthy here (a paravirt\n  clock resync), so any blackout report for this window is withheld\n  rather than guessed"
            )
        )
    }
}
