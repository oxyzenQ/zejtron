// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The live lane's Unaccounted entry pins (night-frontier-Z2 moved
//! the builders here - a pure move; the pins moved with them).

use super::*;

#[test]
fn the_file_ring_drop_entry_is_count_backed() {
    // Zero renders nothing (the extend_stats_entries class: the
    // boundary exists only when it fired); a nonzero count rides
    // with the ring named and the window's exposure said plainly.
    assert!(file_ring_drop_entry(0).is_none());
    let entry = file_ring_drop_entry(7).expect("a nonzero drop count carries an entry");
    assert_eq!(entry.count, 7);
    assert_eq!(entry.category, "ring drops");
    assert!(
        entry
            .reason
            .contains("file_events reserve failures since attach"),
        "{}",
        entry.reason
    );
    assert!(entry.reason.contains("may be missing records the same way"));
}

#[test]
fn the_wall_skew_entry_names_the_signed_movement_and_the_bound() {
    let entry = wall_skew_entry(1_700_000_000);
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "wall clock skew");
    // The signed movement: forward and backward both name their
    // direction (a clock stepped back is a different story from one
    // stepped forward).
    assert!(
        wall_skew_entry(1_700_000_000)
            .reason
            .contains("moved +1700000000 ns"),
        "{}",
        wall_skew_entry(1_700_000_000).reason
    );
    assert!(
        wall_skew_entry(-1_700_000_000)
            .reason
            .contains("moved -1700000000 ns"),
        "{}",
        wall_skew_entry(-1_700_000_000).reason
    );
    // The bound and the rows' exposure are said plainly.
    assert!(
        entry.reason.contains("beyond the 500 ms bound"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("can sit that far from the times the events happened at"),
        "{}",
        entry.reason
    );
}

// ── night-frontier-Z6, D3: the sleep blackout entry pins ─────────────

#[test]
fn the_sleep_blackout_entry_names_the_span_and_the_absence() {
    // The blackout arm: the span the host spent asleep inside this
    // capture, the mechanism (the stamps' clock does not run there),
    // and the proof-of-absence reading - the hole carried as
    // evidence.
    let entry = sleep_blackout_entry(852_000_000_000 + 7);
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "sleep blackout");
    assert!(
        entry.reason.contains("spent 14m 12s asleep"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("no event can exist in that span"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("the rows above are the only evidence this window could have"),
        "{}",
        entry.reason
    );
}

#[test]
fn the_sleep_anomaly_entry_names_the_untrustworthy_pairing() {
    // The paravirt arm: a pairing that moved backwards cannot measure
    // a sleep honestly - the withheld measurement is named, never a
    // guessed blackout.
    let entry = sleep_blackout_entry(-300_000_000_000);
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "sleep clock anomaly");
    assert!(
        entry.reason.contains("moved backwards by 5m 00s"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("paravirt clock resync"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("withheld rather than guessed"),
        "{}",
        entry.reason
    );
}

// ── The watch truth (night-frontier-Z10, D7) ────────────────────────

#[test]
fn the_watch_gap_entry_names_the_attach_instant_and_the_span() {
    let entry = watch_gap_entry(1_680_000_000_000, Some("2026-11-19 09:41:00".to_owned()));
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "pre-attach watch gap");
    assert!(
        entry
            .reason
            .contains("the camera was planted at 2026-11-19 09:41:00 (UTC)"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("began 28m 00s earlier"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("no event can exist in that span, because the camera was not watching"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("the rows above are the only evidence this window could have"),
        "{}",
        entry.reason
    );
}

#[test]
fn the_watch_gap_entry_degrades_when_the_wall_clock_is_unreadable() {
    let entry = watch_gap_entry(60_000_000_000, None);
    assert!(
        entry
            .reason
            .contains("the camera's attach instant is unreadable"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("began 1m 00s earlier"),
        "{}",
        entry.reason
    );
}

// The production caller (lane.rs) feeds `format_unix_secs` output,
// which already carries the trailing "(UTC)" - the wrapper adds its
// own, and the render carries the doubled "(UTC) (UTC)" (observed
// live on night-dragon-lts hardware, the sudo-lane audit). The byte
// sits inside the v80.0.0 freeze (`why`'s output bytes), so the
// freeze keeps it and the audit records it (the holds-seam law: the
// freeze keeps the bytes, the audit records them). This pin holds
// the EXACT production render so the seam is a recorded contract,
// not an accident (night-dragon-lts-3); dropping the wrapper's
// "(UTC)" is a deliberate boundary change for the next freeze
// window, never a silent patch.
#[test]
fn the_watch_gap_entry_pins_the_frozen_doubled_utc_byte() {
    let entry = watch_gap_entry(
        1_680_000_000_000,
        Some("2026-11-19 09:41:00 (UTC)".to_owned()),
    );
    assert_eq!(
        entry.reason,
        "the camera was planted at 2026-11-19 09:41:00 (UTC) (UTC); \
         the requested window began 28m 00s earlier - no event can exist \
         in that span, because the camera was not watching: the rows above \
         are the only evidence this window could have",
        "{}",
        entry.reason
    );
}

#[test]
fn the_clocksource_switch_entry_names_both_regimes() {
    let entry = clocksource_switch_entry("tsc", "hpet");
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "clocksource regime");
    assert!(
        entry
            .reason
            .contains("the kernel's clocksource switched across this capture (tsc -> hpet)"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("the stamps stay one CLOCK_MONOTONIC domain"),
        "{}",
        entry.reason
    );
}

// ── night-frontier-Z11: the silent-deletion entry pins ──────────────

#[test]
fn the_silent_deletion_entry_names_the_lanes_disagreement() {
    let entry = silent_deletion_entry("2026-11-23 18:30:00 UTC");
    assert_eq!(entry.count, 1);
    assert_eq!(entry.category, "silent deletions");
    // The disagreement, with the log's record instant carried: the
    // log lane spoke, the ring did not.
    assert!(
        entry.reason.contains("the log lane recorded a deletion"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("at 2026-11-23 18:30:00 UTC"),
        "{}",
        entry.reason
    );
    assert!(
        entry
            .reason
            .contains("the event ring holds no unlink or rename for its inode"),
        "{}",
        entry.reason
    );
}

#[test]
fn the_silent_deletion_entry_names_both_readings_and_stays_honest() {
    let entry = silent_deletion_entry("2026-11-23 18:30:00 UTC");
    // The bypass reading and the replaced-path reading share the
    // shape - the entry says so, and hands the cross-validation to
    // the reader instead of claiming the rootkit word on its own.
    assert!(
        entry
            .reason
            .contains("a deletion the camera's hook did not see"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("bypassed or blocked"),
        "{}",
        entry.reason
    );
    assert!(entry.reason.contains("a replaced path"), "{}", entry.reason);
    assert!(
        entry.reason.contains("cross-validate with doctor"),
        "{}",
        entry.reason
    );
}
