// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
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
