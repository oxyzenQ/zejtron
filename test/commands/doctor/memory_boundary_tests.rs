// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The memory ledger's boundary-line pins (night-frontier-Z2 moved
//! the builders here - a pure move; the pins moved with them).

use super::*;

#[test]
fn the_exit_ring_drop_line_is_count_backed_and_names_the_ring() {
    assert!(ring_drop_line(0).is_none());
    let line = ring_drop_line(3).expect("a nonzero drop count carries a line");
    // The count rides unwrapped (the value), the reason carries the
    // ring, the boundary, and the window's exposure. Mono-identity:
    // the raw bytes carry no escapes.
    assert!(line.starts_with("  3 "), "{line}");
    assert!(line.contains("ring drops on the proc_events ring since attach"));
    assert!(line.contains("may be missing exits the same way"));
    // The singular form: one drop reads "1 ring drop", not "drops".
    let one = ring_drop_line(1).expect("one drop carries a line");
    assert!(one.contains("1 ring drop on the proc_events ring"), "{one}");
}

#[test]
fn the_wall_skew_line_names_the_signed_movement_and_the_bound() {
    let line = wall_skew_line(1_700_000_000).expect("a measured skew carries a line");
    // The signed movement leads the line (the value), unwrapped.
    assert!(line.contains("+1700000000 ns"), "{line}");
    assert!(line.contains("wall-clock skew measured since the exit collection began"));
    assert!(line.contains("beyond the 500 ms bound"), "{line}");
    assert!(line.contains("can sit that far from the times the exits happened at"));
    // Backward steps name their direction too.
    let back = wall_skew_line(-900_000_000).expect("a backward skew carries a line");
    assert!(back.contains("-900000000 ns"), "{back}");
}
