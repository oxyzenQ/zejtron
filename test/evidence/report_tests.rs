// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Report-type pins for the Evidence Ledger (night-improve-3): the
//! mode line's base and lane qualifier for every ladder step, the
//! unaccounted entry grammar, the changes-section states. Wired
//! from src/evidence/mod.rs.

use super::*;

#[test]
fn mode_base_words_are_the_locked_three() {
    assert_eq!(Mode::Live.base(), "live");
    assert_eq!(Mode::SnapshotJournal.base(), "snapshot");
    assert_eq!(Mode::SnapshotNoLane.base(), "snapshot");
    assert_eq!(Mode::Mixed.base(), "mixed");
}

#[test]
fn lane_qualifiers_name_the_ladder_steps() {
    assert_eq!(Mode::Live.lane_qualifier(), "");
    assert_eq!(Mode::SnapshotJournal.lane_qualifier(), ", journal fallback");
    assert_eq!(
        Mode::SnapshotNoLane.lane_qualifier(),
        ", no event lane available"
    );
    assert_eq!(Mode::Mixed.lane_qualifier(), "");
}

#[test]
fn the_three_mode_lines_render_verbatim() {
    // The spec's locked shapes, composed from base + window + qualifier.
    assert_eq!(
        format!(
            "Mode: {} (window 60s{})",
            Mode::Live.base(),
            Mode::Live.lane_qualifier()
        ),
        "Mode: live (window 60s)"
    );
    assert_eq!(
        format!(
            "Mode: {} (window 60s{})",
            Mode::SnapshotJournal.base(),
            Mode::SnapshotJournal.lane_qualifier()
        ),
        "Mode: snapshot (window 60s, journal fallback)"
    );
    assert_eq!(
        format!(
            "Mode: {} (window 60s{})",
            Mode::SnapshotNoLane.base(),
            Mode::SnapshotNoLane.lane_qualifier()
        ),
        "Mode: snapshot (window 60s, no event lane available)"
    );
}

#[test]
fn unaccounted_entry_is_count_category_reason() {
    let entry = UnaccountedEntry::new(3, "opens", "no visible PID - namespace boundary");
    assert_eq!(
        entry.render_line(),
        "3 opens (no visible PID - namespace boundary)"
    );
}

#[test]
fn changes_section_defaults_to_empty_and_available() {
    let section = ChangesSection::default();
    assert!(section.rows.is_empty());
    assert!(!section.unavailable);
}
