// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Row-level pins for the Evidence Ledger (night-improve-3): the
//! locked row grammar, the four-tier vocabulary, the (UTC) marking
//! rule, the unknown-time degradation. Lives under the single
//! test/ tree and is #[path]-wired from src/evidence/row.rs.

use super::*;

const FIXED_SECS: i64 = 1_760_000_000; // 2025-10-09-ish, deterministic

#[test]
fn all_four_tiers_render_their_lowercase_bracketed_tags() {
    assert_eq!(Provenance::Observed.tag(), "observed");
    assert_eq!(Provenance::Measured.tag(), "measured");
    assert_eq!(Provenance::Inferred.tag(), "inferred");
    assert_eq!(Provenance::Unaccounted.tag(), "unaccounted");
}

#[test]
fn row_line_is_timestamp_action_actor_tag_with_double_spaces() {
    let row = EvidenceRow::new(
        Some(FIXED_SECS),
        "held via fd 3 (rw)",
        "sshd (pid 1234, root)",
        Provenance::Measured,
    );
    let line = row.render_line(true);
    // The exact clock bytes come from the one formatter; the shape
    // around them is the locked grammar.
    let ts = crate::info::clock::format_unix_secs(FIXED_SECS);
    assert_eq!(
        line,
        format!("{ts}  held via fd 3 (rw)  sshd (pid 1234, root)  [measured]")
    );
}

#[test]
fn first_row_keeps_the_utc_suffix_and_later_rows_drop_it() {
    let row = EvidenceRow::new(
        Some(FIXED_SECS),
        "opened",
        "cat (pid 9)",
        Provenance::Observed,
    );
    let marked = row.render_line(true);
    let bare = row.render_line(false);
    // The (UTC) rides the timestamp, mid-line; the bare row drops it.
    assert!(
        marked.contains(" (UTC)  opened"),
        "the marked row: {marked}"
    );
    assert!(marked.ends_with("[observed]"));
    assert!(bare.starts_with("2025-"));
    assert!(
        !bare.contains("(UTC)"),
        "the bare row must drop the suffix: {bare}"
    );
}

#[test]
fn unknown_timestamp_renders_unknown_never_a_guess() {
    let row = EvidenceRow::new(None, "modified", "—", Provenance::Inferred);
    assert_eq!(row.render_line(true), "unknown  modified  —  [inferred]");
    assert_eq!(row.render_line(false), "unknown  modified  —  [inferred]");
}

#[test]
fn the_clock_formatter_is_unix_seconds_to_utc_with_suffix() {
    // 2026-01-01 00:00:00 UTC == 1767225600; the algorithm is pinned
    // at the info layer, this pins the row layer rides it verbatim.
    assert_eq!(
        crate::info::clock::format_unix_secs(1_767_225_600),
        "2026-01-01 00:00:00 (UTC)"
    );
}
