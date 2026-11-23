// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The recorded-pid compare's truth-table pins (night-frontier-Z11):
//! the /proc snapshot's facts against the recorded event's stamp, the
//! recycle compare's tick boundary, and the two boundary entries'
//! wording - all pure, no live kernel and no tampered namespace.

use super::*;

// ── the classify_pid truth table ─────────────────────────────────────

#[test]
fn a_listed_pid_that_predates_the_event_is_live() {
    // The plain live attribution: status readable, listed, born
    // before the recorded event.
    let visibility = classify_pid(true, true, true, Some(1_000_000_000), 5_000_000_000);
    assert_eq!(visibility, PidVisibility::Live);
}

#[test]
fn a_later_birth_is_recycled_whatever_the_listing_says() {
    // The anti-false-positive arm: the pid now names a process born
    // after the recorded event - the recorded identity is the old
    // holder's. The recycle compare runs FIRST, so a hidden new
    // holder cannot launder the verdict into Hidden.
    let late_birth = 6_000_000_000;
    assert_eq!(
        classify_pid(true, true, true, Some(late_birth), 5_000_000_000),
        PidVisibility::Recycled
    );
    assert_eq!(
        classify_pid(true, true, false, Some(late_birth), 5_000_000_000),
        PidVisibility::Recycled
    );
}

#[test]
fn the_recycle_compare_needs_more_than_one_tick() {
    // The birth's own granularity: a jiffy boundary can read a birth
    // one tick late but never early, so one tick past the event is
    // ambiguous (same process) and a hair past one tick is not.
    let event = 5_000_000_000;
    let tick = 10_000_000;
    assert_eq!(
        classify_pid(true, true, true, Some(event + tick), event),
        PidVisibility::Live
    );
    assert_eq!(
        classify_pid(true, true, true, Some(event + tick + 1), event),
        PidVisibility::Recycled
    );
}

#[test]
fn an_unlisted_pid_with_a_resolving_directory_is_hidden() {
    // The disagreement arm: the status read fine (the process is
    // there, alive) but the listing does not name it - the getdents
    // view and the direct-lookup view of the same namespace disagree.
    assert_eq!(
        classify_pid(true, true, false, Some(1_000_000_000), 5_000_000_000),
        PidVisibility::Hidden
    );
}

#[test]
fn an_unreadable_status_splits_by_the_direct_lookup() {
    // Status failed: the directory reachable by direct lookup while
    // the listing omits it is the hidden shape; every other answer is
    // the exited-or-namespace truth the old message named.
    assert_eq!(
        classify_pid(false, true, false, None, 5_000_000_000),
        PidVisibility::Hidden
    );
    assert_eq!(
        classify_pid(false, false, false, None, 5_000_000_000),
        PidVisibility::Gone
    );
    // Listed but status-unreadable: a mid-read exit race, the honest
    // absence - never a hidden verdict from a race.
    assert_eq!(
        classify_pid(false, true, true, None, 5_000_000_000),
        PidVisibility::Gone
    );
}

#[test]
fn an_unreadable_birth_never_invents_a_recycling() {
    // The honest default: no birth stamp, no recycle verdict - the
    // live attribution stands on the facts that did answer.
    assert_eq!(
        classify_pid(true, true, true, None, 5_000_000_000),
        PidVisibility::Live
    );
}

// ── the boundary entries' wording pins ───────────────────────────────

#[test]
fn the_hidden_pid_entry_names_both_causes_and_the_caveat() {
    let entry = hidden_pid_entry(2);
    assert_eq!(entry.count, 2);
    assert_eq!(entry.category, "hidden pids");
    assert!(
        entry
            .reason
            .contains("the directory listing does not show them"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("getdents filter (stealth)"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("hidepid-style mount"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("cross-validate with sudo"),
        "{}",
        entry.reason
    );
}

#[test]
fn the_recycled_pid_entry_names_the_holder_not_the_actor() {
    let entry = recycled_pid_entry(3);
    assert_eq!(entry.count, 3);
    assert_eq!(entry.category, "recycled pids");
    assert!(
        entry
            .reason
            .contains("born after the events - the old holders exited"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("never the new holders' names"),
        "{}",
        entry.reason
    );
}
