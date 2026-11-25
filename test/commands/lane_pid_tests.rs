// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The recorded-pid compare's truth-table pins (night-frontier-Z11):
//! the /proc snapshot's facts against the recorded event's stamp, the
//! recycle compare's tick boundary, and the two boundary entries'
//! wording - all pure, no live kernel and no tampered namespace.

use super::*;
use std::collections::BTreeMap;

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
    let entry = hidden_pid_entry(2, &BTreeMap::from([(499_478u32, 2usize)]));
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
    let entry = recycled_pid_entry(3, &BTreeMap::from([(9u32, 3usize)]));
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
    assert!(
        entry.reason.contains("the 3 events carry 1 distinct pid;"),
        "{}",
        entry.reason
    );
}

// ── the event-versus-distinct clause (night-witness-pids) ────────────

#[test]
fn the_clause_answers_the_distinct_process_question() {
    // The misread the clause exists for: a count of 388 read as "388
    // distinct hidden processes" when it is 388 events from one pid.
    let per_pid = BTreeMap::from([(499_478u32, 388usize)]);
    let entry = hidden_pid_entry(388, &per_pid);
    assert!(
        entry
            .reason
            .contains("the 388 events carry 1 distinct pid;"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("sample: pid 499478 x388"),
        "{}",
        entry.reason
    );
    // The plural arm: two pids, the clause names the pair and its
    // ascending sample.
    let pair = BTreeMap::from([(10u32, 5usize), (20u32, 2usize)]);
    let entry = hidden_pid_entry(7, &pair);
    assert!(
        entry
            .reason
            .contains("2 distinct pids; sample: pid 10 x5, pid 20 x2"),
        "{}",
        entry.reason
    );
}

#[test]
fn the_clause_lists_ascending_and_bounds_at_32() {
    // Forty distinct pids: the sample lists the first 32 in ascending
    // pid order and names what it omits - bounded, never a dump.
    let per_pid: BTreeMap<u32, usize> = (0..40u32).map(|pid| (pid, 1usize)).collect();
    let entry = hidden_pid_entry(40, &per_pid);
    assert!(
        entry
            .reason
            .contains("the 40 events carry 40 distinct pids;"),
        "{}",
        entry.reason
    );
    assert!(
        entry.reason.contains("(+8 more pids unlisted)"),
        "{}",
        entry.reason
    );
    assert!(entry.reason.contains("pid 31 x1"), "{}", entry.reason);
    assert!(
        !entry.reason.contains("pid 39 x1"),
        "the cap bounds the sample: {}",
        entry.reason
    );
}

#[test]
fn the_clause_is_byte_deterministic() {
    // BTreeMap's ascending walk makes the sample stable across runs -
    // the same input, the same bytes, pinnable.
    let per_pid = BTreeMap::from([(20u32, 2usize), (10u32, 5usize)]);
    assert_eq!(
        hidden_pid_entry(7, &per_pid).reason,
        hidden_pid_entry(7, &per_pid).reason
    );
    assert!(
        hidden_pid_entry(7, &per_pid)
            .reason
            .contains("sample: pid 10 x5, pid 20 x2"),
        "ascending pid order: {}",
        hidden_pid_entry(7, &per_pid).reason
    );
}
