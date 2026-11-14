// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The drain-boundary re-verification pins (night-frontier-Z1). The
//! live re-derivation (a real pinned offsets map against a real
//! /sys/kernel/btf/vmlinux) belongs to the owner's live session; the
//! host-tolerant shape is pinned by the drift law itself - the pure
//! compare, the refusal text, and the slot-name contract - driven
//! with synthetic walk tables. The IO wrappers name their stage (the
//! readback module's error-shape law); their live behavior is the
//! netrunner legs' proof, not a unit pin's.

use super::*;

/// A walk table where every slot agrees: the all-clear verdict, and
/// the base every drift test perturbs.
fn agreed() -> [u64; OFF_SLOTS as usize] {
    let mut table = [0u64; OFF_SLOTS as usize];
    for (slot, value) in table.iter_mut().enumerate() {
        // Distinct, nonzero values: a slot compare that silently
        // coerced could pass a table of zeros.
        *value = 16 + slot as u64 * 8;
    }
    table
}

#[test]
fn agreeing_tables_read_as_the_all_clear() {
    let planted = agreed();
    let derived = agreed();
    assert_eq!(drift_slot(&planted, &derived), None);
}

#[test]
fn the_first_drifting_slot_is_the_named_one() {
    let planted = agreed();
    let mut derived = agreed();
    // Drift the LAST slot: the compare must still name the first
    // mismatch in order, not the deepest one, not a count.
    derived[OFF_SLOTS as usize - 1] += 1;
    assert_eq!(drift_slot(&planted, &derived), Some(OFF_SLOTS as usize - 1));
    // And the FIRST slot.
    let mut derived_first = agreed();
    derived_first[0] += 1;
    assert_eq!(drift_slot(&planted, &derived_first), Some(0));
}

#[test]
fn every_slot_drifts_by_name() {
    // One drifting slot at a time, across the whole table: no slot is
    // exempt from the compare - the walk table is fifteen slots, and
    // a single stale one is enough to make records untrustworthy.
    let planted = agreed();
    for slot in 0..OFF_SLOTS as usize {
        let mut derived = agreed();
        derived[slot] = planted[slot] + 8;
        assert_eq!(
            drift_slot(&planted, &derived),
            Some(slot),
            "slot {slot} ({}) drifted and the compare missed it",
            SLOT_NAMES[slot]
        );
    }
}

#[test]
fn the_refusal_names_slot_planted_and_current() {
    let planted = agreed();
    let mut derived = agreed();
    derived[3] = 999;
    let message = drift_message(3, planted[3], derived[3]);
    // The repo-owned sentinel carries the class (the
    // PIN_ACCESS_DENIED precedent: classifiers match the constant,
    // never the prose).
    assert!(message.starts_with(OFFSETS_DRIFT));
    // By slot: the index, its OFF_SLOT_* name, and both values -
    // the planted word first (the records were written with it),
    // the current kernel's word beside it.
    assert!(message.contains("offsets[3]"), "{message}");
    assert!(message.contains(SLOT_NAMES[3]), "{message}");
    assert!(message.contains("planted 40"), "{message}");
    assert!(message.contains("derives 999"), "{message}");
    // The recovery path is named: re-attach, not a guess.
    assert!(message.contains("re-attach"), "{message}");
}

#[test]
fn the_anchor_slots_carry_their_own_names() {
    // The two non-byte-offset slots (the unlink dentry argument
    // POSITION and the renamedata old_dentry MEMBER OFFSET) are
    // named as what they are - a refusal that called a position a
    // byte offset would teach the wrong lesson about slot 13.
    assert_eq!(SLOT_NAMES[13], "vfs_unlink dentry argument position");
    assert_eq!(SLOT_NAMES[14], "renamedata.old_dentry offset");
    // And the frozen struct-walk slots keep the attach trace's own
    // names (loader.rs's OFF_TRACE order): the same slot, one name,
    // both boundaries.
    assert_eq!(SLOT_NAMES[0], "dentry.d_inode");
    assert_eq!(SLOT_NAMES[12], "inode.i_sb");
}

#[test]
fn the_slot_name_table_covers_every_slot() {
    // The refusal renders SLOT_NAMES[slot] - a short table would
    // panic mid-refusal. One name per slot, every name non-empty.
    assert_eq!(SLOT_NAMES.len(), OFF_SLOTS as usize);
    for (slot, name) in SLOT_NAMES.iter().enumerate() {
        assert!(!name.is_empty(), "slot {slot} carries no name");
    }
}

#[test]
fn the_drift_marker_is_the_refusal_class() {
    // The sentinel is the only thing a matcher should need: stable
    // text, distinctive prefix, no OS prose riding it.
    assert_eq!(OFFSETS_DRIFT, "offsets drift at the drain boundary");
}

#[test]
fn the_derived_table_lays_the_anchors_at_their_slots() {
    // The derived-table assembly rides the OFF_SLOT_* constants for
    // the two anchors (the night-hunter-3 lesson: a lagging writer
    // breeds a silent misread). Pinned through the contract values:
    // slot 13 is the dentry ARGUMENT POSITION (a small index, 1 or
    // 2 on real hosts), slot 14 the old_dentry byte offset - and
    // the struct walk's thirteen values land at slots 0..13 in
    // order, never shifted.
    assert_eq!(OFF_SLOT_UNLINK_DENTRY_ARG, 13);
    assert_eq!(OFF_SLOT_RENAMEDATA_OLD_DENTRY, 14);
    // The struct walk's table is thirteen slots wide (the two anchor
    // slots ride past it at 13..15) - the size pin holds the shape.
    assert_eq!(std::mem::size_of::<btf::ProbeOffsets>(), 13 * 8);
}
