// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! readback unit pins (feature builds only - the readback module
//! itself is feature-gated). Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/ebpf/readback.rs. The live read (a real pinned map on a
//! host with an attached probe) belongs to the owner's live session;
//! what IS pinned here is the absent-pin error shape - a missing pin
//! reads as a diagnosis that names the path, never a generic failure.

use super::*;

#[test]
fn missing_pin_reads_as_a_named_diagnosis() {
    // Host-tolerant: a host carrying a live probe (complete pins) has a
    // readable counter - the error-path pin only applies when the pin
    // is genuinely absent.
    if crate::ebpf::any_pin_present() {
        return;
    }
    let error = read_events_counter().unwrap_err();
    assert!(
        error.contains("pinned stats map /sys/fs/bpf/zejtron/stats"),
        "the error must name the pin path: {error}"
    );
    // No pin, no attach moment - absent stays absent.
    assert!(attach_moment().is_none());
}

#[test]
fn stats_index_is_the_kernel_side_contract() {
    // The readback reads stats[0] - the same slot the kernel side
    // increments (ebpf/src/main.rs's STATS_EVENTS). Both sides keep
    // the index in lockstep; this pin holds the userspace half.
    assert_eq!(STATS_EVENTS, 0);
}

#[test]
fn census_slots_are_the_kernel_side_contract() {
    // The write probe's census slots (night-hunter-2): the two totals
    // and the per-stage counter block (stage s lives in
    // STATS_ZJW_STAGE_BASE + s - 1, stages 1..14). The kernel side
    // (ebpf/src/main.rs's STATS_ZJW_*) keeps the same indices in
    // lockstep; this pin holds the userspace half - a renumber on
    // either side must fail a gate here, never drift silently.
    assert_eq!(STATS_ZJW_DROPS, 1);
    assert_eq!(STATS_ZJW_WALKED, 2);
    assert_eq!(STATS_ZJW_STAGE_BASE, 3);
    assert_eq!(STATS_ZJW_STAGE_COUNT, 14);
}

#[test]
fn furthest_stage_picks_the_highest_nonzero_hop() {
    // The derivation is the diagnosis: the highest stage with a
    // nonzero count is the blocker hop, ties impossible by
    // construction (one slot per stage).
    let all_zero = [0u64; 14];
    assert_eq!(furthest_stage(&all_zero), None);
    let mut counts = [0u64; 14];
    counts[2] = 5; // stage 3
    counts[7] = 1; // stage 8
    assert_eq!(furthest_stage(&counts), Some((8, 1)));
    let mut only_first = [0u64; 14];
    only_first[0] = 9; // stage 1
    assert_eq!(furthest_stage(&only_first), Some((1, 9)));
    let mut only_last = [0u64; 14];
    only_last[13] = 2; // stage 14
    assert_eq!(furthest_stage(&only_last), Some((14, 2)));
}
