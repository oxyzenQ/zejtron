// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
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

#[test]
fn fd_walk_slots_are_the_offsets_map_contract() {
    // night-hunter-3's lesson, pinned: the fd-walk slots the write
    // probe reads sit exactly at 8..11 of the offsets map, and the
    // parsed array's element count IS the map's slot count - the
    // map writer rides the whole array (slot = index), so a contract
    // that grows on one side only fails this pin or the map write,
    // never a host's walk (the plant bug starved slots 8..11 and the
    // census blamed stage 4 on every host).
    assert_eq!(OFF_SLOT_TASK_FILES, 8);
    assert_eq!(OFF_SLOT_FILES_FDT, 9);
    assert_eq!(OFF_SLOT_FDT_MAX_FDS, 10);
    assert_eq!(OFF_SLOT_FDT_FD, 11);
    // night-frontier-2's growth, pinned as a chain: the struct walk's
    // last slot abuts the first anchor slot, the last anchor slot
    // abuts the map's end - the two producers (the struct parse and
    // the unlink/rename lane verifier) fill the map's slots with no
    // gap, no overlap, and the parsed array's element count IS the
    // struct-walk half of the map.
    assert_eq!(crate::ebpf::events::OFF_SLOT_INODE_I_SB, 12);
    assert_eq!(
        crate::ebpf::events::OFF_SLOT_UNLINK_DENTRY_ARG,
        crate::ebpf::events::OFF_SLOT_INODE_I_SB + 1
    );
    assert_eq!(
        crate::ebpf::events::OFF_SLOT_RENAMEDATA_OLD_DENTRY,
        crate::ebpf::events::OFF_SLOT_UNLINK_DENTRY_ARG + 1
    );
    assert_eq!(
        crate::ebpf::events::OFF_SLOTS,
        crate::ebpf::events::OFF_SLOT_RENAMEDATA_OLD_DENTRY + 1
    );
    assert_eq!(
        std::mem::size_of::<crate::ebpf::btf::ProbeOffsets>() / std::mem::size_of::<u64>(),
        (crate::ebpf::events::OFF_SLOT_INODE_I_SB + 1) as usize
    );
}

// ── night-frontier-Z1, the drop census pins ─────────────────────────

#[test]
fn the_drop_census_maps_slots_to_rings_in_map_order() {
    // The census rides the DROP_SLOT_* contract (events.rs): the
    // slots the kernel bumps map to the fields the surfaces read -
    // sock first, file second, proc third, map order = field order.
    let census = census_from_slots([7, 11, 13]);
    assert_eq!(census.sock, 7);
    assert_eq!(census.file, 11);
    assert_eq!(census.proc, 13);
}

#[test]
fn the_drop_census_slots_are_the_kernel_side_contract() {
    // Both sides compile events.rs - this pin holds the userspace
    // half of the slot indices the BPF side bumps (the stats
    // lockstep law's shape, one file, no drift).
    assert_eq!(DROP_SLOT_SOCK, 0);
    assert_eq!(DROP_SLOT_FILE, 1);
    assert_eq!(DROP_SLOT_PROC, 2);
    assert_eq!(crate::ebpf::events::DROP_SLOTS, 3);
}

#[test]
fn the_drop_census_read_names_its_pin_when_absent() {
    // Host-tolerant (the missing-pin error shape law): a host
    // carrying a live probe has a readable census - the error-path
    // pin only applies when the pin is genuinely absent (a camera
    // planted by a pre-Z1 binary is exactly that shape).
    if crate::ebpf::any_pin_present() {
        return;
    }
    let error = read_drop_census().unwrap_err();
    assert!(
        error.contains("pinned drop-census map /sys/fs/bpf/zejtron/drop_census"),
        "the error must name the pin path: {error}"
    );
}
