// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The camera cost pins (night-frontier-Z4): the price of the
//! camera, measured from the tree's own artifacts and pinned as
//! test facts. A probe change that grows a program's instruction
//! count, or a ring resize, fails here until the table is
//! consciously re-pinned - the cost regression gate, the same shape
//! the corpus digests ride. The buyer re-derives every number with
//! one command (`readelf -SW ebpf-prebuilt/zejtron-ebpf.o`, the
//! section size divided by eight) - the table below is arithmetic,
//! not marketing.
//!
//! A NEW DIALECT of the cost table (a program added, a ring added)
//! joins by: run `cargo test camera_cost -- --nocapture` (the
//! derivation harness prints the table), update the pins and
//! docs/CAMERA-COST.md, and state the why in the commit.

use crate::ebpf::cost;

/// The pinned instruction table: one row per program section, the
/// shared helper text separate. Sorted by section name (the walker's
/// own order), frozen.
const PROGRAM_PINS: [(&str, usize); 8] = [
    ("kprobe/vfs_open", 109),
    ("kprobe/vfs_rename", 21),
    ("kprobe/vfs_unlink", 36),
    ("kprobe/vfs_writev", 104),
    ("tracepoint/raw_syscalls/sys_enter", 591),
    ("tracepoint/sched/sched_process_exec", 12),
    ("tracepoint/sched/sched_process_exit", 75),
    ("tracepoint/sock/inet_sock_set_state", 144),
];

const SHARED_TEXT_PIN: usize = 346;

/// The kernel-side ring contract: three bounded rings, the file
/// events ring, the sock events ring, and the process exit ring,
/// 256 KiB each.
const RING_COUNT_PIN: usize = 3;
const RING_TOTAL_BYTES_PIN: usize = 3 * 256 * 1024;

#[test]
fn the_camera_instruction_cost_is_pinned_per_program() {
    // The regression gate: the measured counts must equal the pin,
    // row for row. A probe that grew (or shrank) fails here until
    // the table is consciously re-pinned - a cost change is a
    // contract change, named in the commit.
    let cost = cost::measured().expect("the prebuilt object walks");
    assert_eq!(
        cost.programs.len(),
        PROGRAM_PINS.len(),
        "the program count moved: the cost table needs a conscious re-pin"
    );
    for (pin, measured) in PROGRAM_PINS.iter().zip(cost.programs.iter()) {
        assert_eq!(measured.section, pin.0, "the section order moved");
        assert_eq!(
            measured.instructions, pin.1,
            "the instruction count of {} moved: a cost change needs a conscious re-pin",
            pin.0
        );
    }
    assert_eq!(
        cost.shared_text_instructions, SHARED_TEXT_PIN,
        "the shared helper text moved: a cost change needs a conscious re-pin"
    );
}

#[test]
fn the_camera_total_instruction_cost_is_pinned() {
    let cost = cost::measured().expect("the prebuilt object walks");
    let total = cost.total_instructions();
    assert_eq!(
        total,
        PROGRAM_PINS.iter().map(|p| p.1).sum::<usize>() + SHARED_TEXT_PIN,
        "the walker's total disagrees with its own rows"
    );
}

#[test]
fn the_kernel_ring_contract_is_pinned_from_source() {
    // The rings ride the SOURCE, not a copy: the scan walks the BPF
    // crate for the RingBuf sites, so a resize moves the sum and
    // this pin fails until the contract is consciously re-pinned.
    let (count, total) = cost::kernel_rings_from_source().expect("the BPF sources scan");
    assert_eq!(
        count, RING_COUNT_PIN,
        "the ring count moved: the cost contract needs a conscious re-pin"
    );
    assert_eq!(
        total, RING_TOTAL_BYTES_PIN,
        "the kernel-side ring bytes moved: the cost contract needs a conscious re-pin"
    );
}

#[test]
fn the_cost_derivation_table_renders_whole() {
    // The derivation harness: prints every number the published
    // table (docs/CAMERA-COST.md) carries. Run with --nocapture.
    let cost = cost::measured().expect("the prebuilt object walks");
    let rings = cost::kernel_rings_from_source().expect("the BPF sources scan");
    let table = cost::render_table(&cost, rings);
    println!("=== the camera cost table (night-frontier-Z4) ===");
    println!("{table}");
    assert!(table.contains("programs total:"));
    assert!(table.contains("kernel-side rings: 3 rings, 786432 bytes total"));
}
