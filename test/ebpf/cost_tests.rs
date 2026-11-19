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
const PROGRAM_PINS: [(&str, usize); 12] = [
    // night-frontier-Z7 (D4), the conscious re-pin: the off-path
    // trio rides the same cost contract - the folio-shape dirty
    // anchor is a 4-instruction stub over the shared subprogram
    // (bpf2bpf call; the walk itself lives in the shared text), the
    // page-shape anchor reads the page.mapping hop inline, the
    // io_uring probe carries its opcode filter and request walk,
    // and the splice probe rides the sys_enter section beside the
    // write probe (the two programs share the one section, the
    // walker sums them). THE INLINE LAW (found live by the C77 root
    // leg): a bpf2bpf call into .text leaves an unresolved
    // pseudo-call at BPF_PROG_LOAD - the 5.15 runner's verifier
    // refused the splice probe with EPERM - so every walk is
    // #[inline(always)] and each program carries its own hops (the
    // folio anchor 95, the page anchor 109, the splice probe's 344
    // beside the write probe's 591 in the shared section). The rows
    // stay in the walker's own (byte-sorted) section order.
    // night-frontier-Z8 (D5), the conscious re-pin: the actor
    // identity rides EVERY record now - cgroup id (one helper call),
    // comm (one helper call), netns inode (the four-hop walk,
    // inline-always per the INLINE LAW, each probe carrying its own
    // hops). The inline-only programs each grew by their own identity
    // fill (the dirty anchor 109 -> 225, vfs_open 109 -> 225, the
    // sys_enter section 935 -> 1323 across the write and splice
    // probes, the sock probe 144 -> 261, io_uring 143 -> 261); the
    // unlink/rename pair stayed at their own stub sizes because their
    // shared publish tail lives in .text, which grew 382 -> 547 for
    // the same identity fill. The price of "who did this, and from
    // where" riding every record without a cross-lookup - and the
    // rings grew with it (the file ring doubled, the conscious
    // re-pin below).
    // night-frontier-Z9 (D6), the conscious re-pin: the memory-backed
    // rung joins the camera - ONE new program (287 instructions,
    // inline-always like every walk in this crate: the vm_fault.page
    // hop, the mapping descent, the tracked gate, the class gate, and
    // the registered-filesystem-name read through the kernel's own
    // string helper). The shared text grew 547 -> 583 because the
    // fs-name classification is shared by nothing - it is the probe's
    // own tail; the .text growth rides the string helper's call
    // framing the compiler laid down beside the identity fill. The
    // price of closing the tmpfs/ramfs/memfd residual: one probe, 287
    // instructions, zero new maps, zero new rings.
    ("kprobe/__set_page_dirty_nobuffers", 225),
    ("kprobe/fault_dirty_shared_page", 287),
    ("kprobe/filemap_dirty_folio", 211),
    ("kprobe/vfs_open", 225),
    ("kprobe/vfs_rename", 21),
    ("kprobe/vfs_unlink", 36),
    ("kprobe/vfs_writev", 219),
    ("tracepoint/io_uring/io_uring_submit_sqe", 261),
    ("tracepoint/raw_syscalls/sys_enter", 1323),
    ("tracepoint/sched/sched_process_exec", 12),
    ("tracepoint/sched/sched_process_exit", 75),
    ("tracepoint/sock/inet_sock_set_state", 261),
];

const SHARED_TEXT_PIN: usize = 583;

/// The kernel-side ring contract: three bounded rings - the file
/// events ring at 512 KiB (night-frontier-Z8, D5's conscious re-pin:
/// the record grew 40 -> 72 bytes carrying the actor identity, and
/// the ring doubled so the held-record window GREW - 6553 records at
/// the 80-byte aya stride versus the 5461 the old 256 KiB held at
/// the 48-byte stride - the +256 KiB is the price of identity riding
/// every record), the sock events ring at 256 KiB (kept: its filter
/// bounds it to LISTEN/UDP-close transitions too rare to need the
/// memory), and the process exit ring at 256 KiB (its record did not
/// grow).
const RING_COUNT_PIN: usize = 3;
const RING_TOTAL_BYTES_PIN: usize = 512 * 1024 + 256 * 1024 + 256 * 1024;

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
    assert!(table.contains("kernel-side rings: 3 rings, 1048576 bytes total"));
}
