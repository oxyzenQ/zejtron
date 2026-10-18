// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! loader unit pins (feature builds only - the loader module itself
//! is feature-gated). Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/ebpf/loader.rs. The privileged one-shot itself (attach on
//! a live host) is exercised by the owner's live session, not by unit
//! pins - what IS pinned here is the embedded object's structural
//! truth and the contract constants the kernel side mirrors.

use super::*;

#[test]
fn tap_elf_is_an_aligned_bpf_object() {
    // The real embedded object, as it ships inside the binary: ELF
    // magic, and 8-byte aligned (the AlignedElf contract - aya's
    // parser reads ELF64 structures straight out of the buffer).
    assert!(TAP_ELF.starts_with(&[0x7f, b'E', b'L', b'F']));
    assert_eq!(
        embedded::alignment_violation(TAP_ELF, "zejtron-ebpf"),
        None,
        "the embedded tap must sit 8-byte aligned by construction"
    );
}

#[test]
fn contract_constants_pin_the_attach_point() {
    // The userspace constants mirror the kernel side's contracts
    // (ebpf/src/main.rs): the program symbol, the tracepoint pair,
    // the map name. Both sides keep them in lockstep.
    assert_eq!(PROGRAM, "sched_process_exec");
    assert_eq!(TRACEPOINT_CATEGORY, "sched");
    assert_eq!(TRACEPOINT_EVENT, "sched_process_exec");
    assert_eq!(MAP_STATS, "stats");
}

#[test]
fn pin_paths_are_the_one_directory_contract() {
    // Every pin the loader plants lives under /sys/fs/bpf/zejtron -
    // the single directory detach removes whole.
    assert_eq!(PIN_DIR, "/sys/fs/bpf/zejtron");
    assert!(PIN_LINK.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_PROG.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_MAP_STATS.starts_with("/sys/fs/bpf/zejtron/"));
}
