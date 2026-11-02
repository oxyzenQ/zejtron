// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! loader unit pins (feature builds only - the loader module itself
//! is feature-gated). Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/ebpf/loader.rs. The privileged one-shot itself (attach on
//! a live host) is exercised by the owner's live session, not by unit
//! pins - what IS pinned here is the embedded object's structural
//! truth and the contract constants the kernel side mirrors.

use super::*;
// The contract constants moved to plant.rs (night-hunter-4's pure
// move at the 600 LOC cap); the pins follow the contract, and the
// pin-path constants ride the ebpf module's one directory truth.
use crate::ebpf::plant::{
    EXIT_PROGRAM, EXIT_TRACEPOINT_CATEGORY, EXIT_TRACEPOINT_EVENT, MAP_PROC_EVENTS, MAP_STATS,
    PROGRAM, TRACEPOINT_CATEGORY, TRACEPOINT_EVENT,
};
use crate::ebpf::{
    PIN_LINK, PIN_LINK_EXIT, PIN_MAP_PROC_EVENTS, PIN_MAP_STATS, PIN_PROG, PIN_PROG_EXIT,
};

#[test]
fn probe_elf_is_an_aligned_bpf_object() {
    // The real embedded object, as it ships inside the binary: ELF
    // magic, and 8-byte aligned (the AlignedElf contract - aya's
    // parser reads ELF64 structures straight out of the buffer).
    assert!(PROBE_ELF.starts_with(&[0x7f, b'E', b'L', b'F']));
    assert_eq!(
        embedded::alignment_violation(PROBE_ELF, "zejtron-ebpf"),
        None,
        "the embedded probe must sit 8-byte aligned by construction"
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
fn contract_constants_pin_the_post_mortem_exit_attach_point() {
    // night-improve-47's exit probe (ebpf/src/exits.rs) carries its
    // own contract, pinned the same way: the program symbol, the
    // tracepoint pair, the ring map. The exit tracepoint exists
    // on every kernel the 5.15 floor allows.
    assert_eq!(EXIT_PROGRAM, "sched_process_exit");
    assert_eq!(EXIT_TRACEPOINT_CATEGORY, "sched");
    assert_eq!(EXIT_TRACEPOINT_EVENT, "sched_process_exit");
    assert_eq!(MAP_PROC_EVENTS, "proc_events");
}

#[test]
fn pin_paths_are_the_one_directory_contract() {
    // Every pin the loader plants lives under /sys/fs/bpf/zejtron -
    // the single directory detach removes whole.
    assert_eq!(PIN_DIR, "/sys/fs/bpf/zejtron");
    assert!(PIN_LINK.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_PROG.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_MAP_STATS.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_LINK_EXIT.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_PROG_EXIT.starts_with("/sys/fs/bpf/zejtron/"));
    assert!(PIN_MAP_PROC_EVENTS.starts_with("/sys/fs/bpf/zejtron/"));
}

// ── The quiet-by-default summary law (the verbosity masterclass) ────
//
// The default human output of the attach/detach verbs is ONE short
// line - no probe-name wall, no pin dump (the data lives behind -v).
// These guards pin the law from both directions: the default line
// stays quiet and small, and the -v branch is where the wall went.

#[test]
fn estate_counts_classify_the_whole_pin_estate() {
    // The classifier's naming contract against the real constants:
    // six programs, six links, six maps - and the three counts cover
    // every pin, so a future probe pair updates the summary line
    // without touching it, and a naming drift fails here instead of
    // printing a wrong count.
    let (programs, links, maps) = estate_counts();
    assert_eq!(programs, 6, "the estate plants six probe programs");
    assert_eq!(links, 6, "every program rides one link pin");
    assert_eq!(maps, 6, "the estate plants six maps");
    assert_eq!(
        programs + links + maps,
        crate::ebpf::ALL_PINS.len(),
        "every pin must classify into exactly one role"
    );
}

#[test]
fn attach_success_default_is_one_quiet_line() {
    // The default success line: single-line, under 100 chars, no
    // probe names, no pin list, no pin directory - the estate's
    // shape and the camera's posture, nothing else.
    let concise = attach_success_summary(&Ok(0), "vfs_writev", false);
    assert!(
        !concise.contains('\n'),
        "default output is one line: {concise}"
    );
    assert!(
        concise.chars().count() < 100,
        "default attach output must stay under 100 chars, got {}: {concise}",
        concise.chars().count()
    );
    assert!(!concise.contains("sched_process_exec"));
    assert!(!concise.contains("vfs_"), "no probe names: {concise}");
    assert!(!concise.contains("sys_enter"));
    assert!(!concise.contains("inet_sock"));
    assert!(!concise.contains("probe_link"), "no pin list: {concise}");
    assert!(!concise.contains(PIN_DIR), "no pin directory: {concise}");
    assert!(!concise.contains("BTF"), "no BTF detail: {concise}");
    // The shape it DOES carry: the counts and the camera posture.
    assert!(concise.contains("6 programs"));
    assert!(concise.contains("6 links"));
    assert!(concise.contains("6 maps"));
    assert!(concise.contains("probes attached successfully"));
    assert!(concise.contains("Lazy Camera is now recording"));
}

#[test]
fn attach_verbose_carries_the_probe_and_pin_details() {
    // -v is where the wall lives: the probe names, the BTF
    // verification claims, the counter read, and the whole pin
    // list, multi-line - strictly more than the quiet line.
    let concise = attach_success_summary(&Ok(0), "vfs_writev", false);
    let verbose = attach_success_summary(&Ok(0), "vfs_writev", true);
    assert!(verbose.contains("sched_process_exec"));
    assert!(verbose.contains("vfs_writev"));
    assert!(verbose.contains("vfs_open"));
    assert!(verbose.contains("sys_enter"));
    assert!(verbose.contains("offsets verified from this host's BTF"));
    assert!(verbose.contains("pins:"));
    assert!(verbose.contains(PIN_DIR));
    assert!(verbose.contains("events since attach: N=0"));
    assert!(verbose.contains('\n'), "the verbose report is multi-line");
    assert!(verbose.chars().count() > concise.chars().count());
}

#[test]
fn attach_already_default_is_quiet_and_verbose_names_the_pointer() {
    // The idempotent re-attach: default stays one quiet line with
    // the live counter; -v keeps the full shape with the detach
    // pointer.
    let concise = attach_already_summary(&Ok(7), false);
    assert!(
        !concise.contains('\n'),
        "default output is one line: {concise}"
    );
    assert!(
        concise.chars().count() < 100,
        "default already-attached output must stay under 100 chars: {concise}"
    );
    assert!(!concise.contains(PIN_DIR));
    assert!(concise.contains("already attached"));
    assert!(concise.contains("events since attach: N=7"));
    let verbose = attach_already_summary(&Ok(7), true);
    assert!(verbose.contains("doctor --detach"));
    assert!(verbose.contains("all pins present"));
    assert!(verbose.chars().count() > concise.chars().count());
}

#[test]
fn attach_counter_unreadable_stays_honest_in_both_lanes() {
    // A counter readback failure never fabricates a number: the
    // default line says unreadable (short), the verbose line keeps
    // the exact error.
    let err = Err("no such map".to_owned());
    let concise = attach_already_summary(&err, false);
    assert!(concise.contains("counter unreadable"), "{concise}");
    assert!(!concise.contains("N="), "no fabricated count: {concise}");
    let verbose = attach_already_summary(&err, true);
    assert!(verbose.contains("counter unreadable (no such map)"));
}

#[test]
fn detach_default_is_one_quiet_line() {
    // The default detach line: the task's masterclass shape, no pin
    // directory path, one line. The swept note rides only when the
    // sledgehammer actually swept something.
    let concise = detach_summary(18, 0, false);
    assert_eq!(concise, "eBPF probes detached (18 pins removed).");
    assert!(
        concise.chars().count() < 100,
        "default detach output must stay under 100 chars: {concise}"
    );
    assert!(!concise.contains(PIN_DIR));
    let swept = detach_summary(18, 2, false);
    assert!(swept.contains("2 foreign entries swept"), "{swept}");
    assert!(!swept.contains('\n'));
    let verbose = detach_summary(18, 0, true);
    assert!(verbose.contains("unpinned 18 pin(s)"));
    assert!(verbose.contains(PIN_DIR));
    assert!(verbose.chars().count() > concise.chars().count());
}
