// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! readback unit pins (feature builds only - the readback module
//! itself is feature-gated). Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/ebpf/readback.rs. The live read (a real pinned map on a
//! host with an attached tap) belongs to the owner's live session;
//! what IS pinned here is the absent-pin error shape - a missing pin
//! reads as a diagnosis that names the path, never a generic failure.

use super::*;

#[test]
fn missing_pin_reads_as_a_named_diagnosis() {
    // Host-tolerant: a host carrying a live tap (complete pins) has a
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
