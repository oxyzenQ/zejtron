// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! tracked_inodes writer pins (night-improve-3). The writer's
//! behavior against a live pin cannot be exercised without an
//! attached probe (the sandbox and CI are clean hosts); the pin-level
//! contract is the failure text: a missing pin reads as a diagnosis
//! naming the attach step, never a generic failure. Wired from
//! src/ebpf/tracked.rs.

use super::*;

#[test]
fn a_clean_host_refuses_by_naming_the_pin_and_the_attach_step() {
    // Only pin the refusal shape when the probe is genuinely absent
    // (an attached host would succeed - the idempotence contract).
    if std::path::Path::new(PIN_MAP_TRACKED_INODES).exists() {
        return;
    }
    // Two legal refusals, the host's own call (night-hunter-5): an
    // unprivileged host refuses the bpf(2) call itself with EPERM
    // BEFORE the filesystem lookup (unprivileged bpf disabled) - the
    // ladder's degrade-marker shape; a privileged host with a missing
    // pin walks to ENOENT - the attach-step shape. Both name the pin;
    // the assertion accepts the union the host selects between, never
    // a shape the host cannot promise.
    let err = track_file(0x1234, 0x800002).unwrap_err();
    assert!(err.contains(PIN_MAP_TRACKED_INODES), "names the pin: {err}");
    assert!(
        err.starts_with(crate::ebpf::PIN_ACCESS_DENIED)
            || (err.contains("is the probes attached") && err.contains("doctor")),
        "names the boundary (the degrade marker or the attach step): {err}"
    );

    let err = untrack_file(0x1234, 0x800002).unwrap_err();
    assert!(err.contains(PIN_MAP_TRACKED_INODES));
    assert!(
        err.starts_with(crate::ebpf::PIN_ACCESS_DENIED)
            || (err.contains("cannot untrack") && err.contains("is the probes attached")),
        "the untrack refusal names its verb or carries the marker: {err}"
    );
}

#[test]
fn both_verbs_key_the_same_pack_as_the_kprobe() {
    // The key packing is events.rs's one implementation; the writer
    // rides it (asserted by the file_events pins), so this test only
    // documents the coupling - the same (inode, device) pair must
    // produce the same key that passed through pack_filter_key.
    use crate::ebpf::events::pack_filter_key;
    assert_eq!(
        pack_filter_key(0x1234, 0x800002),
        (0x1234u64 << 32) | 0x800002u64
    );
}
