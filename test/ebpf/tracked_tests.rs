// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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

#[test]
fn a_full_hash_map_is_classified_by_the_kernel_s_own_errno() {
    // night-frontier-Z5: the question census counts only CAPACITY
    // refusals. The kernel answers E2BIG for a full BPF hash map; the
    // syscall-error carrier is the shape aya's insert surfaces. Two
    // neighbours must NOT classify as full: EPERM (a privilege
    // refusal - the census would lie about capacity it never ran out
    // of) and a non-syscall carrier with a different errno.
    let full = MapError::SyscallError(aya::sys::SyscallError {
        call: "bpf_map_update_elem",
        io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
    });
    assert!(is_map_full_error(&full));
    let denied = MapError::SyscallError(aya::sys::SyscallError {
        call: "bpf_map_update_elem",
        io_error: std::io::Error::from_raw_os_error(libc::EPERM),
    });
    assert!(!is_map_full_error(&denied));
    // The IoError twin (the same errno, the non-syscall carrier).
    let io_full = MapError::IoError(std::io::Error::from_raw_os_error(libc::E2BIG));
    assert!(is_map_full_error(&io_full));
    let io_denied = MapError::IoError(std::io::Error::from_raw_os_error(libc::EPERM));
    assert!(!is_map_full_error(&io_denied));
}

#[test]
fn the_refusal_names_the_camera_the_count_and_the_remedy() {
    // night-frontier-Z5: the refusal-with-a-name shape. Counted: the
    // cause, the cumulative count (this refusal included), and the
    // remedy - the detach that clears the stale questions.
    let full = MapError::SyscallError(aya::sys::SyscallError {
        call: "bpf_map_update_elem",
        io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
    });
    let counted = refused_question_error(&full, Ok(2));
    assert!(counted.contains("refused this question"), "{counted}");
    assert!(counted.contains("no capacity left"), "{counted}");
    assert!(counted.contains("2 refused since attach"), "{counted}");
    assert!(counted.contains("doctor --detach"), "{counted}");
    // Degraded: the census is unreadable on this camera - the count
    // is dropped (never invented), the unreadability is named with
    // its reason, the remedy stays.
    let degraded = refused_question_error(&full, Err("stats[17] read failed: gone".to_owned()));
    assert!(!degraded.contains("refused since attach"), "{degraded}");
    assert!(degraded.contains("census is unreadable"), "{degraded}");
    assert!(
        degraded.contains("stats[17] read failed: gone"),
        "{degraded}"
    );
    assert!(degraded.contains("doctor --detach"), "{degraded}");
}
