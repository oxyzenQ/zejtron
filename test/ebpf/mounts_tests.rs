// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Mounts pins (night-improve-61): the UAPI magic numbers, the
//! statfs probe on known filesystems, and the state machine's
//! coherence. The ensure pair's mount half is the attach-time
//! behavior - exercised live by doctor --attach on the micro-VM
//! floor, not pinnable here without CAP_SYS_ADMIN.

use super::*;

/// procfs magic (include/uapi/linux/magic.h) - the one filesystem
/// every test environment has mounted.
const PROC_SUPER_MAGIC: i64 = 0x9fa0;

#[test]
fn the_uapi_magics_are_the_kernel_numbers() {
    // Pinned to include/uapi/linux/magic.h: a wrong magic reads every
    // mounted tracefs as absent (or worse, a placeholder as mounted).
    assert_eq!(TRACEFS_MAGIC, 0x74726163);
    assert_eq!(DEBUGFS_MAGIC, 0x64626720);
    assert_eq!(BPF_FS_MAGIC, 0xcafe4a11);
}

#[test]
fn fs_magic_reads_the_mounted_filesystem() {
    // /proc is mounted in every environment the test suite runs in:
    // the statfs probe must see its magic.
    assert_eq!(fs_magic("/proc"), Some(PROC_SUPER_MAGIC));
}

#[test]
fn fs_magic_reads_an_absent_path_as_none() {
    // The honest absence: an unstatable path is not a mounted
    // anything, and the state machine must treat it as absent.
    assert_eq!(fs_magic("/definitely/not/a/real/path"), None);
}

#[test]
fn tracefs_state_is_always_a_coherent_verdict() {
    // Host-dependent by nature: a tracing host answers Mounted, a
    // container answers Absent. The pin is the coherence - the
    // probe never panics and always names one of the two seats it
    // walked when it answers Mounted.
    match tracefs_state() {
        TracefsState::Mounted(seat) => {
            assert!(
                [TRACEFS_PRIMARY, TRACEFS_FALLBACK].contains(&seat),
                "a mounted verdict must name a walked seat: {seat}"
            );
        }
        TracefsState::Absent => {}
    }
}

#[test]
fn the_seats_are_the_two_paths_aya_walks() {
    // aya's find_tracefs_path walks exactly these two, in this
    // order; the doctor's row and the attach-time ensure must walk
    // the same seats or the row lies about what attach will find.
    assert_eq!(TRACEFS_PRIMARY, "/sys/kernel/tracing");
    assert_eq!(TRACEFS_FALLBACK, "/sys/kernel/debug/tracing");
    assert_eq!(BPFFS_DIR, "/sys/fs/bpf");
}
