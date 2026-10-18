// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! FileEvent contract pins (night-improve-3): the 40-byte layout,
//! every offset, the filter key packing, the device-token
//! cross-encoding proof (st_dev and s_dev are two encodings of one
//! (major, minor) pair - both sides must land on the same canonical
//! integer or the filter never matches), the op numbering, the
//! offsets slot indices. Wired from src/ebpf/events.rs.

use super::*;
use crate::commands::lane::device_token_from_stat;
use core::mem::offset_of;
use std::os::unix::fs::MetadataExt;

#[test]
fn file_event_is_exactly_40_bytes() {
    assert_eq!(FILE_EVENT_BYTES, 40);
    assert_eq!(core::mem::size_of::<FileEvent>(), 40);
}

#[test]
fn file_event_offsets_are_pinned_field_by_field() {
    assert_eq!(offset_of!(FileEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(FileEvent, op), 8);
    assert_eq!(offset_of!(FileEvent, _pad), 9);
    assert_eq!(offset_of!(FileEvent, inode), 16);
    assert_eq!(offset_of!(FileEvent, device), 24);
    assert_eq!(offset_of!(FileEvent, pid), 32);
    assert_eq!(offset_of!(FileEvent, _pad2), 36);
}

#[test]
fn op_numbering_is_open_write_unlink() {
    assert_eq!(FILE_OP_OPEN, 1);
    assert_eq!(FILE_OP_WRITE, 2);
    // Reserved (the vfs_unlink skip is named in the module docs);
    // the numbering never renumbers.
    assert_eq!(FILE_OP_UNLINK, 3);
}

#[test]
fn pack_filter_key_is_inode_shifted_32_or_device_low_32() {
    // The spec's packing, pinned: (inode << 32) | device.
    assert_eq!(pack_filter_key(0x1234, 0x5678), 0x1234_0000_5678);
    // The device half masks to its low 32 bits (majors > 4095, none
    // in mainline use, compare like every other device).
    assert_eq!(pack_filter_key(1, 0x1_0000_0002), (1u64 << 32) | 2);
    // Inodes >= 2^32 alias into the low half - the named residual;
    // the full identity rides the record and the host mirror drops
    // mismatches, so an alias wastes ring space, never renders wrong.
    assert_eq!(pack_filter_key(0x1_0000_0001, 0x22), (1u64 << 32) | 0x22);
}

#[test]
fn device_tokens_cross_encodings_to_one_canonical_integer() {
    // The classic sda2 shape: the kernel's s_dev is (8 << 20) | 2 =
    // 0x800002; the userspace st_dev glibc reports is 0x802. Both
    // encodings of one (major 8, minor 2) pair must land on the
    // same canonical token or the kernel's filter key and the
    // host's query key would never meet.
    assert_eq!(device_token_from_kernel(0x800002), 0x800002);
    assert_eq!(device_token_from_stat(0x802), 0x800002);
    assert_eq!(
        device_token_from_stat(0x802),
        device_token_from_kernel(0x800002)
    );

    // A big-minor pair (major 259, minor 12): the userspace value
    // (259 << 8) | 12 = 0x1030c; the kernel form (259 << 20) | 12.
    let st_dev: u64 = (259u64 << 8) | 12;
    let s_dev: u32 = (259u32 << 20) | 12;
    assert_eq!(device_token_from_stat(st_dev), u64::from(s_dev));
}

#[test]
fn device_token_from_stat_matches_a_real_stat_call() {
    // On a live host the token must equal what the BPF side would
    // read from the superblock: assert the decode against an actual
    // stat(2) of / (or skip when / is unreadable - CI sandboxes
    // without a root mount).
    let Ok(meta) = std::fs::metadata("/") else {
        return;
    };
    let token = device_token_from_stat(meta.dev());
    // The token is the kernel form (major << 20) | minor: major
    // under 4096, minor under 2^20 - the plausibility bounds that
    // also hold on the owner host.
    let major = token >> 20;
    let minor = token & 0xFFFFF;
    assert!(major < 4096, "major {major} out of range");
    assert!(minor < 1 << 20);
    // And the encode back: the userspace value for that pair
    // round-trips to the same st_dev stat reported.
    let round_trip = (major << 8) | (minor & 0xff) | ((minor & !0xffu64) << 12);
    assert_eq!(round_trip, meta.dev() & 0xFFFF_FFFF, "st_dev round-trip");
}

#[test]
fn offsets_slots_are_indices_zero_through_seven() {
    assert_eq!(OFF_SLOT_DENTRY_D_INODE, 0);
    assert_eq!(OFF_SLOT_INODE_I_INO, 1);
    assert_eq!(OFF_SLOT_FILE_F_PATH, 2);
    assert_eq!(OFF_SLOT_FILE_F_INODE, 3);
    assert_eq!(OFF_SLOT_VFSMOUNT_MNT_SB, 4);
    assert_eq!(OFF_SLOT_SUPER_BLOCK_S_DEV, 5);
    assert_eq!(OFF_SLOT_PATH_MNT, 6);
    assert_eq!(OFF_SLOT_PATH_DENTRY, 7);
    assert_eq!(OFF_SLOTS, 8);
}
