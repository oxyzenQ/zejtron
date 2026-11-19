// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// zejtron eBPF probe, the open and writev programs - the entry side
// of the file lane, in their own module under the 600-LOC no-mercy
// cap (night-frontier-Z8, a PURE move of the two probes
// night-improve-3 and night-improve-42 planted; the exits.rs/write.rs
// precedent: a dedicated module beside the seven, same crate, same
// single-sourced record contract, same license law).
//
// The walks, the filter map, and the records they publish are
// unchanged: vfs_open hands the open probe the path being bound, and
// vfs_writev hands the writev probe the file the vectorized writes
// funnel into - the same BTF-verified hops, the same tracked_inodes
// gate, and (night-frontier-Z8, D5) the same identity block in every
// record.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
};

use super::{count_ring_drop, read_offset_set, read_ptr_at, read_u32_at, read_u64_at};
use crate::events::{
    DROP_SLOT_FILE, FILE_OP_OPEN, FILE_OP_WRITEV, OFF_SLOT_DENTRY_D_INODE, OFF_SLOT_FILE_F_INODE,
    OFF_SLOT_FILE_F_PATH, OFF_SLOT_INODE_I_INO, OFF_SLOT_PATH_DENTRY, OFF_SLOT_PATH_MNT,
    OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_VFSMOUNT_MNT_SB, device_token_from_kernel,
    pack_filter_key,
};
use crate::{events::FileEvent, file_events, identity, tracked_inodes};

/// The open probe: vfs_open hands the program the path being bound to
/// a file. The walk: path->dentry->d_inode for the inode,
/// path->mnt->mnt_sb->s_dev for the device; the filter map decides
/// whether the event is worth a ring slot; the record carries the
/// acting process's pid (bpf_get_current_pid_tgid's tgid half).
///
/// Every aya-ebpf call inside is an `unsafe fn` (ctx arg reads, probe
/// reads, the ktime and pid helpers) — the unsafe block is that API
/// contract, nothing more.
#[kprobe(function = "vfs_open")]
pub fn open_probe(ctx: ProbeContext) -> u32 {
    // SAFETY: the context is read through aya's ctx.arg probe-read
    // and fixed-register volatile loads (the pinned-offset shape the
    // unlink probe documents at length), every kernel hop goes
    // through the probe-read helpers (a bad address returns None,
    // never a fault), every offset comes from the BTF-verified
    // offsets map written at attach, and the verifier re-proves the
    // whole body at load time.
    unsafe {
        // arg0: const struct path * — extraction failure drops the
        // event (never fail the probed path).
        let Some(path) = ctx.arg::<u64>(0) else {
            return 0;
        };
        let path = path as usize;
        if path == 0 {
            return 0;
        }
        let Some(o) = read_offset_set() else { return 0 };

        let Some(dentry) = read_ptr_at(path, o[OFF_SLOT_PATH_DENTRY as usize]) else {
            return 0;
        };
        let Some(inode) = read_ptr_at(dentry, o[OFF_SLOT_DENTRY_D_INODE as usize]) else {
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            return 0;
        };
        let Some(mnt) = read_ptr_at(path, o[OFF_SLOT_PATH_MNT as usize]) else {
            return 0;
        };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else {
            return 0;
        };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else {
            return 0;
        };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            // Not the file anyone asked about — this is the whole
            // price control: the check happens in the kernel, before
            // a single byte of ring traffic is spent.
            return 0;
        }

        // night-frontier-Z1: a failed reservation counts in the drop
        // census (the file-events slot - five probes share the one
        // ring), never silent. The identity block (night-frontier-Z8,
        // D5) rides the same record: cgroup id, comm, netns inode.
        let actor = identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op: FILE_OP_OPEN,
                    _pad: [0; 7],
                    inode: ino,
                    device,
                    pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                    _pad2: 0,
                    cgroup_id: actor.cgroup_id,
                    comm: actor.comm,
                    netns_inum: actor.netns_inum,
                    _pad3: 0,
                },
                0,
            )
            .is_err()
        {
            count_ring_drop(DROP_SLOT_FILE);
        }
    }
    0
}

/// The writev probe (night-improve-42, the false-negative closer):
/// vfs_writev hands the program the file being written through the
/// vectorized path - the shape writev(2)/pwritev(2)/pwritev2(2) all
/// funnel into (arg0: struct file *, the same contract as the write
/// probe, verified from the host's own BTF at attach by the loader).
/// The walk, the filter, and the record mirror the write probe; the op
/// is FILE_OP_WRITEV so the ledger names the write path that
/// crossed. The section name carries the primary symbol; the loader
/// attaches the BTF-verified one (vfs_writev, do_iter_write
/// fallback) - aya's kprobe attach takes its symbol as an argument,
/// the section only types the program.
#[kprobe(function = "vfs_writev")]
pub fn writev_probe(ctx: ProbeContext) -> u32 {
    // SAFETY: the same contract as the open probe: aya probe-reads
    // and fixed-register volatile loads on the context, every kernel
    // hop through the probe-read helpers (a bad address returns
    // None, never a fault), BTF-verified offsets from the attach-time
    // map, and the verifier re-proves the whole body at load time.
    unsafe {
        // arg0: struct file * (BTF-verified at attach).
        let Some(file) = ctx.arg::<u64>(0) else {
            return 0;
        };
        let file = file as usize;
        if file == 0 {
            return 0;
        }
        let Some(o) = read_offset_set() else { return 0 };

        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else {
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            return 0;
        };
        let f_path = file.wrapping_add(o[OFF_SLOT_FILE_F_PATH as usize] as usize);
        let Some(mnt) = read_ptr_at(f_path, o[OFF_SLOT_PATH_MNT as usize]) else {
            return 0;
        };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else {
            return 0;
        };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else {
            return 0;
        };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            return 0;
        }

        // night-frontier-Z1: the writev probe's reservation failure
        // counts in the same file-events drop slot, never silent.
        // The identity block (night-frontier-Z8, D5) rides the same
        // record: cgroup id, comm, netns inode.
        let actor = identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op: FILE_OP_WRITEV,
                    _pad: [0; 7],
                    inode: ino,
                    device,
                    pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                    _pad2: 0,
                    cgroup_id: actor.cgroup_id,
                    comm: actor.comm,
                    netns_inum: actor.netns_inum,
                    _pad3: 0,
                },
                0,
            )
            .is_err()
        {
            count_ring_drop(DROP_SLOT_FILE);
        }
    }
    0
}
