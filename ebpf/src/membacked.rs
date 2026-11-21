// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! zejtron eBPF probe, the memory-backed write program (night-
//! frontier-Z9, D6 - the dedicated module under the 600-LOC no-mercy
//! cap, the exits.rs/write.rs/unlink.rs precedent): the third rung of
//! the off-path estate, closing the Z7 residual the dirty anchors
//! cannot reach. A store through a MAP_SHARED mapping on a
//! tmpfs/ramfs file (memfd rides tmpfs's superblock class) never
//! dirties through the writeback path - the kernel skips the dirty
//! call for no-writeback mappings - so the fault path itself is the
//! only mechanism the store crosses. The anchor is the shared-write
//! fault funnel: `fault_dirty_shared_page(struct vm_fault *)` on the
//! 5.15-6.8 dialects (both fault arms behind one symbol), the
//! surviving `wp_page_shared(struct vm_fault *)` arm on the 7.x line
//! (the non-present arm is inlined past any symbol there - a PARTIAL
//! coverage the attach summary names; the corpus pins the ladder's
//! verdict per dialect). The probe's gate is the kernel's own
//! registration table, read at event time: the superblock's
//! registered filesystem name must be a memory-backed one - data,
//! never a compiled guess, and the reason a regular file's fault
//! (which ALSO crosses this funnel) stays silent here while the dirty
//! anchor records it: one store, one record, whichever class the
//! kernel put the file in. Walk: vm_fault.page (the BTF-derived hop)
//! -> page.mapping -> mapping.host -> the tracked_inodes gate, then
//! the class gate, then the op=10 record - cost bounded by QUESTIONS
//! as always. Record-verified at attach with a real memfd store (the
//! verify_offpath door); a host that cannot demonstrate its own
//! record carries the capability named down. THE INLINE LAW (found
//! live by the C77 root leg): every walk is #[inline(always)] - a
//! bpf2bpf call into .text leaves an unresolved pseudo-call at
//! BPF_PROG_LOAD.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes},
    macros::kprobe,
    programs::ProbeContext,
};

use super::{count_ring_drop, read_ptr_at, read_u32_at, read_u64_at, tracked_inodes};
use crate::events::{
    device_token_from_kernel, pack_filter_key, FileEvent, FILE_OP_MMAP_MEMBACKED,
    OFF_SLOT_ADDR_SPACE_HOST, OFF_SLOT_FS_TYPE_NAME, OFF_SLOT_INODE_I_INO, OFF_SLOT_INODE_I_SB,
    OFF_SLOT_PAGE_MAPPING, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_SUPER_BLOCK_S_TYPE,
    OFF_SLOT_VM_FAULT_PAGE, DROP_SLOT_FILE,
};
use crate::file_events;

/// The memory-backed class gate's own vocabulary: the registered
/// filesystem names the gate serves (tmpfs covers memfd_create and
/// /dev/shm; ramfs covers the initramfs/rootfs shapes). The list is
/// the capability's own named coverage - a filesystem outside it
/// stays outside the record class, named, never guessed. The string
/// helper returns the bytes UP TO the NUL, so the names compare
/// without it.
const MEMBACKED_TMPFS: &[u8] = b"tmpfs";
const MEMBACKED_RAMFS: &[u8] = b"ramfs";

/// The mapping low-bit guard: an anon/ksm page's mapping carries
/// PAGE_MAPPING flags in the low bits (anon=1, ksm=2) - not an
/// address_space, and descending it would read garbage. A page-cache
/// mapping is a clean pointer. The offpath module's own guard,
/// restated here (the write.rs walk-restated precedent): three
/// lines, one ABI fact - the kernel puts the flag bits in the
/// pointer itself.
fn mapping_is_page_cache(mapping: usize) -> bool {
    mapping != 0 && (mapping & 0b11) == 0
}

/// The memory-backed publish walk (night-frontier-Z9, D6): the
/// vm_fault (arg0 of the shared-write-fault anchor) through the page
/// to its mapping, the backing inode, the tracked_inodes gate, then
/// the class gate - the superblock's registered filesystem name must
/// be a memory-backed one (tmpfs/ramfs), read through
/// bpf_probe_read_kernel_str_bytes at event time. A regular file's
/// fault (which crosses the same funnel) fails the class gate here
/// and is the dirty anchor's record instead: one store, one record.
/// A failed hop or a failed reservation drops silently into the same
/// named channels every probe in this crate rides.
#[inline(always)]
unsafe fn membacked_publish(vmf: usize) -> u32 {
    // SAFETY: every dereference goes through the probe-read helpers
    // (a bad address returns None, never a fault) with offsets from
    // the BTF-verified offsets map the host wrote at attach; the
    // verifier re-proves the whole body at load time.
    unsafe {
        let Some(o) = super::read_offset_set() else {
            return 0;
        };
        let Some(page) = read_ptr_at(vmf, o[OFF_SLOT_VM_FAULT_PAGE as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let Some(mapping) =
            read_ptr_at(page, o[OFF_SLOT_PAGE_MAPPING as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        if !mapping_is_page_cache(mapping) {
            return 0;
        }
        let Some(inode) =
            read_ptr_at(mapping, o[OFF_SLOT_ADDR_SPACE_HOST as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            return 0;
        };
        let Some(sb) = read_ptr_at(inode, o[OFF_SLOT_INODE_I_SB as usize]).filter(|p| *p != 0)
        else {
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
        // The class gate: the superblock's registered filesystem name,
        // read through the kernel's own string helper (NUL-terminated,
        // truncated to the buffer). "tmpfs" or "ramfs" is the
        // memory-backed class; anything else (ext4, xfs, overlayfs,
        // bdev) rides the writeback path and is the dirty anchor's
        // record, never this one.
        let Some(fst) =
            read_ptr_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_TYPE as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let Some(name_ptr) =
            read_ptr_at(fst, o[OFF_SLOT_FS_TYPE_NAME as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let mut name = [0u8; 8];
        let Ok(filled) = bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, &mut name) else {
            return 0;
        };
        if !filled.starts_with(MEMBACKED_TMPFS) && !filled.starts_with(MEMBACKED_RAMFS) {
            return 0;
        }
        // The identity block (night-frontier-Z8, D5) rides the same
        // record: cgroup id, comm, netns inode.
        let actor = super::identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op: FILE_OP_MMAP_MEMBACKED,
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

/// The memory-backed fault probe (night-frontier-Z9, D6): the
/// shared-write-fault anchor the ladder vouches for
/// (fault_dirty_shared_page on the 5.15-6.8 dialects, the surviving
/// wp_page_shared arm on the 7.x line - arg0 is the vm_fault on
/// every dialect the corpus carries, so ONE program serves the
/// ladder; the section name carries the primary symbol, the loader
/// attaches the BTF-verified one - the writev probe's precedent).
#[kprobe(function = "fault_dirty_shared_page")]
pub fn membacked_fault_probe(ctx: ProbeContext) -> u32 {
    // SAFETY: aya's ctx.arg is a probe-read of the kprobe context at
    // a fixed register slot (a bad read returns None, never a fault);
    // the walk below re-proves itself at load time.
    unsafe {
        let Some(vmf) = ctx.arg::<u64>(0) else {
            return 0;
        };
        membacked_publish(vmf as usize)
    }
}
