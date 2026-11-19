// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! zejtron eBPF probe, the off-path write programs (night-frontier-
//! Z7, D4): the dedicated module under the 600-LOC no-mercy cap (the
//! write.rs/unlink.rs precedent) that closes the largest forensic gap
//! this estate has ever named - the README Limitations line that
//! stood for eras: "They do not see mmap'd writes, async kiocb
//! (io_uring/AIO), splice-class copies."
//!
//! THREE CLASSES, FIVE PROGRAMS, ONE RING (file_events, the same
//! record the five file probes carry):
//!
//! 1. mmap writes. A memory store through a MAP_SHARED mapping
//!    crosses no syscall at all - the attacker's favorite because
//!    every kprobe write camera watches write(2). The kernel's own
//!    page-dirtying path is the truth: a write fault dirties the
//!    page, and the dirty carries the mapping chain to the backing
//!    inode. Two anchor shapes, chosen from the host's own BTF at
//!    attach (the loader plants exactly one):
//!    - `filemap_dirty_folio(struct address_space *, struct folio *)`
//!      - the folio-shape kernels (5.16+): arg0 IS the mapping,
//!      BTF-vouched at attach, so the walk starts there;
//!    - `__set_page_dirty_nobuffers(struct page *)` - the page-shape
//!      kernels (the folio-less line, 5.15 and older): arg0 is the
//!      page, and page.mapping is the one hop to the mapping.
//!    Both walk mapping->host (the backing inode) through the
//!    BTF-verified offsets map, then the tracked_inodes gate - the
//!    cost of a "expensive-looking" page-dirty probe is bounded by
//!    QUESTIONS, not by host activity: only the files an operator is
//!    asking about answer. The residual the Z7 estate named here -
//!    tmpfs/ramfs files keep no clean page to dirty (their aops never
//!    call either anchor), so an mmap write to a memory-backed file
//!    stayed outside the record class - is night-frontier-Z9's
//!    subject: the memory-backed rung below closes it.
//!
//! 1b. The memory-backed rung (night-frontier-Z9, D6). A store
//!     through a MAP_SHARED mapping on a tmpfs/ramfs file (memfd
//!     rides tmpfs's superblock class) never dirties through the
//!     writeback path - the kernel skips the dirty call for
//!     no-writeback mappings - so the fault path itself is the only
//!     mechanism the store crosses. The anchor is the shared-write
//!     fault funnel: `fault_dirty_shared_page(struct vm_fault *)` on
//!     the 5.15-6.8 dialects (both fault arms behind one symbol),
//!     the surviving `wp_page_shared(struct vm_fault *)` arm on the
//!     7.x line (the non-present arm is inlined past any symbol
//!     there - a PARTIAL coverage the attach summary names; the
//!     corpus pins the ladder's verdict per dialect). The probe's
//!     gate is the kernel's own registration table, read at event
//!     time: inode->i_sb->s_type->name must be "tmpfs" or "ramfs" -
//!     data, never a compiled guess, and the reason a regular file's
//!     fault (which ALSO crosses this funnel) stays silent here
//!     while the dirty anchor records it: one store, one record,
//!     whichever class the kernel put the file in. Walk:
//!     vm_fault.page (the BTF-derived hop) -> page.mapping ->
//!     mapping.host -> the tracked_inodes gate, then the class gate,
//!     then the op=10 record - cost bounded by QUESTIONS as always.
//!     Record-verified at attach with a real memfd store (the
//!     verify_offpath door); a host that cannot demonstrate its own
//!     record carries the capability named down.
//!
//! 2. splice-class copies. splice(2) moves bytes between descriptors
//!    without any write(2) on the receiving side - the copy and
//!    exfiltration half the write-class probes never see. The probe
//!    rides raw_syscalls/sys_enter - the SAME tracepoint the write
//!    probe uses, the one mechanism with zero observed failures
//!    across the whole estate - filtered to __NR_splice (275, the
//!    x86_64 ABI), resolving BOTH descriptors through the same
//!    BTF-verified fd-table walk (task_struct->files->fdt->fd[fd],
//!    the four slots night-improve-57 appended). The tracked side
//!    names the direction: fd_out tracked is a splice INTO the file
//!    (op=7), fd_in tracked is a splice OUT OF it (op=8). vmsplice
//!    stays the named residual (its direction is flags-dependent,
//!    not descriptor-shaped).
//!
//! 3. io_uring writes. Async kiocb writes call call_write_iter
//!    directly and cross NEITHER write probe - the named residual
//!    since night-improve-42. The probe rides the
//!    io_uring:io_uring_submit_sqe tracepoint (available 5.5+; the
//!    camera floor is 5.15, and a host without the tracepoint - a
//!    kernel built without io_uring event tracing - refuses the
//!    CAPABILITY by name at attach, never the whole camera). The
//!    trace-event ABI's fixed layout gives the submitted io_kiocb
//!    pointer; io_kiocb.file and io_kiocb.opcode are BTF-walked per
//!    host (a kernel whose io_kiocb carries neither under a
//!    verifiable shape leaves the capability unplanted, named); the
//!    opcode filter keeps the write-class only (IORING_OP_WRITEV=2,
//!    WRITE_FIXED=4, WRITE=23 - the liburing ABI numbers), so a
//!    tracked file's async READ never renders as a write. The record
//!    fires at submission, in the submitting task's context: for an
//!    io-wq offload the row's pid IS the worker that drove the kernel
//!    path - named as such in the row's vocabulary.
//!
//! EVERY hop reads its offset from the offsets map (written at
//! attach from the host's own BTF); every memory read is a probe
//! read (a bad address drops the event, never faults the kernel
//! path); every record is gated by tracked_inodes BEFORE a byte of
//! ring traffic is spent; a failed reservation counts in the
//! file-events drop slot (night-frontier-Z1's law, one ring, one
//! census). The record-verify door (verify_offpath.rs) applies to
//! every capability: an anchor that cannot record one real mmap
//! write, one real splice, one real io_uring write is unplanted and
//! NAMED - the silent-anchor class cannot survive attach, anywhere.
//!
//! THE INLINE LAW (found live by the C77 root leg): the shared walk
//! helpers are `#[inline(always)]` because a bpf2bpf call into .text
//! leaves an unresolved pseudo-call at BPF_PROG_LOAD - the 5.15
//! runner's verifier refused the splice probe with EPERM while the
//! log stopped at instruction zero (aya 0.16 loads each program's
//! own section alone). The estate's own probes are inline-only for
//! the same reason; this module now carries the same discipline, and
//! the cost table's per-program counts prove it (no 4-instruction
//! call stubs, no shared-text growth).

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, tracepoint},
    programs::{ProbeContext, TracePointContext},
};

use super::{count_ring_drop, read_ptr_at, read_u32_at, read_u64_at, tracked_inodes};
use crate::events::{
    DROP_SLOT_FILE, FILE_OP_IO_URING_WRITE, FILE_OP_MMAP_DIRTY, FILE_OP_SPLICE_IN,
    FILE_OP_SPLICE_OUT, FileEvent, OFF_SLOT_ADDR_SPACE_HOST, OFF_SLOT_FDT_FD,
    OFF_SLOT_FDT_MAX_FDS, OFF_SLOT_FILE_F_INODE, OFF_SLOT_FILE_F_PATH, OFF_SLOT_FILES_FDT,
    OFF_SLOT_INODE_I_INO, OFF_SLOT_INODE_I_SB, OFF_SLOT_IO_KIOCB_FILE, OFF_SLOT_PAGE_MAPPING,
    OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_TASK_FILES, OFF_SLOT_VFSMOUNT_MNT_SB,
    device_token_from_kernel, pack_filter_key,
};
use crate::file_events;

// The sys_enter record layout - the trace-event ABI's own fixed
// prefix (the write.rs constants, restated here: one ABI, two
// filters, the same class of stable constant).
/// args[0] - splice's fd_in (offset 16).
const SYS_ENTER_ARG0: usize = 16;
/// args[2] - splice's fd_out (offset 32).
const SYS_ENTER_ARG2: usize = 32;
/// __NR_splice on x86_64 - the ABI itself, not a kernel fact.
const NR_SPLICE: i64 = 275;
/// The io_uring_submit_sqe trace-event layout: the 8-byte
/// trace_entry header, then the request pointer at 16 and the opcode
/// at 24 - the field order the tracepoint has carried since 5.5
/// (ctx at 8, req at 16, opcode at 24; the later fields - user_data,
/// force_nonblock - moved AFTER these three, never before them).
const IOURING_CTX_REQ: usize = 16;
const IOURING_CTX_OPCODE: usize = 24;
/// The write-class io_uring opcodes (the liburing ABI): WRITEV=2,
/// WRITE_FIXED=4, WRITE=23. A tracked file's async READ never
/// renders as a write.
const IORING_OP_WRITEV: u8 = 2;
const IORING_OP_WRITE_FIXED: u8 = 4;
const IORING_OP_WRITE: u8 = 23;

/// The mapping low-bit guard: an anon/ksm page's mapping carries
/// PAGE_MAPPING flags in the low bits (anon=1, ksm=2) - not an
/// address_space, and descending it would read garbage. A page-cache
/// mapping is a clean pointer. The guard is the data-driven shape
/// check, not a hardcoded offset: the kernel puts the flag bits in
/// the pointer itself, by ABI.
fn mapping_is_page_cache(mapping: usize) -> bool {
    mapping != 0 && (mapping & 0b11) == 0
}

/// The dirty-path publish walk, shared by both anchor shapes: the
/// mapping (arg0 of the folio anchor, page.mapping of the page
/// anchor) to its backing inode, the tracked_inodes gate, and the
/// op=6 record. A failed hop drops the event (a passive probe never
/// fails the path it rides); a failed reservation counts in the
/// file-events drop slot.
#[inline(always)]
unsafe fn dirty_publish(mapping: usize) -> u32 {
    if !mapping_is_page_cache(mapping) {
        return 0;
    }
    // SAFETY: every dereference goes through the probe-read helpers
    // (a bad address returns None, never a fault) with offsets from
    // the BTF-verified offsets map the host wrote at attach; the
    // verifier re-proves the whole body at load time.
    unsafe {
        let Some(o) = super::read_offset_set() else {
            return 0;
        };
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
        // The identity block (night-frontier-Z8, D5) rides the same
        // record: cgroup id, comm, netns inode.
        let actor = super::identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op: FILE_OP_MMAP_DIRTY,
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

/// The mmap-dirty probe, folio shape (night-frontier-Z7, D4):
/// `filemap_dirty_folio(struct address_space *, struct folio *)` -
/// arg0 IS the mapping, BTF-vouched at attach (btf_offpath.rs scans
/// the FUNC prototype; a shape that moved refuses by name). The
/// section name carries the primary symbol; the loader attaches the
/// BTF-verified one - the writev probe's precedent (the section
/// types the program, the attach selects the event).
#[kprobe(function = "filemap_dirty_folio")]
pub fn dirty_folio_probe(ctx: ProbeContext) -> u32 {
    // SAFETY: aya's ctx.arg is a probe-read of the kprobe context at
    // a fixed register slot (a bad read returns None, never a fault);
    // the walk below re-proves itself at load time.
    unsafe {
        let Some(mapping) = ctx.arg::<u64>(0) else {
            return 0;
        };
        dirty_publish(mapping as usize)
    }
}

/// The mmap-dirty probe, page shape (night-frontier-Z7, D4):
/// `__set_page_dirty_nobuffers(struct page *)` - the folio-less
/// kernels' anchor. arg0 is the page; page.mapping (the
/// OFF_SLOT_PAGE_MAPPING hop, BTF-derived per host) is the one hop
/// to the mapping; the anon/ksm low-bit guard keeps the descent on
/// page-cache mappings only.
#[kprobe(function = "__set_page_dirty_nobuffers")]
pub fn dirty_page_probe(ctx: ProbeContext) -> u32 {
    // SAFETY: the same contract as the folio shape: a probe-read
    // context read, BTF-verified offsets, probe-read hops, and the
    // verifier's load-time proof over the whole body.
    unsafe {
        let Some(page) = ctx.arg::<u64>(0) else {
            return 0;
        };
        let Some(o) = super::read_offset_set() else {
            return 0;
        };
        let Some(mapping) = read_ptr_at(page as usize, o[OFF_SLOT_PAGE_MAPPING as usize]) else {
            return 0;
        };
        dirty_publish(mapping)
    }
}

/// The memory-backed fault probe rides its own dedicated module
/// (ebpf/src/membacked.rs, the exits.rs/write.rs precedent at the
/// 600-LOC no-mercy cap): night-frontier-Z9, D6 - the shared-write
/// fault funnel anchors the tmpfs/ramfs/memfd mmap-store truth, the
/// class gate reading the superblock's registered filesystem name at
/// event time. The ladder, the slots, and the record-verified memfd
/// door live with it.

/// Resolve one fd through the caller's descriptor table - the
/// write.rs walk, restated compactly (the same four BTF-verified
/// slots: task_struct.files, files_struct.fdt, fdtable.max_fds,
/// fdtable.fd). Returns the struct file address, `None` on any
/// failed hop (a bad fd, an unreadable table - the event drops,
/// never the kernel path).
#[inline(always)]
unsafe fn resolve_fd(fd: u64) -> Option<usize> {
    // SAFETY: bpf_get_current_task is a helper call the verifier
    // types; every dereference is a probe read bounded by the
    // BTF-verified offsets map; the fd is bounds-checked against
    // max_fds before the fd array is indexed.
    unsafe {
        let o = super::read_offset_set()?;
        let task = aya_ebpf::helpers::bpf_get_current_task() as usize;
        let files = read_ptr_at(task, o[OFF_SLOT_TASK_FILES as usize]).filter(|p| *p != 0)?;
        let fdt = read_ptr_at(files, o[OFF_SLOT_FILES_FDT as usize]).filter(|p| *p != 0)?;
        let max_fds = read_u32_at(fdt, o[OFF_SLOT_FDT_MAX_FDS as usize])?;
        if fd >= u64::from(max_fds) {
            return None;
        }
        let fd_array = read_ptr_at(fdt, o[OFF_SLOT_FDT_FD as usize]).filter(|p| *p != 0)?;
        read_ptr_at(fd_array, fd * 8).filter(|p| *p != 0)
    }
}

/// One splice record for one resolved file: the inode/device walk
/// (file->f_inode / file->f_path.mnt->mnt_sb - the writev probe's
/// shape), the filter map, and the direction-named record. Returns
/// 0 always (a passive probe never fails the path).
#[inline(always)]
unsafe fn splice_publish(file: usize, op: u8) -> u32 {
    // SAFETY: the same probe-read contract as every walk in this
    // crate: offsets from the attach-time map, probe reads that
    // return None on bad addresses, the verifier's load-time proof.
    unsafe {
        let Some(o) = super::read_offset_set() else {
            return 0;
        };
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
        // The identity block (night-frontier-Z8, D5) rides the same
        // record: cgroup id, comm, netns inode.
        let actor = super::identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op,
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

/// The splice probe (night-frontier-Z7, D4): the write probe's own
/// tracepoint, filtered to splice(2), both descriptors resolved, the
/// tracked side naming the direction (fd_out tracked = INTO, op=7;
/// fd_in tracked = OUT OF, op=8). A file that is on BOTH ends
/// records both directions - the grammar carries the truth either
/// way.
#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn splice_probe(ctx: TracePointContext) -> u32 {
    // SAFETY: aya's TracePointContext::read_at is a probe-read of the
    // tracepoint context at compile-time-constant offsets (Err on a
    // bad offset, never a fault); the fd walks and the publish walk
    // re-prove themselves at load time.
    unsafe {
        let id: i64 = match ctx.read_at::<i64>(8) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        if id != NR_SPLICE {
            return 0;
        }
        let fd_in: u64 = match ctx.read_at::<u64>(SYS_ENTER_ARG0) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let fd_out: u64 = match ctx.read_at::<u64>(SYS_ENTER_ARG2) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        // Both descriptors resolve: fd_out tracked is a splice INTO
        // the tracked file (op 7), fd_in tracked is the content
        // moving AWAY from it (op 8, the exfiltration shape); a file
        // on both ends records both directions.
        if let Some(file) = resolve_fd(fd_out) {
            splice_publish(file, FILE_OP_SPLICE_IN);
        }
        if let Some(file) = resolve_fd(fd_in) {
            splice_publish(file, FILE_OP_SPLICE_OUT);
        }
    }
    0
}

/// The io_uring probe (night-frontier-Z7, D4): the
/// io_uring:io_uring_submit_sqe tracepoint, the submitted io_kiocb
/// descended to its struct file (BTF-walked per host), the write-
/// class opcode filter, the tracked_inodes gate, the op=9 record at
/// submission. A host without the tracepoint never gets here - the
/// capability refuses by name at attach.
#[tracepoint(category = "io_uring", name = "io_uring_submit_sqe")]
pub fn iouring_probe(ctx: TracePointContext) -> u32 {
    // SAFETY: probe-reads of the tracepoint context at the fixed ABI
    // offsets (the constants above, the sock probe's verified-layout
    // class), then the same BTF-verified walk discipline as every
    // program in this crate; the verifier re-proves the whole body
    // at load time.
    unsafe {
        let opcode: u8 = match ctx.read_at::<u8>(IOURING_CTX_OPCODE) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        if opcode != IORING_OP_WRITEV
            && opcode != IORING_OP_WRITE_FIXED
            && opcode != IORING_OP_WRITE
        {
            return 0;
        }
        let req: usize = match ctx.read_at::<usize>(IOURING_CTX_REQ) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        if req == 0 {
            return 0;
        }
        let Some(o) = super::read_offset_set() else {
            return 0;
        };
        let Some(file) = read_ptr_at(req, o[OFF_SLOT_IO_KIOCB_FILE as usize]).filter(|p| *p != 0)
        else {
            return 0;
        };
        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else {
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            return 0;
        };
        // The device hop rides the file's own path (the writev
        // probe's shape): file->f_path.mnt->mnt_sb->s_dev.
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
        // The identity block (night-frontier-Z8, D5) rides the same
        // record: cgroup id, comm, netns inode.
        let actor = super::identity::actor_identity(Some(&o));
        if file_events
            .output::<FileEvent>(
                &FileEvent {
                    timestamp_ns: bpf_ktime_get_ns(),
                    op: FILE_OP_IO_URING_WRITE,
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
