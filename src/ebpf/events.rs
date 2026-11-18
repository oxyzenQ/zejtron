// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The socket-event record - the layout contract between the BPF
//! program and the userspace reader (night-improve-2, the zylaxion
//! args.rs single-sourcing discipline: the userspace crate owns this
//! file so its layout tests run in the gate lanes, and
//! ebpf/src/main.rs compiles the very same bytes via `#[path]` - one
//! struct, one truth, no drift between the kernel side that writes
//! the record and the host side that reads it).
//!
//! The layout is `repr(C)` natural alignment, and the field order is
//! chosen so the record holds every field in exactly 32 bytes: the
//! two u64s first (timestamp, socket address), then the narrowing
//! scalars, the pid last. Three pad bytes ride inside (offsets 21 and
//! 26..27); `core::mem::offset_of!` pins every offset in
//! test/ebpf/ringbuf_tests.rs so a field reorder cannot slip through
//! silently. The 32-byte size is the ring-buffer record size both
//! sides agree on - the kernel side's `output` call and the host
//! side's record-length check both carry it.
//!
//! Everything in this module is plain `core` Rust (no_std, no aya) so
//! the same bytes compile into the bpfel-unknown-none object and into
//! the host binary.

/// IPPROTO_TCP, the protocol number in the tracepoint record.
pub const IPPROTO_TCP: u8 = 6;

/// IPPROTO_UDP, the protocol number in the tracepoint record.
pub const IPPROTO_UDP: u8 = 17;

/// TCP_LISTEN from include/net/tcp_states.h - the state a TCP socket
/// enters when it starts accepting, and the state whose loss this
/// surface reports.
pub const TCP_LISTEN: u8 = 10;

/// TCP_CLOSE from include/net/tcp_states.h - for a UDP socket (whose
/// state is CLOSE for its whole bound life) the CLOSE transition is
/// the interesting one: the socket stopped existing.
pub const TCP_CLOSE: u8 = 7;

/// AF_INET - the IPv4 address family.
pub const AF_INET: u16 = 2;

/// AF_INET6 - the IPv6 address family.
pub const AF_INET6: u16 = 10;

/// One socket state change, as the kernel saw it at the moment it
/// happened: what the tracepoint recorded, not what a later snapshot
/// could infer. `timestamp_ns` is CLOCK_MONOTONIC
/// (`bpf_ktime_get_ns`) - the same clock the window arithmetic uses.
///
/// Offsets (repr(C), natural alignment, pinned by test):
/// timestamp_ns 0, skaddr 8, family 16, protocol 18, oldstate 19,
/// newstate 20, _pad 21, sport 22, dport 24, _pad2 26..27,
/// pid 28; total 32 bytes. The pads are EXPLICIT fields, the
/// FileEvent discipline: the ring record's every byte is written
/// by the probe constructor, because the 5.15 verifier (the
/// documented kernel floor, proven live by the kernel-floor
/// micro-VM lane) rejects an `output` read whose stack bytes were
/// never initialized - "invalid indirect read from stack" - while
/// newer verifiers tolerate the holes. A pad that rides implicit
/// is a pad a future field reorder can silently un-write.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockEvent {
    /// CLOCK_MONOTONIC nanoseconds at the state change.
    pub timestamp_ns: u64,
    /// The socket's kernel address - the identity that ties repeated
    /// transitions of one socket together across the window.
    pub skaddr: u64,
    /// AF_INET (2) or AF_INET6 (10).
    pub family: u16,
    /// IPPROTO_TCP (6) or IPPROTO_UDP (17).
    pub protocol: u8,
    /// The state before the transition (tcp_states.h numbering).
    pub oldstate: u8,
    /// The state after the transition (tcp_states.h numbering).
    pub newstate: u8,
    /// Padding to 2-byte alignment for `sport` (pinned by test at 21).
    pub _pad: u8,
    /// The local (source) port, host byte order - the tracepoint
    /// already applied ntohs.
    pub sport: u16,
    /// The remote (destination) port, host byte order.
    pub dport: u16,
    /// Padding to 4-byte alignment for `pid` (pinned by test at
    /// 26..27).
    pub _pad2: u16,
    /// The pid of the process whose syscall made the change (the
    /// tgid half of bpf_get_current_pid_tgid) - the truth the /proc
    /// snapshot cannot see: who changed it, not who holds it now.
    pub pid: u32,
}

/// The size of one ring-buffer record, in bytes - the number both the
/// kernel side's `output` call and the host side's record-length
/// check agree on.
pub const SOCK_EVENT_BYTES: usize = core::mem::size_of::<SockEvent>();

/// The port-surface filter, shared verbatim by the BPF program (the
/// in-kernel bound on ring traffic) and the host tests (the pinned
/// mirror). A busy host fires thousands of ESTABLISHED transitions
/// per second that no `port` user cares about; only LISTEN
/// enter/leave (TCP) and socket death (UDP) cross the ring:
///
/// - TCP: the transition INTO LISTEN (newstate == TCP_LISTEN) and
///   the transition OUT OF LISTEN (oldstate == TCP_LISTEN, any
///   other newstate);
/// - UDP: the transition to CLOSE (newstate == TCP_CLOSE) - a UDP
///   socket exists whenever bound, so its close is the change;
/// - every other protocol, and every non-INET family, is dropped.
///
/// This file carries ONLY what both sides share - the record and the
/// filter. The row-rendering helpers (the transition label, the
/// protocol+family token) live with the port surface, where they are
/// used; the BPF crate compiles this file and would flag them dead.
pub fn is_port_surface_event(family: u16, protocol: u8, oldstate: u8, newstate: u8) -> bool {
    if !matches!(family, AF_INET | AF_INET6) {
        return false;
    }
    match protocol {
        IPPROTO_TCP => newstate == TCP_LISTEN || oldstate == TCP_LISTEN,
        IPPROTO_UDP => newstate == TCP_CLOSE,
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────
// night-improve-3, the file-event contract (the Evidence Ledger pass).
// Same file, same discipline: the record, the filter key, the device
// tokens, and the offsets-map slot indices live here once, compiled
// into the bpfel object AND into the host binary through #[path] -
// one truth for both sides of the ring.
// ─────────────────────────────────────────────────────────────────────

/// `op` for FileEvent: a file was opened (the vfs_open kprobe fired
/// on the queried inode's path).
pub const FILE_OP_OPEN: u8 = 1;

/// `op` for FileEvent: a file was written (the syscall-anchored
/// write probe fired on the queried inode's file - night-improve-57:
/// the write(2) entry itself, not the inlinable interior).
pub const FILE_OP_WRITE: u8 = 2;

/// `op` for FileEvent: a file was unlinked. DEFINED at night-improve-3
/// but left unproduced there: the vfs_unlink kprobe was skipped - its
/// signature churned across the floor (mnt_userns prepended in 5.12
/// shifted dentry from arg1 to arg2, the idmap args landed in 6.x),
/// so no single compiled offset serves the floor-to-now range. The
/// gap stayed named in README Limitations while op=3 stayed reserved
/// so the record contract never renumbers. night-frontier-2 produces
/// it at last: the unlink probe's dentry argument position is derived
/// from the host's own BTF at attach (src/ebpf/btf_unlink.rs) and
/// rides the offsets map - the position is per-host data, not a
/// compiled constant, and a signature move re-derives instead of
/// misreading.
pub const FILE_OP_UNLINK: u8 = 3;

/// `op` for FileEvent: a file was written through the vectorized
/// path (the vfs_writev kprobe fired on the queried inode's file).
/// op=4, night-improve-42: the false-negative gap named in README
/// Limitations since phase 3 - a writev/pwritev write never crossed
/// vfs_write, so the ledger could read silent ("no writes") while a
/// vectorized writer was active on the file. writev(2), pwritev(2),
/// and pwritev2(2) all funnel through vfs_writev, so one op covers
/// the syscall family; the host-side label names the path ("writev")
/// so the row tells the operator WHICH write path crossed. The op
/// vocabulary renumbers never: 3 stays reserved for unlink.
pub const FILE_OP_WRITEV: u8 = 4;

/// `op` for FileEvent: a file was renamed (night-frontier-2): the
/// vfs_rename kprobe fired on the queried inode's file - the rename
/// half of the forensic pair (the ledger can now answer "who moved
/// it" beside "who deleted it"). The record carries the OLD dentry's
/// identity: at vfs_rename entry the file still sits at its old name,
/// so the (inode, device) the filter map knows is the old side's.
/// op=5, the vocabulary's sixth word; the numbering never renumbers.
pub const FILE_OP_RENAME: u8 = 5;

/// `op` for FileEvent: an mmap'd page of the file became dirty
/// (night-frontier-Z7, D4 - the off-path write truth): a memory
/// store through a MAP_SHARED mapping wrote the file WITHOUT any
/// write(2) crossing - the exact gap every kprobe write camera
/// (this one included, until now) renders as silence, and the gap a
/// real attacker writes through deliberately. The probe anchors the
/// kernel's own page-dirtying path (filemap_dirty_folio on folio
/// kernels, __set_page_dirty_nobuffers on the page-shape ones - the
/// anchor chosen from the host's own BTF at attach), descends the
/// mapping to the backing inode through BTF-walked offsets, and the
/// tracked_inodes gate keeps the cost bounded by questions, not by
/// host activity. The record carries the dirtying process's pid (the
/// write fault runs in the writer's context). Named residual: tmpfs/
/// ramfs-backed files keep no clean page to dirty (their aops never
/// call the anchors), so an mmap write to a memory-backed file stays
/// outside this record class - named in the README, never guessed at.
/// op=6, the vocabulary's seventh word.
pub const FILE_OP_MMAP_DIRTY: u8 = 6;

/// `op` for FileEvent: splice moved data INTO the file (night-
/// frontier-Z7, D4): splice(2) copied from another descriptor (a
/// pipe, another file) into the tracked file's descriptor - a copy
/// path that crosses no write(2) and no writev probe. The probe
/// rides raw_syscalls/sys_enter (the write probe's own tracepoint,
/// the zero-observed-failures anchor class), filters to __NR_splice,
/// resolves BOTH descriptors through the BTF-verified fd-table walk,
/// and records the tracked side. op=7, the vocabulary's eighth word.
pub const FILE_OP_SPLICE_IN: u8 = 7;

/// `op` for FileEvent: splice moved data OUT OF the file (night-
/// frontier-Z7, D4): splice(2) copied the tracked file's content
/// away - the exfiltration half of the copy-path truth, the
/// direction the write-class probes never saw because nothing wrote
/// the file. Same probe, same fd-table walk, the tracked side named.
/// op=8, the vocabulary's ninth word.
pub const FILE_OP_SPLICE_OUT: u8 = 8;

/// `op` for FileEvent: an io_uring write-class submission targeted
/// the file (night-frontier-Z7, D4): async kiocb writes call
/// call_write_iter directly and cross NEITHER write probe - the
/// named residual since night-improve-42. The probe rides the
/// io_uring:io_uring_submit_sqe tracepoint (availability-scanned per
/// host at attach; a kernel without it refuses the capability by
/// name, never guesses), descends the submitted io_kiocb to its
/// struct file through BTF-walked offsets, filters to the write-class
/// opcodes (IORING_OP_WRITEV / WRITE_FIXED / WRITE - the liburing ABI
/// numbers), and the tracked_inodes gate bounds the cost. The record
/// fires at submission; the acting pid is the submitting task (for
/// io-wq offload, the worker's own - the task that drove the kernel
/// path, named as such by the row). op=9, the vocabulary's tenth
/// word.
pub const FILE_OP_IO_URING_WRITE: u8 = 9;

/// One file action, as the kernel saw it at the moment it happened.
///
/// Offsets (repr(C), natural alignment, pinned by test):
/// timestamp_ns 0, op 8 (pad 9..16), inode 16, device 24, pid 32
/// (pad2 36..40); total 40 bytes.
///
/// `device` is the canonical device token - the kernel's dev_t
/// encoding (major << 20) | minor, the same integer the superblock's
/// s_dev carries - so the record, the filter key, and the host's
/// stat(2) all speak one number for one device.
///
/// `pid` is the tgid half of bpf_get_current_pid_tgid: the process
/// whose syscall made the change - the fact no snapshot can see.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileEvent {
    /// CLOCK_MONOTONIC nanoseconds at the action.
    pub timestamp_ns: u64,
    /// One of FILE_OP_OPEN / FILE_OP_WRITE / FILE_OP_UNLINK /
    /// FILE_OP_WRITEV / FILE_OP_RENAME.
    pub op: u8,
    /// Padding to 8-byte alignment (pinned by test at 9..16).
    pub _pad: [u8; 7],
    /// The inode number, full 64 bits (the display truth).
    pub inode: u64,
    /// The canonical device token (see [`device_token_from_kernel`]).
    pub device: u64,
    /// The acting process (tgid).
    pub pid: u32,
    /// Padding to 40 bytes (pinned by test at 36..40).
    pub _pad2: u32,
}

/// The size of one file_events ring record, in bytes.
pub const FILE_EVENT_BYTES: usize = core::mem::size_of::<FileEvent>();

/// The canonical device token from the kernel's own dev_t
/// (super_block.s_dev): the kernel form already IS
/// (major << 20) | minor, so this is the identity cast to u64.
///
/// BPF-side-only by design (the host's stat decode is
/// [`crate::commands::lane::device_token_from_stat`]); the scoped
/// allow names the split, the mirror of from_stat's allow.
#[allow(dead_code)]
pub fn device_token_from_kernel(s_dev: u32) -> u64 {
    u64::from(s_dev)
}

/// Pack the filter-map key for one file: (inode << 32) | device.
///
/// Named residuals, accepted once and pinned by test:
/// - inodes >= 2^32 alias into the low 32 bits of another inode on
///   the same device (no filesystem in common use assigns numbers
///   that high; the full 64-bit inode rides the record, so the host
///   drops any event whose full identity does not match the query -
///   an alias can waste ring space, never render a wrong row);
/// - devices with major > 4095 (none in mainline use) compare on
///   their low 32 bits like every other device.
pub fn pack_filter_key(inode: u64, device: u64) -> u64 {
    (inode << 32) | (device & 0xFFFF_FFFF)
}

// ── The offsets config map slots ────────────────────────────────────
//
// Every struct offset the four kprobes read is written into the
// `offsets` Array<u64> map at attach time, parsed from the host's
// own /sys/kernel/btf/vmlinux (src/ebpf/btf.rs, plus the two
// BTF-derived kprobe anchors src/ebpf/btf_unlink.rs resolves). The
// programs read their offsets from the map; the slot indices below
// are the contract between the host writers and the BPF readers.
// The eight file-walk slots are frozen; night-improve-57 appended
// the four fd-walk slots at 8..11 (the syscall-stub write probe),
// and night-frontier-2 appends the three unlink/rename slots at
// 12..14, so the legacy indices never renumber. The host writer
// rides the parsed array whole (slot = index, the night-hunter-3
// lesson), so the host crate no longer names the eight file-walk
// constants - the readers below are BPF-side, and the allows name
// that split.

/// `offsets[0]`: struct dentry, member d_inode.
#[allow(dead_code)]
pub const OFF_SLOT_DENTRY_D_INODE: u32 = 0;
/// `offsets[1]`: struct inode, member i_ino.
#[allow(dead_code)]
pub const OFF_SLOT_INODE_I_INO: u32 = 1;
/// `offsets[2]`: struct file, member f_path.
#[allow(dead_code)]
pub const OFF_SLOT_FILE_F_PATH: u32 = 2;
/// `offsets[3]`: struct file, member f_inode.
#[allow(dead_code)]
pub const OFF_SLOT_FILE_F_INODE: u32 = 3;
/// `offsets[4]`: struct vfsmount, member mnt_sb.
#[allow(dead_code)]
pub const OFF_SLOT_VFSMOUNT_MNT_SB: u32 = 4;
/// `offsets[5]`: struct super_block, member s_dev.
#[allow(dead_code)]
pub const OFF_SLOT_SUPER_BLOCK_S_DEV: u32 = 5;
/// `offsets[6]`: struct path, member mnt.
#[allow(dead_code)]
pub const OFF_SLOT_PATH_MNT: u32 = 6;
/// `offsets[7]`: struct path, member dentry.
#[allow(dead_code)]
pub const OFF_SLOT_PATH_DENTRY: u32 = 7;
/// `offsets[8]`: struct task_struct, member files (night-improve-57,
/// the syscall-stub write probe's fd-to-file walk).
#[allow(dead_code)]
pub const OFF_SLOT_TASK_FILES: u32 = 8;
/// `offsets[9]`: struct files_struct, member fdt.
#[allow(dead_code)]
pub const OFF_SLOT_FILES_FDT: u32 = 9;
/// `offsets[10]`: struct fdtable, member max_fds (the index bound
/// read BEFORE the fd array is dereferenced).
#[allow(dead_code)]
pub const OFF_SLOT_FDT_MAX_FDS: u32 = 10;
/// `offsets[11]`: struct fdtable, member fd (the pointer array;
/// the probe indexes it by the syscall's fd).
#[allow(dead_code)]
pub const OFF_SLOT_FDT_FD: u32 = 11;
/// `offsets[12]`: struct inode, member i_sb (night-frontier-2, the
/// unlink/rename probes' device hop: dentry->d_inode->i_sb->s_dev,
/// the sb reach the file walks get from f_path->vfsmount instead).
#[allow(dead_code)]
pub const OFF_SLOT_INODE_I_SB: u32 = 12;
/// `offsets[13]`: the vfs_unlink parameter index that carries the
/// `struct dentry *` (night-frontier-2). A kprobe argument POSITION,
/// not a byte offset: the BTF parameter scan (src/ebpf/btf_unlink.rs)
/// resolves it at attach - 2 on the idmap+ kernels, 1 before them -
/// and the probe reads its context argument through this slot, so a
/// signature move re-derives per host instead of misreading.
#[allow(dead_code)]
pub const OFF_SLOT_UNLINK_DENTRY_ARG: u32 = 13;
/// `offsets[14]`: struct renamedata, member old_dentry (night-
/// frontier-2). vfs_rename funnels every rename through one
/// renamedata argument; the member offset is BTF-derived at attach
/// (direct or through anonymous aggregates - the 6.18 lesson), so
/// the member's own reshuffles stay data, never a compiled guess.
#[allow(dead_code)]
pub const OFF_SLOT_RENAMEDATA_OLD_DENTRY: u32 = 14;
/// `offsets[15]`: struct page, member mapping (night-frontier-Z7,
/// D4): the page-shape dirty anchor's one hop from a struct page to
/// the address_space that backs it. The folio-shape kernels need no
/// hop at all (the anchor's arg0 IS the address_space, BTF-vouched),
/// and on them struct folio embeds struct page at offset 0 anyway -
/// one slot serves every kernel that anchors either shape.
#[allow(dead_code)]
pub const OFF_SLOT_PAGE_MAPPING: u32 = 15;
/// `offsets[16]`: struct address_space, member host (night-frontier-
/// Z7, D4): the mapping-to-inode hop - the backing inode the
/// tracked_inodes gate reads. The one offset the mmap-dirty truth
/// rides on every anchor shape.
#[allow(dead_code)]
pub const OFF_SLOT_ADDR_SPACE_HOST: u32 = 16;
/// `offsets[17]`: struct io_kiocb, member file (night-frontier-Z7,
/// D4): the submitted request to its struct file - the descent the
/// io_uring probe walks before the filter map. Derived per host; a
/// kernel whose io_kiocb carries the member under no verifiable
/// shape leaves the io_uring capability unplanted, named at attach.
/// The write-class opcode filter needs NO slot: the tracepoint's own
/// record carries the opcode at its stable ABI offset (third field
/// since 5.5), one fewer host-shaped value to derive.
#[allow(dead_code)]
pub const OFF_SLOT_IO_KIOCB_FILE: u32 = 17;

/// The number of slots the offsets map carries (the map's
/// max_entries on the BPF side, the write count on the host side).
/// Eighteen: the fifteen the ledger grammar carried through
/// night-frontier-2 plus the three off-path slots night-frontier-Z7
/// appends (15..17 - the page.mapping / address_space.host dirty
/// descent and the io_kiocb file hop). The file slots were never
/// renumbered - the vocabulary's append-only law holds: a capability
/// the host cannot verify leaves its slots zero, and the programs
/// that would read them are never attached.
///
/// BPF-side-only by design (the BPF crate sizes the offsets Array
/// with it; the host writes the slots by OFF_SLOT_* index and never
/// needs the count); the scoped allow names the split.
#[allow(dead_code)]
pub const OFF_SLOTS: u32 = 18;

// ── The drop-census map slots ───────────────────────────────────────
//
// night-frontier-Z1, the drop-truth half of the Unaccounted law: a
// bounded ring whose reserve fails drops the event SILENTLY - the
// kernel cannot remember what it did not record, but it CAN count
// how many times it failed to record. Every failed
// `RingBuf::output` reservation bumps one slot in the `drop_census`
// map (Array<AtomicU64>, BPF_ATOMIC fetch_add - the phase-1 counter
// discipline: RMW atomics, no plain shared-field access, exact and
// race-free), and the userspace drains read the census through the
// pin so a lane that renders kernel events can also name how many
// the kernel saw but could not hold. The slot indices below are the
// contract between the BPF writers (ebpf/src/main.rs's
// count_ring_drop call sites and ebpf/src/exits.rs) and the host
// readers (src/ebpf/readback.rs's DropCensus) - both sides compile
// this file, one truth, no drift.

/// `drop_census[0]`: sock_events reserve failures since attach - the
/// transitions the port surface's camera saw but the ring could not
/// hold.
pub const DROP_SLOT_SOCK: u32 = 0;

/// `drop_census[1]`: file_events reserve failures since attach - the
/// file actions (opens, writes, writevs, unlinks, renames, and the
/// off-path trio night-frontier-Z7 adds: mmap dirties, splice moves
/// both ways, io_uring writes) eight probes saw but the ring could
/// not hold.
pub const DROP_SLOT_FILE: u32 = 1;

/// `drop_census[2]`: proc_events reserve failures since attach - the
/// process exits the post-mortem camera saw but the ring could not
/// hold.
pub const DROP_SLOT_PROC: u32 = 2;

/// The number of slots the drop_census map carries (the map's
/// max_entries on the BPF side). BPF-side-only by design (the host
/// reader names the three slots by constant and never needs the
/// count); the scoped allow names the split.
#[allow(dead_code)]
pub const DROP_SLOTS: u32 = 3;

// ─────────────────────────────────────────────────────────────────────
// night-improve-47, the process-exit record (the post-mortem doctor
// pass). Same file, same discipline: the record the proc_events
// ring carries is compiled into the bpfel object AND into the host
// binary through #[path] - one truth for both sides of the ring.
// ─────────────────────────────────────────────────────────────────────

/// One process exit, as the kernel recorded it at the moment it
/// happened - the post-mortem doctor's evidence, and the only thing
/// that survives the exit: a second later /proc has no entry to
/// read, so the process's own name (the comm, the same bytes
/// /proc's `Name:` field would have shown) rides the record itself.
///
/// Offsets (repr(C), natural alignment, pinned by test):
/// timestamp_ns 0, pid 8, _pad 12, comm 16..32; total 32 bytes.
/// The pads are EXPLICIT fields, the SockEvent discipline: the ring
/// record's every byte is written by the probe constructor, because
/// the 5.15 verifier (the documented kernel floor) rejects an
/// `output` read whose stack bytes were never initialized.
///
/// `pid` is the tgid half of bpf_get_current_pid_tgid - the process
/// (thread group), not the exiting thread: the probe's leader-only
/// filter (ebpf/src/exits.rs) keeps one record per process exit, so
/// the pid IS the process identity and the comm IS the leader's
/// name, exactly the pair a /proc read would have named before the
/// exit.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcExitEvent {
    /// CLOCK_MONOTONIC nanoseconds at the exit.
    pub timestamp_ns: u64,
    /// The exiting process (tgid).
    pub pid: u32,
    /// Padding to 8-byte alignment for `comm` (pinned by test at 12).
    pub _pad: u32,
    /// The process's comm (`bpf_get_current_comm`, TASK_COMM_LEN =
    /// 16 bytes), NUL-terminated by the helper's contract and
    /// zeroed past its end - the host renders up to the first NUL.
    pub comm: [u8; 16],
}

/// The size of one proc_events ring record, in bytes - the number
/// both the kernel side's `output` call and the host side's
/// record-length check agree on.
pub const PROCEXIT_EVENT_BYTES: usize = core::mem::size_of::<ProcExitEvent>();

// The contract pins live in test/ebpf/file_events_tests.rs, wired
// from src/ebpf/mod.rs (night-datapath-1): this file is a leaf law
// library - plain core Rust the proofs package compiles through
// #[path] alongside the binary - so no #[cfg(test)] module may ride
// inside it. The host-side wiring keeps the same test file in the
// same gate lanes; nothing moved but the declaration.
