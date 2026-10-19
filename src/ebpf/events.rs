// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
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
/// newstate 20, sport 22, dport 24, pid 28; total 32 bytes.
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
    /// The local (source) port, host byte order - the tracepoint
    /// already applied ntohs.
    pub sport: u16,
    /// The remote (destination) port, host byte order.
    pub dport: u16,
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

/// `op` for FileEvent: a file was written (the vfs_write kprobe fired
/// on the queried inode's file).
pub const FILE_OP_WRITE: u8 = 2;

/// `op` for FileEvent: a file was unlinked. DEFINED but not produced
/// (night-improve-3): the vfs_unlink kprobe was skipped - its
/// signature churned across the floor (mnt_userns prepended in 5.12
/// shifted dentry from arg1 to arg2, the idmap args landed in 6.x),
/// so no single offset serves the floor-to-now range. The gap is
/// named in README Limitations; op=3 stays reserved so the record
/// contract never renumbers. The host's op label match carries the
/// reserved arm; the BPF side compiles this file for the record
/// contract and never reads the constant - the scoped allow names
/// exactly that split.
#[allow(dead_code)]
pub const FILE_OP_UNLINK: u8 = 3;

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
    /// One of FILE_OP_OPEN / FILE_OP_WRITE / FILE_OP_UNLINK.
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

// ─────────────────────────────────────────────────────────────────────
// night-improve-4, the process-lifecycle contract (Part C). Same file,
// same discipline: the record and the offset-map slot indices live
// here once, compiled into the bpfel object AND into the host binary
// through #[path] - one truth for both sides of the ring.
// ─────────────────────────────────────────────────────────────────────

/// `op` for ProcEvent: the task executed a new program image
/// (sched_process_exec - the image swap, not a birth).
pub const PROC_OP_EXEC: u8 = 1;

/// `op` for ProcEvent: a task was created (sched_process_fork - the
/// birth; the child inherits the creator's comm until it execs).
pub const PROC_OP_FORK: u8 = 2;

/// `op` for ProcEvent: a task died (sched_process_exit).
pub const PROC_OP_EXIT: u8 = 3;

/// One process lifecycle event, as the kernel saw it at the moment
/// it happened.
///
/// Offsets (repr(C), natural alignment, pinned by test):
/// timestamp_ns 0, op 8 (pad 9..12), pid 12, ppid 16, uid 20,
/// comm 24..40; total 40 bytes.
///
/// `pid` is the event's own task identifier: the tgid half of
/// bpf_get_current_pid_tgid for exec, the tracepoint's child_pid for
/// fork, the tracepoint's pid for exit. `ppid` is the creating task's
/// pid: the fork tracepoint's parent_pid for fork, the
/// BTF-verified task_struct.real_parent walk for exec and exit (0
/// when the walk was refused - the absent fact stays absent). `comm`
/// is the 16-byte task comm as the kernel holds it (NUL-padded):
/// the exec'ing image's name, the fork's inherited name, the dying
/// task's name.
///
/// Thread births and deaths also cross sched_process_fork/_exit (a
/// thread is a task); the stream records what the tracepoints say,
/// task-level, and the README names that residual.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcEvent {
    /// CLOCK_MONOTONIC nanoseconds at the lifecycle event.
    pub timestamp_ns: u64,
    /// One of PROC_OP_EXEC / PROC_OP_FORK / PROC_OP_EXIT.
    pub op: u8,
    /// Padding to 4-byte alignment (pinned by test at 9..12).
    pub _pad: [u8; 3],
    /// The task the event is about.
    pub pid: u32,
    /// The creating task's pid (0 when unavailable).
    pub ppid: u32,
    /// The task's effective uid at the event.
    pub uid: u32,
    /// The 16-byte task comm, NUL-padded.
    pub comm: [u8; 16],
}

/// The size of one proc_events ring record, in bytes.
pub const PROC_EVENT_BYTES: usize = core::mem::size_of::<ProcEvent>();

// ── The offsets config map slots ────────────────────────────────────
//
// Every struct offset the two kprobes read is written into the
// `offsets` Array<u64> map at attach time, parsed from the host's
// own /sys/kernel/btf/vmlinux (src/ebpf/btf.rs). The programs read
// their offsets from the map; the slot indices below are the
// contract between the host writer and the BPF readers. Fixed at
// eight so the map never renumbers.

/// `offsets[0]`: struct dentry, member d_inode.
pub const OFF_SLOT_DENTRY_D_INODE: u32 = 0;
/// `offsets[1]`: struct inode, member i_ino.
pub const OFF_SLOT_INODE_I_INO: u32 = 1;
/// `offsets[2]`: struct file, member f_path.
pub const OFF_SLOT_FILE_F_PATH: u32 = 2;
/// `offsets[3]`: struct file, member f_inode.
pub const OFF_SLOT_FILE_F_INODE: u32 = 3;
/// `offsets[4]`: struct vfsmount, member mnt_sb.
pub const OFF_SLOT_VFSMOUNT_MNT_SB: u32 = 4;
/// `offsets[5]`: struct super_block, member s_dev.
pub const OFF_SLOT_SUPER_BLOCK_S_DEV: u32 = 5;
/// `offsets[6]`: struct path, member mnt.
pub const OFF_SLOT_PATH_MNT: u32 = 6;
/// `offsets[7]`: struct path, member dentry.
pub const OFF_SLOT_PATH_DENTRY: u32 = 7;
/// `offsets[8]`: struct trace_event_raw_sched_process_fork, member
/// parent_pid (the fork tracepoint's context layout, parsed from the
/// host's own BTF at attach - the Phase 3 pattern applied to
/// tracepoint contexts).
pub const OFF_SLOT_TP_FORK_PARENT_PID: u32 = 8;
/// `offsets[9]`: struct trace_event_raw_sched_process_fork, member
/// child_pid.
pub const OFF_SLOT_TP_FORK_CHILD_PID: u32 = 9;
/// `offsets[10]`: struct trace_event_raw_sched_process_exit, member
/// pid (the dying task's pid in the exit tracepoint's context).
pub const OFF_SLOT_TP_EXIT_PID: u32 = 10;
/// `offsets[11]`: struct task_struct, member real_parent (the pointer
/// the exec/exit ppid walk dereferences).
pub const OFF_SLOT_TASK_REAL_PARENT: u32 = 11;
/// `offsets[12]`: struct task_struct, member tgid (read through the
/// real_parent pointer for the parent's process id).
pub const OFF_SLOT_TASK_TGID: u32 = 12;

/// The number of slots the offsets map carries (the map's
/// max_entries on the BPF side, the write count on the host side).
/// Eight through night-improve-3; night-improve-4 grows it to
/// thirteen for the process stream's tracepoint and task_struct
/// offsets. The map was never renumbered - the file slots stay
/// 0..8, the proc slots append.
///
/// BPF-side-only by design (the BPF crate sizes the offsets Array
/// with it; the host writes the slots by OFF_SLOT_* index and never
/// needs the count); the scoped allow names the split.
#[allow(dead_code)]
pub const OFF_SLOTS: u32 = 13;

#[cfg(test)]
#[path = "../../test/ebpf/file_events_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../test/ebpf/proc_events_tests.rs"]
mod proc_tests;
