// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF tap, the pure-Rust BPF source (night-improve-1, the
// zelynic/zylaxion lineage precedent: there is no C twin, the
// aya-ebpf program IS the production source).
//
// FIVE programs, one object (night-improve-34 removes the two
// sched_process lifecycle tracepoints the `proc --live` surface
// drove; night-improve-42 adds the fifth program, the writev tap -
// the false-negative closer for the file-write arena); SIXTH in
// its own module under the LOC cap (night-improve-47, exits.rs):
// the post-mortem exit tap, the exit half of the lifecycle tap
// returning with a new consumer and a new shape - a bounded
// post-mortem record the doctor's ram symptom drains, not a live
// stream.
//
//   1. sched_process_exec (phase 1, unchanged since): count process
//      executions. The counter is the phase-1 chain proof, still the
//      doctor's readback. The exec event emission night-improve-4
//      rode on this tracepoint is gone with `proc --live`.
//
//   2. inet_sock_set_state (phase 2, untouched): the port surface's
//      event window, reading the socket facts at the pinned offsets,
//      filtering to the port-surface transitions, and publishing
//      the 32-byte SockEvent with the changer's pid.
//
//   3. open_tap on vfs_open (phase 3, the Evidence Ledger pass): a
//      kprobe at the head of the syscall open path. vfs_open(const
//      struct path *, struct file *) hands this program the path
//      being bound; it walks path->dentry->d_inode for the inode,
//      path->mnt->mnt_sb->s_dev for the device, checks the
//      tracked_inodes filter map FIRST (the price control: vfs_open
//      fires on every open on the host - only the queried file's
//      events are allowed to cross), and publishes a 40-byte
//      FileEvent with the acting process's pid to the file_events
//      ring. The tap records the binding attempt at entry; whether
//      the open later failed is not recorded (the same residual
//      class as vfs_write at entry). O_PATH peeks never reach
//      vfs_open and are not recorded - an O_PATH fd is not an open
//      in the data sense.
//
//   4. write_tap on vfs_write (phase 3): a kprobe at the head of
//      write(2). vfs_write(struct file *, ...) hands this program
//      the file; it walks file->f_inode for the inode and
//      file->f_path.mnt->mnt_sb->s_dev for the device, checks the
//      filter map, publishes op=2. mmap'd writes cross no syscall at
//      all - the gap is named in the README's Limitations and the
//      log lane (audit) may still catch it.
//
//   5. writev_tap on vfs_writev (night-improve-42): a kprobe at
//      the head of the vectorized write path. writev(2), pwritev(2),
//      and pwritev2(2) all funnel through vfs_writev(struct file *,
//      ...), so one probe covers the family; do_iter_write is the
//      verified fallback the host side may attach instead (the
//      arg0 contract is identical: a pointer to struct file,
//      verified from the host's own BTF at attach). The walk, the
//      filter, and the record mirror the write tap; the op
//      vocabulary gains op=4. Before this tap a vectorized writer
//      (a database, a web server, an advanced logger) never crossed
//      the kernel lane - the ledger could read silent while the
//      file was under active write, and a silent detective is a
//      lying one. Async kiocb writes (io_uring, libaio) call
//      call_write_iter directly and cross neither write tap - the
//      named residual.
//
//   6. sched_process_exit (night-improve-47, exits.rs): the
//      post-mortem exit tap. The tracepoint fires for every
//      exiting task; the program keeps only the thread-group
//      leader (the tgid/tid halves of bpf_get_current_pid_tgid
//      are equal only there - one record per process, and the
//      leader's comm IS the process name /proc would have shown)
//      and publishes the 32-byte ProcExitEvent - pid, comm,
//      monotonic time - to the proc_events ring, unfiltered by
//      design (every exit is potentially the one the doctor is
//      asked about; the ring's rolling window is the bound). The
//      doctor's ram symptom drains the last five seconds on
//      demand; nothing streams, nothing is written to disk.
//
//   stats           (Array<AtomicU64>) — phase 1's counter, one slot,
//                                    unchanged. stats[0] counts
//                                    sched_process_exec events since
//                                    attach; BPF_ATOMIC fetch_add only.
//   sock_events     (RingBuf)          — phase 2's event stream, the
//                                    port surface's window.
//   proc_events     (RingBuf)          — night-improve-47's exit
//                                    stream, the post-mortem
//                                    doctor's window (exits.rs
//                                    owns the program and the
//                                    record contract).
//   tracked_inodes  (HashMap<u64, u8>) — phase 3's filter map. The
//                                    host inserts (inode<<32)|device
//                                    for the one file a command is
//                                    asking about, and removes it
//                                    when the command ends; the
//                                    kprobes check it before
//                                    recording. 1024 entries bounds
//                                    the leak of an interrupted
//                                    command (a stale key dies with
//                                    the map at detach).
//   file_events     (RingBuf)          — phase 3's event stream. The
//                                    kernel-side filter is the bound
//                                    (only tracked inodes cross);
//                                    256 KiB holds 6553 40-byte
//                                    records of history.
//   offsets         (Array<u64>, 8)    — phase 3's struct offsets, the
//                                    eight file-walk slots, written
//                                    once at attach from the host's
//                                    own BTF (src/ebpf/btf.rs).
//                                    Every struct walk below reads
//                                    its offsets from THIS map,
//                                    never from compiled-in
//                                    constants: struct inode's
//                                    i_ino sat at @64 on this
//                                    repo's own reference probe
//                                    (kernel 5.10.134, where the
//                                    textbook order would say @16) -
//                                    offsets that vary by version or
//                                    build config are data, not
//                                    code, and a wrong hardcoded
//                                    offset would read garbage
//                                    SILENTLY. Refusing to attach
//                                    without a BTF-verified set
//                                    (src/ebpf/btf.rs) is the loud
//                                    alternative.
//
// Deliberately absent (later passes own them): no keying by pid or
// uid, no address reads (the sock record carries the port and the
// changer; the bind address stays the snapshot's truth), no
// file-content or file-sequence reads anywhere (a path is metadata;
// the record carries inode + device + action + pid, nothing else),
// no vfs_unlink kprobe (its signature churned across the floor —
// mnt_userns in 5.12 moved dentry from arg1 to arg2 — so no single
// argument position serves the range; op=3 stays reserved and the
// gap is named in README Limitations).
//
// Map update discipline: the counter rides a 64-bit BPF_ATOMIC
// fetch_add (the zelynic NIGHT-improve-29 lost-update lesson — the
// BPF ISA has RMW atomics but no atomic load/store, so the counter
// is core AtomicU64 and the program performs no plain shared-field
// access on its update path). The atomic RMW instructions require
// cpu v3 bytecode (see .cargo/config.toml) — Linux 5.12+, under the
// verified 5.15 floor.
//
// The attach points: sched/sched_process_exec (phase 1),
// sock/inet_sock_set_state (phase 2), and sched/sched_process_exit
// (night-improve-47, exits.rs). Each #[tracepoint] macro
// carries BOTH halves into the ELF — the section name becomes
// tracepoint/<category>/<event> and the no_mangle trampoline keeps
// the symbol as the program name the loader looks up. The userspace
// attach (src/ebpf/loader.rs) repeats each pair explicitly — aya's
// TracePoint::attach("<category>", "<event>") — so the section and
// the attach call name the same event twice, by design: the section
// types the program, the attach selects the event.
//
// Build: cd ebpf && cargo build --release

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

// The record contract, single-sourced: the userspace crate owns the
// file (so its layout tests run in every gate lane) and this crate
// compiles the very same bytes via #[path]. See src/ebpf/events.rs
// for the layout and the filter discipline.
#[path = "../../src/ebpf/events.rs"]
mod events;

// The post-mortem exit program (night-improve-47) - its own module
// under the LOC cap, carrying its own map and the program that
// publishes to it.
mod exits;

use events::{
    FILE_EVENT_BYTES, FILE_OP_OPEN, FILE_OP_WRITE, FILE_OP_WRITEV, FileEvent, OFF_SLOTS,
    OFF_SLOT_DENTRY_D_INODE, OFF_SLOT_FILE_F_INODE, OFF_SLOT_FILE_F_PATH,
    OFF_SLOT_INODE_I_INO, OFF_SLOT_PATH_DENTRY, OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV,
    OFF_SLOT_VFSMOUNT_MNT_SB, SOCK_EVENT_BYTES, SockEvent, device_token_from_kernel,
    is_port_surface_event, pack_filter_key,
};

// The compile-time layout pins on the BPF side: the sock record the
// ring carries is exactly 32 bytes, the file record exactly 40,
// asserted where the output() calls live (their internal align
// asserts cover the 8-byte halves).
const _: () = assert!(SOCK_EVENT_BYTES == 32);
const _: () = assert!(FILE_EVENT_BYTES == 40);

/// The one stats slot: the count of sched_process_exec events since
/// attach. The index contract with the userspace read side
/// (src/ebpf/readback.rs reads the same slot; keep both sides in
/// lockstep).
pub const STATS_EVENTS: u32 = 0;

// The static name IS the userspace contract (the loader opens the
// map by name), so it stays lowercase exactly like the object's
// symbol; the allow attribute suppresses the non-upper-case globals
// lint for that reason.
#[allow(non_upper_case_globals)]
#[map(name = "stats")]
static stats: Array<AtomicU64> = Array::with_max_entries(1, 0);

/// The sock_events ring buffer: 256 KiB, 8192 records of 32 bytes
/// each. The kernel-side filter is the bound — only LISTEN
/// enter/leave and UDP close cross — so on any host short of a
/// port-churn benchmark the ring holds minutes of history; when it
/// does fill, the oldest records are overwritten in the kernel (a
/// ring buffer's own rolling window) and a failed reservation drops
/// the event without failing the tracepoint.
#[allow(non_upper_case_globals)]
#[map(name = "sock_events")]
static sock_events: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// The tracked_inodes filter map (night-improve-3): BPF_HASH<u64,
/// u8>, 1024 entries. Present = tracked: the kprobes check this map
/// BEFORE recording, so only the queried file's events reach the
/// ring — the in-kernel price control that keeps a busy host's open
/// traffic from flooding the ring with events nobody asked for. The
/// host writes and clears it through the pin (src/ebpf/tracked.rs);
/// the value is always 1 (presence is the whole meaning).
#[allow(non_upper_case_globals)]
#[map(name = "tracked_inodes")]
static tracked_inodes: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// The file_events ring buffer (night-improve-3): 256 KiB, 6553
/// records of 40 bytes. The filter map is the bound; a failed
/// reservation drops the event without failing the probe.
#[allow(non_upper_case_globals)]
#[map(name = "file_events")]
static file_events: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// The offsets config map (night-improve-3): Array<u64>, the eight
/// file-walk slots (see events.rs OFF_SLOT_*), written once at
/// attach time from the host's own BTF
/// (src/ebpf/btf.rs). The slot indices are the shared contract in
/// events.rs — OFF_SLOT_* on both sides.
#[allow(non_upper_case_globals)]
#[map(name = "offsets")]
static offsets: Array<u64> = Array::with_max_entries(OFF_SLOTS, 0);

// The inet_sock_set_state context layout — the field offsets of
// struct trace_event_raw_inet_sock_set_state, verified against
// vmlinux BTF (this repo's own sandbox probe, kernel 5.10.134): the
// 8-byte trace_entry header, then skaddr, oldstate, newstate, sport,
// dport, family, protocol — a prefix layout that has been stable
// since the tracepoint landed in 4.16 (the saddr/daddr fields later
// kernels append ride AFTER protocol, past offset 32, and are not
// read). sport/dport are host byte order already (the kernel's
// TP_fast_assign applied ntohs).
mod ctx_offsets {
    /// const void *skaddr — the socket's kernel address.
    pub const SKADDR: usize = 8;
    /// int oldstate — tcp_states.h numbering, narrowed to u8.
    pub const OLDSTATE: usize = 16;
    /// int newstate.
    pub const NEWSTATE: usize = 20;
    /// __u16 sport — local port, host byte order.
    pub const SPORT: usize = 24;
    /// __u16 dport — remote port, host byte order.
    pub const DPORT: usize = 26;
    /// unsigned short family — AF_INET / AF_INET6.
    pub const FAMILY: usize = 28;
    /// unsigned short protocol — IPPROTO_TCP / IPPROTO_UDP.
    pub const PROTOCOL: usize = 30;
}

/// The tap: increment stats[STATS_EVENTS] on every process exec.
/// The counter is the phase-1 chain proof - the doctor's readback.
/// (night-improve-34: the exec lifecycle event emission is gone with
/// `proc --live`; the tap reads no tracepoint context fields.)
///
/// Returning 0 is the tracepoint contract:
/// the return value is recorded but never acts as a filter.
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    // aya-ebpf 0.2.1's map API is safe code: the lookup is
    // bounds-checked (Array::get returns Option) and the verifier
    // re-proves the whole program at load time.
    if let Some(counter) = stats.get(STATS_EVENTS) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    0
}

/// The port surface's event tap: read the socket facts at the pinned
/// offsets, keep only the port-surface transitions, publish the
/// 32-byte record with the changing process's pid.
///
/// Every aya-ebpf call inside is an `unsafe fn` (ctx reads, the
/// ktime and pid helpers) — the one unsafe block is that API
/// contract, nothing more: every read is probe-read (a bad offset
/// returns an error, never a fault) and the verifier re-proves the
/// whole body at load time.
#[tracepoint(name = "inet_sock_set_state", category = "sock")]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    // The reads come first (an unread fact is dropped, never
    // guessed); the filter bounds the ring traffic before anything
    // else happens.
    let event = unsafe {
        let skaddr: u64 = match ctx.read_at::<u64>(ctx_offsets::SKADDR) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let oldstate: i32 = match ctx.read_at::<i32>(ctx_offsets::OLDSTATE) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let newstate: i32 = match ctx.read_at::<i32>(ctx_offsets::NEWSTATE) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let sport: u16 = match ctx.read_at::<u16>(ctx_offsets::SPORT) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let dport: u16 = match ctx.read_at::<u16>(ctx_offsets::DPORT) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let family: u16 = match ctx.read_at::<u16>(ctx_offsets::FAMILY) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let protocol: u16 = match ctx.read_at::<u16>(ctx_offsets::PROTOCOL) {
            Ok(value) => value,
            Err(_) => return 0,
        };

        let oldstate = oldstate as u8;
        let newstate = newstate as u8;
        let protocol = protocol as u8;

        if !is_port_surface_event(family, protocol, oldstate, newstate) {
            return 0;
        }

        SockEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            skaddr,
            family,
            protocol,
            oldstate,
            newstate,
            // The explicit pads, zeroed: the ring record's every
            // byte is written before output() reads it — the 5.15
            // verifier (the floor kernel) refuses an output read
            // that touches a never-written stack byte, exactly the
            // refusal the kernel-floor micro-VM lane caught live.
            _pad: 0,
            sport,
            dport,
            _pad2: 0,
            // The tgid half: the process (thread group) whose
            // syscall made the change — the /proc snapshot cannot
            // see this, only the record can.
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        }
    };

    // Publish to the ring. The size assert inside output() is the
    // compile-time layout pin (SOCK_EVENT_BYTES == 32, align 8 — the
    // const is imported so both sides carry the same number); a
    // failed reservation (buffer full) drops the event silently — a
    // passive tracepoint never fails, and the ring's own rolling
    // window keeps the newest history.
    let _ = sock_events.output::<SockEvent>(&event, 0);

    0
}

// ── The file taps (night-improve-3, the Evidence Ledger pass) ────────
//
// Shared reading helpers: every struct walk reads its offset from the
// `offsets` map (written at attach from the host's own BTF) and every
// memory read is probe-read (a bad address returns an error, never a
// fault). A read that fails drops the event — a passive probe never
// fails the kernel path it is riding.

/// Read one u64 field of a kernel struct: `base + offset`.
///
/// # Safety
/// The caller passes a kernel address; the read is probe-read, so a
/// bad address returns `None` instead of faulting.
unsafe fn read_u64_at(base: usize, offset: u64) -> Option<u64> {
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const u64).ok() }
}

/// Read one u32 field (dev_t-sized scalars like s_dev).
///
/// # Safety
/// Same contract as [`read_u64_at`].
unsafe fn read_u32_at(base: usize, offset: u64) -> Option<u32> {
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const u32).ok() }
}

/// Read one pointer field, returned as the raw address.
///
/// # Safety
/// Same contract as [`read_u64_at`].
unsafe fn read_ptr_at(base: usize, offset: u64) -> Option<usize> {
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const usize).ok() }
}

/// The offset set, read from the `offsets` map in one pass. `None`
/// (an unparsable or absent map) drops the event — the host wrote
/// these at attach; an unreadable set this late is a chain that was
/// never alive. The array length is the shared OFF_SLOTS contract
/// (eight) - the kprobes read the same map, and a map resize cannot
/// desync the two files.
pub(crate) unsafe fn read_offset_set() -> Option<[u64; 8]> {
    let mut set = [0u64; 8];
    for slot in 0..OFF_SLOTS {
        set[slot as usize] = *offsets.get(slot)?;
    }
    Some(set)
}

/// The open tap: vfs_open hands the program the path being bound to
/// a file. The walk: path->dentry->d_inode for the inode,
/// path->mnt->mnt_sb->s_dev for the device; the filter map decides
/// whether the event is worth a ring slot; the record carries the
/// acting process's pid (bpf_get_current_pid_tgid's tgid half).
///
/// Every aya-ebpf call inside is an `unsafe fn` (ctx arg reads, probe
/// reads, the ktime and pid helpers) — the unsafe block is that API
/// contract, nothing more.
#[kprobe(function = "vfs_open")]
pub fn open_tap(ctx: ProbeContext) -> u32 {
    unsafe {
        // arg0: const struct path * — extraction failure drops the
        // event (never fail the probed path).
        let Some(path) = ctx.arg::<u64>(0) else { return 0 };
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
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else { return 0 };
        let Some(mnt) = read_ptr_at(path, o[OFF_SLOT_PATH_MNT as usize]) else { return 0 };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else { return 0 };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else { return 0 };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            // Not the file anyone asked about — this is the whole
            // price control: the check happens in the kernel, before
            // a single byte of ring traffic is spent.
            return 0;
        }

        let _ = file_events.output::<FileEvent>(
            &FileEvent {
                timestamp_ns: bpf_ktime_get_ns(),
                op: FILE_OP_OPEN,
                _pad: [0; 7],
                inode: ino,
                device,
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                _pad2: 0,
            },
            0,
        );
    }
    0
}

/// The write tap: vfs_write hands the program the file being
/// written. The walk: file->f_inode for the inode,
/// file->f_path.mnt->mnt_sb->s_dev for the device (f_path is an
/// embedded struct path, so the path-member offsets apply to the
/// f_path base). The filter and the record mirror the open tap.
#[kprobe(function = "vfs_write")]
pub fn write_tap(ctx: ProbeContext) -> u32 {
    unsafe {
        // arg0: struct file *.
        let Some(file) = ctx.arg::<u64>(0) else { return 0 };
        let file = file as usize;
        if file == 0 {
            return 0;
        }
        let Some(o) = read_offset_set() else { return 0 };

        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else { return 0 };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else { return 0 };
        let f_path = file.wrapping_add(o[OFF_SLOT_FILE_F_PATH as usize] as usize);
        let Some(mnt) = read_ptr_at(f_path, o[OFF_SLOT_PATH_MNT as usize]) else { return 0 };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else { return 0 };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else { return 0 };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            return 0;
        }

        let _ = file_events.output::<FileEvent>(
            &FileEvent {
                timestamp_ns: bpf_ktime_get_ns(),
                op: FILE_OP_WRITE,
                _pad: [0; 7],
                inode: ino,
                device,
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                _pad2: 0,
            },
            0,
        );
    }
    0
}

/// The writev tap (night-improve-42, the false-negative closer):
/// vfs_writev hands the program the file being written through the
/// vectorized path - the shape writev(2)/pwritev(2)/pwritev2(2) all
/// funnel into (arg0: struct file *, the same contract as the write
/// tap, verified from the host's own BTF at attach by the loader).
/// The walk, the filter, and the record mirror the write tap; the op
/// is FILE_OP_WRITEV so the ledger names the write path that
/// crossed. The section name carries the primary symbol; the loader
/// attaches the BTF-verified one (vfs_writev, do_iter_write
/// fallback) - aya's kprobe attach takes its symbol as an argument,
/// the section only types the program.
#[kprobe(function = "vfs_writev")]
pub fn writev_tap(ctx: ProbeContext) -> u32 {
    unsafe {
        // arg0: struct file * (BTF-verified at attach).
        let Some(file) = ctx.arg::<u64>(0) else { return 0 };
        let file = file as usize;
        if file == 0 {
            return 0;
        }
        let Some(o) = read_offset_set() else { return 0 };

        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else { return 0 };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else { return 0 };
        let f_path = file.wrapping_add(o[OFF_SLOT_FILE_F_PATH as usize] as usize);
        let Some(mnt) = read_ptr_at(f_path, o[OFF_SLOT_PATH_MNT as usize]) else { return 0 };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else { return 0 };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else { return 0 };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            return 0;
        }

        let _ = file_events.output::<FileEvent>(
            &FileEvent {
                timestamp_ns: bpf_ktime_get_ns(),
                op: FILE_OP_WRITEV,
                _pad: [0; 7],
                inode: ino,
                device,
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                _pad2: 0,
            },
            0,
        );
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section must stay GPL: zejtron is GPL-3.0-only and a
// mismatch here would fail the verifier at program load time on a
// real host (tracepoint programs are GPL-addressable).
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
