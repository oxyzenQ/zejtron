// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
// zejtron eBPF probe, the pure-Rust BPF source (night-improve-1, the
// zelynic/zylaxion lineage precedent: there is no C twin, the
// aya-ebpf program IS the production source).
//
// FIVE programs, one object (night-improve-34 removes the two
// sched_process lifecycle tracepoints the `proc --live` surface
// drove; night-improve-42 adds the fifth program, the writev probe -
// the false-negative closer for the file-write arena); SIXTH in
// its own module under the LOC cap (night-improve-47, exits.rs):
// the post-mortem exit probe, the exit half of the lifecycle probe
// returning with a new consumer and a new shape - a bounded
// post-mortem record the doctor's ram symptom drains, not a live
// stream. SEVENTH and EIGHTH in their own module (night-frontier-2,
// unlink.rs): the unlink and rename probes, the forensic closer for
// the file arena - the death-and-movement half the open/write
// probes never saw.
//
//   1. sched_process_exec (phase 1, unchanged since): count process
//      executions. The counter is the phase-1 chain proof, still the
//      doctor's readback. The exec event emission night-improve-4
//      rode on this tracepoint is gone with `proc --live`.
//
//   2. inet_sock_set_state (phase 2, untouched): the port surface's
//      event window, reading the socket facts at the pinned offsets,
//      filtering to the port-surface transitions, and publishing
//      the 32-byte SockEvent with the changer's pid. night-frontier-
//      Z8 (D5) widens the record to 64 bytes - the identity block
//      (cgroup id, comm, netns inode) rides the appended tail.
//
//   3. open_probe on vfs_open (phase 3, the Evidence Ledger pass): a
//      kprobe at the head of the syscall open path. vfs_open(const
//      struct path *, struct file *) hands this program the path
//      being bound; it walks path->dentry->d_inode for the inode,
//      path->mnt->mnt_sb->s_dev for the device, checks the
//      tracked_inodes filter map FIRST (the price control: vfs_open
//      fires on every open on the host - only the queried file's
//      events are allowed to cross), and publishes a 72-byte
//      file that anyone asked about. The probe records the binding
//      attempt at entry; whether the open later failed is not
//      recorded (the same residual class as the write probe at
//      entry). O_PATH peeks never reach vfs_open and are not
//      recorded - an O_PATH fd is not an open in the data sense.
//
//   4. write_probe on __x64_sys_write (night-improve-57, the second
//      generation - ebpf/src/write.rs owns the full story): the
//      first generation anchored at vfs_write, which the newest
//      -O3 distro builds (cachyos 7.x, found live by the
//      moving-latest witness) inline into the syscall stub - the
//      anchor stays attachable and never executes. The stub hands
//      the probe the fd register; task_struct->files->fdt->fd[fd]
//      resolves the file through BTF-verified offsets, then the
//      inode/device walk, the filter map, and op=2 mirror the open
//      probe. mmap'd writes cross no syscall at all - the gap is
//      named in the README's Limitations and the log lane (audit)
//      may still catch it.
//
//   5. writev_probe on vfs_writev (night-improve-42): a kprobe at
//      the head of the vectorized write path. writev(2), pwritev(2),
//      and pwritev2(2) all funnel through vfs_writev(struct file *,
//      ...), so one probe covers the family; do_iter_write is the
//      verified fallback the host side may attach instead (the
//      arg0 contract is identical: a pointer to struct file,
//      verified from the host's own BTF at attach). The walk, the
//      filter, and the record mirror the write probe; the op
//      vocabulary gains op=4. Before this probe a vectorized writer
//      (a database, a web server, an advanced logger) never crossed
//      the kernel lane - the ledger could read silent while the
//      file was under active write, and a silent detective is a
//      lying one. Async kiocb writes (io_uring, libaio) call
//      call_write_iter directly and cross neither write probe - the
//      named residual.
//
//   6. sched_process_exit (night-improve-47, exits.rs): the
//      post-mortem exit probe. The tracepoint fires for every
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
//                                    512 KiB holds 6553 72-byte
//                                    records of history (D5's own
//                                    re-pin; see the map below).
//   offsets         (Array<u64>, 22)   — phase 3's struct offsets, the
//                                    file-walk slots plus every
//                                    appended walk, written
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
//   drop_census     (Array<AtomicU64>, 3) — night-frontier-Z1's
//                                    ring reserve-failure census,
//                                    one slot per ring
//                                    (DROP_SLOT_* in events.rs).
//                                    One fetch_add per FAILED
//                                    `RingBuf::output`
//                                    reservation: the kernel cannot
//                                    remember what it did not
//                                    record, but it can count the
//                                    failures - the number the
//                                    Unaccounted blocks read
//                                    (src/ebpf/readback.rs) so a
//                                    silent drop stops being
//                                    silent.
//
// Deliberately absent (later passes own them): no keying by pid or
// uid, no address reads (the sock record carries the port and the
// changer; the bind address stays the snapshot's truth), no
// file-content or file-sequence reads anywhere (a path is metadata;
// the record carries inode + device + action + pid and, since
// night-frontier-Z8 (D5), the actor's own identity block - cgroup
// id, comm, netns inode, all read by the kernel at event time -
// nothing else).
// The vfs_unlink absence night-improve-3 named here is GONE as of
// night-frontier-2: unlink.rs carries the unlink and rename probes,
// and the signature churn that motivated the skip (mnt_userns in
// 5.12 moved dentry from arg1 to arg2) is answered with data, not a
// compiled position - the host's BTF parameter scan derives the
// dentry argument index per host at attach
// (src/ebpf/btf_unlink.rs), the index rides the offsets map, and an
// unrecognizable shape refuses loudly instead of anchoring wrong.
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
    helpers::bpf_probe_read_kernel,
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
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

// The plain-write probe, second generation (night-improve-57): the
// module owns the probe, the syscall-stub anchor story, and the
// fd-to-file walk - the exits.rs precedent (a dedicated module
// under the 600-LOC no-mercy cap, same crate, same record).
mod write;

// The socket-state program (night-frontier-Z1 moved it here - a PURE
// move under the 600-LOC cap, the exits.rs precedent): the port
// surface's camera, its map and verified context layout beside it.
mod sock;

// The unlink/rename probes (night-frontier-2): the module owns both
// forensic programs and the BTF-derived anchor story - the same
// dedicated-module shape, publishing to the file_events ring the
// file probes already carry.
mod unlink;

// The off-path write programs (night-frontier-Z7, D4): the mmap-dirty
// truth (two anchor shapes, the loader plants the one the host's BTF
// vouches for), the splice copy truth (the write probe's own
// tracepoint, both descriptors resolved), and the io_uring submission
// truth (the availability-scanned tracepoint, BTF-walked io_kiocb) -
// the dedicated-module shape again, publishing to the same file_events
// ring under the same tracked_inodes gate.
mod offpath;

// The memory-backed write program (night-frontier-Z9, D6): the
// shared-write fault funnel anchors the tmpfs/ramfs/memfd mmap-store
// truth - the Z7 residual's closer - its own dedicated module under
// the LOC cap, the same ring, the same gate, plus the class gate
// (the superblock's registered filesystem name, read at event time).
mod membacked;

// The actor-identity helper (night-frontier-Z8, D5): the identity
// fill every record constructor shares - cgroup id, comm, netns
// inode - the dedicated-module shape again. No programs here: the
// eight file constructors and the sock constructor call its
// inline(always) helper.
mod identity;

// The open and writev kprobes (night-improve-3 / night-improve-42),
// in their own module under the 600-LOC no-mercy cap
// (night-frontier-Z8, the exits.rs/write.rs precedent): the two
// entry-side file programs, same crate, same single-sourced record
// contract, same license law.
mod filelane;

use events::{DROP_SLOTS, FILE_EVENT_BYTES, OFF_SLOTS};

// The compile-time layout pins on the BPF side: the sock record the
// ring carries is exactly 64 bytes, the file record exactly 72
// (night-frontier-Z8, D5: the identity block rides the appended
// tail), asserted where the output() calls live (their internal align
// asserts cover the 8-byte halves).
const _: () = assert!(FILE_EVENT_BYTES == 72);

/// The stats slot contract (the userspace read side
/// src/ebpf/readback.rs reads the same slots; keep both sides in
/// lockstep).
/// stats[0]: the count of sched_process_exec events since attach.
pub const STATS_EVENTS: u32 = 0;
/// stats[1]: the write probe's drop census - one increment per walk
/// that dropped at any stage (night-hunter-2: the census moves from
/// program-local static atomics into the stats map so a silent verification
/// names its stage instead of staying mute).
pub const STATS_ZJW_DROPS: u32 = 1;
/// stats[2]: the write probe's completed-walk count (a walk that
/// crossed every hop and published, or missed the filter).
pub const STATS_ZJW_WALKED: u32 = 2;
/// stats[3..16]: one counter per census stage - stage s lives in
/// slot STATS_ZJW_STAGE_BASE + (s - 1), stages 1..14. Per-stage
/// counters (each stage owning its slot) instead of one fetch_max
/// high-water mark: LLVM's BPF backend cannot lower atomicumax
/// (bpf-linker aborts with "Cannot select: AtomicLoadUMax"), and the
/// per-stage shape is exact and race-free - the furthest stage
/// derives userspace-side as the highest stage with a nonzero count.
pub const STATS_ZJW_STAGE_BASE: u32 = 3;
/// The number of census stages that carry a slot (write.rs's stage
/// map: 1 and 3..14).
pub const STATS_ZJW_STAGE_COUNT: u32 = 14;
/// stats[17]: the question census (night-frontier-Z5): one increment
/// per REFUSED question - a tracked_inodes insert the kernel refused
/// because the hash map is full (E2BIG). The insert is a userspace
/// syscall (src/ebpf/tracked.rs), so this slot's writer is the
/// userspace writer too - the BPF programs only ever READ the filter
/// map and never touch this slot. The count is cumulative since
/// attach: the camera cannot remember the questions it never took,
/// but it can count the refusals - the same honesty the drop_census
/// slots carry for the rings - and every refusal also names itself
/// in its own command's error, so a question that was never answered
/// is at least never silent.
pub const STATS_QUESTIONS_REFUSED: u32 = STATS_ZJW_STAGE_BASE + STATS_ZJW_STAGE_COUNT;
/// The stats map's slot count (the map's max_entries): the three
/// scalar slots plus the fourteen stage counters plus the question
/// census slot.
pub const STATS_SLOTS: u32 = STATS_QUESTIONS_REFUSED + 1;

// The static name IS the userspace contract (the loader opens the
// map by name), so it stays lowercase exactly like the object's
// symbol; the allow attribute suppresses the non-upper-case globals
// lint for that reason. pub(crate): the write probe's census
// (ebpf/src/write.rs) writes its slots through the same map.
#[allow(non_upper_case_globals)]
#[map(name = "stats")]
pub(crate) static stats: Array<AtomicU64> = Array::with_max_entries(STATS_SLOTS, 0);

/// The tracked_inodes filter map (night-improve-3): BPF_HASH<u64,
/// u8>, 1024 entries. Present = tracked: the kprobes check this map
/// BEFORE recording, so only the queried file's events reach the
/// ring — the in-kernel price control that keeps a busy host's open
/// traffic from flooding the ring with events nobody asked for. The
/// host writes and clears it through the pin (src/ebpf/tracked.rs);
/// the value is always 1 (presence is the whole meaning).
#[allow(non_upper_case_globals)]
#[map(name = "tracked_inodes")]
pub(crate) static tracked_inodes: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

/// The file_events ring buffer (night-improve-3; resized
/// night-frontier-Z8, D5 - the conscious re-pin the cost contract
/// mandates): 512 KiB. The record is 72 bytes since D5 (the actor
/// identity rides every record), and aya's ring accounting (the
/// 8-byte length header, the page framing) decides the real
/// capacity - at the D5 record shape the same arithmetic the old
/// contract measured (5461 held records at the 48-byte stride a
/// 40-byte record produced) gives 6553 held records at the 80-byte
/// stride: the ring was DOUBLED precisely so the held-record window
/// would GROW, not shrink, under the wider record. The filter map is
/// the bound; a failed reservation drops the event without failing
/// the probe.
#[allow(non_upper_case_globals)]
#[map(name = "file_events")]
pub(crate) static file_events: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// The offsets config map (night-improve-3, grown by
/// night-improve-57): Array<u64>, the twelve slots - eight
/// file-walk slots plus the four fd-walk slots the syscall-stub
/// write probe rides (see events.rs OFF_SLOT_*), written once at
/// attach time from the host's own BTF
/// (src/ebpf/btf.rs). The slot indices are the shared contract in
/// events.rs — OFF_SLOT_* on both sides.
#[allow(non_upper_case_globals)]
#[map(name = "offsets")]
static offsets: Array<u64> = Array::with_max_entries(OFF_SLOTS, 0);

/// The drop census map (night-frontier-Z1): Array<AtomicU64>, one
/// slot per ring - DROP_SLOT_SOCK, DROP_SLOT_FILE, DROP_SLOT_PROC
/// (the shared contract in events.rs). One increment per FAILED
/// `RingBuf::output` reservation: the kernel cannot remember what it
/// did not record, but it can count how many times it failed to
/// record - the last honesty limit the Unaccounted law can reach,
/// and the number the userspace drains read back (src/ebpf/
/// readback.rs) so a lane that renders kernel events also names how
/// many the camera saw but could not hold. The increments ride the
/// same BPF_ATOMIC fetch_add discipline the stats counter carries
/// (exact and race-free); the slots are cumulative since attach, the
/// only form a cross-run reader can compare without a reset write
/// (a read-and-reset census would be racy and would make the host
/// write the camera's own truth).
#[allow(non_upper_case_globals)]
#[map(name = "drop_census")]
pub(crate) static drop_census: Array<AtomicU64> = Array::with_max_entries(DROP_SLOTS, 0);

/// Count ONE failed ring reservation into the census slot `slot`
/// (the DROP_SLOT_* contract in events.rs). The fetch_add discipline:
/// the stats counter's atomic RMW law, one slot per ring so the
/// three cameras count independently.
pub(crate) fn count_ring_drop(slot: u32) {
    if let Some(counter) = drop_census.get(slot) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The generation stamp map (night-frontier-Z2): Array<u64>, five
/// slots the LOADER writes once at attach and the drains read back -
/// boot identity, probe object identity, attach instant (unix
/// seconds), the off-path capability mask, and the watch-truth
/// attach instant in CLOCK_MONOTONIC nanoseconds (night-frontier-Z10
/// grew the map from four to five; the GEN_SLOT_* contract in
/// src/ebpf/estate.rs is the whole layout). The BPF programs
/// never touch it: it is the estate's passive identity record, the
/// fact the camera uses to prove it is this boot's own camera,
/// planted by this build. The map lives beside the others so the pin
/// estate plants and sweeps as one atomic unit.
#[allow(non_upper_case_globals)]
#[map(name = "generation")]
pub(crate) static generation: Array<u64> = Array::with_max_entries(5, 0);

/// The probe: increment stats[STATS_EVENTS] on every process exec.
/// The counter is the phase-1 chain proof - the doctor's readback.
/// (night-improve-34: the exec lifecycle event emission is gone with
/// `proc --live`; the probe reads no tracepoint context fields.)
///
/// Returning 0 is the tracepoint contract:
/// the return value is recorded but never acts as a filter.
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    // aya-ebpf 0.3's map API is safe code: the lookup is
    // bounds-checked (Array::get returns Option) and the verifier
    // re-proves the whole program at load time.
    if let Some(counter) = stats.get(STATS_EVENTS) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    0
}

// ── The file probes (night-improve-3, the Evidence Ledger pass) ────────
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
pub(crate) unsafe fn read_u64_at(base: usize, offset: u64) -> Option<u64> {
    // SAFETY: bpf_probe_read_kernel is a helper the verifier types:
    // wrapping_add cannot overflow the address arithmetic, and a bad
    // kernel address returns Err (mapped to None below), never a
    // fault - the fn's documented contract is honored by the probe
    // read itself.
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const u64).ok() }
}

/// Read one u32 field (dev_t-sized scalars like s_dev).
///
/// # Safety
/// Same contract as [`read_u64_at`].
pub(crate) unsafe fn read_u32_at(base: usize, offset: u64) -> Option<u32> {
    // SAFETY: the same probe-read contract as read_u64_at -
    // wrapping_add address math, a helper-typed read, Err on a bad
    // address, never a fault.
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const u32).ok() }
}

/// Read one pointer field, returned as the raw address.
///
/// # Safety
/// Same contract as [`read_u64_at`].
pub(crate) unsafe fn read_ptr_at(base: usize, offset: u64) -> Option<usize> {
    // SAFETY: the same probe-read contract as read_u64_at -
    // wrapping_add address math, a helper-typed read, Err on a bad
    // address, never a fault.
    unsafe { bpf_probe_read_kernel(base.wrapping_add(offset as usize) as *const usize).ok() }
}

/// The offset set, read from the `offsets` map in one pass. `None`
/// (an unparsable or absent map) drops the event — the host wrote
/// these at attach; an unreadable set this late is a chain that was
/// never alive. The array length is the shared OFF_SLOTS contract
/// (twenty-five since night-frontier-Z8's identity slots) - the
/// kprobes read the same map, and a map resize cannot desync the two
/// files. The set travels to the publish tails by REFERENCE
/// (night-frontier-Z11, D8): the 5.15 verifier caps a CALL CHAIN's
/// combined stack, and the floor kernel's first real attach refused
/// the by-value copies - one set, one frame, shared.
pub(crate) unsafe fn read_offset_set() -> Option<[u64; OFF_SLOTS as usize]> {
    let mut set = [0u64; OFF_SLOTS as usize];
    for slot in 0..OFF_SLOTS {
        set[slot as usize] = *offsets.get(slot)?;
    }
    Some(set)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The ELF `license` section must keep the kernel-facing "GPL" marker:
// the verifier grants gpl-only helper access only to programs whose
// license section is one of the kernel's GPL-compatible strings (AGPL
// is not on that kernel list), and a mismatch here would fail program
// load on a real host (tracepoint programs are GPL-addressable). This
// byte string is a kernel-interface constant, not the project's
// license claim: zejtron's source is AGPL-3.0-only.
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
