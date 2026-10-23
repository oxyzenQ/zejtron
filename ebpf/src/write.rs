// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF probe, the plain-write program (night-improve-59, the
// third generation - a dedicated module under the 600-LOC no-mercy
// cap, the exits.rs precedent).
//
// WHY THE THIRD GENERATION: the first anchored at vfs_write, which
// the -O3 distro builds (cachyos 7.x) inline into the syscall stub -
// present, attachable, never executed (found live by the
// moving-latest witness, three ftrace evidence rounds). The second
// anchored at the stub itself, __x64_sys_write - and the kprobe
// perf-attach there stayed absolutely silent on every VM while
// ftrace probes at the same name and the same raw kallsyms address
// fired beside it (the drop census proved the program never ran:
// not one drop, not one walk, across millions of writes) - an
// aya-0.14 kprobe-on-syscall-stub quirk this pass does not pretend
// to explain. The third generation rides the one mechanism with
// zero observed failures across the whole estate: the tracepoint,
// the same machinery the sock, exec, and exit probes already use on
// every kernel from the 5.15 floor through the 7.2 line.
//
// THE ANCHOR: raw_syscalls/sys_enter - the syscall tracepoint,
// present on every distro kernel this project promises (the
// CONFIG_FTRACE_SYSCALLS estate; the floor kernel's own init probes
// its sibling machinery). The record is the trace-event ABI's own
// fixed layout (stable since the tracepoint landed): the 8-byte
// trace_entry header, then the syscall id (offset 8), then the six
// syscall arguments (offset 16 on) - constants here, the same class
// as the sock probe's verified ctx_offsets. The probe reads the id
// and returns for everything that is not write(2) (__NR_write = 1
// on x86_64, the ABI itself); for writes it reads the fd from
// args[0] and walks the caller's descriptor table -
// task_struct->files->fdt->max_fds bounds the index, fdt->fd[fd]
// resolves the file, every hop a BTF-verified offset in the grown
// offsets map - then the inode/device walk, the kernel-side filter,
// and the record mirror the open probe exactly.
//
// THE HONEST NARROWING (named, not hidden): a syscall-entry probe
// sees syscall-origin writes only. Kernel-internal writes
// (kernel_write) and compat-ia32 syscalls never enter it, and
// neither kind ever produced a row the ledger could attribute to a
// process. And the loader no longer trusts ANY anchor silently:
// plant_write_probe verifies a recorded write through the probe before
// attach declares success (src/ebpf/verify_write.rs) - a probe that
// cannot record one byte refuses the whole attach, the same
// doctrine the offsets and the writev symbol already carried,
// extended from parse-verify to record-verify. The silent-anchor
// class this pass spent five CI rounds hunting is now structurally
// impossible: it cannot survive attach.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_printk},
    macros::tracepoint,
    programs::TracePointContext,
};

use super::{
    read_ptr_at, read_u32_at, read_u64_at, stats, STATS_ZJW_DROPS, STATS_ZJW_STAGE_BASE,
    STATS_ZJW_WALKED,
};
use crate::{file_events, tracked_inodes};
use crate::events::{
    device_token_from_kernel, pack_filter_key, FileEvent, FILE_OP_WRITE, OFF_SLOT_FILE_F_INODE,
    OFF_SLOT_FILE_F_PATH, OFF_SLOT_FDT_FD, OFF_SLOT_FDT_MAX_FDS, OFF_SLOT_FILES_FDT,
    OFF_SLOT_INODE_I_INO, OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_TASK_FILES,
    OFF_SLOT_VFSMOUNT_MNT_SB,
};

// The sys_enter record layout - the trace-event ABI's own fixed
// prefix (the sock probe's ctx_offsets class: stable since the
// tracepoint landed, asserted here as plain constants).
/// The syscall id, right after the 8-byte trace_entry header
/// (type, flags, preempt_count, pid - the record's fixed prefix).
const SYS_ENTER_ID: usize = 8;
/// args[0] - the first syscall argument, write(2)'s fd (offset 16).
const SYS_ENTER_ARG0: usize = 16;
/// __NR_write on x86_64 - the ABI itself, not a kernel fact.
const NR_WRITE: i64 = 1;

// The fd-walk offsets ride the offsets map (OFF_SLOT_TASK_FILES
// and friends, night-improve-57's four slots) - the same map the
// kprobes read; no new slots, no BTF growth.

// The drop census (night-improve-58's evidence instrument, UPGRADED
// by night-hunter-2: the counters moved from BPF-local statics into
// the stats map's slots - STATS_ZJW_DROPS, STATS_ZJW_WALKED, and one
// counter per stage at STATS_ZJW_STAGE_BASE + (stage - 1) - so the
// userspace verify (src/ebpf/verify_write.rs) reads them through the
// pinned map and names the exact stage the walk died at, instead of
// a mute refusal): every drop names its stage, every 1024th drop
// prints to tracefs (the flood gate), the first completed walk
// prints its proof. Stage map: 1 offsets, 2 not-a-write (never
// censused - the id check returns first), 3 files, 4 fdt, 5
// max_fds, 6 fd>=max, 7 fd-array, 8 file, 9 inode, 10 ino, 11 mnt,
// 12 sb, 13 s_dev, 14 filter-miss.
unsafe fn zjw_drop(stage: u64, fd: u64) {
    if let Some(drops) = stats.get(STATS_ZJW_DROPS) {
        let n = drops.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if n % 1024 == 0 {
            bpf_printk!(c"[zjw] drop stage=%d fd=%d n=%d\n", stage, fd, n);
        }
    }
    // Per-stage counters: each stage owns its slot, so the counts are
    // exact and race-free, and the furthest-reached stage derives
    // userspace-side as the highest stage with a nonzero count. (A
    // fetch_max high-water mark was tried first: LLVM's BPF backend
    // cannot lower atomicumax - bpf-linker aborts with "Cannot select:
    // AtomicLoadUMax" - so the per-stage shape is the one the
    // toolchain can prove.)
    if (1..=14).contains(&stage) {
        if let Some(slot) = stats.get(STATS_ZJW_STAGE_BASE + (stage as u32 - 1)) {
            let _ = slot.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// The write probe, third generation (night-improve-59): the
/// raw_syscalls/sys_enter tracepoint, filtered to write(2) by the
/// syscall id, walking the fd from the record's args[0] through the
/// BTF-verified fd-table hops to the struct file*, then mirroring
/// the open probe's walk, filter, and record. The module doc carries
/// the full story.
#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn write_probe(ctx: TracePointContext) -> u32 {
    // The id check first: sys_enter fires for EVERY syscall, so the
    // non-write traffic leaves after one comparison.
    let id: i64 = match unsafe { ctx.read_at::<i64>(SYS_ENTER_ID) } {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if id != NR_WRITE {
        return 0;
    }
    let fd: u64 = match unsafe { ctx.read_at::<u64>(SYS_ENTER_ARG0) } {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let fd = fd as u32;
    let fdu = u64::from(fd);

    unsafe {
        let Some(o) = super::read_offset_set() else {
            zjw_drop(1, fdu);
            return 0;
        };
        let task = bpf_get_current_task() as usize;
        let Some(files) = read_ptr_at(task, o[OFF_SLOT_TASK_FILES as usize]).filter(|f| *f != 0)
        else {
            zjw_drop(3, fdu);
            return 0;
        };
        let Some(fdt) = read_ptr_at(files, o[OFF_SLOT_FILES_FDT as usize]).filter(|f| *f != 0)
        else {
            zjw_drop(4, fdu);
            return 0;
        };
        let Some(max_fds) = read_u32_at(fdt, o[OFF_SLOT_FDT_MAX_FDS as usize]) else {
            zjw_drop(5, fdu);
            return 0;
        };
        if fd >= max_fds {
            zjw_drop(6, fdu);
            return 0;
        }
        // fdtable->fd is the array POINTER, not the array: dereference
        // it first, then index - two hops, not one.
        let Some(fd_array) = read_ptr_at(fdt, o[OFF_SLOT_FDT_FD as usize]) else {
            zjw_drop(7, fdu);
            return 0;
        };
        if fd_array == 0 {
            zjw_drop(7, fdu);
            return 0;
        }
        let Some(file) = read_ptr_at(fd_array, fdu * 8).filter(|f| *f != 0) else {
            zjw_drop(8, fdu);
            return 0;
        };

        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else {
            zjw_drop(9, fdu);
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            zjw_drop(10, fdu);
            return 0;
        };
        let f_path = file.wrapping_add(o[OFF_SLOT_FILE_F_PATH as usize] as usize);
        let Some(mnt) = read_ptr_at(f_path, o[OFF_SLOT_PATH_MNT as usize]) else {
            zjw_drop(11, fdu);
            return 0;
        };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else {
            zjw_drop(12, fdu);
            return 0;
        };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else {
            zjw_drop(13, fdu);
            return 0;
        };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            zjw_drop(14, fdu);
            return 0;
        }
        let walked = match stats.get(STATS_ZJW_WALKED) {
            Some(counter) => counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            None => 0,
        };
        if walked == 0 {
            bpf_printk!(c"[zjw] walk ok fd=%d ino=%d\n", fdu, ino);
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
