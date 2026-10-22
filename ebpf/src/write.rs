// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF tap, the plain-write program (night-improve-57, the
// second generation - a dedicated module under the 600-LOC no-mercy
// cap, the exits.rs precedent).
//
// WHY THE SECOND GENERATION: the first-generation probe anchored at
// vfs_write, and the moving-latest witness (the cachyos 7.2.7
// kernel-witnesses leg, night-improve-53) found the anchor dead on
// the newest distro line: ftrace proved a controlled write(2)
// crossed NEITHER vfs_write NOR ksys_write (both probes zero,
// while the file verifiably changed), because CachyOS builds its
// kernels at -O3 and on the 7.x source ksys_write is a
// single-caller static with vfs_write its only remaining caller -
// GCC folds the whole chain INTO the syscall stub
// __x64_sys_write, leaving the exported vfs_write entry present,
// kprobe-attachable, and never executed. The open and writev
// lanes kept working (their symbols have multiple callers), which
// is exactly what the witness saw: opens and vectorized writes
// [observed], plain writes zero. The evidence rode three CI
// rounds of the storm surface's post-mortem (the kallsyms census
// ruled out compiler clones, the vfs_open control ruled out a void
// ftrace, and __x64_sys_write fired while every interior symbol
// stayed silent).
//
// THE NEW ANCHOR: __x64_sys_write(const struct pt_regs *), the
// syscall entry itself. It fires on every native write(2) on every
// kernel in the floor span (4.17 through the current line), so ONE
// anchor covers the whole range with no candidates and no fallback
// ladder. The walk is deeper: the register frame hands the probe
// the fd (pt_regs.rdi, the x86_64 ABI's own fixed layout - not a
// kernel struct, so it is a constant here, not a BTF slot), and the
// file resolves through the caller's own descriptor table -
// task_struct->files->fdt->fd[fd], every hop a BTF-verified offset
// read from the offsets map at attach, max_fds bounding the index
// before a single pointer is read. From struct file* the walk, the
// kernel-side filter, and the record mirror the open tap exactly.
//
// THE HONEST NARROWING (named, not hidden): a stub-anchored probe
// sees syscall-origin writes only. Kernel-internal writes through
// kernel_write (module loads, /proc writes by the kernel itself)
// never enter the stub, and neither do compat-ia32 syscalls from a
// 32-bit binary on a 64-bit host. The first-generation vfs_write
// anchor caught some of the former; neither catch was ever a row
// the ledger could attribute to a process, and attribution is the
// product's subject. The README's Limitations section carries the
// narrowed sentence.

use core::sync::atomic::{AtomicU64, Ordering};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_printk},
    macros::kprobe,
    programs::ProbeContext,
};

use super::{read_offset_set, read_ptr_at, read_u32_at, read_u64_at};
use crate::{file_events, tracked_inodes};
use crate::events::{
    device_token_from_kernel, pack_filter_key, FileEvent, FILE_OP_WRITE, OFF_SLOT_FILE_F_INODE,
    OFF_SLOT_FILE_F_PATH, OFF_SLOT_FDT_FD, OFF_SLOT_FDT_MAX_FDS, OFF_SLOT_FILES_FDT,
    OFF_SLOT_INODE_I_INO, OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_TASK_FILES,
    OFF_SLOT_VFSMOUNT_MNT_SB,
};

/// x86_64 pt_regs.rdi - write(2)'s first argument, the fd. The
/// register frame is the ABI's own fixed layout (unchanged since
/// the beginning), so it is a constant here, not a BTF slot.
const PT_REGS_RDI: u64 = 112;

/// The write tap, second generation (night-improve-57): anchored at
/// the syscall entry because the -O3 distro builds inline vfs_write
/// out of the executed path (the module doc carries the full
/// story). The walk: regs->di is the fd; task_struct->files->
/// fdt->fd[fd] resolves the file (BTF-verified hops, max_fds
/// bounding the index); from struct file* the inode, the device,
/// the filter, and the record mirror the open tap.
/// The drop census (night-improve-58's evidence round, temporary):
/// every drop names its stage, every 1024th drop prints to tracefs
/// (the flood gate), and the first completed walk prints its proof -
/// so the storm post-mortem reads the drop point straight from the
/// trace buffer. Stage map: 1 no-arg0, 2 offsets, 3 fd-read,
/// 4 files, 5 fdt, 6 max_fds, 7 fd>=max, 8 fd-array, 9 file,
/// 10 inode, 11 ino, 12 mnt, 13 sb, 14 s_dev, 15 filter-miss.
static ZJW_DROPS: AtomicU64 = AtomicU64::new(0);
static ZJW_WALKED: AtomicU64 = AtomicU64::new(0);

unsafe fn zjw_drop(stage: u64, fd: u64) {
    let n = ZJW_DROPS.fetch_add(1, Ordering::Relaxed);
    if n % 1024 == 0 {
        bpf_printk!(c"[zjw] drop stage=%d fd=%d n=%d\n", stage, fd, n);
    }
}

#[kprobe(function = "__x64_sys_write")]
pub fn write_tap(ctx: ProbeContext) -> u32 {
    unsafe {
        // arg0: const struct pt_regs * - the syscall's own frame.
        let Some(regs) = ctx.arg::<u64>(0) else {
            zjw_drop(1, 0);
            return 0;
        };
        let regs = regs as usize;
        if regs == 0 {
            zjw_drop(1, 0);
            return 0;
        }
        let Some(o) = read_offset_set() else {
            zjw_drop(2, 0);
            return 0;
        };
        let Some(fd) = read_u32_at(regs, PT_REGS_RDI) else {
            zjw_drop(3, 0);
            return 0;
        };
        let fdu = u64::from(fd);
        let task = bpf_get_current_task() as usize;
        let Some(files) = read_ptr_at(task, o[OFF_SLOT_TASK_FILES as usize]) else {
            zjw_drop(4, fdu);
            return 0;
        };
        let Some(fdt) = read_ptr_at(files, o[OFF_SLOT_FILES_FDT as usize]) else {
            zjw_drop(5, fdu);
            return 0;
        };
        let Some(max_fds) = read_u32_at(fdt, o[OFF_SLOT_FDT_MAX_FDS as usize]) else {
            zjw_drop(6, fdu);
            return 0;
        };
        if fd >= max_fds {
            zjw_drop(7, fdu);
            return 0;
        }
        // fdtable->fd is the array POINTER, not the array: dereference
        // it first, then index - two hops, not one.
        let Some(fd_array) = read_ptr_at(fdt, o[OFF_SLOT_FDT_FD as usize]) else {
            zjw_drop(8, fdu);
            return 0;
        };
        if fd_array == 0 {
            zjw_drop(8, fdu);
            return 0;
        }
        let Some(file) = read_ptr_at(fd_array, fdu * 8).filter(|f| *f != 0) else {
            zjw_drop(9, fdu);
            return 0;
        };

        let Some(inode) = read_ptr_at(file, o[OFF_SLOT_FILE_F_INODE as usize]) else {
            zjw_drop(10, fdu);
            return 0;
        };
        let Some(ino) = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize]) else {
            zjw_drop(11, fdu);
            return 0;
        };
        let f_path = file.wrapping_add(o[OFF_SLOT_FILE_F_PATH as usize] as usize);
        let Some(mnt) = read_ptr_at(f_path, o[OFF_SLOT_PATH_MNT as usize]) else {
            zjw_drop(12, fdu);
            return 0;
        };
        let Some(sb) = read_ptr_at(mnt, o[OFF_SLOT_VFSMOUNT_MNT_SB as usize]) else {
            zjw_drop(13, fdu);
            return 0;
        };
        let Some(s_dev) = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize]) else {
            zjw_drop(14, fdu);
            return 0;
        };

        let device = device_token_from_kernel(s_dev);
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            zjw_drop(15, fdu);
            return 0;
        }
        let walked = ZJW_WALKED.fetch_add(1, Ordering::Relaxed);
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
