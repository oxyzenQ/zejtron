// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// zejtron eBPF probe, the unlink/rename programs (night-frontier-2).
// A dedicated module under the 600-LOC no-mercy cap, the exits.rs /
// write.rs precedent: two programs live beside the six - same crate,
// same single-sourced record contract, same license law.
//
// WHY THESE PROGRAMS EXIST: the ledger's oldest named hole (the
// README's Limitations carried it since phase 3) is the forensic
// question it could not answer: WHO DELETED THIS FILE. The open and
// write probes see a file's life; its death crossed nothing. The
// vfs_unlink kprobe was skipped at night-improve-3 for the right
// reason - its signature churned across the floor (mnt_userns
// prepended in 5.12 shifted dentry from arg1 to arg2), and a kprobe
// argument position is compiled into the program, so no single
// compiled position serves the floor-to-now range. op=3 stayed
// reserved for the whole wait.
//
// THE ANCHOR IS DATA, NOT CODE: the position problem dissolves when
// the position stops being compiled. The host's BTF parameter scan
// (src/ebpf/btf_unlink.rs) derives the vfs_unlink argument index
// that carries the `struct dentry *` on THIS kernel (2 on the idmap+
// kernels, 1 before them) and the struct renamedata member offset of
// old_dentry, both into the offsets map (OFF_SLOT_UNLINK_DENTRY_ARG,
// OFF_SLOT_RENAMEDATA_OLD_DENTRY); the probes below read their
// context arguments through the map, and a signature move re-derives
// per host instead of misreading. A kernel whose shapes are
// unrecognizable refuses at attach, by name, before anything is
// planted - the offsets law, applied to argument positions.
//
// RENAME rides vfs_rename, the funnel every rename(2) flavor passes
// through - one renamedata argument carrying old_dir, old_dentry,
// new_dir, new_dentry. At entry the file still sits at its OLD name,
// so the old dentry's (inode, device) is the side the filter map
// knows; the record says the file the ledger is watching was renamed
// away by this pid, at this time. The new name is a path - metadata
// the record contract deliberately does not carry (the main.rs map
// discipline: inode + device + action + pid, nothing else).
//
// THE HONEST BOUNDARY: a kprobe argument read reaches the six
// register arguments (x86_64 SysV); a dentry parameter living past
// arg5 would return None here and drop the event (no mainline
// signature puts it there - vfs_unlink carries four). A failed walk
// drops the event - a passive probe never fails the kernel path it
// is riding, the same posture as the open and writev probes. No
// drop census: the walk is two hops shorter than the write probe's
// fd-table climb, and the anchor itself is BTF-verified at attach
// (the census exists because the WRITE probe's anchor history earned
// it; this one refuses instead of anchoring wrong).

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::kprobe,
    programs::ProbeContext,
    EbpfContext,
};

// The kprobe context's argument-register offsets: struct pt_regs, the
// kernel's own x86_64 layout (r15..r10, then r9, r8, rax, rcx, rdx,
// rsi, rdi - include/asm/ptrace.h ordering), pinned as constants by
// the same law as the sock probe's verified ctx_offsets: the kprobes
// attach to x86_64 kernels only (the estate's one architecture), so
// the offsets are the OBJECT's truth, not the build host's. The aya
// bindings' pt_regs type follows the host arch - a shape that broke
// the arm64 e2e leg's cross-build (found live) and would have shipped
// aarch64 register semantics into an x86_64 object - which is why
// these reads carry their own offsets instead of the binding's fields.
const PT_REGS_R9: usize = 64;
const PT_REGS_R8: usize = 72;
const PT_REGS_RCX: usize = 88;
const PT_REGS_RDX: usize = 96;
const PT_REGS_RSI: usize = 104;
const PT_REGS_RDI: usize = 112;

use super::{read_offset_set, read_ptr_at, read_u32_at, read_u64_at};
use crate::{file_events, tracked_inodes};
use crate::events::{
    device_token_from_kernel, pack_filter_key, FileEvent, FILE_OP_RENAME, FILE_OP_UNLINK,
    OFF_SLOT_DENTRY_D_INODE, OFF_SLOT_INODE_I_INO, OFF_SLOT_INODE_I_SB,
    OFF_SLOT_RENAMEDATA_OLD_DENTRY, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_UNLINK_DENTRY_ARG,
};

/// The shared identity walk: from the dentry in hand to the
/// (inode, device) pair the filter map keys on - dentry->d_inode for
/// the inode, d_inode->i_ino for the number, d_inode->i_sb->s_dev
/// for the canonical device token. Every hop a BTF-verified offset
/// from the offsets map, every read probe-read (a bad address
/// returns None, never a fault). `None` drops the event.
unsafe fn identity_of(
    dentry: usize,
    o: &[u64; crate::events::OFF_SLOTS as usize],
) -> Option<(u64, u64)> {
    unsafe {
        let inode = read_ptr_at(dentry, o[OFF_SLOT_DENTRY_D_INODE as usize])?;
        let ino = read_u64_at(inode, o[OFF_SLOT_INODE_I_INO as usize])?;
        let sb = read_ptr_at(inode, o[OFF_SLOT_INODE_I_SB as usize])?;
        let s_dev = read_u32_at(sb, o[OFF_SLOT_SUPER_BLOCK_S_DEV as usize])?;
        Some((ino, device_token_from_kernel(s_dev)))
    }
}

/// The filter-and-publish tail, shared verbatim by both probes: the
/// tracked_inodes check happens in the kernel, before a single byte
/// of ring traffic is spent (the open probe's price control), and a
/// pass publishes the 40-byte record with the acting process's pid.
unsafe fn publish_if_tracked(dentry: usize, op: u8) {
    unsafe {
        let Some(o) = read_offset_set() else { return };
        let Some((ino, device)) = identity_of(dentry, &o) else { return };
        let key = pack_filter_key(ino, device);
        if tracked_inodes.get(&key).is_none() {
            return;
        }
        let _ = file_events.output::<FileEvent>(
            &FileEvent {
                timestamp_ns: bpf_ktime_get_ns(),
                op,
                _pad: [0; 7],
                inode: ino,
                device,
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                _pad2: 0,
            },
            0,
        );
    }
}

/// The unlink probe: vfs_unlink hands the program the dentry being
/// unlinked, at the BTF-derived argument index (read from the
/// offsets map - the position is this kernel's data). The walk, the
/// filter, and the record mirror the open probe; the op is
/// FILE_OP_UNLINK, the slot op=3 reserved for since night-improve-3.
/// Every aya-ebpf call inside is an `unsafe fn` (ctx arg reads, the
/// ktime and pid helpers) - the unsafe block is that API contract,
/// nothing more.
#[kprobe(function = "vfs_unlink")]
pub fn unlink_probe(ctx: ProbeContext) -> u32 {
    unsafe {
        let Some(o) = read_offset_set() else { return 0 };
        let arg = o[OFF_SLOT_UNLINK_DENTRY_ARG as usize] as usize;
        // The dentry read, FIXED-SHAPE AT THE BYTECODE LEVEL: the
        // position is this host's data (the offsets map, BTF-derived
        // at attach), but the context is touched ONLY through six
        // fixed-register loads - every one unconditional, every one a
        // compile-time pt_regs offset - and the BTF-derived index
        // selects among the pre-loaded values on the stack. The
        // pointer arithmetic aya's own arg(n) performs on the context
        // is a coin flip in LLVM's lowering: the same source compiled
        // into `ctx += computed; load *(ctx)` - a variable-offset
        // context read, the exact class the 5.15 and 6.8 verifiers
        // refuse while the newest accept - found live when the same
        // object attached on the 6.1x moving-latest witness and was
        // refused on the 5.15 floor kernel. A source-level match of
        // fixed branches compiles to the same computed load (the
        // constants fold), so the six-loads-first shape is the only
        // honest guarantee: the disassembly carries six `ldx *(ctx +
        // C)` and no arithmetic on the context pointer.
        // Six volatile register reads at the pinned offsets: volatile
        // cannot be folded by LLVM, so the disassembly carries six
        // fixed `ldx *(ctx + C)` loads and the pointer arithmetic
        // never returns - proven by the disassembly gate, not by hope
        // (the fixed-branch shape folded into the same computed load).
        let regs = ctx.as_ptr() as *const u8;
        let arg0 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_RDI) as *const u64) };
        let arg1 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_RSI) as *const u64) };
        let arg2 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_RDX) as *const u64) };
        let arg3 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_RCX) as *const u64) };
        let arg4 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_R8) as *const u64) };
        let arg5 =
            unsafe { core::ptr::read_volatile(regs.add(PT_REGS_R9) as *const u64) };
        let dentry = match arg {
            0 => arg0,
            1 => arg1,
            2 => arg2,
            3 => arg3,
            4 => arg4,
            5 => arg5,
            _ => 0,
        };
        let dentry = dentry as usize;
        if dentry == 0 {
            return 0;
        }
        publish_if_tracked(dentry, FILE_OP_UNLINK);
    }
    0
}

/// The rename probe: vfs_rename hands the program the renamedata
/// aggregate (arg0, the shape func_arg0_struct pinned at attach);
/// the old_dentry member offset (BTF-derived, anonymous-descent
/// hardened) turns it into the dentry the filter map knows. The op
/// is FILE_OP_RENAME - the ledger learns the file moved, and which
/// process moved it.
#[kprobe(function = "vfs_rename")]
pub fn rename_probe(ctx: ProbeContext) -> u32 {
    unsafe {
        let Some(o) = read_offset_set() else { return 0 };
        // arg0: struct renamedata * (BTF-verified at attach). The one
        // register read carries the same pinned-offset volatile shape
        // as the unlink probe's six: fixed load, host-independent,
        // verifier-safe from the 5.15 floor up.
        let renamedata = unsafe {
            core::ptr::read_volatile(
                (ctx.as_ptr() as *const u8).add(PT_REGS_RDI) as *const u64,
            )
        };
        let renamedata = renamedata as usize;
        if renamedata == 0 {
            return 0;
        }
        let Some(dentry) =
            read_ptr_at(renamedata, o[OFF_SLOT_RENAMEDATA_OLD_DENTRY as usize])
        else {
            return 0;
        };
        if dentry == 0 {
            return 0;
        }
        publish_if_tracked(dentry, FILE_OP_RENAME);
    }
    0
}
