// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The writev-lane symbol verification (night-improve-42, split from
//! btf.rs at the 600 LOC no-mercy cap, night-hunter-4 - a pure move,
//! gates green in between): the kprobe attach point and its first
//! argument shape are read from the host's own BTF at attach time,
//! never compiled in. A kprobe at a symbol whose arg0 is not the
//! expected pointer reads garbage SILENTLY - the loud refusal is the
//! only honest alternative. The offsets parser itself stays in
//! [`super::btf`]; the BTF walker ([`BtfFile`]) is shared. The file
//! is path-included by the fuzz harness beside its sibling
//! (fuzz/fuzz_targets/btf_parser.rs), so the include law holds here
//! too: the sibling reach is `super::`, never `crate::`, and the
//! night-hunter-4 trace lives at the attach boundary
//! (src/ebpf/loader.rs).

use super::btf::BtfFile;

/// The writev-lane attach symbols, in preference order: vfs_writev
/// is the direct analog of the write probe (writev(2), pwritev(2), and
/// pwritev2(2) all funnel through it, 5.15 through the current 6.x
/// line); do_iter_write is the convergence one layer deeper, the
/// verified fallback for a host whose BTF omits the former (inlined
/// away or refactored). Both carry the same arg0 contract: a
/// pointer to struct file.
const WRITEV_SYMBOLS: [&str; 2] = ["vfs_writev", "do_iter_write"];

/// Verify the writev probe's attach point from the host's own BTF:
/// return the symbol whose FUNC prototype the host vouches for
/// (first argument a pointer to struct file), or an error naming
/// exactly what could not be verified. The refusal, not a guess,
/// is the point.
pub fn verify_writev_symbol() -> Result<&'static str, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    verify_writev_symbol_in(&data)
}

/// The pure verifier: given the raw BTF file bytes, return the
/// verified symbol. Separated from [`verify_writev_symbol`] so the
/// tests can drive it with synthetic blobs end to end. Preference
/// order: the first symbol whose FUNC record the host carries wins;
/// a symbol PRESENT with a different first-argument shape is a hard
/// refusal (the name exists but the contract moved - the loud
/// moment, never a silent fallthrough); an ABSENT symbol falls
/// through to the next candidate.
pub fn verify_writev_symbol_in(data: &[u8]) -> Result<&'static str, String> {
    let ctx = BtfFile::new(data)?;
    for symbol in WRITEV_SYMBOLS {
        let Some(func) = ctx.find_func(symbol) else {
            continue;
        };
        let struct_name = ctx.func_arg0_struct(func, symbol)?;
        if struct_name == "file" {
            return Ok(symbol);
        }
        return Err(format!(
            "{symbol}'s first argument is struct {struct_name}, not struct file - the \
             symbol exists but its shape moved; refusing rather than guessing"
        ));
    }
    Err(format!(
        "no BTF FUNC record for {} - this kernel does not carry the \
         vectorized-write path under a verifiable name",
        WRITEV_SYMBOLS.join(" or ")
    ))
}
