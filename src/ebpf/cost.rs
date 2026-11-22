// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The camera cost contract (night-frontier-Z4): the camera's price,
//! measured from the tree's own artifacts and pinned as test facts.
//! A forensic tool that claims "lightweight" publishes marketing; the
//! cost contract publishes ARITHMETIC - the eBPF instruction count
//! per program, the kernel-side ring bytes, and the userland
//! budgets, every number derived from an artifact a buyer can
//! re-derive with one command, and every number a test refuses to
//! let drift.
//!
//! The instruction counts walk the COMMITTED prebuilt eBPF object
//! (`ebpf-prebuilt/zejtron-ebpf.o`, 36 KB) - a pure std ELF64 section
//! walk, no external tool, no nightly, no bpf-linker needed to audit
//! it. The commit gate keeps that object in parity with `ebpf/`
//! source (the manifest's tree digest, enforced at commit time), so
//! the pinned counts are the programs that actually RUN: a probe
//! change that grows the instruction count fails the cost test until
//! the table is consciously re-pinned - the cost regression gate,
//! the same shape the corpus pins ride. One BPF instruction is 8
//! bytes, so the instruction count is the section's own size divided
//! by eight; the shared `.text` section carries the helpers the
//! programs call (BPF-to-BPF calls) and is reported separately.
//!
//! The kernel-side ring bytes ride the SOURCE (not a copy): the
//! scan walks `ebpf/src/*.rs` for the `RingBuf::with_byte_size(N, 0)`
//! sites and sums them - a ring resized in the BPF crate moves the
//! sum and the test fails until the contract is re-pinned.
//!
//! The userland budgets live in the suite's camera-cost surface (the
//! attach wall-time ceiling, the memory ceiling enforced with
//! `ulimit -v`, the binary size ceiling) - runtime facts, enforced
//! live per push on the witness kernels, not pinned numbers here.
//! The published table rides docs/CAMERA-COST.md; the derivation
//! harness (the tests, `--nocapture`) prints every number.

// The cost contract's consumers are the pin tests below and the
// derivation harness - the runtime graph never calls the walker
// (no CLI surface reads the table; the published doc cites the
// pins). The walker still ships IN the artifact so the audit rides
// the binary's own source; the scoped allow names the split, the
// same shape the events module's BPF-side constants ride.
#![allow(dead_code)]

use std::fmt::Write as _;

/// The prebuilt object the cost walk reads (the registry lane's
/// bytes, kept in source parity by the commit gate).
const PREBUILT_OBJECT: &str = "ebpf-prebuilt/zejtron-ebpf.o";

/// One measured program section: the ELF section name (the attach
/// hook the program rides) and its instruction count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfProgramCost {
    pub section: String,
    pub instructions: usize,
}

/// The object's cost: every program section, the shared helper text,
/// and the whole-object instruction total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfCost {
    pub programs: Vec<EbpfProgramCost>,
    pub shared_text_instructions: usize,
}

impl EbpfCost {
    /// The whole camera's instruction count: every program plus the
    /// shared helper text.
    pub fn total_instructions(&self) -> usize {
        self.shared_text_instructions + self.programs.iter().map(|p| p.instructions).sum::<usize>()
    }
}

/// Walk the ELF64 section table of a BPF object: every PROGBITS
/// section named `kprobe/*` or `tracepoint/*` is a program (one
/// instruction = 8 bytes), `.text` is the shared helper text.
/// Pure std - the buyer can re-derive this with one `readelf -SW`.
pub fn measure_object_bytes(bytes: &[u8]) -> Result<EbpfCost, String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 {
        return Err("not a 64-bit little-endian ELF object".to_owned());
    }
    let e_shoff = read_u64(bytes, 0x28)?;
    let (e_shentsize, e_shnum, e_shstrndx) = (
        read_u16(bytes, 0x3A)?,
        read_u16(bytes, 0x3C)?,
        read_u16(bytes, 0x3E)?,
    );
    if e_shentsize == 0 || e_shnum == 0 {
        return Err("the object carries no section table".to_owned());
    }
    // The section-name string table's own offset.
    let shstr_off = read_u64(
        bytes,
        e_shoff as usize + e_shstrndx as usize * e_shentsize as usize + 0x18,
    )?;
    let mut programs = Vec::new();
    let mut shared_text_instructions = 0usize;
    for index in 0..u64::from(e_shnum) {
        let header = e_shoff as usize + index as usize * e_shentsize as usize;
        let sh_name = read_u32(bytes, header)?;
        let sh_type = read_u32(bytes, header + 4)?;
        let sh_size = read_u64(bytes, header + 0x20)?;
        let name = section_name(bytes, shstr_off, sh_name)?;
        // SHT_PROGBITS == 1: the loaded sections. The programs ride
        // their attach hook's name; the helpers ride .text.
        if sh_type != 1 {
            continue;
        }
        if name.starts_with("kprobe/") || name.starts_with("tracepoint/") {
            programs.push(EbpfProgramCost {
                section: name,
                instructions: sh_size as usize / 8,
            });
        } else if name == ".text" {
            shared_text_instructions = sh_size as usize / 8;
        }
    }
    programs.sort_by(|left, right| left.section.cmp(&right.section));
    Ok(EbpfCost {
        programs,
        shared_text_instructions,
    })
}

/// The committed prebuilt object, read from the repo checkout.
pub fn measured() -> Result<EbpfCost, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PREBUILT_OBJECT);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("the committed prebuilt object {PREBUILT_OBJECT} must exist: {e}"))?;
    measure_object_bytes(&bytes)
}

/// The kernel-side ring bytes, measured from the SOURCE (not a
/// copy): every `RingBuf::with_byte_size(N, 0)` site under `ebpf/src`
/// contributes N. Returns (ring count, total bytes).
pub fn kernel_rings_from_source() -> Result<(usize, usize), String> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ebpf/src");
    let mut count = 0usize;
    let mut total = 0usize;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot walk {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let mut rest = text.as_str();
            while let Some(at) = rest.find("RingBuf::with_byte_size(") {
                let tail = &rest[at + "RingBuf::with_byte_size(".len()..];
                // The size argument is a constant expression of the
                // forms `N` and `N * M` (the estate's own shapes) -
                // take everything up to the next comma and evaluate
                // the product.
                let expr = tail
                    .split(',')
                    .next()
                    .ok_or_else(|| "unterminated ring size argument".to_owned())?
                    .trim();
                let bytes: usize =
                    expr.split('*')
                        .map(|factor| {
                            factor.trim().parse::<usize>().map_err(|e| {
                                format!("unparsable ring size {expr:?} at {path:?}: {e}")
                            })
                        })
                        .try_fold(1usize, |acc, f| f.map(|value| acc * value))?;
                count += 1;
                total += bytes;
                rest = tail;
            }
        }
    }
    Ok((count, total))
}

/// The derivation table, rendered plain (the test harness prints it
/// with --nocapture; docs/CAMERA-COST.md carries the pinned copy).
pub fn render_table(cost: &EbpfCost, rings: (usize, usize)) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "eBPF programs (instructions per section):");
    for program in &cost.programs {
        let _ = writeln!(out, "  {}: {}", program.section, program.instructions);
    }
    let _ = writeln!(
        out,
        "  .text (shared helpers): {}",
        cost.shared_text_instructions
    );
    let _ = writeln!(out, "  programs total: {}", cost.total_instructions());
    let _ = writeln!(
        out,
        "kernel-side rings: {} rings, {} bytes total",
        rings.0, rings.1
    );
    out
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| "ELF truncated in the section table".to_owned())
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "ELF truncated in the section table".to_owned())
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, String> {
    bytes
        .get(at..at + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| "ELF truncated in the section table".to_owned())
}

fn section_name(bytes: &[u8], strtab_off: u64, sh_name: u32) -> Result<String, String> {
    let start = strtab_off as usize + sh_name as usize;
    let tail = bytes
        .get(start..)
        .ok_or_else(|| "section name out of the string table".to_owned())?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "unterminated section name".to_owned())?;
    String::from_utf8(tail[..end].to_vec()).map_err(|_| "section name is not UTF-8".to_owned())
}

#[cfg(test)]
#[path = "../../test/ebpf/cost_tests.rs"]
mod tests;
