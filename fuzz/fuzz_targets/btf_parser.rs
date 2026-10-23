// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the BTF parser (night-improve-43).
//!
//! `/sys/kernel/btf/vmlinux` is host-controlled bytes: a corrupted or
//! malicious host can feed zejtron any byte stream, and the parser
//! must answer with a named error, never a panic. The harness drives
//! the two pure entry points end to end - [`btf::parse_btf_offsets`]
//! (the twelve-offset struct walk) and
//! [`btf_writev::verify_writev_symbol_in`] (the writev attach-symbol
//! walk) - over arbitrary bytes, including the hostile classes: short
//! files, wrong magic, section bounds that
//! lie past the file end, truncated type records, and deep type-id
//! chains. The contract: a `Result`, `Ok` or `Err`, always.
//!
//! The sources are path-included, not copied (see fuzz/Cargo.toml
//! for the full rationale): the harness compiles the same bytes the
//! binary ships, so the guarantee the lane proves is the guarantee
//! the binary carries. The writev verifier reaches the parser as a
//! sibling (`super::btf`) - the include law keeps every included
//! file free of `crate::` paths, and gate 18 holds the law.

#![no_main]

#[path = "../../src/ebpf/btf.rs"]
mod btf;

#[path = "../../src/ebpf/btf_writev.rs"]
mod btf_writev;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = btf::parse_btf_offsets(data);
    let _ = btf_writev::verify_writev_symbol_in(data);
});
