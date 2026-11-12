// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz target: the BTF parser (night-improve-43).
//!
//! `/sys/kernel/btf/vmlinux` is host-controlled bytes: a corrupted or
//! malicious host can feed zejtron any byte stream, and the parser
//! must answer with a named error, never a panic. The harness drives
//! the three pure entry points end to end - [`btf::parse_btf_offsets`]
//! (the thirteen-offset struct walk), [`btf_writev::verify_writev_symbol_in`]
//! (the writev attach-symbol walk), and
//! [`btf_unlink::verify_unlink_lane_in`] (the unlink/rename anchor
//! walk - the parameter scan and the renamedata member resolution,
//! night-frontier-2) - over arbitrary bytes, including the hostile
//! classes: short files, wrong magic, section bounds that lie past
//! the file end, truncated type records, and deep type-id chains.
//! The contract: a `Result`, `Ok` or `Err`, always.
//!
//! The sources are path-included, not copied (see fuzz/Cargo.toml
//! for the full rationale): the harness compiles the same bytes the
//! binary ships, so the guarantee the lane proves is the guarantee
//! the binary carries. The writev and unlink verifiers reach the
//! parser as siblings (`super::btf`) - the include law keeps every
//! included file free of `crate::` paths, and gate 18 holds the law.

#![no_main]

#[path = "../../src/ebpf/btf.rs"]
mod btf;

#[path = "../../src/ebpf/btf_writev.rs"]
mod btf_writev;

#[path = "../../src/ebpf/btf_unlink.rs"]
mod btf_unlink;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = btf::parse_btf_offsets(data);
    let _ = btf_writev::verify_writev_symbol_in(data);
    let _ = btf_unlink::verify_unlink_lane_in(data);
});
