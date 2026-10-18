// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! embedded-object unit pins (feature builds only - the embedded
//! module itself is feature-gated). Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/ebpf/embedded.rs. What is pinned: the AlignedElf type's
//! alignment guarantee (the NIGHT-hunt-30 lesson), the misalignment
//! detector, and the preflight's error shape.

use super::*;

#[test]
fn aligned_wrapper_guarantees_alignment() {
    // Alignment is a property of the TYPE (#[repr(C, align(8))]), so
    // every instance is 8-aligned by construction - verified here on
    // a locally built wrapper, which is the same construction the
    // loader's TAP_ELF static rides.
    let wrapped = AlignedElf::new([0xAA; 24]);
    assert_eq!(misalignment(&wrapped.bytes), None);
    assert_eq!(&wrapped.bytes[..4], &[0xAA; 4]);
    // The guard value rides at offset 0, the bytes at offset 8: the
    // projection serves a slice INTO the aligned allocation.
    assert_eq!(wrapped._guard, ALIGNED_ELF_GUARD);
}

#[test]
fn misalignment_detector_names_offalignment() {
    // Deterministic misalignment: whatever address the stack gives
    // the buffer, the slice starts at an address that is NOT a
    // multiple of 8 - base%8==0 shifts by 1, any other residue keeps
    // the unshifted base.
    let buf = [0u8; 33];
    let base = buf.as_ptr() as usize;
    let start = if base.is_multiple_of(8) { 1 } else { 0 };
    let slice = &buf[start..start + 8];
    assert_eq!(
        misalignment(slice),
        Some(slice.as_ptr() as usize % 8),
        "the detector must report the exact residue"
    );
    // An aligned slice (by construction, not by luck) reads clean: the
    // AlignedElf wrapper is the same construction the loader rides.
    let good = AlignedElf::new([0x55u8; 8]);
    assert_eq!(misalignment(&good.bytes), None);
}

#[test]
fn alignment_violation_names_the_object() {
    let buf = [0u8; 33];
    let base = buf.as_ptr() as usize;
    let start = if base.is_multiple_of(8) { 1 } else { 0 };
    let bad = &buf[start..start + 8];
    let violation = alignment_violation(bad, "zejtron-ebpf");
    assert!(violation.is_some());
    let text = violation.unwrap();
    assert!(text.contains("zejtron-ebpf"));
    assert!(text.contains("8-byte boundary"));

    // Aligned bytes pass without a word.
    let good = AlignedElf::new([0x55u8; 8]);
    assert_eq!(alignment_violation(&good.bytes, "zejtron-ebpf"), None);
}
