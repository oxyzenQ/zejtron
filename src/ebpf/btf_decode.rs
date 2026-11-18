// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The pure BTF record-decoding helpers (night-zen-lts-1), split out
//! of btf.rs so the no-mercy 600 cap stays honest: the walk's position
//! arithmetic lives beside the parser, the byte-level decode lives
//! here - both small enough to read in one breath.

/// Decode a type record's info word: `(kind, vlen)`. When the
/// kind_flag (bit 31) is set the low field is `vlen:10 | klen:6` per
/// the kernel's btf.h, not a 16-bit vlen - reading all sixteen bits
/// desyncs the sequential walk the day a kernel sets a nonzero klen
/// (the 5.15-7.3 corpus carries hundreds of flagged records, all with
/// klen zero, so this is the future-kernel guard the corpus tests
/// pin).
pub(crate) fn decode_info(info: u32) -> (u32, usize) {
    let kind = (info >> 24) & 0x1F;
    let vlen = if info & 0x8000_0000 != 0 {
        (info & 0x3FF) as usize
    } else {
        (info & 0xFFFF) as usize
    };
    (kind, vlen)
}

/// The per-kind trailing payload sizes in bytes. None when the
/// record cannot fit: the walk stops.
pub(crate) fn kind_extra_bytes(kind: u32, vlen: usize) -> Option<usize> {
    match kind {
        1 => Some(4), // INT
        2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => Some(0),
        3 => Some(12),                        // ARRAY
        4 | 5 => Some(vlen.checked_mul(12)?), // STRUCT / UNION
        6 => Some(vlen.checked_mul(8)?),      // ENUM
        13 => Some(vlen.checked_mul(8)?),     // FUNC_PROTO
        14 => Some(4),                        // VAR
        15 => Some(vlen.checked_mul(12)?),    // DATASEC
        17 => Some(4),                        // DECL_TAG
        19 => Some(vlen.checked_mul(12)?),    // ENUM64
        _ => None,
    }
}

/// One little-endian u32 at `off`, zero instead of a panic past the
/// end - the walk's bounds check rides the caller, this only reads.
pub(crate) fn u32_at(data: &[u8], off: usize) -> u32 {
    let b = data.get(off..off + 4).unwrap_or(&[0; 4]);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
