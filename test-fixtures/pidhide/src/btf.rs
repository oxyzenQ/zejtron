// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The fixture's minimal BTF offsets walker (night-frontier-Z11,
//! phase c, D9). Test-fixture only - it never ships in any binary.
//!
//! The hide's absorb rides two fields of the `getdents_callback64`
//! container: the write cursor (`current_dir`) and the predecessor's
//! record length (`prev_reclen`). Hardcoding their byte offsets broke
//! on the first kernel that moved them - upstream hoisted the
//! user-buffer budget into `dir_context` itself, everything after the
//! embedded context sat 8 bytes higher, and the program read the
//! budget where the cursor belonged: the parse matched, the absorb
//! overflowed, and the skip returned without a counter (the census
//! named the symptom: matches with zero writes, no stage).
//!
//! The lesson is the camera's own (src/ebpf/btf.rs): offsets come
//! from the host's kernel BTF, never from constants. This walker is
//! the fixture-sized cut of that parser - direct members of one
//! struct only, no anonymous descent, no func records - with the
//! same discipline: every bound checked, every refusal named, a
//! bitfield result refused (no field in the container is one, and a
//! straddled read would be a guess).

use std::fs;

/// Where the container's field offsets come from: the host's own
/// BTF (/sys/kernel/btf/vmlinux), read once and parsed in memory.
pub(crate) fn resolve_container_offsets() -> Result<(u32, u32), String> {
    let data = fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("the host's BTF is unreadable: {e}"))?;
    parse_container_offsets(&data)
}

/// The container's field byte offsets, parsed from a BTF blob. Pure
/// so the failure modes stay exercisable without a kernel.
pub(crate) fn parse_container_offsets(data: &[u8]) -> Result<(u32, u32), String> {
    let blob = BtfBlob::parse(data)?;
    let entry = blob.find_struct("getdents_callback64")?;
    let cursor = blob.member_byte_offset(&entry, "current_dir")?;
    let prev = blob.member_byte_offset(&entry, "prev_reclen")?;
    Ok((cursor, prev))
}

/// The walked BTF file: header, type section, string section -
/// sliced and bounds-checked once, every later access inside them.
struct BtfBlob<'a> {
    types: &'a [u8],
    strings: &'a [u8],
}

/// One located STRUCT record: member-list position and member count.
struct StructEntry<'a> {
    members: &'a [u8],
    vlen: usize,
}

/// The BTF magic, little-endian (the fixture targets x86_64; a
/// big-endian blob fails the magic check and is named, never parsed).
const BTF_MAGIC: u16 = 0xEB9F;
/// The BTF type-record header: name offset, info, size-or-type.
const TYPE_RECORD: usize = 12;
/// One STRUCT/UNION member: name offset, type, bit offset.
const MEMBER_RECORD: usize = 12;
/// The offsets the program consumes are masked to this bound on the
/// eBPF side; the parse refuses anything wider, so the two agree.
const OFFSET_MAX: u32 = 128;
/// The base offset a container field can sit at: below it lies the
/// embedded dir_context itself, never the fields the hide reads.
const OFFSET_MIN: u32 = 8;

impl<'a> BtfBlob<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, String> {
        let u16_at = |off: usize| -> Result<u16, String> {
            data.get(off..off + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .ok_or_else(|| format!("BTF too short for the header: {} bytes", data.len()))
        };
        let u32_at = |off: usize| -> Result<u32, String> {
            data.get(off..off + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .ok_or_else(|| format!("BTF too short for the header: {} bytes", data.len()))
        };
        if u16_at(0)? != BTF_MAGIC {
            return Err(format!(
                "not a BTF file: magic {:#06x}",
                u16_at(0).unwrap_or(0)
            ));
        }
        let hdr_len = u32_at(4)? as usize;
        if hdr_len < 24 {
            return Err(format!("BTF header length {hdr_len} is under 24"));
        }
        let slice = |base: u32, len: u32, what: &str| -> Result<&'a [u8], String> {
            let start = hdr_len.checked_add(base as usize).ok_or_else(|| {
                format!("BTF {what} section offset overflows the header length")
            })?;
            let end = start
                .checked_add(len as usize)
                .ok_or_else(|| format!("BTF {what} section length overflows"))?;
            data.get(start..end)
                .ok_or_else(|| format!("BTF {what} section lies past the file end"))
        };
        let types = slice(u32_at(8)?, u32_at(12)?, "type")?;
        let strings = slice(u32_at(16)?, u32_at(20)?, "string")?;
        Ok(Self {
            types,
            strings,
        })
    }

    /// The NUL-terminated string at `off` inside the string section.
    fn string_at(&self, off: u32) -> Result<&'a str, String> {
        let start = off as usize;
        let rest = self
            .strings
            .get(start..)
            .ok_or_else(|| format!("BTF string offset {start} lies past the string section"))?;
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| format!("BTF string at {start} is not NUL-terminated"))?;
        core::str::from_utf8(&rest[..end])
            .map_err(|_| format!("BTF string at {start} is not valid UTF-8"))
    }

    /// The STRUCT record named `sname`, found by one linear walk of
    /// the type section (a vmlinux-sized scan is a memory-resident
    /// pass, bounded by the file itself, never a grind).
    fn find_struct(&self, sname: &str) -> Result<StructEntry<'a>, String> {
        let mut pos = 0usize;
        while pos + TYPE_RECORD <= self.types.len() {
            let u32_at = |off: usize| -> u32 {
                let b = &self.types[off..off + 4];
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            };
            let name_off = u32_at(pos);
            let info = u32_at(pos + 4);
            // The info word (linux/btf.h): bits 0-15 vlen, bits 24-28
            // kind, bit 31 kind_flag - and when the flag is set the
            // low field is vlen:10 | klen:6, not a 16-bit vlen. The
            // first shape read kind from the LOW bits and vlen from
            // the high half: the synthetic blobs were built with the
            // same swapped encoding, so the tests agreed with the
            // walk and the real vmlinux desynced at the first flagged
            // record (the refusal named it: a string offset of
            // 0x0A000000, past the section). This is the camera's
            // decode_info, ported whole.
            let kind = (info >> 24) & 0x1f;
            let vlen = if info & 0x8000_0000 != 0 {
                (info & 0x3ff) as usize
            } else {
                (info & 0xffff) as usize
            };
            let payload = kind_payload(kind, vlen)?;
            if kind == 4 {
                // BTF_KIND_STRUCT: the members start after the record
                // header and the name answers the caller's question.
                if self.string_at(name_off)? == sname {
                    let members = self
                        .types
                        .get(pos + TYPE_RECORD..pos + TYPE_RECORD + vlen * MEMBER_RECORD)
                        .ok_or_else(|| {
                            format!("struct {sname} member list lies past the type section")
                        })?;
                    return Ok(StructEntry { members, vlen });
                }
            }
            pos += TYPE_RECORD + payload;
        }
        Err(format!("struct {sname} not found in BTF"))
    }

    /// One member's byte offset inside a located struct, direct
    /// members only. A bitfield result is refused by name.
    fn member_byte_offset(&self, entry: &StructEntry<'_>, mname: &str) -> Result<u32, String> {
        for index in 0..entry.vlen {
            let base = index * MEMBER_RECORD;
            let Some(rec) = entry.members.get(base..base + MEMBER_RECORD) else {
                return Err(format!(
                    "struct member list is shorter than its vlen ({})",
                    entry.vlen
                ));
            };
            let name_off = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            let raw = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]);
            if self.string_at(name_off)? != mname {
                continue;
            }
            let bitfield_size = raw >> 24;
            if bitfield_size != 0 {
                return Err(format!(
                    "struct member {mname} is a bitfield (width {bitfield_size}) - refusing"
                ));
            }
            let bit_offset = raw & 0x00ff_ffff;
            if bit_offset % 8 != 0 {
                return Err(format!(
                    "struct member {mname} is not byte-aligned (bit {bit_offset}) - refusing"
                ));
            }
            let byte = bit_offset / 8;
            if byte < OFFSET_MIN || byte > OFFSET_MAX {
                return Err(format!(
                    "struct member {mname} sits at byte {byte}, outside the {OFFSET_MIN}..={OFFSET_MAX} band - refusing"
                ));
            }
            return Ok(byte);
        }
        Err(format!("struct has no member {mname} in BTF"))
    }
}

/// One type record's payload bytes beyond its 12-byte header, by
/// kind (linux/btf.h). A kind this walker does not know is a named
/// refusal - guessing a stride would walk the section blind.
fn kind_payload(kind: u32, vlen: usize) -> Result<usize, String> {
    let members = vlen
        .checked_mul(MEMBER_RECORD)
        .ok_or_else(|| format!("BTF kind {kind} member count overflows"))?;
    let entries8 = vlen
        .checked_mul(8)
        .ok_or_else(|| format!("BTF kind {kind} entry count overflows"))?;
    Ok(match kind {
        0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
        1 | 14 | 17 => 4,
        3 => 12,
        4 | 5 | 15 | 19 => members,
        6 | 13 => entries8,
        other => return Err(format!("BTF kind {other} is unknown to this walker - refusing")),
    })
}
