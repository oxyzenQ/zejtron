// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The BTF offsets parser (night-improve-3, feature builds only):
//! the loud half of the offsets contract. Every struct walk the two
//! kprobes perform reads its offset from the `offsets` map - and the
//! values in that map are parsed from THE HOST'S OWN
//! /sys/kernel/btf/vmlinux at attach time, never compiled in.
//!
//! Why runtime, why refused-when-unverifiable: this repo's own
//! reference probe (kernel 5.10.134) puts struct inode's i_ino at
//! @64 - the "textbook" order would say @16, and other
//! versions/configs put it elsewhere again. A hardcoded offset that
//! is wrong on some host does not fail loudly; it reads the wrong
//! field SILENTLY, and the tap goes blind without anyone knowing.
//! Parsing the host's BTF - the kernel's own description of its
//! structs - is the one source that cannot drift from the kernel it
//! describes; refusing to attach when it cannot be parsed is the
//! honest alternative to a guess. BTF presence is already a fact the
//! doctor's \[eBPF] section reports; a 5.15+ distro kernel ships it.
//!
//! night-improve-49: the member lookups learned the anonymous union.
//! The 6.18 kernel line (Al Viro's constification, merged as the
//! pull-f_path tag) wraps struct file's f_path in an unnamed union
//! carrying `const struct path f_path` beside a writable
//! `struct path __f_path`, so the direct-member walk found nothing
//! and every 6.18+ host refused at attach. The walk now descends
//! anonymous struct/union members, and only those, accumulating bit
//! offsets; a member still unfound after the descent is the named error, never a guess.
//!
//! The parser is deliberately minimal: a BTF header check, a type
//! walk, nine struct lookups, twelve member lookups. Pure std, no
//! unsafe - it reads a file, trusts nothing, returns what THE HOST
//! says, and names every lookup failure.
//!
//! night-improve-57: the plain-write tap left vfs_write behind
//! (the newest -O3 distro builds inline it out of the executed
//! path; found dead on cachyos 7.2 by the moving-latest witness;
//! the tap now rides the raw_syscalls/sys_enter tracepoint,
//! night-improve-59), so the parse grows the four fd-walk slots
//! that turn the syscall's fd register back into the struct file*
//! the walk reads: task_struct.files, files_struct.fdt,
//! fdtable.max_fds, and fdtable.fd.

/// The BTF magic, as a little-endian u16 over the file's first two
/// bytes (0x9F 0xEB in the file).
const BTF_MAGIC: u16 = 0xEB9F;

/// The fixed size of the btf_header every version carries.
const BTF_HEADER_BYTES: usize = 24;

/// The offsets the probes read, slot-aligned to the events.rs
/// OFF_SLOT_* indices: [dentry.d_inode, inode.i_ino, file.f_path,
/// file.f_inode, vfsmount.mnt_sb, super_block.s_dev, path.mnt,
/// path.dentry], every value a byte offset - the eight frozen
/// file-walk slots - plus the four fd-walk slots night-improve-57
/// appends for the syscall-stub write tap: [task_struct.files,
/// files_struct.fdt, fdtable.max_fds, fdtable.fd].
pub type ProbeOffsets = [u64; 12];

/// Parse the host's own /sys/kernel/btf/vmlinux. Every error names
/// its stage; nothing is guessed, ever.
pub fn parse_probe_offsets() -> Result<ProbeOffsets, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    parse_btf_offsets(&data)
}

// ── The writev-lane symbol verification (night-improve-42) ──────
//
// The same law the offsets parse rides, extended from member
// offsets to argument positions: the kprobe's attach point and its
// first argument shape are read from the host's own BTF at attach
// time, never compiled in. A kprobe at a symbol whose arg0 is not
// the expected pointer reads garbage SILENTLY - the loud refusal is
// the only honest alternative.

/// The writev-lane attach symbols, in preference order: vfs_writev
/// is the direct analog of the write tap (writev(2), pwritev(2), and
/// pwritev2(2) all funnel through it, 5.15 through the current 6.x
/// line); do_iter_write is the convergence one layer deeper, the
/// verified fallback for a host whose BTF omits the former (inlined
/// away or refactored). Both carry the same arg0 contract: a
/// pointer to struct file.
const WRITEV_SYMBOLS: [&str; 2] = ["vfs_writev", "do_iter_write"];

/// Verify the writev tap's attach point from the host's own BTF:
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

/// The pure parser: given the raw BTF file bytes, return the eight
/// offsets. Separated from [`parse_probe_offsets`] so the tests can
/// drive it with synthetic blobs end to end. The six struct lookups
/// cover the file walks only: the exec tap reads no context fields
/// (its counter rides helpers alone) and the lifecycle tracepoints
/// are gone with the lifecycle stream (night-improve-34), so no
/// tracepoint context and no task_struct offset is verified or
/// stored any more.
pub fn parse_btf_offsets(data: &[u8]) -> Result<ProbeOffsets, String> {
    let ctx = BtfFile::new(data)?;
    let inode = ctx
        .find_struct("inode")
        .ok_or_else(|| "struct inode not found in BTF".to_owned())?;
    let dentry = ctx
        .find_struct("dentry")
        .ok_or_else(|| "struct dentry not found in BTF".to_owned())?;
    let file = ctx
        .find_struct("file")
        .ok_or_else(|| "struct file not found in BTF".to_owned())?;
    let vfsmount = ctx
        .find_struct("vfsmount")
        .ok_or_else(|| "struct vfsmount not found in BTF".to_owned())?;
    let super_block = ctx
        .find_struct("super_block")
        .ok_or_else(|| "struct super_block not found in BTF".to_owned())?;
    let path = ctx
        .find_struct("path")
        .ok_or_else(|| "struct path not found in BTF".to_owned())?;
    let task = ctx
        .find_struct("task_struct")
        .ok_or_else(|| "struct task_struct not found in BTF".to_owned())?;
    let files = ctx
        .find_struct("files_struct")
        .ok_or_else(|| "struct files_struct not found in BTF".to_owned())?;
    let fdtable = ctx
        .find_struct("fdtable")
        .ok_or_else(|| "struct fdtable not found in BTF".to_owned())?;

    Ok([
        member_offset(&ctx, dentry, "dentry", "d_inode")?,
        member_offset(&ctx, inode, "inode", "i_ino")?,
        member_offset(&ctx, file, "file", "f_path")?,
        member_offset(&ctx, file, "file", "f_inode")?,
        member_offset(&ctx, vfsmount, "vfsmount", "mnt_sb")?,
        member_offset(&ctx, super_block, "super_block", "s_dev")?,
        member_offset(&ctx, path, "path", "mnt")?,
        member_offset(&ctx, path, "path", "dentry")?,
        member_offset(&ctx, task, "task_struct", "files")?,
        member_offset(&ctx, files, "files_struct", "fdt")?,
        member_offset(&ctx, fdtable, "fdtable", "max_fds")?,
        member_offset(&ctx, fdtable, "fdtable", "fd")?,
    ])
}

/// One member's byte offset inside a located struct, direct or
/// through any anonymous aggregate the struct embeds. A bitfield
/// result (a bit offset that is not byte-aligned) is refused by
/// name: no struct in the set carries one, and a straddled read
/// would be a guess.
fn member_offset(
    ctx: &BtfFile<'_>,
    entry: StructEntry,
    sname: &str,
    mname: &str,
) -> Result<u64, String> {
    let Some(bit_offset) = ctx.find_member(entry, mname, 0, 8) else {
        return Err(format!("struct {sname} has no member {mname} in BTF"));
    };
    if bit_offset % 8 != 0 {
        return Err(format!(
            "struct {sname} member {mname} is a bitfield (bit {bit_offset}) - refusing"
        ));
    }
    Ok(u64::from(bit_offset / 8))
}

/// The walked BTF file: the type records and the string section,
/// sliced and bounds-checked once.
struct BtfFile<'a> {
    data: &'a [u8],
    types_base: usize,
    types_len: usize,
    strings_base: usize,
    strings_len: usize,
}

/// One located STRUCT or UNION record: its member-list position
/// and member count - the anonymous-descent walk rides the same
/// pair for both aggregate kinds.
#[derive(Clone, Copy)]
struct StructEntry {
    members_pos: usize,
    vlen: usize,
}

/// One located FUNC record (night-improve-42): its header position -
/// the FUNC_PROTO type id rides in the size/type field at pos+8.
#[derive(Clone, Copy)]
struct FuncEntry {
    pos: usize,
}

impl<'a> BtfFile<'a> {
    fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < BTF_HEADER_BYTES {
            return Err(format!("BTF too short for a header: {} bytes", data.len()));
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(format!("not a BTF file: magic {magic:#06x}"));
        }
        let u32_at = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let hdr_len = u32_at(4) as usize;
        if hdr_len < BTF_HEADER_BYTES {
            return Err(format!(
                "BTF header length {hdr_len} is under {BTF_HEADER_BYTES}"
            ));
        }
        let type_off = u32_at(8) as usize;
        let type_len = u32_at(12) as usize;
        let str_off = u32_at(16) as usize;
        let str_len = u32_at(20) as usize;

        let types_base = hdr_len
            .checked_add(type_off)
            .ok_or("BTF type section offset overflows")?;
        let types_end = types_base
            .checked_add(type_len)
            .ok_or("BTF type section end overflows")?;
        let strings_base = hdr_len
            .checked_add(str_off)
            .ok_or("BTF string section offset overflows")?;
        let strings_end = strings_base
            .checked_add(str_len)
            .ok_or("BTF string section end overflows")?;
        if types_end > data.len() || strings_end > data.len() {
            return Err(format!(
                "BTF sections lie past the file end ({} bytes): types..{types_end}, strings..{strings_end}",
                data.len()
            ));
        }
        Ok(Self {
            data,
            types_base,
            types_len: type_len,
            strings_base,
            strings_len: str_len,
        })
    }

    /// The name at a string-table offset, or None when the offset is
    /// out of the section (anonymous names use offset 0).
    fn name(&self, name_off: u32) -> Option<&'a str> {
        if name_off == 0 {
            return Some("");
        }
        let start = self.strings_base.checked_add(name_off as usize)?;
        let bytes = self.data.get(start..self.strings_base + self.strings_len)?;
        let end = bytes.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    /// Walk the type records looking for the first STRUCT with the
    /// given name. The walk mirrors the reference parser this pass
    /// was designed against: 12-byte records, per-kind trailing
    /// payloads (INT +4, ARRAY +12, STRUCT/UNION vlen*12, ENUM
    /// vlen*8, FUNC_PROTO vlen*8, VAR +4, DATASEC vlen*12, DECL_TAG
    /// +4, ENUM64 vlen*12) - one miscalculated kind desyncs the whole
    /// walk, so the bounds are checked at every step.
    fn find_struct(&self, want: &str) -> Option<StructEntry> {
        let mut pos = self.types_base;
        let end = self.types_base + self.types_len;
        while pos + 12 <= end {
            let name_off = u32_at(self.data, pos);
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let vlen = (info & 0xFFFF) as usize;
            let extra = kind_extra_bytes(kind, vlen);
            let Some(extra) = extra else {
                // A truncated record: stop the walk rather than read
                // past the section (find_struct only fails to find,
                // the caller turns that into the named error).
                break;
            };
            if pos + 12 + extra > end {
                break;
            }
            if kind == 4 {
                // BTF_KIND_STRUCT
                if self.name(name_off) == Some(want) {
                    return Some(StructEntry {
                        members_pos: pos + 12,
                        vlen,
                    });
                }
            }
            pos += 12 + extra;
        }
        None
    }

    /// Walk the type records looking for the FUNC record (kind 12)
    /// with the given name - the same walk discipline as
    /// [`Self::find_struct`]. The FUNC record's vlen is the linkage
    /// (static/global/extern), not a count; the payload is zero
    /// bytes either way.
    fn find_func(&self, want: &str) -> Option<FuncEntry> {
        let mut pos = self.types_base;
        let end = self.types_base + self.types_len;
        while pos + 12 <= end {
            let name_off = u32_at(self.data, pos);
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let vlen = (info & 0xFFFF) as usize;
            let extra = kind_extra_bytes(kind, vlen);
            let Some(extra) = extra else {
                break;
            };
            if pos + 12 + extra > end {
                break;
            }
            if kind == 12 && self.name(name_off) == Some(want) {
                return Some(FuncEntry { pos });
            }
            pos += 12 + extra;
        }
        None
    }

    /// The record start position for a BTF type id. Ids are assigned
    /// sequentially from 1 in section order (0 is the void type), so
    /// the position is the id-th record - one bounded walk. `None`
    /// when the id is out of the section; the caller refuses by name.
    fn record_pos(&self, want_id: u32) -> Option<usize> {
        if want_id == 0 {
            return None;
        }
        let mut pos = self.types_base;
        let end = self.types_base + self.types_len;
        let mut id = 1u32;
        while pos + 12 <= end {
            if id == want_id {
                return Some(pos);
            }
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let vlen = (info & 0xFFFF) as usize;
            let extra = kind_extra_bytes(kind, vlen)?;
            if pos + 12 + extra > end {
                return None;
            }
            pos += 12 + extra;
            id = id.checked_add(1)?;
        }
        None
    }

    /// The FUNC's first-argument shape: the struct name arg0 points
    /// at, resolved through the pointer and any typedef/qualifier
    /// chains. Every refusal names its stage; a pointer to a pointer
    /// or a by-value struct is refused as loudly as an absent proto -
    /// each is a different wrong answer at the same attach point.
    fn func_arg0_struct(&self, func: FuncEntry, fname: &str) -> Result<String, String> {
        let proto_id = u32_at(self.data, func.pos + 8);
        let Some(proto_pos) = self.record_pos(proto_id) else {
            return Err(format!(
                "{fname}'s FUNC_PROTO (type id {proto_id}) is not in the section"
            ));
        };
        let info = u32_at(self.data, proto_pos + 4);
        let kind = (info >> 24) & 0x1F;
        let vlen = (info & 0xFFFF) as usize;
        if kind != 13 {
            return Err(format!(
                "{fname}'s type id {proto_id} is not a FUNC_PROTO (kind {kind})"
            ));
        }
        if vlen == 0 {
            return Err(format!("{fname} takes no arguments in BTF"));
        }
        let param_pos = proto_pos + 12;
        if param_pos + 8 > self.types_base + self.types_len {
            return Err(format!(
                "{fname}'s first parameter lies past the type section"
            ));
        }
        let arg0_id = u32_at(self.data, param_pos + 4);
        // Resolve arg0: exactly one PTR, then typedef/qualifier
        // chains, then a named STRUCT/UNION - anything else is the
        // wrong shape for the probe's first read.
        let mut id = arg0_id;
        let mut through_ptr = false;
        for _ in 0..8 {
            let Some(pos) = self.record_pos(id) else {
                return Err(format!(
                    "{fname}'s first argument type id {id} is not in the section"
                ));
            };
            let name_off = u32_at(self.data, pos);
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let target = u32_at(self.data, pos + 8);
            match kind {
                // PTR: follow the pointee - but only once; a pointer
                // to a pointer is not the file contract.
                2 => {
                    if through_ptr {
                        return Err(format!(
                            "{fname}'s first argument is a pointer to a pointer, \
                             not a pointer to struct file"
                        ));
                    }
                    through_ptr = true;
                    id = target;
                }
                // TYPEDEF / VOLATILE / CONST / RESTRICT / TYPE_TAG:
                // follow the target.
                8 | 9 | 10 | 11 | 18 => id = target,
                // STRUCT / UNION: the terminal shape.
                4 | 5 => {
                    let name = self.name(name_off).unwrap_or("");
                    if name.is_empty() {
                        return Err(format!(
                            "{fname}'s first argument points at an anonymous struct"
                        ));
                    }
                    if !through_ptr {
                        return Err(format!(
                            "{fname}'s first argument is struct {name} by value, \
                             not a pointer to struct file"
                        ));
                    }
                    return Ok(name.to_owned());
                }
                other => {
                    return Err(format!(
                        "{fname}'s first argument is BTF kind {other}, \
                         not a pointer to struct file"
                    ));
                }
            }
        }
        Err(format!(
            "{fname}'s first argument resolves through too many indirections - refusing"
        ))
    }

    /// The aggregate's members as (name, type id, bit offset)
    /// triples - the type id is what the anonymous-aggregate
    /// descent follows, and a name that reads empty is BTF's
    /// anonymous-member marker.
    fn members_of(&self, entry: StructEntry) -> Vec<(&'a str, u32, u32)> {
        let mut out = Vec::with_capacity(entry.vlen);
        for i in 0..entry.vlen {
            let m_pos = entry.members_pos + i * 12;
            let Some(m) = self.data.get(m_pos..m_pos + 12) else {
                break;
            };
            let m_name_off = u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
            let m_type = u32::from_le_bytes([m[4], m[5], m[6], m[7]]);
            let bit_offset = u32::from_le_bytes([m[8], m[9], m[10], m[11]]);
            let name = self.name(m_name_off).unwrap_or("");
            out.push((name, m_type, bit_offset));
        }
        out
    }

    /// One member's bit offset anywhere in the aggregate tree rooted
    /// at `entry`, C-correct: `file->f_path` names a direct member
    /// or a member of an anonymous struct/union the aggregate embeds,
    /// never a named nested aggregate's field (which is a different
    /// expression, `file->inner.field`). Kernel 6.18 wraps struct
    /// file's f_path in exactly such an unnamed union, so the
    /// direct-member walk found nothing on every 6.18+ host and the
    /// descent restores the reach. The depth budget only bounds a
    /// malformed blob's type graph - no kernel struct nests
    /// anonymous aggregates eight levels deep.
    fn find_member(
        &self,
        entry: StructEntry,
        want: &str,
        base_bits: u32,
        depth: u8,
    ) -> Option<u32> {
        if depth == 0 {
            return None;
        }
        for (name, type_id, bit_offset) in self.members_of(entry) {
            // The anonymous member: its fields ride the inner
            // aggregate's own member list, at this member's base. A
            // sum that overflows belongs to a malformed blob and
            // only skips the member.
            let Some(absolute) = base_bits.checked_add(bit_offset) else {
                continue;
            };
            if name == want {
                return Some(absolute);
            }
            if name.is_empty()
                && let Some(nested) = self.aggregate_of(type_id)
                && let Some(found) = self.find_member(nested, want, absolute, depth - 1)
            {
                return Some(found);
            }
        }
        None
    }

    /// The aggregate a member's type points at, through any
    /// const/volatile/restrict/typedef chain wrapping it - the only
    /// shape an anonymous member can be walked into. Everything
    /// else stays skipped: a pointer or a scalar member hides no
    /// field the host's own naming can reach.
    fn aggregate_of(&self, type_id: u32) -> Option<StructEntry> {
        let mut id = type_id;
        for _ in 0..8 {
            let pos = self.record_pos(id)?;
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let target = u32_at(self.data, pos + 8);
            match kind {
                // STRUCT / UNION: the shape that can be entered.
                4 | 5 => {
                    let vlen = (info & 0xFFFF) as usize;
                    return Some(StructEntry {
                        members_pos: pos + 12,
                        vlen,
                    });
                }
                // TYPEDEF / VOLATILE / CONST / RESTRICT / TYPE_TAG.
                8 | 9 | 10 | 11 | 18 => id = target,
                _ => return None,
            }
        }
        None
    }
}

/// The per-kind trailing payload sizes in bytes. None when the
/// record cannot fit: the walk stops.
fn kind_extra_bytes(kind: u32, vlen: usize) -> Option<usize> {
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

fn u32_at(data: &[u8], off: usize) -> u32 {
    let b = data.get(off..off + 4).unwrap_or(&[0; 4]);
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
#[path = "../../test/ebpf/btf_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../test/ebpf/btf_flatten_tests.rs"]
mod flatten_tests;
#[cfg(test)]
#[path = "../../test/ebpf/btf_writev_tests.rs"]
mod writev_tests;
