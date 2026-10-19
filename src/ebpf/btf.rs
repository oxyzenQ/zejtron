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
//! The parser is deliberately minimal: a BTF header check, a type
//! walk, nine struct lookups by name, ten member lookups by name.
//! Pure std, no unsafe - it reads a file and slices bytes. The walk
//! mirrors the reference dump this pass was designed against
//! (scripts-side probe, kernel 5.10.134: struct file f_path@16
//! f_inode@32; struct path mnt@0 dentry@8; struct vfsmount mnt_sb@8;
//! struct super_block s_dev@16; struct dentry d_inode@48; struct
//! inode i_ino@64) - but the parser trusts nothing: it returns
//! whatever THE HOST says, and every lookup failure is an error that
//! names the missing piece.

/// The BTF magic, as a little-endian u16 over the file's first two
/// bytes (0x9F 0xEB in the file).
const BTF_MAGIC: u16 = 0xEB9F;

/// The fixed size of the btf_header every version carries.
const BTF_HEADER_BYTES: usize = 24;

/// The offsets the probes read, slot-aligned to the events.rs
/// OFF_SLOT_* indices: [dentry.d_inode, inode.i_ino, file.f_path,
/// file.f_inode, vfsmount.mnt_sb, super_block.s_dev, path.mnt,
/// path.dentry, tp_fork.parent_pid, tp_fork.child_pid,
/// tp_exit.pid, task_struct.real_parent, task_struct.tgid], every
/// value a byte offset. Eight file-walk slots through night-improve-3;
/// night-improve-4 appends the five process-stream slots (the two
/// tracepoint contexts and the task_struct pair the ppid walk rides).
pub type ProbeOffsets = [u64; 13];

/// Parse the host's own /sys/kernel/btf/vmlinux. Every error names
/// its stage; nothing is guessed, ever.
pub fn parse_probe_offsets() -> Result<ProbeOffsets, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    parse_btf_offsets(&data)
}

/// The pure parser: given the raw BTF file bytes, return the thirteen
/// offsets. Separated from [`parse_probe_offsets`] so the tests can
/// drive it with synthetic blobs end to end. The nine struct lookups
/// cover both probe families: the file walks (six structs) and the
/// process stream (the two sched tracepoint contexts plus
/// task_struct, whose real_parent and tgid the exec/exit ppid walk
/// dereferences). The exec tracepoint's context needs no offset -
/// its record reads only helpers - but the exec context STRUCT is
/// still verified present: a kernel whose exec tracepoint changed
/// shape under this program is a kernel the attach refuses.
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
    let tp_fork = ctx
        .find_struct("trace_event_raw_sched_process_fork")
        .ok_or_else(|| "struct trace_event_raw_sched_process_fork not found in BTF".to_owned())?;
    let tp_exit = ctx
        .find_struct("trace_event_raw_sched_process_exit")
        .ok_or_else(|| "struct trace_event_raw_sched_process_exit not found in BTF".to_owned())?;
    let tp_exec = ctx
        .find_struct("trace_event_raw_sched_process_exec")
        .ok_or_else(|| "struct trace_event_raw_sched_process_exec not found in BTF".to_owned())?;
    let task_struct = ctx
        .find_struct("task_struct")
        .ok_or_else(|| "struct task_struct not found in BTF".to_owned())?;

    // Presence proof for the exec context: no offset to store (the
    // exec record reads only helpers), but the struct must exist.
    let _ = tp_exec;

    Ok([
        member_offset(&ctx, dentry, "dentry", "d_inode")?,
        member_offset(&ctx, inode, "inode", "i_ino")?,
        member_offset(&ctx, file, "file", "f_path")?,
        member_offset(&ctx, file, "file", "f_inode")?,
        member_offset(&ctx, vfsmount, "vfsmount", "mnt_sb")?,
        member_offset(&ctx, super_block, "super_block", "s_dev")?,
        member_offset(&ctx, path, "path", "mnt")?,
        member_offset(&ctx, path, "path", "dentry")?,
        member_offset(
            &ctx,
            tp_fork,
            "trace_event_raw_sched_process_fork",
            "parent_pid",
        )?,
        member_offset(
            &ctx,
            tp_fork,
            "trace_event_raw_sched_process_fork",
            "child_pid",
        )?,
        member_offset(&ctx, tp_exit, "trace_event_raw_sched_process_exit", "pid")?,
        member_offset(&ctx, task_struct, "task_struct", "real_parent")?,
        member_offset(&ctx, task_struct, "task_struct", "tgid")?,
    ])
}

/// One member's byte offset inside a located struct. A bitfield
/// member (a bit offset that is not byte-aligned) is refused by
/// name: no struct in the set carries one, and a straddled read
/// would be a guess.
fn member_offset(
    ctx: &BtfFile<'_>,
    entry: StructEntry,
    sname: &str,
    mname: &str,
) -> Result<u64, String> {
    let members = ctx.members_of(entry);
    for (name, bit_offset) in members {
        if name == mname {
            if bit_offset % 8 != 0 {
                return Err(format!(
                    "struct {sname} member {mname} is a bitfield (bit {bit_offset}) - refusing"
                ));
            }
            return Ok(u64::from(bit_offset / 8));
        }
    }
    Err(format!("struct {sname} has no member {mname} in BTF"))
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

/// One located STRUCT record: its position and member count.
#[derive(Clone, Copy)]
struct StructEntry {
    members_pos: usize,
    vlen: usize,
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

    /// The struct's members as (name, bit offset) pairs.
    fn members_of(&self, entry: StructEntry) -> Vec<(&'a str, u32)> {
        let mut out = Vec::with_capacity(entry.vlen);
        for i in 0..entry.vlen {
            let m_pos = entry.members_pos + i * 12;
            let Some(m_name_off) = self.data.get(m_pos..m_pos + 4) else {
                break;
            };
            let m_name_off =
                u32::from_le_bytes([m_name_off[0], m_name_off[1], m_name_off[2], m_name_off[3]]);
            let Some(bits) = self.data.get(m_pos + 8..m_pos + 12) else {
                break;
            };
            let bit_offset = u32::from_le_bytes([bits[0], bits[1], bits[2], bits[3]]);
            let name = self.name(m_name_off).unwrap_or("");
            out.push((name, bit_offset));
        }
        out
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
