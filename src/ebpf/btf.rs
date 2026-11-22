// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The BTF offsets parser (night-improve-3, feature builds only):
//! the loud half of the offsets contract. Every struct walk the two
//! kprobes perform reads its offset from the `offsets` map - and the
//! values in that map are parsed from THE HOST'S OWN
//! /sys/kernel/btf/vmlinux at attach time, never compiled in.
//!
//! Why runtime, why refused-when-unverifiable: this repo's own
//! reference probe (kernel 5.10.134) puts struct inode's i_ino at
//! @64 - the "textbook" order would say @16, and other versions
//! again. A wrong hardcoded offset reads the wrong field SILENTLY;
//! the host's own BTF is the one source that cannot drift from the
//! kernel it describes, and refusing to attach when it cannot be
//! parsed is the honest alternative to a guess. A 5.15+ distro
//! kernel ships it.
//!
//! night-improve-49: the member lookups learned the anonymous union
//! (the 6.18 kernel wraps struct file's f_path in an unnamed union):
//! the walk descends anonymous struct/union members only,
//! accumulating bit offsets; still unfound is the named error.
//!
//! The parser is deliberately minimal: a BTF header check, a type
//! walk, nine struct lookups, thirteen member lookups. Pure std,
//! no unsafe - it reads a file, trusts nothing, returns what THE HOST
//! says, and names every lookup failure. night-frontier-2 grows the
//! parse by one member (inode.i_sb, the unlink/rename probes' device
//! hop) and widens the walker's seam to pub(crate) - the btf_writev
//! sibling's precedent - so src/ebpf/btf_unlink.rs drives the same
//! BtfFile for the FUNC-parameter scan the unlink/rename anchors
//! ride; one walker serves every lane. night-frontier-Z8 adds the
//! second parse of the same walker (the btf_offpath sibling): the
//! D5 identity chain (task_struct.nsproxy, nsproxy.net_ns, net.ns,
//! ns_common.inum) rides
//! [`parse_identity_offsets`], refusal-by-name when a field is
//! absent, written to the map at its own slots.
//!
//! night-improve-57: the plain-write probe left vfs_write behind
//! (the newest -O3 distro builds inline it out of the executed
//! path; found dead on cachyos 7.2 by the moving-latest witness;
//! the probe now rides the raw_syscalls/sys_enter tracepoint,
//! night-improve-59), so the parse grows the four fd-walk slots
//! that turn the syscall's fd register back into the struct file*
//! the walk reads: task_struct.files, files_struct.fdt,
//! fdtable.max_fds, and fdtable.fd.
//!
//! The file is path-included by the fuzz harness and compiled
//! standalone there (the include law): pure std, zero `crate::`
//! references. The night-hunter-4 diagnostic trace lives at the
//! attach boundary (src/ebpf/loader.rs), not here.

// The byte-level decode lives beside the parser (night-zen-lts-1):
// the 600-cap split put decode_info / kind_extra_bytes / u32_at in
// their own read-in-one-breath module
use super::btf_decode::{decode_info, kind_extra_bytes, u32_at};

/// The BTF magic, as a little-endian u16 over the file's first two
/// bytes (0x9F 0xEB in the file).
const BTF_MAGIC: u16 = 0xEB9F;

/// The fixed size of the btf_header every version carries.
const BTF_HEADER_BYTES: usize = 24;

/// The offsets the probes read, slot-aligned to the events.rs
/// OFF_SLOT_* indices: the eight frozen file-walk slots, the four
/// fd-walk slots night-improve-57 appends, and the inode i_sb hop
/// night-frontier-2 appends. Every appended tail the map carries
/// rides its OWN parse at the attach boundary (btf_unlink.rs,
/// btf_offpath.rs, and [`parse_identity_offsets`] the D5 identity
/// chain), each written at its own OFF_SLOT_* indices, never by
/// array position (the night-hunter-3 lesson).
pub type ProbeOffsets = [u64; 13];

/// Parse the host's own /sys/kernel/btf/vmlinux. Every error names
/// its stage; nothing is guessed, ever.
pub fn parse_probe_offsets() -> Result<ProbeOffsets, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    parse_btf_offsets(&data)
}

/// The pure parser: given the raw BTF file bytes, return the
/// thirteen struct-walk offsets. Separated from
/// [`parse_probe_offsets`] so the tests can
/// drive it with synthetic blobs end to end. The twelve struct
/// lookups cover the file walks and the identity walk: the exec
/// probe reads no context fields (its counter rides helpers alone)
/// and the lifecycle tracepoints are gone with the lifecycle stream
/// (night-improve-34), so no tracepoint context and no other
/// task_struct offsets are verified or stored beyond the two the
/// fd walk and the netns walk ride.
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
        member_offset(&ctx, inode, "inode", "i_sb")?,
    ])
}

/// The identity walk's pure parse: given the raw BTF file bytes,
/// return the four identity offsets in OFF_SLOT_TASK_NSPROXY order.
pub fn parse_identity_offsets(data: &[u8]) -> Result<IdentityOffsets, String> {
    let ctx = BtfFile::new(data)?;
    let task = ctx
        .find_struct("task_struct")
        .ok_or_else(|| "struct task_struct not found in BTF".to_owned())?;
    let nsproxy = ctx
        .find_struct("nsproxy")
        .ok_or_else(|| "struct nsproxy not found in BTF".to_owned())?;
    let net = ctx
        .find_struct("net")
        .ok_or_else(|| "struct net not found in BTF".to_owned())?;
    let ns_common = ctx
        .find_struct("ns_common")
        .ok_or_else(|| "struct ns_common not found in BTF".to_owned())?;
    Ok([
        member_offset(&ctx, task, "task_struct", "nsproxy")?,
        member_offset(&ctx, nsproxy, "nsproxy", "net_ns")?,
        member_offset(&ctx, net, "net", "ns")?,
        member_offset(&ctx, ns_common, "ns_common", "inum")?,
    ])
}

/// The anonymous-member walk's total-work budget (night-zen-lts-1):
/// a malformed blob's type graph is bounded, never a grind.
const MEMBER_WALK_BUDGET: u64 = 1024;

/// One member's byte offset inside a located struct, direct or
/// through any anonymous aggregate the struct embeds. A bitfield
/// result (a bit offset that is not byte-aligned) is refused by
/// name: no struct in the set carries one, and a straddled read
/// would be a guess.
pub(crate) fn member_offset(
    ctx: &BtfFile<'_>,
    entry: StructEntry,
    sname: &str,
    mname: &str,
) -> Result<u64, String> {
    let mut budget = MEMBER_WALK_BUDGET;
    let Some(bit_offset) = ctx.find_member(entry, mname, 0, 8, &mut budget) else {
        return Err(format!("struct {sname} has no member {mname} in BTF"));
    };
    if bit_offset % 8 != 0 {
        return Err(format!(
            "struct {sname} member {mname} is a bitfield (bit {bit_offset}) - refusing"
        ));
    }
    let offset = u64::from(bit_offset / 8);
    Ok(offset)
}

/// The walked BTF file: the type records and the string section,
/// sliced and bounds-checked once.
pub(crate) struct BtfFile<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) types_base: usize,
    pub(crate) types_len: usize,
    strings_base: usize,
    strings_len: usize,
}

/// One located STRUCT or UNION record: member-list position and
/// member count.
#[derive(Clone, Copy)]
pub(crate) struct StructEntry {
    members_pos: usize,
    vlen: usize,
}

/// One located FUNC record (night-improve-42): its header position.
#[derive(Clone, Copy)]
pub(crate) struct FuncEntry {
    pub(crate) pos: usize,
}

impl<'a> BtfFile<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, String> {
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

    /// The name at a string-table offset (anonymous names: offset 0).
    pub(crate) fn name(&self, name_off: u32) -> Option<&'a str> {
        if name_off == 0 {
            return Some("");
        }
        let start = self.strings_base.checked_add(name_off as usize)?;
        let bytes = self.data.get(start..self.strings_base + self.strings_len)?;
        let end = bytes.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    /// Walk the type records looking for the first STRUCT with the
    /// given name: 12-byte records, per-kind trailing payloads, the
    /// bounds checked at every step (one wrong kind desyncs the
    /// walk).
    pub(crate) fn find_struct(&self, want: &str) -> Option<StructEntry> {
        let mut pos = self.types_base;
        let end = self.types_base + self.types_len;
        while pos + 12 <= end {
            let name_off = u32_at(self.data, pos);
            let info = u32_at(self.data, pos + 4);
            let (kind, vlen) = decode_info(info);
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
    pub(crate) fn find_func(&self, want: &str) -> Option<FuncEntry> {
        let mut pos = self.types_base;
        let end = self.types_base + self.types_len;
        while pos + 12 <= end {
            let name_off = u32_at(self.data, pos);
            let info = u32_at(self.data, pos + 4);
            let (kind, vlen) = decode_info(info);
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

    /// The record start position for a BTF type id (ids run from 1;
    /// 0 is void) - one bounded walk, `None` past the section.
    pub(crate) fn record_pos(&self, want_id: u32) -> Option<usize> {
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
            let (kind, vlen) = decode_info(info);
            let extra = kind_extra_bytes(kind, vlen)?;
            if pos + 12 + extra > end {
                return None;
            }
            pos += 12 + extra;
            id = id.checked_add(1)?;
        }
        None
    }

    /// The FUNC's first-argument shape: the struct arg0 points at,
    /// through pointer + typedef/qualifier chains. Every refusal
    /// names its stage.
    pub(crate) fn func_arg0_struct(&self, func: FuncEntry, fname: &str) -> Result<String, String> {
        let proto_id = u32_at(self.data, func.pos + 8);
        let Some(proto_pos) = self.record_pos(proto_id) else {
            return Err(format!(
                "{fname}'s FUNC_PROTO (type id {proto_id}) is not in the section"
            ));
        };
        let info = u32_at(self.data, proto_pos + 4);
        let (kind, vlen) = decode_info(info);
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
    /// triples - the anonymous-descent's fuel.
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
        budget: &mut u64,
    ) -> Option<u32> {
        if depth == 0 {
            return None;
        }
        for (name, type_id, bit_offset) in self.members_of(entry) {
            // The shared ceiling: member visits and aggregate hops
            // both spend it, so a hostile graph exhausts the budget
            // instead of the clock.
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
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
                && let Some(nested) = self.aggregate_of(type_id, budget)
                && let Some(found) = self.find_member(nested, want, absolute, depth - 1, budget)
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
    /// field the host's own naming can reach. The shared walk budget
    /// bounds the record hops a malformed blob can force.
    fn aggregate_of(&self, type_id: u32, budget: &mut u64) -> Option<StructEntry> {
        let mut id = type_id;
        for _ in 0..8 {
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
            let pos = self.record_pos(id)?;
            let info = u32_at(self.data, pos + 4);
            let kind = (info >> 24) & 0x1F;
            let target = u32_at(self.data, pos + 8);
            match kind {
                // STRUCT / UNION: the shape that can be entered.
                4 | 5 => {
                    let (_, vlen) = decode_info(info);
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

#[cfg(test)]
#[path = "../../test/ebpf/btf_corpus_tests.rs"]
mod corpus_tests;
#[cfg(test)]
#[path = "../../test/ebpf/btf_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../test/ebpf/btf_flatten_tests.rs"]
mod flatten_tests;
#[cfg(test)]
#[path = "../../test/ebpf/btf_writev_tests.rs"]
mod writev_tests;

// The unlink/rename anchor pins (night-frontier-2): a sibling test
// module of the btf suite (the flatten-twin law) - it shares the
// pub(super) blob builders and drives src/ebpf/btf_unlink.rs's
// verifier against synthetic FUNC records.
#[cfg(test)]
#[path = "../../test/ebpf/btf_unlink_tests.rs"]
mod unlink_lane_tests;
// The off-path lanes' anchor pins (night-frontier-Z7, D4): the same
// sibling shape - the shared pub(super) blob builders drive the dirty
// anchor ladder and the io_kiocb shape against synthetic records;
// the REAL-dialect pins ride the corpus suite.
#[cfg(test)]
#[path = "../../test/ebpf/btf_offpath_tests.rs"]
mod offpath_lane_tests;

/// The identity offsets one parse returns, in IDENT_SLOT_* order.
pub type IdentityOffsets = [u64; 4];

/// The identity walk's own parse (night-frontier-Z8, D5): the four
/// offsets every record's netns identity rides, written to the map
/// at its OFF_SLOT_ indices EXPLICITLY, never by array position.
/// The member is net_ns, NOT net - the corpus proves the guess
/// wrong on every committed dialect; a wrong name refuses at
/// attach, by name. Identity is CORE: a host whose BTF cannot
/// vouch for the chain refuses at attach. Separated so tests drive
/// it with synthetic blobs.
/// The identity array's own slot indices (the parse's return order,
/// which write_offsets maps onto the OFF_SLOT_TASK_NSPROXY..OFF_SLOT_
/// NS_COMMON_INUM map indices explicitly). Named so a caller cannot
/// ride array positions by accident.
pub const IDENT_SLOT_TASK_NSPROXY: usize = 0;
pub const IDENT_SLOT_NSPROXY_NET: usize = 1;
pub const IDENT_SLOT_NET_NS: usize = 2;
pub const IDENT_SLOT_NS_COMMON_INUM: usize = 3;
