// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The unlink/rename-lane anchor verification (night-frontier-2,
//! split from btf.rs along the btf_writev seam precedent): the two
//! kprobe attach points and their argument shapes are read from the
//! host's own BTF at attach time, never compiled in.
//!
//! WHY THE SCAN, NOT A POSITION: the vfs_unlink signature churned
//! across the floor (mnt_userns prepended in 5.12 shifted dentry
//! from arg1 to arg2), which is why night-improve-3 skipped the
//! probe and reserved op=3 for a decade of releases. A kprobe
//! argument position is compiled into the program; a guessed
//! position reads garbage SILENTLY - the exact failure class the
//! offsets law exists to prevent, one layer up. The scan derives the
//! position from the host's own BTF instead: the parameter whose
//! type resolves to a pointer to struct dentry IS the dentry, at
//! whatever index this kernel's signature carries it. The position
//! rides the offsets map (events.rs OFF_SLOT_UNLINK_DENTRY_ARG) and
//! the probe reads its context argument through it, so a signature
//! move re-derives per host instead of misreading, and a kernel
//! whose vfs_unlink carries no recognizable dentry parameter refuses
//! at attach, by name, with zero pins touched.
//!
//! RENAME: vfs_rename funnels the whole rename(2) family through one
//! `struct renamedata *` argument (old_dir, old_dentry, new_dir,
//! new_dentry and friends - the struct's own member list churned
//! more than the signature ever did). The verifier pins arg0 to
//! renamedata by name (the func_arg0_struct contract, the writev
//! lane's law) and resolves old_dentry's member offset through the
//! same anonymous-aggregate descent the struct walk uses - the 6.18
//! unnamed-union lesson applies to renamedata's members exactly as
//! it did to struct file's f_path. At rename entry the file still
//! sits at its old name, so the OLD dentry is the side the
//! tracked_inodes filter knows; the record carries the old identity.
//!
//! The file is path-included by the fuzz harness beside its
//! siblings (fuzz/fuzz_targets/btf_parser.rs), so the include law
//! holds here too: pure std, the sibling reach is `super::`, never
//! `crate::`, and the diagnostic trace lives at the attach boundary
//! (src/ebpf/loader.rs). The arg0 walk stays self-contained in
//! btf.rs (the harness's compile graph stays minimal); this file is
//! the parameter-index generalization of that walk.

use super::btf::{BtfFile, FuncEntry, member_offset, u32_at};

/// The verified unlink/rename anchors, in the offsets-map slots they
/// ride: the vfs_unlink parameter index that carries the
/// `struct dentry *`, and the struct renamedata member offset of
/// old_dentry. The loader merges both into the offsets map at the
/// slots events.rs names (OFF_SLOT_UNLINK_DENTRY_ARG,
/// OFF_SLOT_RENAMEDATA_OLD_DENTRY); the BPF probes read them from
/// the map, never from a compiled constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlinkLane {
    /// The vfs_unlink argument index whose type is a pointer to
    /// struct dentry (2 on the idmap+ kernels, 1 before them).
    pub dentry_arg: u32,
    /// The byte offset of struct renamedata's old_dentry member,
    /// direct or through anonymous aggregates.
    pub old_dentry_offset: u64,
}

/// Verify the unlink/rename probes' anchors from the host's own BTF:
/// return the verified lane, or an error naming exactly what could
/// not be verified. The refusal, not a guess, is the point.
pub fn verify_unlink_lane() -> Result<UnlinkLane, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    verify_unlink_lane_in(&data)
}

/// The pure verifier: given the raw BTF file bytes, return the
/// verified lane. Separated from [`verify_unlink_lane`] so the tests
/// and the fuzz harness can drive it with synthetic blobs end to
/// end. Both anchors are verified from the same parse; a refusal on
/// either names its own stage.
pub fn verify_unlink_lane_in(data: &[u8]) -> Result<UnlinkLane, String> {
    let ctx = BtfFile::new(data)?;
    let dentry_arg = verify_unlink_dentry_arg(&ctx)?;
    let old_dentry_offset = verify_rename_old_dentry(&ctx)?;
    Ok(UnlinkLane {
        dentry_arg,
        old_dentry_offset,
    })
}

/// vfs_unlink's dentry parameter: exactly one parameter whose type
/// resolves to a pointer to struct dentry, at whatever index this
/// kernel's signature carries it. Zero such parameters (the shape
/// moved beyond recognition) and more than one (the anchor is
/// ambiguous) refuse by name - the loud alternatives to a guessed
/// argument position.
fn verify_unlink_dentry_arg(ctx: &BtfFile<'_>) -> Result<u32, String> {
    let fname = "vfs_unlink";
    let Some(func) = ctx.find_func(fname) else {
        return Err(format!(
            "no BTF FUNC record for {fname} - this kernel does not carry \
             the unlink path under a verifiable name"
        ));
    };
    let count = func_param_count(ctx, func, fname)?;
    let mut found: Option<usize> = None;
    for index in 0..count {
        match param_shape(ctx, func, fname, index)? {
            ParamShape::PtrStruct(name) if name == "dentry" => {
                if found.is_some() {
                    return Err(format!(
                        "{fname} carries more than one struct dentry * parameter - \
                         the anchor is ambiguous, refusing rather than guessing"
                    ));
                }
                found = Some(index);
            }
            // Every other shape (scalars, by-value aggregates, the
            // idmap/inode/delegated pointers) is simply not the
            // dentry - the scan skips it, the ambiguity check above
            // is the only decision.
            _ => {}
        }
    }
    let Some(index) = found else {
        return Err(format!(
            "{fname} carries no struct dentry * parameter in BTF - the \
             signature moved beyond recognition; refusing rather than guessing"
        ));
    };
    Ok(index as u32)
}

/// vfs_rename's old-dentry anchor: arg0 must be a pointer to struct
/// renamedata (the writev lane's arg0 contract), and the renamedata
/// record must carry old_dentry at a resolvable member offset - the
/// anonymous-descent walk, so a future unnamed-union wrap re-derives
/// instead of refusing.
fn verify_rename_old_dentry(ctx: &BtfFile<'_>) -> Result<u64, String> {
    let fname = "vfs_rename";
    let Some(func) = ctx.find_func(fname) else {
        return Err(format!(
            "no BTF FUNC record for {fname} - this kernel does not carry \
             the rename path under a verifiable name"
        ));
    };
    let arg0 = ctx.func_arg0_struct(func, fname)?;
    if arg0 != "renamedata" {
        return Err(format!(
            "{fname}'s first argument is struct {arg0}, not struct renamedata - \
             the symbol exists but its shape moved; refusing rather than guessing"
        ));
    }
    let Some(renamedata) = ctx.find_struct("renamedata") else {
        return Err("struct renamedata not found in BTF".to_owned());
    };
    member_offset(ctx, renamedata, "renamedata", "old_dentry")
}

/// The FUNC's prototype parameter count: the FUNC_PROTO's vlen. The
/// structural lies (a missing proto, a non-proto type id) refuse by
/// name - the scan refuses on them, never skips.
fn func_param_count(ctx: &BtfFile<'_>, func: FuncEntry, fname: &str) -> Result<usize, String> {
    let proto_id = u32_at(ctx.data, func.pos + 8);
    let Some(proto_pos) = ctx.record_pos(proto_id) else {
        return Err(format!(
            "{fname}'s FUNC_PROTO (type id {proto_id}) is not in the section"
        ));
    };
    let info = u32_at(ctx.data, proto_pos + 4);
    let kind = (info >> 24) & 0x1F;
    let vlen = (info & 0xFFFF) as usize;
    if kind != 13 {
        return Err(format!(
            "{fname}'s type id {proto_id} is not a FUNC_PROTO (kind {kind})"
        ));
    }
    Ok(vlen)
}

/// One parameter's resolved shape: the terminal of the pointer and
/// typedef/qualifier chain, the same walk btf.rs's func_arg0_struct
/// runs for arg0, generalized to any index and neutral in its arms.
/// The scan skips every non-matching shape; only the structural
/// lies (a record past the section, a type id not in the section)
/// come back as `Err`.
enum ParamShape {
    /// A pointer (through any typedef/qualifier chain) to a named
    /// struct/union - the only shape the scan matches on.
    PtrStruct(String),
    /// A pointer to a pointer.
    PtrToPtr,
    /// A struct/union passed by value (named or anonymous - the
    /// scan skips both).
    ByValue,
    /// A pointer to an anonymous struct/union.
    Anonymous,
    /// Any other BTF kind (a scalar, an array, a function pointer).
    Kind,
    /// The chain resolves through too many indirections.
    TooDeep,
}

/// Resolve ONE parameter (0-based) of the FUNC's prototype to its
/// shape. Mirrors btf.rs's func_arg0_struct resolution arm for arm
/// (PTR once, typedef/qualifier chains, named STRUCT/UNION terminal)
/// with the refusal edges returned as data instead of strings: the
/// caller decides which shapes match its contract.
fn param_shape(
    ctx: &BtfFile<'_>,
    func: FuncEntry,
    fname: &str,
    index: usize,
) -> Result<ParamShape, String> {
    let count = func_param_count(ctx, func, fname)?;
    if index >= count {
        return Err(format!(
            "{fname}'s argument {index} does not exist (the BTF prototype \
             carries {count})"
        ));
    }
    let proto_id = u32_at(ctx.data, func.pos + 8);
    let proto_pos = ctx
        .record_pos(proto_id)
        .ok_or_else(|| format!("{fname}'s proto position vanished mid-walk"))?;
    let param_pos = proto_pos + 12 + index * 8;
    if param_pos + 8 > ctx.types_base + ctx.types_len {
        return Err(format!(
            "{fname}'s argument {index} lies past the type section"
        ));
    }
    let mut id = u32_at(ctx.data, param_pos + 4);
    let mut through_ptr = false;
    for _ in 0..8 {
        let Some(pos) = ctx.record_pos(id) else {
            return Err(format!(
                "{fname}'s argument {index} type id {id} is not in the section"
            ));
        };
        let name_off = u32_at(ctx.data, pos);
        let info = u32_at(ctx.data, pos + 4);
        let kind = (info >> 24) & 0x1F;
        let target = u32_at(ctx.data, pos + 8);
        match kind {
            // PTR: follow the pointee - but only once; a pointer to
            // a pointer is not the anchor's shape.
            2 => {
                if through_ptr {
                    return Ok(ParamShape::PtrToPtr);
                }
                through_ptr = true;
                id = target;
            }
            // TYPEDEF / VOLATILE / CONST / RESTRICT / TYPE_TAG:
            // follow the target.
            8 | 9 | 10 | 11 | 18 => id = target,
            // STRUCT / UNION: the terminal shape.
            4 | 5 => {
                let name = ctx.name(name_off).unwrap_or("");
                if name.is_empty() {
                    return Ok(ParamShape::Anonymous);
                }
                if !through_ptr {
                    return Ok(ParamShape::ByValue);
                }
                return Ok(ParamShape::PtrStruct(name.to_owned()));
            }
            _other => return Ok(ParamShape::Kind),
        }
    }
    Ok(ParamShape::TooDeep)
}
