// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The off-path lanes' anchor verification (night-frontier-Z7, D4 -
//! the btf_writev/btf_unlink sibling precedent): the mmap-dirty
//! anchor ladder and the io_uring capability's shape, read from the
//! host's own BTF at attach time, never compiled in. A kprobe at a
//! symbol whose shape the host cannot vouch for reads garbage
//! SILENTLY; the loud refusal (or the named-down capability) is the
//! only honest alternative. The offsets parser stays in
//! [`super::btf`]; the BTF walker ([`BtfFile`]) is shared, the
//! sibling reach is `super::`, never `crate::` (the include law the
//! fuzz harness carries for this file family).
//!
//! THE DIRTY ANCHOR LADDER (preference order, data-driven):
//! 1. `filemap_dirty_folio(struct address_space *, struct folio *)`
//!    - the folio-shape kernels: arg0 IS the mapping, so the walk
//!    starts at the BTF-vouched argument and page.mapping is never
//!    read. Present from the folio merge (5.16) forward.
//! 2. `__set_page_dirty_nobuffers(struct page *)` - the page-shape
//!    kernels: arg0 is the page; the probe reads page.mapping (the
//!    OFF_SLOT_PAGE_MAPPING hop, derived per host - on these kernels
//!    struct folio does not exist, so the parser derives the slot
//!    from struct page directly).
//! A symbol present with a MOVED argument shape is a hard refusal
//! (the name exists but the contract moved - never a silent
//! fallthrough); a symbol ABSENT falls through to the next rung.
//! Neither rung vouching names the mmap-dirty capability down.
//!
//! THE IO_URING SHAPE: the io_uring_submit_sqe tracepoint carries
//! the submitted io_kiocb pointer at its stable ABI offset; the
//! probe then walks io_kiocb.file - the ONE host-shaped value the
//! lane needs. A kernel whose BTF carries no io_kiocb struct (no
//! io_uring, or a build without its BTF) names the capability down
//! (Ok(None)); an io_kiocb present with no vouchable `file` member
//! is a hard refusal for the capability (the shape moved - named,
//! never guessed). The tracepoint's own existence is checked at the
//! attach boundary against tracefs (the loader's step, after
//! ensure_tracefs), not here.

use super::btf::BtfFile;

/// The off-path lanes' own offsets (night-frontier-Z7, D4): the
/// three slots the off-path probes read beyond the core file-walk
/// set. `page_mapping` and `address_space_host` are the dirty-descent
/// pair (the mmap-dirty truth rides them on every anchor shape);
/// `io_kiocb_file` is the io_uring submission's request-to-file hop.
/// Each is `None` when the host's BTF cannot vouch for it - the
/// capability that would read it is unplanted and NAMED, never a
/// zero-offset guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffPathOffsets {
    /// struct page, member mapping - the page-shape dirty anchor's
    /// one hop to the mapping (the folio-shape anchor starts at the
    /// BTF-vouched mapping argument and reads nothing here, but the
    /// slot is derived whenever either struct vouches for the
    /// member, and struct folio embeds struct page at offset 0 so
    /// the value is the same number either way).
    pub page_mapping: Option<u64>,
    /// struct address_space, member host - the mapping-to-inode hop
    /// both dirty anchors ride.
    pub address_space_host: Option<u64>,
    /// struct io_kiocb, member file - the io_uring request's struct
    /// file. `None` on a kernel whose BTF carries no io_kiocb (no
    /// io_uring, or a shape the walker cannot vouch for) - the
    /// io_uring capability is named down, not guessed.
    pub io_kiocb_file: Option<u64>,
}

/// Parse the off-path lanes' offsets from the same BTF blob the core
/// parse reads. The dirty-descent pair is required as a PAIR (either
/// both derive or both stay None - a half chain is a guess); the
/// io_kiocb hop stands alone. A folio-carrying kernel derives the
/// page_mapping slot from `folio.mapping` (the same number
/// `page.mapping` yields, through the embedded page); everything
/// else derives it from `page.mapping` directly.
pub fn parse_offpath_offsets(data: &[u8]) -> Result<OffPathOffsets, String> {
    let ctx = BtfFile::new(data)?;
    let page_mapping = match ctx.find_struct("folio") {
        Some(folio) => super::btf::member_offset(&ctx, folio, "folio", "mapping")?,
        None => {
            let page = ctx
                .find_struct("page")
                .ok_or_else(|| "no struct page or struct folio in BTF".to_owned())?;
            super::btf::member_offset(&ctx, page, "page", "mapping")?
        }
    };
    let address_space = ctx
        .find_struct("address_space")
        .ok_or_else(|| "struct address_space not found in BTF".to_owned())?;
    let host = super::btf::member_offset(&ctx, address_space, "address_space", "host")?;
    let io_kiocb_file = ctx
        .find_struct("io_kiocb")
        .and_then(|kiocb| super::btf::member_offset(&ctx, kiocb, "io_kiocb", "file").ok());
    Ok(OffPathOffsets {
        page_mapping: Some(page_mapping),
        address_space_host: Some(host),
        io_kiocb_file,
    })
}

/// The dirty anchor's shape - which anchor symbol planted the
/// mmap-dirty probe, and therefore which context read the program
/// rides. The loader plants exactly one; the other program stays
/// unloaded (aya loads programs lazily, so the unchosen shape never
/// reaches this kernel's verifier).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirtyShape {
    /// `filemap_dirty_folio`: arg0 is the address_space - the walk
    /// starts at the mapping directly.
    Folio,
    /// `__set_page_dirty_nobuffers`: arg0 is the struct page - the
    /// walk's first hop is page.mapping (the derived slot).
    Page,
}

/// The verified mmap-dirty anchor: the symbol to attach and the
/// shape it vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirtyAnchor {
    pub symbol: &'static str,
    pub shape: DirtyShape,
}

/// The io_uring lane's verified shape: the io_kiocb.file member
/// offset, when the host vouches for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IouringLane {
    pub io_kiocb_file_offset: u64,
}

/// The dirty anchor symbols, in preference order, with the shape
/// each vouches for and the struct its first argument must be.
const DIRTY_LADDER: [(&str, DirtyShape, &str); 2] = [
    ("filemap_dirty_folio", DirtyShape::Folio, "address_space"),
    ("__set_page_dirty_nobuffers", DirtyShape::Page, "page"),
];

/// Verify the mmap-dirty anchor from the host's own BTF (the pure
/// verifier seam - the loader reads the blob once and drives this;
/// the tests drive it with synthetic blobs end to end). A
/// present-but-moved symbol refuses hard; no rung at all names the
/// capability down.
pub fn verify_dirty_anchor_in(data: &[u8]) -> Result<DirtyAnchor, String> {
    let ctx = BtfFile::new(data)?;
    for (symbol, shape, want_arg0) in DIRTY_LADDER {
        let Some(func) = ctx.find_func(symbol) else {
            continue;
        };
        let struct_name = ctx.func_arg0_struct(func, symbol)?;
        if struct_name == want_arg0 {
            return Ok(DirtyAnchor { symbol, shape });
        }
        return Err(format!(
            "{symbol}'s first argument is struct {struct_name}, not struct \
             {want_arg0} - the symbol exists but its shape moved; refusing \
             rather than guessing"
        ));
    }
    Err(format!(
        "no BTF FUNC record for {} - this kernel does not carry the \
         page-dirty path under a verifiable name; the mmap-dirty capability \
         stays named-down, not guessed",
        DIRTY_LADDER
            .iter()
            .map(|(s, _, _)| *s)
            .collect::<Vec<_>>()
            .join(" or ")
    ))
}

/// Verify the io_uring lane's shape (the pure verifier seam).
/// `Ok(None)` names the capability down (no io_kiocb in this
/// kernel's BTF); `Ok(Some(lane))` vouches for the request-to-file
/// hop; an Err refuses the capability hard (the shape moved).
pub fn verify_iouring_lane_in(data: &[u8]) -> Result<Option<IouringLane>, String> {
    let ctx = BtfFile::new(data)?;
    let Some(kiocb) = ctx.find_struct("io_kiocb") else {
        return Ok(None);
    };
    match super::btf::member_offset(&ctx, kiocb, "io_kiocb", "file") {
        Ok(offset) => Ok(Some(IouringLane {
            io_kiocb_file_offset: offset,
        })),
        Err(error) => Err(format!(
            "struct io_kiocb exists but carries no vouchable `file` member \
             ({error}) - the io_uring shape moved; the capability refuses \
             rather than guessing"
        )),
    }
}

// ── The memory-backed lane (night-frontier-Z9, D6) ──────────────────
//
// The off-path write truth's third rung: mmap stores on memory-backed
// files (tmpfs/ramfs; memfd_create rides tmpfs's superblock class)
// never reach either dirty anchor - the Z7 estate's own named
// residual, the largest forensic gap the ledger carried. The kernel's
// own reason closes it: a shared write fault IS the event (the store
// enters the kernel through the fault path, the one mechanism that
// cannot be skipped), and the fault path's funnel is a vouchable
// symbol on the floor dialects.

/// The memory-backed anchor symbols, in preference order, with the
/// struct each vouches for as arg0. The census
/// (test/ebpf/btf_corpus_tests.rs's memory-backed pins) froze the
/// span: fault_dirty_shared_page - the shared-write funnel, both
/// fault arms - vouches on the 5.15-6.8 dialects; on the 7.x line it
/// is inlined past any symbol, and the surviving wp_page_shared arm
/// (arg0 = vm_fault, the same context shape) carries the
/// write-protection arm - a PARTIAL coverage the attach summary and
/// the docs name, never a guess. One program rides whichever symbol
/// the ladder vouches (the writev probe's attach-symbol precedent:
/// the section types the program, the attach selects the event).
const MEMBACKED_LADDER: [(&str, &str); 2] = [
    ("fault_dirty_shared_page", "vm_fault"),
    ("wp_page_shared", "vm_fault"),
];

/// The verified memory-backed lane: the anchor symbol to attach and
/// the three walk offsets the probe reads beyond the core set (the
/// vm_fault.page hop, the superblock's s_type hop, and the
/// filesystem-type name pointer the class gate reads through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemBackedLane {
    pub anchor: &'static str,
    /// struct vm_fault, member page.
    pub vm_fault_page_offset: u64,
    /// struct super_block, member s_type.
    pub sb_type_offset: u64,
    /// struct file_system_type, member name.
    pub fst_name_offset: u64,
}

/// Verify the memory-backed lane from the host's own BTF (the pure
/// verifier seam). `Ok(None)` names the capability down (no
/// vouchable shared-write-fault symbol in this kernel's BTF - the
/// additive lanes' law: the camera stands, the class is named);
/// `Ok(Some(lane))` vouches for the anchor and its whole walk chain;
/// an Err refuses the capability hard (a present anchor whose shape
/// moved, or a present anchor whose walk chain cannot be vouched -
/// both are the guess class).
pub fn verify_membacked_lane_in(data: &[u8]) -> Result<Option<MemBackedLane>, String> {
    let ctx = BtfFile::new(data)?;
    for (symbol, want_arg0) in MEMBACKED_LADDER {
        let Some(func) = ctx.find_func(symbol) else {
            continue;
        };
        let struct_name = ctx.func_arg0_struct(func, symbol)?;
        if struct_name != want_arg0 {
            return Err(format!(
                "{symbol}'s first argument is struct {struct_name}, not struct \
                 {want_arg0} - the symbol exists but its shape moved; refusing \
                 rather than guessing"
            ));
        }
        let vm_fault = ctx
            .find_struct("vm_fault")
            .ok_or_else(|| "struct vm_fault not found in BTF".to_owned())?;
        let vm_fault_page = super::btf::member_offset(&ctx, vm_fault, "vm_fault", "page")?;
        let super_block = ctx
            .find_struct("super_block")
            .ok_or_else(|| "struct super_block not found in BTF".to_owned())?;
        let sb_type = super::btf::member_offset(&ctx, super_block, "super_block", "s_type")?;
        let fst = ctx
            .find_struct("file_system_type")
            .ok_or_else(|| "struct file_system_type not found in BTF".to_owned())?;
        let fst_name = super::btf::member_offset(&ctx, fst, "file_system_type", "name")?;
        return Ok(Some(MemBackedLane {
            anchor: symbol,
            vm_fault_page_offset: vm_fault_page,
            sb_type_offset: sb_type,
            fst_name_offset: fst_name,
        }));
    }
    Ok(None)
}
