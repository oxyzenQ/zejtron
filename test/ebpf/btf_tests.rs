// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! BTF parser pins (night-improve-3): a synthetic vmlinux blob built
//! byte by byte exercises the whole walk end to end - the header
//! check, the per-kind trailing payloads (one miscalculated kind
//! desyncs the walk), the struct lookup by name, the member lookup
//! by name, the bitfield refusal, the truncation refusals. A live
//! host probe (skip when /sys/kernel/btf/vmlinux is absent) asserts
//! the parse succeeds and lands in plausible bounds. Wired from
//! src/ebpf/btf.rs.
//!
//! night-improve-42 grows the same discipline for the writev lane:
//! FUNC/FUNC_PROTO records drive the symbol verification end to
//! end - the verified shape, the absent-symbol fallback, the
//! reshaped refusal, the wrong-shape refusals, and the live-host
//! probe.
//!
//! night-improve-49 shares the builders with a flatten twin module
//! (test/ebpf/btf_flatten_tests.rs): the aggregate writers grew
//! member type ids (`strukt_typed`, the unnamed `union_`, the
//! `const_` wrapper), and the shared table pieces are pub(super) so
//! the twin builds its 6.18-shaped blobs from the same source.

use super::*;

// ── The synthetic blob builder ─────────────────────────────────────

pub(super) struct StrTab {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl StrTab {
    pub(super) fn new() -> Self {
        Self {
            bytes: vec![0],
            offsets: vec![0],
        }
    }
    fn add(&mut self, s: &str) -> u32 {
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.offsets.push(off);
        off
    }
}

pub(super) struct TypeWriter {
    bytes: Vec<u8>,
    records: u32,
}

impl TypeWriter {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            records: 0,
        }
    }
    /// The id the NEXT pushed record will carry (BTF ids run from 1
    /// in section order - the contract `record_pos` walks).
    pub(super) fn peek_id(&self) -> u32 {
        self.records + 1
    }
    fn push(&mut self, name_off: u32, kind: u32, vlen: usize, size: u32) {
        let info: u32 = (kind << 24) | (vlen as u32 & 0xFFFF);
        self.bytes.extend_from_slice(&name_off.to_le_bytes());
        self.bytes.extend_from_slice(&info.to_le_bytes());
        self.bytes.extend_from_slice(&size.to_le_bytes());
        self.records += 1;
    }
    /// Filler INT record (+4 trailing bytes) to exercise the walk.
    pub(super) fn int(&mut self, strings: &mut StrTab, name: &str) {
        let off = strings.add(name);
        self.push(off, 1, 0, 4);
        self.bytes.extend_from_slice(&[0, 0, 0, 0]); // btf_int extra
    }
    /// Filler ARRAY record (+12 trailing bytes).
    fn array(&mut self) {
        self.push(0, 3, 0, 8); // "size" reused as the value type id
        self.bytes.extend_from_slice(&[0; 12]); // btf_array
    }
    /// The member trailer both aggregate writers append: (name,
    /// type id, bit offset), twelve bytes each.
    fn members_trailer(&mut self, strings: &mut StrTab, members: &[(&str, u32, u32)]) {
        for (mname, mtype, bit) in members {
            let m_off = strings.add(mname);
            self.bytes.extend_from_slice(&m_off.to_le_bytes());
            self.bytes.extend_from_slice(&mtype.to_le_bytes());
            self.bytes.extend_from_slice(&bit.to_le_bytes());
        }
    }

    /// One STRUCT with members: (name, bit_offset), every member
    /// type pinned to id 1 - the shape every pre-49 blob carried.
    pub(super) fn strukt(
        &mut self,
        strings: &mut StrTab,
        name: &str,
        size: u32,
        members: &[(&str, u32)],
    ) {
        let typed: Vec<(&str, u32, u32)> = members
            .iter()
            .map(|(mname, bit)| (*mname, 1, *bit))
            .collect();
        self.strukt_typed(strings, name, size, &typed);
    }

    /// One STRUCT with typed members: (name, type id, bit_offset)
    /// - the writer the 6.18-shaped blobs ride.
    pub(super) fn strukt_typed(
        &mut self,
        strings: &mut StrTab,
        name: &str,
        size: u32,
        members: &[(&str, u32, u32)],
    ) {
        let off = strings.add(name);
        self.push(off, 4, members.len(), size);
        self.members_trailer(strings, members);
    }

    /// One unnamed UNION record with typed members (kind 5): the
    /// record's own name rides offset 0 - the empty string - the
    /// same way a real anonymous aggregate's BTF record carries it.
    pub(super) fn union_(&mut self, strings: &mut StrTab, size: u32, members: &[(&str, u32, u32)]) {
        self.push(0, 5, members.len(), size);
        self.members_trailer(strings, members);
    }

    /// One CONST record wrapping `target` - the wrapper the 6.18
    /// f_path member's own type carries.
    pub(super) fn const_(&mut self, target: u32) {
        self.push(0, 10, 0, target);
    }
    /// One PTR record (no trailing bytes); the pointee rides the
    /// size/type field. Returns the PTR's id.
    pub(super) fn ptr(&mut self, pointee: u32) -> u32 {
        let id = self.peek_id();
        self.push(0, 2, 0, pointee);
        id
    }
    /// One TYPEDEF record; the target rides the size/type field.
    pub(super) fn typedef(&mut self, strings: &mut StrTab, name: &str, target: u32) {
        let off = strings.add(name);
        self.push(off, 8, 0, target);
    }
    /// One FUNC record (static linkage) whose proto is `proto`.
    pub(super) fn func(&mut self, strings: &mut StrTab, name: &str, proto: u32) {
        let off = strings.add(name);
        self.push(off, 12, 0, proto);
    }
    /// One FUNC_PROTO record: the return type plus (name, type id)
    /// params, each an 8-byte trailer pair.
    pub(super) fn func_proto(&mut self, strings: &mut StrTab, ret: u32, params: &[(&str, u32)]) {
        self.push(0, 13, params.len(), ret);
        for (pname, ptype) in params {
            let p_off = strings.add(pname);
            self.bytes.extend_from_slice(&p_off.to_le_bytes());
            self.bytes.extend_from_slice(&ptype.to_le_bytes());
        }
    }
}

pub(super) fn build_btf(types: TypeWriter, strings: StrTab) -> Vec<u8> {
    let mut out = Vec::new();
    // btf_header: magic u16, version u8, flags u8, hdr_len u32,
    // type_off u32, type_len u32, str_off u32, str_len u32.
    out.extend_from_slice(&0xEB9Fu16.to_le_bytes());
    out.push(1); // version
    out.push(0); // flags
    out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
    out.extend_from_slice(&0u32.to_le_bytes()); // type_off
    out.extend_from_slice(&(types.bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(types.bytes.len() as u32).to_le_bytes()); // str_off = after types
    out.extend_from_slice(&(strings.bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&types.bytes);
    out.extend_from_slice(&strings.bytes);
    out
}

fn sample_blob() -> Vec<u8> {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // type id 1
    w.array();
    // The six structs, offsets chosen to match the reference probe
    // (kernel 5.10.134): the parser must return exactly these.
    w.strukt(
        &mut s,
        "dentry",
        208,
        &[("d_flags", 0), ("d_inode", 48 * 8)],
    );
    w.strukt(
        &mut s,
        "inode",
        656,
        &[("i_mode", 0), ("i_sb", 40 * 8), ("i_ino", 64 * 8)],
    );
    w.strukt(
        &mut s,
        "file",
        256,
        &[("f_path", 16 * 8), ("f_inode", 32 * 8)],
    );
    w.strukt(
        &mut s,
        "vfsmount",
        32,
        &[("mnt_root", 0), ("mnt_sb", 8 * 8)],
    );
    w.strukt(
        &mut s,
        "super_block",
        1536,
        &[("s_list", 0), ("s_dev", 16 * 8)],
    );
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]);
    fd_walk_structs(&mut w, &mut s);
    build_btf(w, s)
}

/// The three fd-walk structs every parse-ready blob carries since
/// night-improve-57 - the syscall-stub write tap's lookups
/// (task_struct.files, files_struct.fdt, fdtable.max_fds,
/// fdtable.fd). Synthetic offsets, stable across the blobs.
fn fd_walk_structs(w: &mut TypeWriter, s: &mut StrTab) {
    w.strukt(s, "task_struct", 4096, &[("files", 16 * 8)]);
    w.strukt(s, "files_struct", 512, &[("fdt", 0)]);
    w.strukt(s, "fdtable", 32, &[("max_fds", 0), ("fd", 8 * 8)]);
}

// ── The pins ────────────────────────────────────────────────────

#[test]
fn the_reference_probe_offsets_parse_end_to_end() {
    let blob = sample_blob();
    let offsets = parse_btf_offsets(&blob).expect("the synthetic blob parses");
    assert_eq!(
        offsets,
        [
            48, // dentry.d_inode
            64, // inode.i_ino
            16, // file.f_path
            32, // file.f_inode
            8,  // vfsmount.mnt_sb
            16, // super_block.s_dev
            0,  // path.mnt
            8,  // path.dentry
            16, // task_struct.files (night-improve-57)
            0,  // files_struct.fdt
            0,  // fdtable.max_fds
            8,  // fdtable.fd
        ]
    );
}

#[test]
fn a_wrong_magic_is_refused_by_name() {
    let mut blob = sample_blob();
    blob[0] = 0x00; // break the magic
    let err = parse_btf_offsets(&blob).unwrap_err();
    assert!(err.contains("not a BTF file"), "got: {err}");
}

#[test]
fn a_missing_struct_is_refused_by_name() {
    // The same blob without the inode struct: build with inode last.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int");
    w.array();
    w.strukt(&mut s, "dentry", 208, &[("d_inode", 48 * 8)]);
    w.strukt(
        &mut s,
        "file",
        256,
        &[("f_path", 16 * 8), ("f_inode", 32 * 8)],
    );
    w.strukt(&mut s, "vfsmount", 32, &[("mnt_sb", 8 * 8)]);
    w.strukt(&mut s, "super_block", 1536, &[("s_dev", 16 * 8)]);
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]);
    fd_walk_structs(&mut w, &mut s);
    let blob = build_btf(w, s);
    let err = parse_btf_offsets(&blob).unwrap_err();
    assert_eq!(err, "struct inode not found in BTF");
}

#[test]
fn a_missing_member_is_refused_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int");
    w.array();
    // inode carries i_sb but not i_ino.
    w.strukt(&mut s, "inode", 656, &[("i_mode", 0), ("i_sb", 40 * 8)]);
    w.strukt(&mut s, "dentry", 208, &[("d_inode", 48 * 8)]);
    w.strukt(
        &mut s,
        "file",
        256,
        &[("f_path", 16 * 8), ("f_inode", 32 * 8)],
    );
    w.strukt(&mut s, "vfsmount", 32, &[("mnt_sb", 8 * 8)]);
    w.strukt(&mut s, "super_block", 1536, &[("s_dev", 16 * 8)]);
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]);
    fd_walk_structs(&mut w, &mut s);
    let blob = build_btf(w, s);
    let err = parse_btf_offsets(&blob).unwrap_err();
    assert_eq!(err, "struct inode has no member i_ino in BTF");
}

#[test]
fn a_bitfield_member_is_refused_not_straddled() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int");
    w.array();
    // i_ino pinned at a non-byte-aligned bit offset.
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8 + 3)]);
    w.strukt(&mut s, "dentry", 208, &[("d_inode", 48 * 8)]);
    w.strukt(
        &mut s,
        "file",
        256,
        &[("f_path", 16 * 8), ("f_inode", 32 * 8)],
    );
    w.strukt(&mut s, "vfsmount", 32, &[("mnt_sb", 8 * 8)]);
    w.strukt(&mut s, "super_block", 1536, &[("s_dev", 16 * 8)]);
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]);
    fd_walk_structs(&mut w, &mut s);
    let blob = build_btf(w, s);
    let err = parse_btf_offsets(&blob).unwrap_err();
    assert!(err.contains("bitfield"), "got: {err}");
}

#[test]
fn truncation_is_refused_by_name() {
    let blob = sample_blob();
    let short = &blob[..16]; // shorter than the header
    let err = parse_btf_offsets(short).unwrap_err();
    assert!(err.contains("too short"), "got: {err}");
}

#[test]
fn sections_lying_past_the_file_end_are_refused() {
    let mut blob = sample_blob();
    // Corrupt str_len to point past the end: the bounds check fires.
    let str_len_off = 20usize;
    let huge: u32 = u32::MAX;
    blob[str_len_off..str_len_off + 4].copy_from_slice(&huge.to_le_bytes());
    let err = parse_btf_offsets(&blob).unwrap_err();
    assert!(err.contains("past the file end"), "got: {err}");
}

#[test]
fn the_live_host_parses_when_btf_exists() {
    // Skip when the host ships no BTF (the attach refusal is the
    // production behavior there); when it exists, the parse must
    // succeed and land in plausible bounds - this runs on the owner
    // host and in CI alike.
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return;
    }
    // Two honest outcomes on a host that ships vmlinux BTF:
    //
    // - the parse succeeds: assert only what holds BY CONSTRUCTION
    //   on any 64-bit host. No layout number is pinned here - not an
    //   absolute one and not a relational one - because kernel
    //   internals move. What the Ok arm guarantees is the attach
    //   contract itself: the host's BTF carries the six structs and
    //   the eight members, and the probe reads THE HOST's numbers.
    //   The layout math is pinned in the synthetic-blob test, whose
    //   layout is chosen by the test itself;
    // - the parse refuses because the kernel's BTF omits one of the
    //   six structs (some trimmed cloud kernels ship BTF without
    //   even core fs structs): the refusal must name the missing
    //   struct - that is the attach-time honesty the whole offsets
    //   contract rides, and the same verdict `doctor --attach`
    //   delivers on that host.
    match parse_probe_offsets() {
        Ok(offsets) => {
            for off in offsets {
                // Class bound, not a magic number: every value is a
                // byte offset into a kernel struct. Nothing in the
                // six structs approaches 64 KiB.
                assert!(off < 65536, "implausible offset {off}");
            }
            // Pointer members are naturally aligned: d_inode, i_ino,
            // f_inode, mnt_sb, path.mnt, path.dentry are
            // 8-byte-typed on a 64-bit kernel, so their byte offsets
            // are multiples of 8 by construction - on every kernel
            // this probe can meet.
            for slot in [0, 1, 3, 4, 6, 7] {
                assert_eq!(offsets[slot] % 8, 0, "slot {slot} is not pointer-aligned");
            }
            // struct path is {mnt, dentry} - two back-to-back
            // pointers, so dentry sits at mnt + 8 by construction.
            // This is UAPI-shaped and stable.
            assert_eq!(offsets[7], offsets[6] + 8, "path.dentry is path.mnt + 8");
            // The parse is deterministic: a second walk over the
            // same vmlinux lands on exactly the same eight.
            let again = parse_probe_offsets().expect("the second parse succeeds");
            assert_eq!(offsets, again, "the parse must be deterministic");
        }
        Err(err) => {
            // Every named refusal qualifies: a missing struct and a
            // missing member are both honest attach-time refusals -
            // the parser names the piece it could not find.
            assert!(
                err.contains("not found in BTF") || err.contains("has no member"),
                "a BTF-present host refuses by naming the missing struct: {err}"
            );
        }
    }
}

// ── The fd-walk pins (night-improve-57) ──────────────────────────

#[test]
fn the_fd_walk_lookups_descend_anonymous_aggregates() {
    // The syscall-stub write tap's four lookups ride the same
    // anonymous-descent walk as the file slots (night-improve-49):
    // task_struct's files pointer behind an unnamed union whose
    // member sits at a nonzero base - the offsets accumulate
    // across the level, the refusal stands when a lookup is still
    // unfound.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // id 1
    let files_id = w.peek_id();
    w.strukt(&mut s, "files_struct", 512, &[("fdt", 0)]); // id 2
    let union_id = w.peek_id();
    w.union_(&mut s, 16, &[("files", files_id, 32)]); // id 3: the pointer at bit 32
    w.strukt_typed(&mut s, "task_struct", 4096, &[("", union_id, 0)]); // id 4
    w.strukt(&mut s, "fdtable", 32, &[("max_fds", 0), ("fd", 8 * 8)]); // id 5
    w.strukt(&mut s, "dentry", 208, &[("d_inode", 48 * 8)]);
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8)]);
    w.strukt(
        &mut s,
        "file",
        256,
        &[("f_path", 16 * 8), ("f_inode", 32 * 8)],
    );
    w.strukt(&mut s, "vfsmount", 32, &[("mnt_sb", 8 * 8)]);
    w.strukt(&mut s, "super_block", 1536, &[("s_dev", 16 * 8)]);
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]);
    let blob = build_btf(w, s);
    let offsets = parse_btf_offsets(&blob).expect("the blob parses");
    assert_eq!(offsets[8], 4, "task_struct.files through the unnamed union");
    assert_eq!(offsets[9], 0, "files_struct.fdt stays direct");
    assert_eq!(offsets[10], 0, "fdtable.max_fds stays direct");
    assert_eq!(offsets[11], 8, "fdtable.fd stays direct");
}
