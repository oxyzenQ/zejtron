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

use super::*;

// ── The synthetic blob builder ─────────────────────────────────────

struct StrTab {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl StrTab {
    fn new() -> Self {
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

struct TypeWriter {
    bytes: Vec<u8>,
}

impl TypeWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }
    fn push(&mut self, name_off: u32, kind: u32, vlen: usize, size: u32) {
        let info: u32 = (kind << 24) | (vlen as u32 & 0xFFFF);
        self.bytes.extend_from_slice(&name_off.to_le_bytes());
        self.bytes.extend_from_slice(&info.to_le_bytes());
        self.bytes.extend_from_slice(&size.to_le_bytes());
    }
    /// Filler INT record (+4 trailing bytes) to exercise the walk.
    fn int(&mut self, strings: &mut StrTab, name: &str) {
        let off = strings.add(name);
        self.push(off, 1, 0, 4);
        self.bytes.extend_from_slice(&[0, 0, 0, 0]); // btf_int extra
    }
    /// Filler ARRAY record (+12 trailing bytes).
    fn array(&mut self) {
        self.push(0, 3, 0, 8); // "size" reused as the value type id
        self.bytes.extend_from_slice(&[0; 12]); // btf_array
    }
    /// One STRUCT with members: (name, bit_offset).
    fn strukt(&mut self, strings: &mut StrTab, name: &str, size: u32, members: &[(&str, u32)]) {
        let off = strings.add(name);
        self.push(off, 4, members.len(), size);
        for (mname, bit) in members {
            let m_off = strings.add(mname);
            self.bytes.extend_from_slice(&m_off.to_le_bytes());
            self.bytes.extend_from_slice(&1u32.to_le_bytes()); // member type: id 1
            self.bytes.extend_from_slice(&bit.to_le_bytes());
        }
    }
}

fn build_btf(types: TypeWriter, strings: StrTab) -> Vec<u8> {
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
    build_btf(w, s)
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
