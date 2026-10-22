// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The anonymous-union pins (night-improve-49): the 6.18 kernel
//! line wraps struct file's f_path in an unnamed union - `const
//! struct path f_path` beside a writable `struct path __f_path` -
//! and the member walk had to learn the descent to keep the offsets
//! contract honest on every host that ships it. The pins hold the
//! walk to C semantics: only anonymous members are entered, bit
//! offsets accumulate across the levels, qualifier wrappers resolve
//! through, and the refusal stands unchanged when the member is
//! still unfound after the descent. The blob builders ride the
//! same shared table btf_tests built (pub(super)); the parser side
//! arrives through the parent module.

use super::tests::{StrTab, TypeWriter, build_btf};
use super::*;

#[test]
fn the_six_point_eighteen_union_file_parses_end_to_end() {
    // The 6.18 shape: f_path rides an unnamed union (a const-wrapped
    // struct path beside its writable alias), f_inode after it.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // type id 1
    let path_id = w.peek_id();
    w.strukt(&mut s, "path", 16, &[("mnt", 0), ("dentry", 8 * 8)]); // id 2
    let const_path = w.peek_id();
    w.const_(path_id); // id 3: CONST -> struct path
    let union_id = w.peek_id();
    w.union_(
        &mut s,
        16,
        &[("f_path", const_path, 0), ("__f_path", path_id, 0)],
    ); // id 4
    w.strukt_typed(
        &mut s,
        "file",
        256,
        &[("", union_id, 0), ("f_inode", 1, 16 * 8)],
    ); // id 5
    w.strukt(&mut s, "dentry", 208, &[("d_inode", 48 * 8)]);
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8)]);
    w.strukt(&mut s, "vfsmount", 32, &[("mnt_sb", 8 * 8)]);
    w.strukt(&mut s, "super_block", 1536, &[("s_dev", 16 * 8)]);
    let offsets = parse_btf_offsets(&build_btf(w, s)).expect("the 6.18 shape parses");
    assert_eq!(
        offsets,
        [
            48, // dentry.d_inode
            64, // inode.i_ino
            0,  // file.f_path - found inside the unnamed union, bit 0
            16, // file.f_inode
            8,  // vfsmount.mnt_sb
            16, // super_block.s_dev
            0,  // path.mnt
            8,  // path.dentry
        ]
    );
}

#[test]
fn an_anonymous_nest_accumulates_offsets() {
    // outer { (bit 128) unnamed union { unnamed struct { target
    // (bit 64) } } } - both levels anonymous, the inner struct
    // wrapped in CONST: the member lands at 128 + 64 = 192 bits,
    // 24 bytes.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // id 1
    let inner_id = w.peek_id();
    w.strukt_typed(&mut s, "", 8, &[("target", 1, 64)]); // id 2: unnamed
    let const_inner = w.peek_id();
    w.const_(inner_id); // id 3: CONST -> the unnamed struct
    let union_id = w.peek_id();
    w.union_(&mut s, 8, &[("", const_inner, 0)]); // id 4
    w.strukt_typed(&mut s, "outer", 32, &[("", union_id, 128)]); // id 5
    let blob = build_btf(w, s);
    let ctx = BtfFile::new(&blob).expect("the blob parses");
    let outer = ctx.find_struct("outer").expect("struct outer is there");
    assert_eq!(
        member_offset(&ctx, outer, "outer", "target").expect("the nest resolves"),
        24
    );
}

#[test]
fn a_named_nested_aggregate_is_not_descended() {
    // outer { u (a union carrying f_path) }: `outer->f_path` names
    // nothing in C - the union member is named, so the walk must
    // refuse rather than peek inside the named aggregate.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // id 1
    let union_id = w.peek_id();
    w.union_(&mut s, 16, &[("f_path", 1, 0), ("__f_path", 1, 0)]); // id 2
    w.strukt_typed(&mut s, "outer", 32, &[("u", union_id, 0)]); // id 3
    let blob = build_btf(w, s);
    let ctx = BtfFile::new(&blob).expect("the blob parses");
    let outer = ctx.find_struct("outer").expect("struct outer is there");
    let err = member_offset(&ctx, outer, "outer", "f_path").unwrap_err();
    assert_eq!(err, "struct outer has no member f_path in BTF");
}

#[test]
fn a_member_still_absent_after_the_descent_refuses() {
    // The anonymous union exists but carries no f_path: the refusal
    // is the same named error the direct walk always answered with.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // id 1
    let union_id = w.peek_id();
    w.union_(&mut s, 16, &[("not_f_path", 1, 0)]); // id 2
    w.strukt_typed(&mut s, "outer", 32, &[("", union_id, 0)]); // id 3
    let blob = build_btf(w, s);
    let ctx = BtfFile::new(&blob).expect("the blob parses");
    let outer = ctx.find_struct("outer").expect("struct outer is there");
    let err = member_offset(&ctx, outer, "outer", "f_path").unwrap_err();
    assert_eq!(err, "struct outer has no member f_path in BTF");
}

#[test]
fn a_nested_bitfield_refuses_on_the_accumulated_offset() {
    // A bitfield found through the descent is still a bitfield: the
    // refusal fires on the accumulated offset (16 + 3 = bit 19),
    // proving the levels really summed on the way to the refusal.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "unsigned int"); // id 1
    let union_id = w.peek_id();
    w.union_(&mut s, 4, &[("f_path", 1, 3)]); // id 2: bit 3, not aligned
    w.strukt_typed(&mut s, "outer", 32, &[("", union_id, 16)]); // id 3
    let blob = build_btf(w, s);
    let ctx = BtfFile::new(&blob).expect("the blob parses");
    let outer = ctx.find_struct("outer").expect("struct outer is there");
    let err = member_offset(&ctx, outer, "outer", "f_path").unwrap_err();
    assert!(err.contains("bitfield"), "got: {err}");
    assert!(err.contains("(bit 19)"), "got: {err}");
}
