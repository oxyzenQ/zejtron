// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The unlink/rename anchor pins (night-frontier-2): synthetic
//! vmlinux blobs drive the parameter scan end to end - the modern
//! idmap shape (dentry at arg2), the pre-idmap shape (dentry at
//! arg1), the skip arms (scalars, by-value aggregates), the
//! ambiguous and unrecognizable refusals, the renamedata anchor with
//! its old_dentry member direct and anonymous-nested, and the
//! structural-lies refusals. The builders are the btf suite's own
//! (the flatten-twin sharing law); the module lives in btf.rs's test
//! tree so the pub(super) builders reach it.

use super::tests::{StrTab, TypeWriter, build_btf};
use crate::ebpf::btf_unlink::verify_unlink_lane_in;

/// The pointer-target structs every blob carries: the int filler
/// (id 1, the TypeWriter's first record) then the named structs at
/// inode=2, dentry=3, mnt_idmap=4 - the ids the pointer records
/// below reference.
fn shared_structs(w: &mut TypeWriter, s: &mut StrTab) {
    w.int(s, "unsigned int");
    w.strukt(s, "inode", 656, &[("i_mode", 0), ("i_sb", 40 * 8)]);
    w.strukt(s, "dentry", 208, &[("d_flags", 0), ("d_inode", 48 * 8)]);
    w.strukt(s, "mnt_idmap", 8, &[("owner", 0)]);
}

/// The rename half both happy-path blobs carry: vfs_rename(arg0:
/// struct renamedata *) and renamedata with old_dentry at 8 bytes.
/// The flags/delegated parameters ride the int filler's id - the
/// skip arms the scan must survive.
fn rename_half(w: &mut TypeWriter, s: &mut StrTab) {
    let renamedata_id = w.peek_id();
    w.strukt(
        s,
        "renamedata",
        64,
        &[("old_dir", 0), ("old_dentry", 8 * 8), ("new_dir", 16 * 8)],
    );
    let rd_ptr = w.ptr(renamedata_id);
    let proto = w.peek_id();
    w.func_proto(s, 1, &[("rd", rd_ptr), ("flags", 1), ("delegated", 1)]);
    w.func(s, "vfs_rename", proto);
}

#[test]
fn the_modern_idmap_shape_resolves_dentry_at_arg_two() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // vfs_unlink(mnt_idmap *, inode *dir, dentry *de, inode
    // **delegated): the 5.12+ shape - dentry is the third parameter,
    // index 2.
    let idmap_ptr = w.ptr(4);
    let inode_ptr = w.ptr(2);
    let dentry_ptr = w.ptr(3);
    let inode_ptr2 = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(
        &mut s,
        1,
        &[
            ("idmap", idmap_ptr),
            ("dir", inode_ptr),
            ("de", dentry_ptr),
            ("delegated", inode_ptr2),
        ],
    );
    w.func(&mut s, "vfs_unlink", proto);
    rename_half(&mut w, &mut s);
    let lane = verify_unlink_lane_in(&build_btf(w, s)).expect("the modern shape verifies");
    assert_eq!(
        lane.dentry_arg, 2,
        "dentry sits at arg2 on the idmap+ shape"
    );
    assert_eq!(
        lane.old_dentry_offset, 8,
        "renamedata.old_dentry at bit 64 = byte 8"
    );
}

#[test]
fn the_pre_idmap_shape_resolves_dentry_at_arg_one() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // vfs_unlink(inode *dir, dentry *de, inode **delegated): the
    // pre-5.12 shape - dentry is the second parameter, index 1. The
    // scan must find it wherever the signature carries it.
    let inode_ptr = w.ptr(2);
    let dentry_ptr = w.ptr(3);
    let inode_ptr2 = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(
        &mut s,
        1,
        &[
            ("dir", inode_ptr),
            ("de", dentry_ptr),
            ("delegated", inode_ptr2),
        ],
    );
    w.func(&mut s, "vfs_unlink", proto);
    rename_half(&mut w, &mut s);
    let lane = verify_unlink_lane_in(&build_btf(w, s)).expect("the pre-idmap shape verifies");
    assert_eq!(
        lane.dentry_arg, 1,
        "dentry sits at arg1 before the idmap args"
    );
}

#[test]
fn the_scalar_and_byvalue_params_are_skipped_not_refused() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // A signature the scan must survive: a by-value struct rides
    // beside the dentry pointer - it is not the anchor, and the scan
    // skips it. (The flags/delegated int parameters of rename_half
    // already exercise the scalar skip arm.)
    let byval_struct = w.peek_id();
    w.strukt(&mut s, "rename_flags", 8, &[("bits", 0)]);
    let dentry_ptr = w.ptr(3);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("de", dentry_ptr), ("by_value", byval_struct)]);
    w.func(&mut s, "vfs_unlink", proto);
    rename_half(&mut w, &mut s);
    let lane = verify_unlink_lane_in(&build_btf(w, s)).expect("mixed shapes verify");
    assert_eq!(lane.dentry_arg, 0);
}

#[test]
fn a_signature_without_dentry_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // Every parameter is an inode pointer: no recognizable dentry.
    let inode_ptr = w.ptr(2);
    let inode_ptr2 = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("dir", inode_ptr), ("delegated", inode_ptr2)]);
    w.func(&mut s, "vfs_unlink", proto);
    rename_half(&mut w, &mut s);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("no dentry refuses");
    assert!(
        err.contains("carries no struct dentry * parameter"),
        "got: {err}"
    );
    assert!(err.contains("refusing rather than guessing"), "got: {err}");
}

#[test]
fn an_ambiguous_two_dentry_signature_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // Two dentry-typed parameters: the anchor position is ambiguous,
    // and the scan refuses rather than guessing.
    let dentry_ptr = w.ptr(3);
    let dentry_ptr2 = w.ptr(3);
    let proto = w.peek_id();
    w.func_proto(
        &mut s,
        1,
        &[("old_de", dentry_ptr), ("new_de", dentry_ptr2)],
    );
    w.func(&mut s, "vfs_unlink", proto);
    rename_half(&mut w, &mut s);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("two dentries refuse");
    assert!(
        err.contains("more than one struct dentry * parameter"),
        "got: {err}"
    );
}

#[test]
fn a_missing_unlink_symbol_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    rename_half(&mut w, &mut s);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("absent vfs_unlink refuses");
    assert!(
        err.contains("no BTF FUNC record for vfs_unlink"),
        "got: {err}"
    );
}

#[test]
fn a_reshaped_rename_arg0_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // vfs_unlink fine; vfs_rename's arg0 points at struct file
    // instead of renamedata - the symbol exists but the shape moved.
    let dentry_ptr = w.ptr(3);
    let proto_unlink = w.peek_id();
    w.func_proto(&mut s, 1, &[("de", dentry_ptr)]);
    w.func(&mut s, "vfs_unlink", proto_unlink);
    let file_id = w.peek_id();
    w.strukt(&mut s, "file", 256, &[("f_path", 0)]);
    let file_ptr = w.ptr(file_id);
    let proto_rename = w.peek_id();
    w.func_proto(&mut s, 1, &[("rd", file_ptr)]);
    w.func(&mut s, "vfs_rename", proto_rename);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("wrong arg0 refuses");
    assert!(err.contains("not struct renamedata"), "got: {err}");
    assert!(err.contains("shape moved"), "got: {err}");
}

#[test]
fn a_missing_rename_symbol_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    // vfs_unlink fine; vfs_rename absent from the section: the
    // rename half refuses on its own stage, by name.
    let dentry_ptr = w.ptr(3);
    let proto_unlink = w.peek_id();
    w.func_proto(&mut s, 1, &[("de", dentry_ptr)]);
    w.func(&mut s, "vfs_unlink", proto_unlink);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("absent vfs_rename refuses");
    assert!(
        err.contains("no BTF FUNC record for vfs_rename"),
        "got: {err}"
    );
}

#[test]
fn a_missing_old_dentry_member_refuses_by_name() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    let dentry_ptr = w.ptr(3);
    let proto_unlink = w.peek_id();
    w.func_proto(&mut s, 1, &[("de", dentry_ptr)]);
    w.func(&mut s, "vfs_unlink", proto_unlink);
    // renamedata carries new_dentry but no old_dentry: the anchor's
    // member is gone, the walk refuses.
    let renamedata_id = w.peek_id();
    w.strukt(&mut s, "renamedata", 64, &[("new_dentry", 8 * 8)]);
    let rd_ptr = w.ptr(renamedata_id);
    let proto_rename = w.peek_id();
    w.func_proto(&mut s, 1, &[("rd", rd_ptr)]);
    w.func(&mut s, "vfs_rename", proto_rename);
    let err = verify_unlink_lane_in(&build_btf(w, s)).expect_err("absent member refuses");
    assert!(
        err.contains("struct renamedata has no member old_dentry in BTF"),
        "got: {err}"
    );
}

#[test]
fn the_anonymous_nest_resolves_through_the_descent() {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    shared_structs(&mut w, &mut s);
    let dentry_ptr = w.ptr(3);
    let proto_unlink = w.peek_id();
    w.func_proto(&mut s, 1, &[("de", dentry_ptr)]);
    w.func(&mut s, "vfs_unlink", proto_unlink);
    // renamedata's old_dentry rides an unnamed union (the 6.18
    // lesson applied to renamedata): renamedata { old_dir (bit 0);
    // (bit 64) union { old_dentry (bit 0), spare (bit 64) } } - the
    // descent enters the anonymous member and accumulates the base,
    // so old_dentry lands at 64 + 0 = 64 bits = 8 bytes.
    let union_id = w.peek_id();
    w.union_(&mut s, 16, &[("old_dentry", 3, 0), ("spare", 1, 64)]);
    let renamedata_id = w.peek_id();
    w.strukt_typed(
        &mut s,
        "renamedata",
        64,
        &[("old_dir", 1, 0), ("", union_id, 64)],
    );
    let rd_ptr = w.ptr(renamedata_id);
    let proto_rename = w.peek_id();
    w.func_proto(&mut s, 1, &[("rd", rd_ptr)]);
    w.func(&mut s, "vfs_rename", proto_rename);
    let lane = verify_unlink_lane_in(&build_btf(w, s)).expect("the descent resolves");
    assert_eq!(
        lane.old_dentry_offset, 8,
        "old_dentry rides the union at bit 64 = byte 8"
    );
}

#[test]
fn truncation_refuses_before_any_scan() {
    // A header with empty sections: the blob parses, the FUNC lookup
    // finds nothing, the refusal names the stage.
    let blob = [
        0x9F, 0xEB, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let err = verify_unlink_lane_in(&blob).expect_err("an empty section refuses");
    assert!(err.contains("no BTF FUNC record"), "got: {err}");
}

#[test]
fn the_live_host_verifies_the_lane_when_btf_exists() {
    // The live twin of the seed pin: on any host that ships
    // /sys/kernel/btf/vmlinux, the lane's anchors verify against the
    // REAL kernel's own BTF - the dentry argument index wherever
    // this kernel's signature carries it (1 on the pre-idmap
    // generations, 2 on the idmap+ ones), the renamedata member
    // offset byte-aligned and bounded. Cross-version by
    // construction: the CI runners ride 6.x HWE kernels, the floor
    // lane rides 5.15.0, this sandbox host rode 5.10 - one pin, the
    // whole range's live answer.
    let Ok(data) = std::fs::read("/sys/kernel/btf/vmlinux") else {
        return;
    };
    // The floor decides the expectation: at/above 5.15 the anchors
    // verify (vfs_rename rides renamedata there); below it the
    // refusal IS the honest answer - a pre-renamedata signature is a
    // shape the lane refuses by name, the same direction the
    // below-floor witness proves in the VM lane. This sandbox host
    // rode 5.10 (refusal), the CI runners ride 6.x HWE (success with
    // bounds), the floor lane rides 5.15.0 (success, the pin's real
    // proof).
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| String::from("0.0"));
    let mut parts = release.split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|p| {
            p.trim_start_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        })
        .unwrap_or(0);
    let lane_result = verify_unlink_lane_in(&data);
    if (major, minor) < crate::ebpf::KERNEL_FLOOR {
        let err = lane_result.expect_err("a below-floor host refuses the lane");
        assert!(
            err.contains("refusing")
                || err.contains("not struct renamedata")
                || err.contains("no BTF FUNC record"),
            "the refusal names its stage, got: {err}"
        );
        return;
    }
    let lane = lane_result.expect("the at/above-floor host verifies the lane");
    assert!(
        lane.dentry_arg <= 5,
        "the dentry argument index must land in the register range, got {}",
        lane.dentry_arg
    );
    assert!(
        lane.old_dentry_offset > 0 && lane.old_dentry_offset % 8 == 0,
        "the old_dentry member offset must be a nonzero byte-aligned u64, got {}",
        lane.old_dentry_offset
    );
}

#[test]
fn a_wrong_magic_refuses_before_any_scan() {
    let err = verify_unlink_lane_in(&[0; 64]).expect_err("non-BTF refuses");
    assert!(err.contains("not a BTF file"), "got: {err}");
}

#[test]
fn the_committed_fuzz_seeds_verify_end_to_end() {
    // The seed anchors (fuzz/seeds/btf_parser/) are the fuzz lane's
    // own contract: the same shapes the tests above pin, carried as
    // files. This pin keeps the mirror honest - a seed that stops
    // verifying is a stale seed, caught here instead of in a fuzz
    // run that silently loses its starting shape.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/seeds/btf_parser");
    let modern = std::fs::read(format!(
        "{dir}/vfs-unlink-dentry-at-arg2-plus-renamedata.bin"
    ))
    .expect("the modern seed is committed");
    let lane = verify_unlink_lane_in(&modern).expect("the modern seed verifies");
    assert_eq!(lane.dentry_arg, 2);
    assert_eq!(lane.old_dentry_offset, 8);
    let pre_idmap = std::fs::read(format!("{dir}/vfs-unlink-pre-idmap-dentry-at-arg1.bin"))
        .expect("the pre-idmap seed is committed");
    let lane = verify_unlink_lane_in(&pre_idmap).expect("the pre-idmap seed verifies");
    assert_eq!(lane.dentry_arg, 1);
    let nested = std::fs::read(format!("{dir}/renamedata-old-dentry-in-unnamed-union.bin"))
        .expect("the union seed is committed");
    let lane = verify_unlink_lane_in(&nested).expect("the union seed verifies");
    assert_eq!(lane.old_dentry_offset, 8);
}
