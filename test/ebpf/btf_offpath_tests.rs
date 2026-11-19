// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The off-path lanes' BTF verification pins (night-frontier-Z7,
//! D4) - the writev-lane sibling's shape: the shared blob builders
//! (super::tests, pub(super) in the parent's tests module) drive the
//! dirty anchor ladder and the io_kiocb shape end to end, synthetic
//! bytes in, named verdicts out. The REAL-dialect pins ride the
//! corpus suite (btf_corpus_tests.rs, the off-path chains test);
//! this file pins the LADDER's decision law itself.

use super::tests::{StrTab, TypeWriter, build_btf};
use crate::ebpf::btf_offpath::parse_offpath_offsets;
use crate::ebpf::btf_offpath::{DirtyShape, verify_dirty_anchor_in, verify_iouring_lane_in};

/// A blob carrying one dirty-anchor shape: an INT return, the struct
/// the anchor's arg0 points at, and FUNC + FUNC_PROTO wired by the
/// caller. `folio_member` rides the folio variant (the parser's
/// folio-first preference), `mapping_offset` is the member's byte
/// offset the parse must derive.
fn ladder_blob(anchor: &str, arg0_struct: &str, with_folio: bool) -> Vec<u8> {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // type id 1 - the return type
    // The ids ride the writer's own counter: int=1, then the folio
    // (when present), then the arg0 struct - the sequential-id
    // contract record_pos walks.
    if with_folio {
        w.strukt(&mut s, "folio", 128, &[("mapping", 24 * 8)]); // id 2
        w.strukt(&mut s, arg0_struct, 128, &[("the_field", 8 * 8)]); // id 3
        let arg0_ptr = w.ptr(3); // PTR -> arg0's struct
        let proto = w.peek_id();
        w.func_proto(&mut s, 1, &[("mapping", arg0_ptr), ("folio", 0)]);
        w.func(&mut s, anchor, proto);
        return build_btf(w, s);
    }
    w.strukt(&mut s, arg0_struct, 128, &[("the_field", 8 * 8)]); // id 2
    let arg0_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("mapping", arg0_ptr), ("folio", 0)]);
    w.func(&mut s, anchor, proto);
    build_btf(w, s)
}

#[test]
fn the_folio_anchor_is_the_primary_rung() {
    // filemap_dirty_folio present with a vouched address_space arg0:
    // the folio shape wins, the walk starts at the mapping argument.
    let blob = ladder_blob("filemap_dirty_folio", "address_space", false);
    let anchor = verify_dirty_anchor_in(&blob).expect("the folio rung verifies");
    assert_eq!(anchor.symbol, "filemap_dirty_folio");
    assert_eq!(anchor.shape, DirtyShape::Folio);
}

#[test]
fn the_page_anchor_is_the_fallback_rung() {
    // No folio FUNC: the ladder falls to the page-shape anchor -
    // the folio-less kernels' verdict (5.15's own shape).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "page", 128, &[("mapping", 24 * 8)]);
    let page_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("page", page_ptr)]);
    w.func(&mut s, "__set_page_dirty_nobuffers", proto);
    let blob = build_btf(w, s);
    let anchor = verify_dirty_anchor_in(&blob).expect("the page rung verifies");
    assert_eq!(anchor.symbol, "__set_page_dirty_nobuffers");
    assert_eq!(anchor.shape, DirtyShape::Page);
}

#[test]
fn a_present_but_moved_anchor_refuses_hard() {
    // The name exists and arg0 points at the WRONG struct - the
    // loud moment: no silent fallthrough to the next rung.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8)]);
    let inode_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("inode", inode_ptr)]);
    w.func(&mut s, "filemap_dirty_folio", proto);
    let blob = build_btf(w, s);
    let error = verify_dirty_anchor_in(&blob).expect_err("the moved shape refuses");
    assert!(
        error.contains("shape moved"),
        "the refusal names the moved contract: {error}"
    );
}

#[test]
fn no_rung_names_the_capability_down() {
    // Neither anchor under any name: the Err IS the named-down
    // signal (the capability unplants, the camera stays).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "page", 128, &[("mapping", 24 * 8)]);
    let page_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("page", page_ptr)]);
    w.func(&mut s, "vfs_read", proto);
    let blob = build_btf(w, s);
    let error = verify_dirty_anchor_in(&blob).expect_err("no rung is the named-down shape");
    assert!(
        error.contains("does not carry the page-dirty path"),
        "the named-down names its class: {error}"
    );
}

#[test]
fn the_iouring_lane_verifies_the_request_hop() {
    // io_kiocb with a file member (through the anonymous-union
    // descent on real kernels; direct here): the hop verifies.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "io_kiocb", 512, &[("file", 0)]);
    let blob = build_btf(w, s);
    let lane = verify_iouring_lane_in(&blob).expect("the lane verifies");
    let lane = lane.expect("the io_kiocb exists");
    assert_eq!(lane.io_kiocb_file_offset, 0);
}

#[test]
fn a_missing_io_kiocb_names_the_capability_down() {
    // No io_kiocb at all: Ok(None) - the named-down shape, not an
    // error (a kernel without io_uring is a fact, not a refusal).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "page", 128, &[("mapping", 24 * 8)]);
    let blob = build_btf(w, s);
    assert!(
        verify_iouring_lane_in(&blob)
            .expect("the absent struct is Ok")
            .is_none()
    );
}

#[test]
fn an_io_kiocb_without_a_file_member_refuses_hard() {
    // The struct exists and the member the probe walks is gone - the
    // shape moved: the loud refusal for the capability.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "io_kiocb", 512, &[("opcode", 8)]);
    let blob = build_btf(w, s);
    let error = verify_iouring_lane_in(&blob).expect_err("the moved shape refuses");
    assert!(
        error.contains("shape moved"),
        "the refusal names the moved contract: {error}"
    );
}

#[test]
fn the_offpath_parse_derives_the_dirty_descent_pair() {
    // folio-first: a folio-carrying blob derives page_mapping from
    // folio.mapping, the host hop from address_space.host, and the
    // io_kiocb hop from the embedded union member.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "folio", 128, &[("mapping", 24 * 8)]);
    w.strukt(&mut s, "address_space", 96, &[("host", 0)]);
    w.strukt(&mut s, "io_kiocb", 512, &[("file", 0)]);
    w.strukt(&mut s, "page", 128, &[("mapping", 16 * 8)]);
    let blob = build_btf(w, s);
    let offpath = parse_offpath_offsets(&blob).expect("the off-path chains derive");
    assert_eq!(
        offpath.page_mapping,
        Some(24),
        "folio.mapping wins (the folio-first law)"
    );
    assert_eq!(
        offpath.address_space_host,
        Some(0),
        "the mapping's first member"
    );
    assert_eq!(offpath.io_kiocb_file, Some(0));
}

#[test]
fn the_offpath_parse_falls_back_to_struct_page() {
    // No folio in the BTF: the page shape derives the same slot from
    // struct page - the folio-less kernels' own law (5.15).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "page", 128, &[("mapping", 24 * 8)]);
    w.strukt(&mut s, "address_space", 96, &[("host", 0)]);
    let blob = build_btf(w, s);
    let offpath = parse_offpath_offsets(&blob).expect("the page shape derives");
    assert_eq!(offpath.page_mapping, Some(24));
    assert_eq!(offpath.address_space_host, Some(0));
    assert_eq!(
        offpath.io_kiocb_file, None,
        "no io_kiocb: the lane names down"
    );
}

#[test]
fn the_offpath_parse_refuses_without_a_dirty_shape() {
    // Neither folio nor page: the parse cannot vouch for the descent
    // - the named refusal, never a zero-offset guess.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "address_space", 96, &[("host", 0)]);
    let blob = build_btf(w, s);
    let error = parse_offpath_offsets(&blob).expect_err("no shape refuses");
    assert!(
        error.contains("no struct page or struct folio"),
        "the refusal names the missing shape: {error}"
    );
}

// ── The memory-backed lane's ladder law (night-frontier-Z9, D6) ─────

use crate::ebpf::btf_offpath::verify_membacked_lane_in;

/// A blob carrying the memory-backed lane's full shape: the anchor
/// FUNC (arg0 = vm_fault when `anchor` rides, a wrong-shaped struct
/// when `wrong_arg0` names one), and - when `with_chain` - the
/// vm_fault.page / super_block.s_type / file_system_type.name chain
/// the walk reads. The TypeWriter's sequential ids: int=1, then the
/// structs in call order.
fn membacked_blob(anchor: Option<&str>, arg0_struct: &str, with_chain: bool) -> Vec<u8> {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // id 1 - the return type
    if with_chain {
        w.strukt(&mut s, "vm_fault", 128, &[("page", 80 * 8)]); // id 2
        w.strukt(&mut s, "super_block", 512, &[("s_type", 40 * 8)]); // id 3
        w.strukt(&mut s, "file_system_type", 64, &[("name", 0)]); // id 4
        let vmf_ptr = w.ptr(2);
        let proto = w.peek_id();
        w.func_proto(&mut s, 1, &[("vmf", vmf_ptr), ("folio", 0)]);
        w.func(
            &mut s,
            anchor.expect("an anchor rides a chained blob"),
            proto,
        );
        return build_btf(w, s);
    }
    w.strukt(&mut s, arg0_struct, 128, &[("the_field", 8 * 8)]); // id 2
    let arg0_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("vmf", arg0_ptr), ("folio", 0)]);
    w.func(&mut s, anchor.expect("an anchor rides a bare blob"), proto);
    build_btf(w, s)
}

#[test]
fn the_memory_backed_funnel_is_the_primary_rung() {
    // fault_dirty_shared_page with a vouched vm_fault arg0 and the
    // whole walk chain: the lane vouches, the funnel rides.
    let blob = membacked_blob(Some("fault_dirty_shared_page"), "vm_fault", true);
    let lane = verify_membacked_lane_in(&blob)
        .expect("the chain parses")
        .expect("the funnel rung vouches");
    assert_eq!(lane.anchor, "fault_dirty_shared_page");
    assert_eq!(lane.vm_fault_page_offset, 80);
    assert_eq!(lane.sb_type_offset, 40);
    assert_eq!(lane.fst_name_offset, 0);
}

#[test]
fn the_memory_backed_ladder_falls_to_the_wp_arm() {
    // No funnel symbol: the 7.x line's surviving wp_page_shared arm
    // carries the capability (the same vm_fault context shape).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "vm_fault", 128, &[("page", 80 * 8)]);
    w.strukt(&mut s, "super_block", 512, &[("s_type", 56 * 8)]);
    w.strukt(&mut s, "file_system_type", 64, &[("name", 0)]);
    let vmf_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("vmf", vmf_ptr), ("folio", 0)]);
    w.func(&mut s, "wp_page_shared", proto);
    let blob = build_btf(w, s);
    let lane = verify_membacked_lane_in(&blob)
        .expect("the chain parses")
        .expect("the wp arm vouches");
    assert_eq!(lane.anchor, "wp_page_shared");
    assert_eq!(lane.sb_type_offset, 56);
}

#[test]
fn a_moved_memory_backed_anchor_refuses_hard() {
    // The funnel's name exists and arg0 points at the wrong struct -
    // the loud refusal, never a silent fallthrough to the next rung.
    let blob = membacked_blob(Some("fault_dirty_shared_page"), "inode", false);
    let error = verify_membacked_lane_in(&blob).expect_err("the moved shape refuses");
    assert!(
        error.contains("shape moved"),
        "the refusal names the moved contract: {error}"
    );
}

#[test]
fn no_memory_backed_rung_names_the_capability_down() {
    // Neither anchor under any name: Ok(None) - the named-down shape
    // (the camera stands, the class is named, never guessed).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "page", 128, &[("mapping", 24 * 8)]);
    let blob = build_btf(w, s);
    assert!(
        verify_membacked_lane_in(&blob)
            .expect("the absent anchors are Ok")
            .is_none()
    );
}

#[test]
fn a_memory_backed_chain_missing_the_class_gate_refuses_hard() {
    // The anchor vouches but the superblock's s_type hop is gone -
    // the walk chain cannot be vouched: the loud refusal for the
    // capability, never a zero-offset guess.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "vm_fault", 128, &[("page", 80 * 8)]);
    w.strukt(&mut s, "super_block", 512, &[("s_dev", 16 * 8)]);
    w.strukt(&mut s, "file_system_type", 64, &[("name", 0)]);
    let vmf_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("vmf", vmf_ptr), ("folio", 0)]);
    w.func(&mut s, "fault_dirty_shared_page", proto);
    let blob = build_btf(w, s);
    let error = verify_membacked_lane_in(&blob).expect_err("the missing hop refuses");
    assert!(
        error.contains("no member s_type"),
        "the refusal names the missing hop: {error}"
    );
}
