// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The writev-lane symbol verification pins (night-improve-42),
//! moved whole out of btf_tests.rs when night-improve-57 grew the
//! offsets parse beyond that file's space (the split-is-the-fix
//! law, a pure move, gates green in between). The blob builders
//! ride the same shared table, pub(super) in the parent's tests
//! module.

use super::tests::{StrTab, TypeWriter, build_btf};
// The verified functions moved to btf_writev.rs (night-hunter-4's
// pure move at the 600 LOC cap); the pins follow the function, the
// wiring stays in the btf module's tests tree.
use crate::ebpf::btf_writev::{verify_writev_symbol, verify_writev_symbol_in};

// ── The writev-lane symbol verification pins (night-improve-42) ──

/// A blob carrying the minimal writev-lane shape: an INT return type,
/// a struct to point at, and FUNC + FUNC_PROTO pairs wired by the
/// caller. The id arithmetic rides the writer's own counter - the
/// same sequential-id contract record_pos walks.
fn writev_blobs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // type id 1 - the return type
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]); // id 2
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8)]); // id 3
    let file_ptr = w.ptr(2); // id 4: PTR -> struct file
    // Blob 1: vfs_writev(file*, ...) - the verified primary.
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", file_ptr), ("vec", 0), ("vlen", 1)]);
    w.func(&mut s, "vfs_writev", proto);
    let primary = build_btf(w, s);

    // Blob 2: no vfs_writev; do_iter_write(file*, ...) - the
    // verified fallback.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]);
    let file_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", file_ptr), ("iter", 0)]);
    w.func(&mut s, "do_iter_write", proto);
    let fallback = build_btf(w, s);

    // Blob 3: vfs_writev PRESENT but reshaped - arg0 points at
    // struct inode, not struct file (the loud moment: the name
    // exists, the contract moved).
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]);
    w.strukt(&mut s, "inode", 656, &[("i_ino", 64 * 8)]);
    let inode_ptr = w.ptr(3);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("inode", inode_ptr)]);
    w.func(&mut s, "vfs_writev", proto);
    let reshaped = build_btf(w, s);

    // Blob 4: neither symbol under any name.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int");
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]);
    let file_ptr = w.ptr(2);
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", file_ptr)]);
    w.func(&mut s, "vfs_read", proto);
    let neither = build_btf(w, s);

    (primary, fallback, reshaped, neither)
}

#[test]
fn vfs_writev_verifies_as_the_primary_symbol() {
    let (primary, _, _, _) = writev_blobs();
    assert_eq!(
        verify_writev_symbol_in(&primary).expect("the primary verifies"),
        "vfs_writev"
    );
}

#[test]
fn do_iter_write_verifies_as_the_fallback_when_the_primary_is_absent() {
    let (_, fallback, _, _) = writev_blobs();
    assert_eq!(
        verify_writev_symbol_in(&fallback).expect("the fallback verifies"),
        "do_iter_write"
    );
}

#[test]
fn a_reshaped_primary_refuses_instead_of_falling_through() {
    let (_, _, reshaped, _) = writev_blobs();
    let err = verify_writev_symbol_in(&reshaped).unwrap_err();
    // The loud moment: the symbol exists but its shape moved - never
    // a silent fallthrough to the fallback.
    assert!(err.contains("struct inode, not struct file"), "got: {err}");
    assert!(err.contains("shape moved"), "got: {err}");
}

#[test]
fn neither_symbol_refuses_by_name() {
    let (_, _, _, neither) = writev_blobs();
    let err = verify_writev_symbol_in(&neither).unwrap_err();
    assert!(err.contains("no BTF FUNC record"), "got: {err}");
    assert!(err.contains("vfs_writev or do_iter_write"), "got: {err}");
}

#[test]
fn wrong_arg0_shapes_are_refused_by_name() {
    // By value: arg0 IS the struct, not a pointer to it.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // id 1
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]); // id 2
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", 2)]);
    w.func(&mut s, "vfs_writev", proto);
    let err = verify_writev_symbol_in(&build_btf(w, s)).unwrap_err();
    assert!(err.contains("by value"), "got: {err}");

    // Pointer to a pointer: not the file contract either.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // id 1
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]); // id 2
    let ptr = w.ptr(2); // id 3
    let ptr_ptr = w.ptr(ptr); // id 4: PTR -> PTR -> struct file
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", ptr_ptr)]);
    w.func(&mut s, "vfs_writev", proto);
    let err = verify_writev_symbol_in(&build_btf(w, s)).unwrap_err();
    assert!(err.contains("pointer to a pointer"), "got: {err}");
}

#[test]
fn a_typedef_chain_still_resolves_to_struct_file() {
    // PTR -> TYPEDEF("file_t") -> struct file: the qualifier/typedef
    // arm, resolved and accepted.
    let mut w = TypeWriter::new();
    let mut s = StrTab::new();
    w.int(&mut s, "int"); // id 1
    w.strukt(&mut s, "file", 256, &[("f_inode", 32 * 8)]); // id 2
    let typedef_id = w.peek_id();
    w.typedef(&mut s, "file_t", 2); // id 3
    let ptr = w.ptr(typedef_id); // id 4
    let proto = w.peek_id();
    w.func_proto(&mut s, 1, &[("file", ptr)]);
    w.func(&mut s, "vfs_writev", proto);
    assert_eq!(
        verify_writev_symbol_in(&build_btf(w, s)).expect("the typedef chain verifies"),
        "vfs_writev"
    );
}

#[test]
fn the_live_host_verifies_the_writev_symbol_or_refuses_by_name() {
    // The live-host twin of the offsets probe (skip when the host
    // ships no BTF). Two honest outcomes on a host that ships
    // vmlinux BTF: the verification names the verified symbol (any
    // kernel 5.10 through the current 6.x line carries vfs_writev or
    // do_iter_write under this exact shape - verified against the
    // reference probe), or a future refactor refuses by naming the
    // piece it could not vouch for - the same attach-time honesty
    // the offsets contract rides.
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return;
    }
    match verify_writev_symbol() {
        Ok(symbol) => {
            assert!(
                symbol == "vfs_writev" || symbol == "do_iter_write",
                "the verified symbol is one of the two candidates: {symbol}"
            );
            // The verification is deterministic: a second walk over
            // the same vmlinux lands on the same symbol.
            let again = verify_writev_symbol().expect("the second verification succeeds");
            assert_eq!(symbol, again, "the verification must be deterministic");
        }
        Err(err) => {
            assert!(
                err.contains("not struct file")
                    || err.contains("no BTF FUNC record")
                    || err.contains("cannot read"),
                "a BTF-present host refuses by naming the unverified piece: {err}"
            );
        }
    }
}
