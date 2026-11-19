// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The real-kernel BTF corpus pins (night-frontier-Z2, E2; the
//! five-dialect span is night-frontier-Z3): the parser's regression
//! lock over REAL kernel dialects - the floor lane's own GA kernel
//! (jammy 5.15.0-25), Debian bookworm's current 6.1 point release
//! (6.1.0-50), the frozen mainline 6.6.95 build, the second GA
//! generation (noble 6.8.0-31), and the 7.x line (cachyos 7.3.3 at
//! capture time) - their .BTF sections extracted from the shipped
//! vmlinuz packages and committed whole under corpus/btf (the
//! provenance law lives in corpus/README.md, the extraction
//! instrument in scripts/ci/corpus-extract-dialect.sh). A parser
//! change that would misread any committed dialect fails here, on
//! every host, forever - the moving kernels stay locked live on the
//! witness legs; the corpus freezes the dialects themselves. The
//! pre-BTF dialect (focal GA 5.4.0-26) is pinned as a NAMED ABSENCE:
//! its payload carries no .BTF section, and the witness lane asserts
//! that refusal direction on every push.
//!
//! THE TABLES ARE THE STORY: the five committed dialects disagree in
//! exactly the slots the kernel generations moved - file.f_path
//! rides three packings (16 pre-rework, 152 after the
//! anonymous-aggregate rework, 64 on the re-packed 7.x line), f_inode
//! rides with it, task_struct.files marches 2928 -> 3552 with the
//! kernel's growth, and the mainline 6.6.95 build is a genuine struct
//! inode outlier (i_ino 80, i_sb 56) against every distro build of
//! its era. A parser change that silently normalized the tables - or
//! pinned one generation's layout over the others - fails here. The
//! integrity half rides the tree's own blake3 implementation
//! (build/blake3.rs, path-included): a committed blob that drifts
//! by one byte refuses by digest before any parse runs.
//!
//! A NEW DIALECT joins by: commit the blob under corpus/btf, run
//! `cargo test the_btf_corpus -- --nocapture` (the derivation
//! harness prints the table), and pin the digest + the table below.

// The blake3 reader rides the ONE include site the tree already
// carries (src/info/provenance.rs) - a second path-include of the
// same file is a rustc error, and one implementation is the law.
use crate::info::provenance::blake3;

use super::super::btf_unlink;
use super::*;

/// The committed dialects: name, integrity digest, the thirteen
/// core struct offsets, the identity chain night-frontier-Z8
/// appends (its own parse, its own four slots), the unlink dentry
/// argument position, and the renamedata old_dentry member offset.
/// One row per real kernel, frozen. The span (night-frontier-Z3):
/// 5.15, 6.1 (Debian bookworm's current point release), 6.6 (the
/// frozen mainline build), 6.8, and the 7.x line (cachyos's
/// flagship at capture time) - the walk table's whole migration
/// history, frozen. The identity tail (night-frontier-Z8):
/// task_struct.nsproxy marches with the kernel's growth exactly
/// like task_struct.files does, nsproxy.net_ns sits at 40 on every
/// committed dialect, net.ns re-packs on the 7.x line (120 -> 128
/// -> 192), and ns_common.inum re-packs with it (16 -> 88 on
/// cachyos) - the identity walk is as version-shaped as every walk
/// before it, which is the whole reason the offsets are data.
struct Dialect {
    blob: &'static str,
    blake3: &'static str,
    offsets: [u64; 13],
    identity: [u64; 4],
    dentry_arg: u32,
    old_dentry_offset: u64,
}

const CORPUS: [Dialect; 5] = [
    Dialect {
        blob: "5.15.0-25-generic.btf",
        blake3: "7e88b941af6ed12b4cdb88951f504a4a2ee2996bb887673181bd8640166e181a",
        offsets: [48, 64, 16, 32, 8, 16, 0, 8, 2928, 32, 0, 8, 40],
        identity: [2944, 40, 120, 16],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
    Dialect {
        blob: "6.1.0-50-amd64.btf",
        blake3: "be59ef22432ab05aabdd205a0ed524db156d8d6623345aeaed0b4105897e7a26",
        offsets: [48, 64, 16, 32, 8, 16, 0, 8, 3048, 32, 0, 8, 40],
        identity: [3064, 40, 128, 16],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
    Dialect {
        blob: "6.6.95-060695-generic.btf",
        blake3: "18e1c444e5a913a5e185b92d1cb35d15812248f6e3dfa69723e6f6a649fbd132",
        offsets: [48, 80, 152, 168, 8, 16, 0, 8, 3056, 32, 0, 8, 56],
        identity: [3072, 40, 128, 16],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
    Dialect {
        blob: "6.8.0-31-generic.btf",
        blake3: "147f8e1e2bad64b65e858e203edd5a8984de456593a0e31db156f42a400fdb35",
        offsets: [48, 64, 152, 168, 8, 16, 0, 8, 3080, 32, 0, 8, 40],
        identity: [3096, 40, 120, 16],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
    Dialect {
        blob: "7.3.3-1-cachyos.btf",
        blake3: "85230401b1c90a414ceed7e46df3f83c02208d753a420205d3ae692b16d936b7",
        offsets: [48, 64, 64, 32, 8, 16, 0, 8, 3552, 32, 0, 8, 40],
        identity: [3576, 40, 192, 88],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
];

fn corpus_btf(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus/btf")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("the committed corpus blob {name} must exist: {e}"))
}

#[test]
fn the_committed_dialects_are_byte_pinned() {
    // Integrity before parsing: a blob that drifted by one byte
    // refuses by digest (the manifest lane's own law, reader-side).
    for dialect in &CORPUS {
        let data = corpus_btf(dialect.blob);
        assert_eq!(
            blake3::blake3_hex(&data),
            dialect.blake3,
            "{} drifted from its committed digest",
            dialect.blob
        );
    }
}

#[test]
fn the_parser_reads_every_committed_dialect_whole() {
    // The regression lock: the parse derives EVERY committed
    // dialect's table, slot by slot, anchors included. A parser
    // change that misreads any committed kernel fails here on every
    // host.
    for dialect in &CORPUS {
        let data = corpus_btf(dialect.blob);
        let offsets =
            parse_btf_offsets(&data).unwrap_or_else(|e| panic!("{} must parse: {e}", dialect.blob));
        assert_eq!(offsets, dialect.offsets, "{} walked wrong", dialect.blob);
        let identity = parse_identity_offsets(&data)
            .unwrap_or_else(|e| panic!("{} identity must parse: {e}", dialect.blob));
        assert_eq!(
            identity, dialect.identity,
            "{} identity walked wrong",
            dialect.blob
        );
        let lane = btf_unlink::verify_unlink_lane_in(&data)
            .unwrap_or_else(|e| panic!("{} anchors must resolve: {e}", dialect.blob));
        assert_eq!(lane.dentry_arg, dialect.dentry_arg, "{}", dialect.blob);
        assert_eq!(
            lane.old_dentry_offset, dialect.old_dentry_offset,
            "{}",
            dialect.blob
        );
    }
}

#[test]
fn the_committed_dialects_disagree_where_the_generations_moved() {
    // The corpus carries a RANGE, not a copy: five generations'
    // tables, every pair distinct. A parser change that normalized
    // them (or a fixture that duplicated one blob under two names)
    // would flatten this pin.
    for left in &CORPUS {
        for right in &CORPUS {
            if std::ptr::eq(left, right) {
                continue;
            }
            assert_ne!(
                left.offsets, right.offsets,
                "{} and {} walk the same table",
                left.blob, right.blob
            );
        }
    }
    // The f_path ladder is the documented story, now across three
    // eras: the pre-rework packing (16) holds through Debian's 6.1
    // point release, the anonymous-aggregate rework lands by 6.6
    // (152 - the offset the parser descends), and the 7.x line
    // re-packs it AGAIN (64 - a third layout no GA kernel ever
    // shipped). A parser pinned to any single era misreads another.
    let f_path: Vec<u64> = CORPUS.iter().map(|d| d.offsets[2]).collect();
    assert_eq!(f_path[0], 16, "5.15 rides the pre-rework packing");
    assert_eq!(f_path[1], 16, "6.1 still rides the pre-rework packing");
    assert_eq!(f_path[2], 152, "6.6 rides the rework packing");
    assert_eq!(f_path[3], 152, "6.8 rides the rework packing");
    assert_eq!(f_path[4], 64, "the 7.x line re-packed the aggregate");
    // f_inode rides with f_path through every migration: the pair
    // moved together, three times, never independently.
    let f_inode: Vec<u64> = CORPUS.iter().map(|d| d.offsets[3]).collect();
    for (path, inode) in f_path.iter().zip(f_inode.iter()) {
        assert_ne!(path, inode, "the pair never collapsed onto itself");
    }
    // task_struct.files - the fd-table anchor the write probe climbs
    // - marched with the kernel's own growth across the frozen span
    // (2928 -> 3048 -> 3056 -> 3080 -> 3552, strictly, in version
    // order). A parser change that sorted or normalized the rows
    // breaks this pin.
    for window in CORPUS.windows(2) {
        assert!(
            window[0].offsets[8] < window[1].offsets[8],
            "task_struct.files marched: {} -> {}",
            window[0].blob,
            window[1].blob
        );
    }
    // The mainline outlier: the frozen 6.6.95 build carries a
    // DIFFERENT struct inode than every distro kernel at the same
    // era - inode.i_ino at 80 (the GA builds ride 64) and
    // inode.i_sb at 56 (the GA builds ride 40). A parser tuned only
    // on distro-published offsets misreads the mainline dialect; the
    // corpus pins the outlier so that change fails here.
    let mainline = &CORPUS[2];
    for (index, dialect) in CORPUS.iter().enumerate() {
        if index == 2 {
            continue;
        }
        assert_ne!(
            dialect.offsets[1], mainline.offsets[1],
            "inode.i_ino: the mainline build is the outlier"
        );
        assert_ne!(
            dialect.offsets[12], mainline.offsets[12],
            "inode.i_sb: the mainline build is the outlier"
        );
    }
    // And the anchor that NEVER moved across the whole 5.15 -> 7.x
    // span: dentry.d_inode at 48, in all five dialects - the
    // stability the offsets law's runtime derivation leans on.
    for dialect in &CORPUS {
        assert_eq!(dialect.offsets[0], 48, "dentry.d_inode stayed");
    }
    // The unlink anchor stayed too: one dentry argument position (2,
    // the idmap+ kernels) and one renamedata old_dentry offset (16)
    // across all five dialects.
    for dialect in &CORPUS {
        assert_eq!(dialect.dentry_arg, 2, "the unlink anchor stayed");
        assert_eq!(dialect.old_dentry_offset, 16, "the rename anchor stayed");
    }
}

#[test]
fn the_btf_corpus_derivation_tables() {
    // The derivation harness: prints the table a new corpus dialect
    // pins (cargo test the_btf_corpus -- --nocapture), so a newly
    // committed blob's pins are DERIVED from the blob, never guessed.
    // In the ordinary suite run it only proves every committed blob
    // still parses; the printed tables are the maintainer's to pin.
    for dialect in &CORPUS {
        let data = corpus_btf(dialect.blob);
        let offsets = parse_btf_offsets(&data).expect("the committed dialect parses");
        let lane = btf_unlink::verify_unlink_lane_in(&data).expect("the anchors resolve");
        println!("=== {} ===", dialect.blob);
        println!("blake3: {}", blake3::blake3_hex(&data));
        println!("offsets: {offsets:?}");
        println!(
            "dentry_arg: {} old_dentry_offset: {}",
            lane.dentry_arg, lane.old_dentry_offset
        );
    }
}

// ── night-frontier-Z7, D4: the off-path chains per dialect ───────────

#[test]
fn the_offpath_chains_derive_per_dialect() {
    // The dirty descent (page.mapping / address_space.host) and the
    // io_uring request hop, derived from every committed blob - the
    // off-path lanes' own corpus lock. The anchor ladder's verdict
    // rides with them: which dirty symbol each dialect's BTF vouches
    // for (the folio shape where the folio exists, the page shape on
    // the folio-less line).
    // The pin table, filled from the derivation harness below
    // (--nocapture), never guessed. The measured story across the
    // whole frozen span: page.mapping at 24 in EVERY dialect, and
    // address_space.host at 0 (the mapping's FIRST member) - the two
    // anchors the mmap-dirty truth rides are the most stable walk
    // values in the corpus, the dentry.d_inode-at-48 law's sibling.
    // io_kiocb.file rides an anonymous union at offset 0 in every
    // dialect that carries io_uring. And the ladder's verdict is the
    // version story itself: the folio-less 5.15 GA vouches
    // __set_page_dirty_nobuffers (the page shape), every folio-era
    // dialect vouches filemap_dirty_folio - both shapes prove real,
    // per kernel, from committed bytes.
    let pinned: [(&str, u64, u64, Option<u64>, &str); 5] = [
        (
            "5.15.0-25-generic.btf",
            24,
            0,
            Some(0),
            "__set_page_dirty_nobuffers",
        ),
        ("6.1.0-50-amd64.btf", 24, 0, Some(0), "filemap_dirty_folio"),
        (
            "6.6.95-060695-generic.btf",
            24,
            0,
            Some(0),
            "filemap_dirty_folio",
        ),
        (
            "6.8.0-31-generic.btf",
            24,
            0,
            Some(0),
            "filemap_dirty_folio",
        ),
        ("7.3.3-1-cachyos.btf", 24, 0, Some(0), "filemap_dirty_folio"),
    ];
    // The stability law: the dirty-descent pair NEVER moved across
    // the whole span - the runtime derivation's sturdiest chain.
    for (dialect, want) in CORPUS.iter().zip(pinned.iter()) {
        assert_eq!(want.1, 24, "{} page.mapping stayed", dialect.blob);
        assert_eq!(want.2, 0, "{} address_space.host stayed", dialect.blob);
        assert_eq!(want.3, Some(0), "{} io_kiocb.file stayed", dialect.blob);
    }
    for (dialect, want) in CORPUS.iter().zip(pinned.iter()) {
        assert_eq!(dialect.blob, want.0, "the pin table rides the corpus order");
        let data = corpus_btf(dialect.blob);
        let offpath = crate::ebpf::btf_offpath::parse_offpath_offsets(&data)
            .unwrap_or_else(|e| panic!("{} must derive the off-path chains: {e}", dialect.blob));
        assert_eq!(
            offpath.page_mapping,
            Some(want.1),
            "{} page.mapping",
            dialect.blob
        );
        assert_eq!(
            offpath.address_space_host,
            Some(want.2),
            "{} address_space.host",
            dialect.blob
        );
        assert_eq!(
            offpath.io_kiocb_file, want.3,
            "{} io_kiocb.file",
            dialect.blob
        );
        let anchor = crate::ebpf::btf_offpath::verify_dirty_anchor_in(&data)
            .unwrap_or_else(|e| panic!("{} must vouch for a dirty anchor: {e}", dialect.blob));
        assert_eq!(anchor.symbol, want.4, "{} dirty anchor", dialect.blob);
    }
}

#[test]
fn the_offpath_derivation_harness() {
    // The derivation harness (the corpus table's own shape): prints
    // every number a new dialect pins. Run with --nocapture.
    for dialect in &CORPUS {
        let data = corpus_btf(dialect.blob);
        let offpath = crate::ebpf::btf_offpath::parse_offpath_offsets(&data)
            .expect("the committed dialect derives");
        let anchor =
            crate::ebpf::btf_offpath::verify_dirty_anchor_in(&data).expect("the anchor resolves");
        println!("=== {} ===", dialect.blob);
        println!("page.mapping: {:?}", offpath.page_mapping);
        println!("address_space.host: {:?}", offpath.address_space_host);
        println!("io_kiocb.file: {:?}", offpath.io_kiocb_file);
        println!("dirty anchor: {}", anchor.symbol);
    }
}
