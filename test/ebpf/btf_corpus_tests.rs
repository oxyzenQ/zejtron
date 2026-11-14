// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The real-kernel BTF corpus pins (night-frontier-Z2, E2): the
//! parser's regression lock over REAL kernel dialects - the floor
//! lane's own GA kernel (jammy 5.15.0-25) and the second GA
//! generation (noble 6.8.0-31), their .BTF sections extracted from
//! the shipped vmlinuz packages and committed whole under corpus/btf
//! (the provenance law lives in corpus/README.md). A parser change
//! that would misread any committed dialect fails here, on every
//! host, forever - the moving kernels stay locked live on the
//! witness legs; the corpus freezes the dialects themselves.
//!
//! THE TABLES ARE THE STORY: the two committed dialects disagree in
//! exactly the slots the kernel generations moved - jammy's
//! struct file.f_path sits at 16 while noble's rides 152 (the
//! anonymous-aggregate rework the parser descends), f_inode follows
//! it 32 -> 168, and task_struct.files moved 2928 -> 3080. A parser
//! change that silently normalized the two tables - or pinned one
//! generation's layout over the other - fails here. The integrity
//! half rides the tree's own blake3 implementation
//! (build/blake3.rs, path-included): a committed blob that drifts
//! by one byte refuses by digest before any parse runs.
//!
//! A NEW DIALECT joins by: commit the blob under corpus/btf, run
//! `cargo test the_btf_corpus -- --nocapture` (the derivation
//! harness prints the table), and pin the digest + the table below.

#[path = "../../build/blake3.rs"]
mod blake3;

use super::super::btf_unlink;
use super::*;

/// The committed dialects: name, integrity digest, the thirteen
/// struct offsets, the unlink dentry argument position, the
/// renamedata old_dentry member offset. One row per real kernel,
/// frozen.
struct Dialect {
    blob: &'static str,
    blake3: &'static str,
    offsets: [u64; 13],
    dentry_arg: u32,
    old_dentry_offset: u64,
}

const CORPUS: [Dialect; 2] = [
    Dialect {
        blob: "5.15.0-25-generic.btf",
        blake3: "7e88b941af6ed12b4cdb88951f504a4a2ee2996bb887673181bd8640166e181a",
        offsets: [48, 64, 16, 32, 8, 16, 0, 8, 2928, 32, 0, 8, 40],
        dentry_arg: 2,
        old_dentry_offset: 16,
    },
    Dialect {
        blob: "6.8.0-31-generic.btf",
        blake3: "147f8e1e2bad64b65e858e203edd5a8984de456593a0e31db156f42a400fdb35",
        offsets: [48, 64, 152, 168, 8, 16, 0, 8, 3080, 32, 0, 8, 40],
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
    // The corpus carries a RANGE, not a copy: the two generations'
    // tables differ in exactly the slots the kernel moved. A parser
    // change that normalized them (or a fixture that duplicated one
    // blob under two names) would flatten this pin.
    let (jammy, noble) = (&CORPUS[0], &CORPUS[1]);
    assert_ne!(
        jammy.offsets, noble.offsets,
        "the dialects are one blob twice"
    );
    // The moved slots are the documented story: file.f_path (the
    // anonymous-aggregate rework), file.f_inode riding after it, and
    // task_struct.files (the fd table anchor the write probe climbs).
    assert_ne!(jammy.offsets[2], noble.offsets[2], "file.f_path moved");
    assert_ne!(jammy.offsets[3], noble.offsets[3], "file.f_inode moved");
    assert_ne!(
        jammy.offsets[8], noble.offsets[8],
        "task_struct.files moved"
    );
    // And the UNMOVED slots are pinned too - the stability the
    // offsets law's runtime derivation leans on.
    assert_eq!(jammy.offsets[0], noble.offsets[0], "dentry.d_inode stayed");
    assert_eq!(jammy.offsets[1], noble.offsets[1], "inode.i_ino stayed");
    assert_eq!(
        jammy.dentry_arg, noble.dentry_arg,
        "the unlink anchor stayed"
    );
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
