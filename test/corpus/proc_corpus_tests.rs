// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The /proc dialect corpus pins (night-frontier-Z2, E2): the
//! snapshot parsers' regression lock over REAL captured bytes. The
//! bundle under corpus/kernel-dialect/5.10.134-kangaroo-al8 was
//! captured from the live sandbox host (kernel 5.10.134 - one
//! dialect BELOW the attach floor: parsing is wider than attaching,
//! and the corpus proves the parsers read formats older than the
//! estate promises). The provenance law per file lives in
//! corpus/README.md. A parser change that would misread the
//! committed format fails here on every host - and the moving
//! kernels stay locked live on the witness legs, which parse their
//! own real /proc on every push.
//!
//! A NEW DIALECT joins by: capture the bundle on a real host, commit
//! it under corpus/kernel-dialect/<release>, and pin the parsed
//! values below (values are DERIVED from the committed bytes, never
//! guessed).

use super::*;
use crate::commands::proc::parse_status;

fn dialect_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus/kernel-dialect/5.10.134-kangaroo-al8")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the committed corpus file {rel} must exist: {e}"))
}

#[test]
fn the_meminfo_dialect_parses_with_its_real_values() {
    // The real 5.10.134 meminfo, byte-pinned: the parser reads the
    // committed bytes and lands on the committed values. A format
    // change in the parser (a field rename, a KiB-vs-page slip) or a
    // fixture edit that changed the bytes both fail here.
    let meminfo = parse_meminfo(&dialect_file("meminfo")).expect("the committed meminfo parses");
    assert_eq!(meminfo.total_kib, 4_259_396);
    assert_eq!(meminfo.available_kib, 3_147_008);
}

#[test]
fn the_status_dialect_parses_its_real_processes() {
    // Two committed status files, byte-pinned: the capture's own
    // worker (cp, pid 13333 - the process that made the bundle, its
    // provenance stated in corpus/README.md) and the sandbox's pid 1
    // (tini). parse_status is the one /proc parser the whole tree
    // shares - the doctor, the holders, the attribution.
    let worker = parse_status(&dialect_file("status")).expect("the committed status parses");
    assert_eq!(worker.pid, 13_333);
    assert_eq!(worker.name, "cp");
    let init =
        parse_status(&dialect_file("status-pid1.txt")).expect("the committed pid-1 status parses");
    assert_eq!(init.pid, 1);
    assert_eq!(init.name, "tini");
}
