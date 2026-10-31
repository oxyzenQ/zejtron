// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The fd walk's identity laws (night-dragon-lts-4): the memfd
//! classifier, the per-(pid, file) row dedupe, and the deleted view's
//! unique-file accounting - pinned with synthetic rows so the laws
//! hold on every host regardless of what the host's own tables carry.

use super::*;

#[test]
fn memfd_targets_are_classified_before_the_deleted_suffix_eats_them() {
    // The kernel's own render (proven live on 5.10 and 6.12 hosts):
    // a memfd's fd target is "/memfd:<name> (deleted)" - leading
    // slash and deleted suffix are both unconditional. The pre-fix
    // walk tested "memfd:" (never matches: the slash) AFTER the
    // deleted suffix (always matches first), so the memfd section
    // rendered "(none observed)" on every host while the deleted
    // lane absorbed every memfd.
    assert!(is_memfd_target("/memfd:pulseaudio (deleted)"));
    assert!(is_memfd_target("/memfd:webkit"));
    // The bare form (some tooling strips the slash) classifies too.
    assert!(is_memfd_target("memfd:bare"));
    // A deleted file whose path merely contains "memfd" is not one:
    // only one leading slash is stripped, so directory components
    // keep the prefix test honest.
    assert!(!is_memfd_target("/tmp/memfd:fake (deleted)"));
    assert!(!is_memfd_target("/var/log/gone.log (deleted)"));
    assert!(!is_memfd_target("/dev/dri/card0"));
    assert!(!is_memfd_target("socket:[12345]"));
}

fn deleted(pid: u32, identity: Option<(u64, u64)>, size: Option<u64>) -> DeletedOpenFile {
    DeletedOpenFile {
        pid,
        name: "holder".to_owned(),
        path: format!("/tmp/gone.{pid} (deleted)"),
        size_bytes: size,
        identity,
    }
}

fn memfd(pid: u32, identity: Option<(u64, u64)>, size: Option<u64>) -> MemfdFile {
    MemfdFile {
        pid,
        name: "holder".to_owned(),
        target: "/memfd:shared (deleted)".to_owned(),
        size_bytes: size,
        identity,
    }
}

#[test]
fn rows_dedupe_per_pid_per_file_not_per_fd() {
    // One process holding one file through two fds (dup(2)): the walk
    // pushed a row per fd, the render speaks one row per holder per
    // file.
    let rows = vec![
        deleted(100, Some((9, 1)), Some(40 * 1024 * 1024)),
        deleted(100, Some((9, 1)), Some(40 * 1024 * 1024)),
    ];
    let deduped = dedupe_by_pid_file(rows);
    assert_eq!(deduped.len(), 1);

    // Two processes holding the same file are two facts: both rows
    // ride through - the fd count is not the fact, the holder is.
    let rows = vec![
        deleted(100, Some((9, 1)), Some(40 * 1024 * 1024)),
        deleted(200, Some((9, 1)), Some(40 * 1024 * 1024)),
    ];
    assert_eq!(dedupe_by_pid_file(rows).len(), 2);

    // One process, two distinct files: both ride.
    let rows = vec![
        deleted(100, Some((9, 1)), Some(1)),
        deleted(100, Some((9, 2)), Some(2)),
    ];
    assert_eq!(dedupe_by_pid_file(rows).len(), 2);

    // Identity-refused rows cannot be matched and all ride through:
    // a guessed dedupe would silently drop a real row.
    let rows = vec![deleted(100, None, None), deleted(100, None, None)];
    assert_eq!(dedupe_by_pid_file(rows).len(), 2);

    // The memfd lane speaks the same law through the same trait.
    let rows = vec![
        memfd(100, Some((7, 7)), Some(1024)),
        memfd(100, Some((7, 7)), Some(1024)),
    ];
    assert_eq!(dedupe_by_pid_file(rows).len(), 1);
}

#[test]
fn the_deleted_total_counts_each_file_once_not_each_holder() {
    // The shape the live audit caught: one 40 MiB memfd held by
    // three processes rendered as 120 MiB of deleted-but-open
    // pressure. The unique accounting counts the file once.
    let rows = vec![
        deleted(100, Some((9, 1)), Some(40 * 1024 * 1024)),
        deleted(200, Some((9, 1)), Some(40 * 1024 * 1024)),
        deleted(300, Some((9, 1)), Some(40 * 1024 * 1024)),
    ];
    let (files, bytes) = deleted_unique(&rows);
    assert_eq!(files, 1);
    assert_eq!(bytes, 40 * 1024 * 1024);

    // Distinct files sum; identity, not path text, is the key.
    let rows = vec![
        deleted(100, Some((9, 1)), Some(1024)),
        deleted(200, Some((9, 2)), Some(2048)),
    ];
    let (files, bytes) = deleted_unique(&rows);
    assert_eq!(files, 2);
    assert_eq!(bytes, 3072);

    // Size-refused rows contribute nothing - an unknown size was
    // never added; identity-refused rows cannot be matched and stay
    // out rather than guessed in.
    let rows = vec![
        deleted(100, Some((9, 1)), None),
        deleted(200, None, Some(999)),
    ];
    let (files, bytes) = deleted_unique(&rows);
    assert_eq!((files, bytes), (0, 0));
}
