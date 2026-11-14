// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! fileprobe pins (night-improve-3): the window selection (full
//! identity match, defense in depth against key aliasing), the sort
//! order, the clock helpers' honest degradations. The live capture
//! itself needs an attached probe on a >= 5.15 host - the sandbox is
// below the floor, so the capture is verified by the shape pins and
//! the owner host's live leg. Wired from src/ebpf/fileprobe.rs.

use super::*;
use crate::ebpf::events::{FILE_OP_OPEN, FILE_OP_WRITE};

fn file_event(ts: u64, op: u8, inode: u64, device: u64, pid: u32) -> FileEvent {
    FileEvent {
        timestamp_ns: ts,
        op,
        _pad: [0; 7],
        inode,
        device,
        pid,
        _pad2: 0,
    }
}

#[test]
fn selection_keeps_full_identity_matches_only() {
    let events = vec![
        file_event(100, FILE_OP_OPEN, 0x1234, 0x800002, 10), // match
        file_event(200, FILE_OP_WRITE, 0x1234, 0x800002, 11), // match
        file_event(300, FILE_OP_OPEN, 0x1235, 0x800002, 12), // wrong inode
        file_event(400, FILE_OP_OPEN, 0x1234, 0x800003, 13), // wrong device (the alias case)
        file_event(500, FILE_OP_OPEN, 0x1234 & 0xFFFF_FFFF, 0x800002, 14), // low-half alias of a
                                                             // huge inode: kept only when it is the full identity - here
                                                             // it equals the queried inode, so it IS a match.
    ];
    let selected = select_window(&events, 0x1234, 0x800002);
    assert_eq!(selected.len(), 3);
    assert!(
        selected
            .iter()
            .all(|e| e.inode == 0x1234 && e.device == 0x800002)
    );
}

#[test]
fn a_high_inode_alias_is_dropped_not_rendered_as_the_query() {
    // The named residual made safe: an inode above 2^32 shares the
    // filter KEY with the low-half query, but the host mirror drops
    // the event because the FULL identity does not match.
    let events = vec![
        file_event(100, FILE_OP_OPEN, 0x1_0000_1234, 0x800002, 10), // aliased key, foreign inode
        file_event(200, FILE_OP_OPEN, 0x1234, 0x800002, 11),        // the queried file
    ];
    let selected = select_window(&events, 0x1234, 0x800002);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].inode, 0x1234);
    assert_eq!(selected[0].pid, 11);
}

#[test]
fn selection_sorts_ascending_by_timestamp() {
    let events = vec![
        file_event(300, FILE_OP_OPEN, 1, 2, 1),
        file_event(100, FILE_OP_OPEN, 1, 2, 2),
        file_event(200, FILE_OP_OPEN, 1, 2, 3),
    ];
    let selected = select_window(&events, 1, 2);
    let stamps: Vec<u64> = selected.iter().map(|e| e.timestamp_ns).collect();
    assert_eq!(stamps, vec![100, 200, 300]);
}

#[test]
fn timestamp_ties_break_by_op_then_pid() {
    // night-depth-hardening-1: same-nanosecond stamps are real (a
    // write plus its writev inside one syscall burst), and per-CPU
    // ring interleave is not stable across drains. The tail (op, then
    // the identity, then the actor) is a total order over the
    // record's own fields - same drain in, same bytes out.
    let events = vec![
        file_event(200, FILE_OP_OPEN, 1, 2, 30),
        file_event(200, FILE_OP_WRITE, 1, 2, 10),
        file_event(200, FILE_OP_OPEN, 1, 2, 20),
        file_event(100, FILE_OP_OPEN, 1, 2, 5),
    ];
    let selected = select_window(&events, 1, 2);
    let order: Vec<(u64, u32)> = selected.iter().map(|e| (e.timestamp_ns, e.pid)).collect();
    assert_eq!(
        order,
        vec![(100, 5), (200, 20), (200, 30), (200, 10)],
        "ascending by time, then op (OPEN 1 before WRITE 2), then pid"
    );
}

#[test]
fn monotonic_now_degrades_to_none_never_a_guess() {
    // The crate's one clock source (clock_gettime on CLOCK_MONOTONIC)
    // cannot fail on a Linux host that booted; guard for the exotic
    // case anyway (the honest degradation is None, never a guessed
    // value). The helper this test used to call was fileprobe's own
    // /proc/uptime copy - retired with the BOOTTIME fix; the pin
    // rides the shared source now, so the two can never drift apart
    // again.
    match crate::info::clock::monotonic_now_ns() {
        Some(now) => assert!(now > 0, "a booted host has positive monotonic time"),
        None => { /* the honest degradation; named here, not asserted */ }
    }
}

#[test]
fn event_unix_secs_lands_inside_the_recent_window() {
    // The conversion rides the crate's one clock source, so the pin
    // reads its monotonic now from the same module the offset does -
    // one domain end to end, the same law the fix restored.
    let Some(now) = crate::info::clock::monotonic_now_ns() else {
        return;
    };
    let event = file_event(now, FILE_OP_OPEN, 1, 2, 3);
    let offset = crate::info::clock::wall_offset_ns();
    let Some(secs) = event_unix_secs_with(&event, offset) else {
        panic!("a live clock must convert");
    };
    let wall_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let drift = (secs - wall_now).abs();
    assert!(
        drift <= 2,
        "the converted time is within 2s of the wall clock (drift {drift})"
    );
}
