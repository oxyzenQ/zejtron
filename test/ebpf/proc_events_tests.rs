// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! ProcEvent contract pins (night-improve-4): the 40-byte layout,
//! every offset, the op numbering, the comm decode, the offset-map
//! slot indices the process stream rides. The layout is the contract
//! both sides of the proc_events ring compile from one file
//! (src/ebpf/events.rs) - a field reorder or a width change moves a
//! pinned number, and the pin names exactly where it moved.

use super::*;
use core::mem::offset_of;

// The comm decode lives on the host renderer (live.rs) - the record
// contract file also compiles no_std into the bpfel object, where a
// String cannot exist.
use crate::commands::proc::live::comm_label;

fn event(op: u8, pid: u32, ppid: u32, comm: &str) -> ProcEvent {
    let mut comm_bytes = [0u8; 16];
    comm_bytes[..comm.len()].copy_from_slice(comm.as_bytes());
    ProcEvent {
        timestamp_ns: 1_000_000_000,
        op,
        _pad: [0; 3],
        pid,
        ppid,
        uid: 1000,
        comm: comm_bytes,
    }
}

#[test]
fn proc_event_is_exactly_40_bytes() {
    assert_eq!(PROC_EVENT_BYTES, 40);
    assert_eq!(core::mem::size_of::<ProcEvent>(), 40);
    assert_eq!(core::mem::align_of::<ProcEvent>(), 8);
}

#[test]
fn proc_event_offsets_are_pinned_field_by_field() {
    assert_eq!(offset_of!(ProcEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(ProcEvent, op), 8);
    assert_eq!(offset_of!(ProcEvent, _pad), 9);
    assert_eq!(offset_of!(ProcEvent, pid), 12);
    assert_eq!(offset_of!(ProcEvent, ppid), 16);
    assert_eq!(offset_of!(ProcEvent, uid), 20);
    assert_eq!(offset_of!(ProcEvent, comm), 24);
}

#[test]
fn the_lifecycle_ops_keep_their_numbers() {
    // The record contract never renumbers: 1=exec, 2=fork, 3=exit -
    // the same discipline the file record's reserved op=3 pins. The
    // op LABELS are the renderer's concern (proc/live.rs) and are
    // pinned there.
    assert_eq!(PROC_OP_EXEC, 1);
    assert_eq!(PROC_OP_FORK, 2);
    assert_eq!(PROC_OP_EXIT, 3);
}

#[test]
fn the_proc_offset_slots_append_without_renumbering() {
    // The eight file-walk slots keep their indices; the process
    // stream's five append after them.
    assert_eq!(OFF_SLOTS, 13);
    assert_eq!(OFF_SLOT_TP_FORK_PARENT_PID, 8);
    assert_eq!(OFF_SLOT_TP_FORK_CHILD_PID, 9);
    assert_eq!(OFF_SLOT_TP_EXIT_PID, 10);
    assert_eq!(OFF_SLOT_TASK_REAL_PARENT, 11);
    assert_eq!(OFF_SLOT_TASK_TGID, 12);
    assert_eq!(OFF_SLOT_PATH_DENTRY, 7);
}

#[test]
fn comm_decode_stops_at_the_nul_and_names_the_empty() {
    assert_eq!(comm_label(&event(1, 1, 0, "python3").comm), "python3");
    // A full 16-byte comm with no NUL decodes whole.
    let full = event(1, 1, 0, "abcdefghijklmnop").comm;
    assert_eq!(comm_label(&full), "abcdefghijklmnop");
    // A comm the kernel never wrote renders as unknown - never an
    // empty name, never a guess.
    assert_eq!(comm_label(&[0u8; 16]), "unknown");
}
