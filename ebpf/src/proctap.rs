// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The process-lifecycle taps (night-improve-4, Part C): the kernel
//! half of the proc_events ring. Two new tracepoint programs live
//! here - sched_process_fork and sched_process_exit - and the shared
//! emit helper the exec tap (main.rs) calls after its counter
//! increment. The exec tracepoint's program predates this module by
//! three passes; its section and pin are the phase-1 ones and stay.
//!
//! Every tracepoint context read rides the `offsets` map (written at
//! attach from the host's own BTF, src/ebpf/btf.rs): the fork
//! context's parent_pid/child_pid and the exit context's pid are
//! BTF-verified offsets, never compiled-in constants - the same
//! discipline the file kprobes apply to struct inode. The exec
//! context carries no field this record needs (its pid comes from
//! bpf_get_current_pid_tgid), and its context STRUCT's presence is
//! still BTF-verified at attach: a kernel whose exec tracepoint
//! changed shape is a kernel the attach refuses.
//!
//! The ppid for exec and exit comes from the task_struct walk:
//! current->real_parent->tgid, both offsets BTF-verified. The fork
//! tracepoint hands the parent's pid directly (parent_pid), so no
//! walk rides it. A refused walk records ppid 0 - the absent fact
//! stays absent, and the renderer drops the token rather than
//! guessing.
//!
//! Threads are tasks: clone() fires fork and every task death fires
//! exit, so the stream records thread churn alongside process churn.
//! No filter map for this pass (the rate argument in the spec names
//! process creation, and the ring's 256 KiB holds 6553 records);
//! the README names the thread residual honestly.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::tracepoint,
    programs::TracePointContext,
};

use crate::events::{
    OFF_SLOT_TASK_REAL_PARENT, OFF_SLOT_TASK_TGID, OFF_SLOT_TP_EXIT_PID,
    OFF_SLOT_TP_FORK_CHILD_PID, OFF_SLOT_TP_FORK_PARENT_PID, PROC_OP_EXIT, PROC_OP_FORK,
    ProcEvent,
};

use crate::{proc_events, read_offset_set};

/// The ppid walk: current->real_parent->tgid, both offsets read from
/// the `offsets` map (BTF-verified at attach). `None` when any step
/// refuses - the caller records ppid 0, and the renderer treats 0 as
/// absent.
///
/// # Safety
/// The walk starts from the kernel's own task_struct pointer (the
/// bpf_get_current_task helper) and every dereference is probe-read:
/// a bad address returns an error, never a fault.
pub(crate) unsafe fn current_ppid() -> Option<u32> {
    unsafe {
        let set = read_offset_set()?;
        let task = bpf_get_current_task();
        if task == 0 {
            return None;
        }
        let real_parent = bpf_probe_read_kernel(
            (task as usize)
                .wrapping_add(set[OFF_SLOT_TASK_REAL_PARENT as usize] as usize)
                as *const u64,
        )
        .ok()?;
        if real_parent == 0 {
            return None;
        }
        let tgid = bpf_probe_read_kernel(
            (real_parent as usize)
                .wrapping_add(set[OFF_SLOT_TASK_TGID as usize] as usize)
                as *const u32,
        )
        .ok()?;
        Some(tgid)
    }
}

/// Build and publish one ProcEvent: the fields every op shares (the
/// clock, the uid, the comm) come from helpers; the caller supplies
/// the op, the pid, and the ppid it read from its own context or
/// walk. A failed ring reservation drops the event silently - a
/// passive tracepoint never fails the path it rides, and the ring's
/// own rolling window keeps the newest history.
pub(crate) fn emit_proc_event(op: u8, pid: u32, ppid: Option<u32>) {
    let mut comm = [0u8; 16];
    if let Ok(read) = bpf_get_current_comm() {
        comm = read;
    }
    let event = ProcEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        op,
        _pad: [0; 3],
        pid,
        ppid: ppid.unwrap_or(0),
        uid: unsafe { bpf_get_current_uid_gid() } as u32,
        comm,
    };
    let _ = proc_events.output::<ProcEvent>(&event, 0);
}

/// The fork tap: sched_process_fork fires with the tracepoint's own
/// parent_pid/child_pid pair - the one event whose ppid needs no
/// task_struct walk. The context offsets come from the BTF-verified
/// map; a refused read drops the event (a passive probe never fails
/// the kernel path it is riding).
#[tracepoint(name = "sched_process_fork", category = "sched")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    unsafe {
        let Some(set) = read_offset_set() else { return 0 };
        let parent_pid: i32 = match ctx
            .read_at::<i32>(set[OFF_SLOT_TP_FORK_PARENT_PID as usize] as usize)
        {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let child_pid: i32 = match ctx
            .read_at::<i32>(set[OFF_SLOT_TP_FORK_CHILD_PID as usize] as usize)
        {
            Ok(value) => value,
            Err(_) => return 0,
        };
        // The event is about the child; the parent's pid is the ppid.
        // The comm at fork time is the creator's - the child inherits
        // it until it execs, so bpf_get_current_comm (current is the
        // forking task) names both, and the record says so.
        emit_proc_event(PROC_OP_FORK, child_pid as u32, Some(parent_pid as u32));
    }
    0
}

/// The exit tap: sched_process_exit fires with the dying task's pid
/// in its context (BTF-verified offset); the ppid rides the
/// task_struct walk (current is the dying task - its real_parent is
/// the reaper-or-parent the kernel holds).
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    unsafe {
        let Some(set) = read_offset_set() else { return 0 };
        let pid: i32 = match ctx.read_at::<i32>(set[OFF_SLOT_TP_EXIT_PID as usize] as usize) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let ppid = current_ppid();
        emit_proc_event(PROC_OP_EXIT, pid as u32, ppid);
    }
    0
}
