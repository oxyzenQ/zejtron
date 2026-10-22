// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF tap, the post-mortem exit program (night-improve-47).
// A dedicated module under the 600-LOC no-mercy cap: the sixth
// program lives beside the five in main.rs - same crate, same
// single-sourced record contract, same license law.
//
// WHY THIS PROGRAM EXISTS: night-improve-34 removed the two
// sched_process lifecycle tracepoints because the lifecycle stream
// surface - their only consumer - was removed. night-improve-47
// gives the exit half a new consumer with a different shape: not a
// live stream, but a post-mortem record. A process that allocated
// RAM and exited three seconds before `doctor --symptom ram` runs
// is invisible to every /proc read - the symptom's Unaccounted
// block has named that hole since night-improve-34. This tap
// records the exit itself (the pid and the process's own name, at
// the moment it happened) into a bounded ring, and the doctor
// drains the last five seconds on demand. The Lazy Camera contract
// holds exactly (docs/EBPF_LIFECYCLE.md): the kernel records, the
// CLI drains once and exits, nothing streams, nothing is written
// to disk.
//
// THE FILTER IS THE LEADER: sched_process_exit fires for every
// exiting TASK - every thread - so a hundred-thread process would
// otherwise leave a hundred records with the same tgid and a
// hundred different thread comms. The record is per PROCESS exit:
// the tgid-vs-tid check (the two halves of bpf_get_current_pid_tgid
// are equal only for the thread group leader) keeps one record per
// process, and the leader's comm IS the process name /proc would
// have shown. No other filter exists, by design: every process
// exit is potentially the one the doctor is asked about, exits are
// rare next to the open traffic the file taps filter, and the
// ring's own rolling window is the bound.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use crate::events::{ProcExitEvent, PROCEXIT_EVENT_BYTES};

// The compile-time layout pin on the BPF side: the exit record the
// ring carries is exactly 32 bytes (the SockEvent size, the same
// asserted-where-output-lives discipline).
const _: () = assert!(PROCEXIT_EVENT_BYTES == 32);

/// The proc_events ring buffer (night-improve-47): 256 KiB, 8192
/// records of 32 bytes. Unfiltered by design (the module header
/// names the leader check as the whole filter); on any host short
/// of a build-storm the ring holds hours of exit history, and when
/// it does fill, the oldest records are overwritten in the kernel
/// (a ring buffer's own rolling window) and a failed reservation
/// drops the event without failing the tracepoint.
#[allow(non_upper_case_globals)]
#[map(name = "proc_events")]
static proc_events: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// The post-mortem exit tap: record the process exit (leader-only)
/// with its comm - the fact no /proc read can recover a second
/// later. Every helper call except `bpf_ktime_get_ns` (the raw
/// binding) is an aya-ebpf safe wrapper; the one unsafe block is
/// that API contract, nothing more. Returning 0 is the tracepoint
/// contract: the return value is recorded but never acts as a
/// filter.
#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    // The two halves: tgid high, tid low - equal only for the
    // thread group leader, the process itself.
    let ptid = bpf_get_current_pid_tgid();
    let tgid = (ptid >> 32) as u32;
    let tid = ptid as u32;
    if tgid != tid {
        // A thread's exit is not a process exit - one record per
        // process, the leader's.
        return 0;
    }
    // The comm, straight from the current task (the exiting
    // process's leader). The helper zeroes the buffer and writes
    // the NUL-terminated name; a failed read drops the record - a
    // passive tracepoint never fails.
    let Ok(comm) = bpf_get_current_comm() else { return 0 };
    let _ = proc_events.output::<ProcExitEvent>(
        &ProcExitEvent {
            timestamp_ns: unsafe { bpf_ktime_get_ns() },
            pid: tgid,
            _pad: 0,
            comm,
        },
        0,
    );

    0
}
