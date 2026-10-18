// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF tap, the pure-Rust BPF source (night-improve-1, the
// zelynic/zylaxion lineage precedent: there is no C twin, the
// aya-ebpf program IS the production source).
//
// ONE job, and Phase 1 is exactly this job and nothing else: count
// process executions. The tracepoint fires, the counter increments.
// That is the whole proof of chain — the BPF program loads, the
// verifier accepts it, the tracepoint fires, the counter increments,
// the loader reads it back, detach unpins every pin.
//
//   stats  (Array<AtomicU64>) — the one map, one slot. stats[0] is
//                             the count of sched_process_exec events
//                             since attach. Accumulated in the kernel
//                             at zero userspace cost; read by
//                             `zejtron doctor` through the pinned
//                             map. Introspectable with stock bpftool.
//
// Deliberately absent (later passes own them): no tracepoint
// argument reads (Phase 2 opens the context for the port surface),
// no ring buffer, no second map, no keying by pid or uid. The tap
// only counts — a no-op tap that proves the infrastructure without
// smuggling in business logic.
//
// Map update discipline: the counter rides a 64-bit BPF_ATOMIC
// fetch_add (the zelynic NIGHT-improve-29 lost-update lesson — the
// BPF ISA has RMW atomics but no atomic load/store, so the counter
// is core AtomicU64 and the program performs no plain shared-field
// access on its update path). The atomic RMW instructions require
// cpu v3 bytecode (see .cargo/config.toml) — Linux 5.12+, under the
// verified 5.15 floor.
//
// The attach point: the sched_process_exec tracepoint (category
// "sched", event "sched_process_exec"), fired by the kernel on every
// successful execve. The macro below carries BOTH halves into the
// ELF - the section name becomes tracepoint/sched/sched_process_exec
// (aya's userspace side maps that section prefix to the TracePoint
// program type) and the no_mangle trampoline keeps the symbol
// "sched_process_exec" as the program name the loader looks up.
// The userspace attach (src/ebpf/loader.rs) repeats the pair
// explicitly - aya's TracePoint::attach("sched",
// "sched_process_exec") - so the section and the attach call name
// the same event twice, by design: the section types the program,
// the attach selects the event.
//
// Build: cd ebpf && cargo build --release

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::Array,
    programs::TracePointContext,
};

/// The one stats slot: the count of sched_process_exec events since
/// attach. The index contract with the userspace read side
/// (src/ebpf/readback.rs reads the same slot; keep both sides in
/// lockstep).
pub const STATS_EVENTS: u32 = 0;

// The static name IS the userspace contract (the loader opens the
// map by name), so it stays lowercase exactly like the object's
// symbol; the allow attribute suppresses the non-upper-case globals
// lint for that reason.
#[allow(non_upper_case_globals)]
#[map(name = "stats")]
static stats: Array<AtomicU64> = Array::with_max_entries(1, 0);

/// The tap: increment stats[STATS_EVENTS] on every process exec.
///
/// The context is deliberately unread — Phase 1 counts events, it
/// does not inspect them. Returning 0 is the tracepoint contract:
/// the return value is recorded but never acts as a filter.
#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    // aya-ebpf 0.2.1's map API is safe code: the lookup is
    // bounds-checked (Array::get returns Option) and the verifier
    // re-proves the whole program at load time.
    if let Some(counter) = stats.get(STATS_EVENTS) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// The license section must stay GPL: zejtron is GPL-3.0-only and a
// mismatch here would fail the verifier at program load time on a
// real host (tracepoint programs are GPL-addressable).
#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
