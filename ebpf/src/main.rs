// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// zejtron eBPF tap, the pure-Rust BPF source (night-improve-1, the
// zelynic/zylaxion lineage precedent: there is no C twin, the
// aya-ebpf program IS the production source).
//
// TWO programs, one object (night-improve-2 grows the tap by one;
// nothing of phase 1 changes shape — the sched_process_exec counter
// is exactly what it was):
//
//   1. sched_process_exec (phase 1, untouched): count process
//      executions. The tracepoint fires, the counter increments —
//      the chain proof, still the doctor's readback.
//
//   2. inet_sock_set_state (phase 2, the port surface's event
//      window): the first context-reading program. At every inet
//      socket state change the kernel fires
//      tracepoint:sock:inet_sock_set_state with the socket's facts
//      laid out in the context record; this program reads them at
//      the pinned offsets, filters to the port-surface transitions
//      (TCP LISTEN enter/leave, UDP close — the shared predicate
//      in events.rs, the same bytes the host tests pin), and
//      publishes a 32-byte SockEvent to the sock_events ring buffer
//      with the pid of the process whose syscall made the change.
//      The /proc snapshot can only see who holds an fd NOW; this
//      record carries who changed the socket, at the moment it
//      happened — the truth that makes the event window race-free
//      by construction.
//
//   stats        (Array<AtomicU64>) — phase 1's counter, one slot,
//                                 unchanged. stats[0] counts
//                                 sched_process_exec events since
//                                 attach; BPF_ATOMIC fetch_add only.
//   sock_events  (RingBuf)          — phase 2's event stream. The
//                                 kernel-side filter bounds the
//                                 traffic (ESTABLISHED churn never
//                                 crosses); 256 KiB holds 8192
//                                 32-byte records of history, and
//                                 the host drains it through the
//                                 pin.
//
// Deliberately absent (later passes own them): no second counter,
// no keying by pid or uid, no address reads (the record carries the
// port and the changer; the bind address stays the snapshot's
// truth), no process or file events (later passes).
//
// Map update discipline: the counter rides a 64-bit BPF_ATOMIC
// fetch_add (the zelynic NIGHT-improve-29 lost-update lesson — the
// BPF ISA has RMW atomics but no atomic load/store, so the counter
// is core AtomicU64 and the program performs no plain shared-field
// access on its update path). The atomic RMW instructions require
// cpu v3 bytecode (see .cargo/config.toml) — Linux 5.12+, under the
// verified 5.15 floor.
//
// The attach points: sched/sched_process_exec (phase 1) and
// sock/inet_sock_set_state (phase 2). Each #[tracepoint] macro
// carries BOTH halves into the ELF — the section name becomes
// tracepoint/<category>/<event> and the no_mangle trampoline keeps
// the symbol as the program name the loader looks up. The userspace
// attach (src/ebpf/loader.rs) repeats each pair explicitly — aya's
// TracePoint::attach("<category>", "<event>") — so the section and
// the attach call name the same event twice, by design: the section
// types the program, the attach selects the event.
//
// Build: cd ebpf && cargo build --release

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
};

// The record contract, single-sourced: the userspace crate owns the
// file (so its layout tests run in every gate lane) and this crate
// compiles the very same bytes via #[path]. See src/ebpf/events.rs
// for the layout and the filter discipline.
#[path = "../../src/ebpf/events.rs"]
mod events;

use events::{SOCK_EVENT_BYTES, SockEvent, is_port_surface_event};

// The compile-time layout pin on the BPF side: the record the ring
// carries is exactly 32 bytes, asserted where the output() call
// lives (its internal align assert covers the 8-byte half).
const _: () = assert!(SOCK_EVENT_BYTES == 32);

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

/// The sock_events ring buffer: 256 KiB, 8192 records of 32 bytes
/// each. The kernel-side filter is the bound — only LISTEN
/// enter/leave and UDP close cross — so on any host short of a
/// port-churn benchmark the ring holds minutes of history; when it
/// does fill, the oldest records are overwritten in the kernel (a
/// ring buffer's own rolling window) and a failed reservation drops
/// the event without failing the tracepoint.
#[allow(non_upper_case_globals)]
#[map(name = "sock_events")]
static sock_events: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// The inet_sock_set_state context layout — the field offsets of
// struct trace_event_raw_inet_sock_set_state, verified against
// vmlinux BTF (this repo's own sandbox probe, kernel 5.10.134): the
// 8-byte trace_entry header, then skaddr, oldstate, newstate, sport,
// dport, family, protocol — a prefix layout that has been stable
// since the tracepoint landed in 4.16 (the saddr/daddr fields later
// kernels append ride AFTER protocol, past offset 32, and are not
// read). sport/dport are host byte order already (the kernel's
// TP_fast_assign applied ntohs).
mod ctx_offsets {
    /// const void *skaddr — the socket's kernel address.
    pub const SKADDR: usize = 8;
    /// int oldstate — tcp_states.h numbering, narrowed to u8.
    pub const OLDSTATE: usize = 16;
    /// int newstate.
    pub const NEWSTATE: usize = 20;
    /// __u16 sport — local port, host byte order.
    pub const SPORT: usize = 24;
    /// __u16 dport — remote port, host byte order.
    pub const DPORT: usize = 26;
    /// unsigned short family — AF_INET / AF_INET6.
    pub const FAMILY: usize = 28;
    /// unsigned short protocol — IPPROTO_TCP / IPPROTO_UDP.
    pub const PROTOCOL: usize = 30;
}

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

/// The port surface's event tap: read the socket facts at the pinned
/// offsets, keep only the port-surface transitions, publish the
/// 32-byte record with the changing process's pid.
///
/// Every aya-ebpf call inside is an `unsafe fn` (ctx reads, the
/// ktime and pid helpers) — the one unsafe block is that API
/// contract, nothing more: every read is probe-read (a bad offset
/// returns an error, never a fault) and the verifier re-proves the
/// whole body at load time.
#[tracepoint(name = "inet_sock_set_state", category = "sock")]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    // The reads come first (an unread fact is dropped, never
    // guessed); the filter bounds the ring traffic before anything
    // else happens.
    let event = unsafe {
        let skaddr: u64 = match ctx.read_at::<u64>(ctx_offsets::SKADDR) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let oldstate: i32 = match ctx.read_at::<i32>(ctx_offsets::OLDSTATE) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let newstate: i32 = match ctx.read_at::<i32>(ctx_offsets::NEWSTATE) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let sport: u16 = match ctx.read_at::<u16>(ctx_offsets::SPORT) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let dport: u16 = match ctx.read_at::<u16>(ctx_offsets::DPORT) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let family: u16 = match ctx.read_at::<u16>(ctx_offsets::FAMILY) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let protocol: u16 = match ctx.read_at::<u16>(ctx_offsets::PROTOCOL) {
            Ok(value) => value,
            Err(_) => return 0,
        };

        let oldstate = oldstate as u8;
        let newstate = newstate as u8;
        let protocol = protocol as u8;

        if !is_port_surface_event(family, protocol, oldstate, newstate) {
            return 0;
        }

        SockEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            skaddr,
            family,
            protocol,
            oldstate,
            newstate,
            sport,
            dport,
            // The tgid half: the process (thread group) whose
            // syscall made the change — the /proc snapshot cannot
            // see this, only the record can.
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        }
    };

    // Publish to the ring. The size assert inside output() is the
    // compile-time layout pin (SOCK_EVENT_BYTES == 32, align 8 — the
    // const is imported so both sides carry the same number); a
    // failed reservation (buffer full) drops the event silently — a
    // passive tracepoint never fails, and the ring's own rolling
    // window keeps the newest history.
    let _ = sock_events.output::<SockEvent>(&event, 0);

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
