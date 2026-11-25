// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
// zejtron eBPF probe, the socket-state program (night-frontier-Z1
// moved here from main.rs - a PURE move under the 600-LOC no-mercy
// cap, the exits.rs/write.rs/unlink.rs precedent: a dedicated module
// beside the other programs, same crate, same single-sourced record
// contract, same license law). The probe itself is phase 2,
// untouched: the port surface's event camera, publishing the SockEvent
// with the changer's pid and (night-frontier-Z8, D5) the changer's
// identity block, its kernel-side filter the in-kernel bound on ring
// traffic.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

use super::count_ring_drop;
use crate::events::{DROP_SLOT_SOCK, SockEvent, is_port_surface_event};

// The compile-time layout pin on the BPF side: the sock record the
// ring carries is exactly 64 bytes (night-frontier-Z8, D5: the
// identity block rides the appended tail; the legacy head never
// renumbers), asserted where the output() call lives (the align-8
// discipline).
const _: () = assert!(SOCK_EVENT_BYTES == 64);

use crate::events::SOCK_EVENT_BYTES;

/// The sock_events ring buffer: 256 KiB, kept at its size through D5
/// (the conscious re-pin raised only the file ring - this surface's
/// filter bounds it to LISTEN enter/leave and UDP close, transitions
/// too rare to need the memory). The record is 64 bytes since D5, so
/// aya's ring accounting (the 8-byte length header, the page
/// framing) gives 3640 held records at the 72-byte stride - the
/// rolling-window shape unchanged, minutes of port-churn history on
/// any host short of a port-churn benchmark; when it does fill, the
/// oldest records are overwritten in the kernel (a ring buffer's own
/// rolling window) and a failed reservation drops the event without
/// failing the tracepoint.
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

/// The port surface's event probe: read the socket facts at the pinned
/// offsets, keep only the port-surface transitions, publish the
/// 64-byte record with the changing process's pid and its identity
/// block (night-frontier-Z8, D5: cgroup id, comm, netns inode).
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
    // SAFETY: every read inside is aya's ctx.read_at probe-read at a
    // compile-time-constant context offset - a bad offset returns
    // Err, never a fault - and the verifier re-proves the whole body
    // at load time (the module doc's contract, this comment is the
    // lint-facing form).
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

        // The identity block (night-frontier-Z8, D5): the changer's
        // cgroup id, comm, and netns inode ride the record, so the
        // row answers "who changed it, and from where" without a
        // cross-lookup. The sock probe's core path reads no offsets
        // map, so the netns walk rides whatever the map holds THIS
        // read: None keeps cgroup+comm (helpers) and leaves the
        // netns zero - the named unavailability, never a guessed
        // namespace number. A zero-cost refusal class: the record's
        // core facts (the transition) never depend on the identity
        // aid.
        let actor = super::identity::actor_identity(super::read_offset_set().as_ref());

        SockEvent {
            timestamp_ns: bpf_ktime_get_ns(),
            skaddr,
            family,
            protocol,
            oldstate,
            newstate,
            // The explicit pads, zeroed: the ring record's every
            // byte is written before output() reads it — the 5.15
            // verifier (the floor kernel) refuses an output read
            // that touches a never-written stack byte, exactly the
            // refusal the kernel-floor micro-VM lane caught live.
            _pad: 0,
            sport,
            dport,
            _pad2: 0,
            // The tgid half: the process (thread group) whose
            // syscall made the change — the /proc snapshot cannot
            // see this, only the record can.
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            cgroup_id: actor.cgroup_id,
            comm: actor.comm,
            netns_inum: actor.netns_inum,
            _pad3: 0,
        }
    };

    // Publish to the ring. The size assert inside output() is the
    // compile-time layout pin (SOCK_EVENT_BYTES == 64, align 8 — the
    // const is imported so both sides carry the same number); a
    // failed reservation (buffer full) drops the event without
    // failing the tracepoint - a passive tracepoint never fails, and
    // the ring's own rolling window keeps the newest history. And the
    // drop is not silent any more (night-frontier-Z1): the failure
    // bumps the drop_census slot, so the drain that renders this
    // ring's rows names how many the camera saw but could not hold.
    if sock_events.output::<SockEvent>(&event, 0).is_err() {
        count_ring_drop(DROP_SLOT_SOCK);
    }

    0
}
