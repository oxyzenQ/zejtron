// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The socket-event record - the layout contract between the BPF
//! program and the userspace reader (night-improve-2, the zylaxion
//! args.rs single-sourcing discipline: the userspace crate owns this
//! file so its layout tests run in the gate lanes, and
//! ebpf/src/main.rs compiles the very same bytes via #[path] - one
//! struct, one truth, no drift between the kernel side that writes
//! the record and the host side that reads it).
//!
//! The layout is `repr(C)` natural alignment, and the field order is
//! chosen so the record holds every field in exactly 32 bytes: the
//! two u64s first (timestamp, socket address), then the narrowing
//! scalars, the pid last. Three pad bytes ride inside (offsets 21 and
//! 26..27); `core::mem::offset_of!` pins every offset in
//! test/ebpf/ringbuf_tests.rs so a field reorder cannot slip through
//! silently. The 32-byte size is the ring-buffer record size both
//! sides agree on - the kernel side's `output` call and the host
//! side's record-length check both carry it.
//!
//! Everything in this module is plain `core` Rust (no_std, no aya) so
//! the same bytes compile into the bpfel-unknown-none object and into
//! the host binary.

/// IPPROTO_TCP, the protocol number in the tracepoint record.
pub const IPPROTO_TCP: u8 = 6;

/// IPPROTO_UDP, the protocol number in the tracepoint record.
pub const IPPROTO_UDP: u8 = 17;

/// TCP_LISTEN from include/net/tcp_states.h - the state a TCP socket
/// enters when it starts accepting, and the state whose loss this
/// surface reports.
pub const TCP_LISTEN: u8 = 10;

/// TCP_CLOSE from include/net/tcp_states.h - for a UDP socket (whose
/// state is CLOSE for its whole bound life) the CLOSE transition is
/// the interesting one: the socket stopped existing.
pub const TCP_CLOSE: u8 = 7;

/// AF_INET - the IPv4 address family.
pub const AF_INET: u16 = 2;

/// AF_INET6 - the IPv6 address family.
pub const AF_INET6: u16 = 10;

/// One socket state change, as the kernel saw it at the moment it
/// happened: what the tracepoint recorded, not what a later snapshot
/// could infer. `timestamp_ns` is CLOCK_MONOTONIC
/// (`bpf_ktime_get_ns`) - the same clock the window arithmetic uses.
///
/// Offsets (repr(C), natural alignment, pinned by test):
/// timestamp_ns 0, skaddr 8, family 16, protocol 18, oldstate 19,
/// newstate 20, sport 22, dport 24, pid 28; total 32 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockEvent {
    /// CLOCK_MONOTONIC nanoseconds at the state change.
    pub timestamp_ns: u64,
    /// The socket's kernel address - the identity that ties repeated
    /// transitions of one socket together across the window.
    pub skaddr: u64,
    /// AF_INET (2) or AF_INET6 (10).
    pub family: u16,
    /// IPPROTO_TCP (6) or IPPROTO_UDP (17).
    pub protocol: u8,
    /// The state before the transition (tcp_states.h numbering).
    pub oldstate: u8,
    /// The state after the transition (tcp_states.h numbering).
    pub newstate: u8,
    /// The local (source) port, host byte order - the tracepoint
    /// already applied ntohs.
    pub sport: u16,
    /// The remote (destination) port, host byte order.
    pub dport: u16,
    /// The pid of the process whose syscall made the change (the
    /// tgid half of bpf_get_current_pid_tgid) - the truth the /proc
    /// snapshot cannot see: who changed it, not who holds it now.
    pub pid: u32,
}

/// The size of one ring-buffer record, in bytes - the number both the
/// kernel side's `output` call and the host side's record-length
/// check agree on.
pub const SOCK_EVENT_BYTES: usize = core::mem::size_of::<SockEvent>();

/// The port-surface filter, shared verbatim by the BPF program (the
/// in-kernel bound on ring traffic) and the host tests (the pinned
/// mirror). A busy host fires thousands of ESTABLISHED transitions
/// per second that no `port` user cares about; only LISTEN
/// enter/leave (TCP) and socket death (UDP) cross the ring:
///
/// - TCP: the transition INTO LISTEN (newstate == TCP_LISTEN) and
///   the transition OUT OF LISTEN (oldstate == TCP_LISTEN, any
///   other newstate);
/// - UDP: the transition to CLOSE (newstate == TCP_CLOSE) - a UDP
///   socket exists whenever bound, so its close is the change;
/// - every other protocol, and every non-INET family, is dropped.
///
/// This file carries ONLY what both sides share - the record and the
/// filter. The row-rendering helpers (the transition label, the
/// protocol+family token) live with the port surface, where they are
/// used; the BPF crate compiles this file and would flag them dead.
pub fn is_port_surface_event(family: u16, protocol: u8, oldstate: u8, newstate: u8) -> bool {
    if !matches!(family, AF_INET | AF_INET6) {
        return false;
    }
    match protocol {
        IPPROTO_TCP => newstate == TCP_LISTEN || oldstate == TCP_LISTEN,
        IPPROTO_UDP => newstate == TCP_CLOSE,
        _ => false,
    }
}
