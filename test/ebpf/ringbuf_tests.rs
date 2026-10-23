// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The sock_events ring reader pins. Lives under the single test/
//! tree (night-improve-18, the discipline contract) and is
//! #[path]-wired from src/ebpf/ringbuf.rs. What is pinned here is
//! the contract, not the host: the record layout both sides agree
//! on (32 bytes, every offset), the rolling window's bound, and the
//! port-surface filter the kernel program applies - the pure mirror
//! of the in-kernel predicate, pinned so a drift between the object
//! and the host side cannot slip through.

use super::*;
use crate::ebpf::events::{
    AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, PROCEXIT_EVENT_BYTES, ProcExitEvent,
    SOCK_EVENT_BYTES, SockEvent, TCP_CLOSE, TCP_LISTEN, is_port_surface_event,
};
use std::mem::offset_of;

fn event(timestamp_ns: u64, sport: u16, pid: u32) -> SockEvent {
    SockEvent {
        timestamp_ns,
        skaddr: 0xffff_8880_0000_0000,
        family: AF_INET,
        protocol: IPPROTO_TCP,
        oldstate: TCP_CLOSE,
        newstate: TCP_LISTEN,
        _pad: 0,
        sport,
        dport: 0,
        _pad2: 0,
        pid,
    }
}

#[test]
fn sock_event_is_exactly_32_bytes() {
    // The ring record size: the kernel side's output() call and the
    // host side's length check both carry this number. A field
    // reorder or a width change moves it - and the pinned offsets
    // below name exactly where it moved.
    assert_eq!(SOCK_EVENT_BYTES, 32);
    assert_eq!(std::mem::size_of::<SockEvent>(), 32);
    assert_eq!(std::mem::align_of::<SockEvent>(), 8);
}

#[test]
fn sock_event_offsets_are_pinned() {
    // repr(C) natural alignment: the two u64s first, the narrowing
    // scalars, the pid last; the pads are EXPLICIT fields (the
    // FileEvent discipline, the 5.15-verifier lesson: every byte of
    // the ring record is written, never left to implicit padding).
    assert_eq!(offset_of!(SockEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(SockEvent, skaddr), 8);
    assert_eq!(offset_of!(SockEvent, family), 16);
    assert_eq!(offset_of!(SockEvent, protocol), 18);
    assert_eq!(offset_of!(SockEvent, oldstate), 19);
    assert_eq!(offset_of!(SockEvent, newstate), 20);
    assert_eq!(offset_of!(SockEvent, _pad), 21);
    assert_eq!(offset_of!(SockEvent, sport), 22);
    assert_eq!(offset_of!(SockEvent, dport), 24);
    assert_eq!(offset_of!(SockEvent, _pad2), 26);
    assert_eq!(offset_of!(SockEvent, pid), 28);
}

#[test]
fn kernel_state_and_protocol_constants_match_the_kernel_numbering() {
    // include/net/tcp_states.h and the IPPROTO numbers - the values
    // the tracepoint record carries, pinned so a typo in the consts
    // cannot quietly invert the filter.
    assert_eq!(IPPROTO_TCP, 6);
    assert_eq!(IPPROTO_UDP, 17);
    assert_eq!(TCP_LISTEN, 10);
    assert_eq!(TCP_CLOSE, 7);
    assert_eq!(AF_INET, 2);
    assert_eq!(AF_INET6, 10);
}

#[test]
fn filter_keeps_listen_enter_and_leave_for_tcp() {
    // The transition INTO LISTEN (CLOSE -> LISTEN) and OUT OF it
    // (LISTEN -> CLOSE) are the two TCP truths the window reports.
    assert!(is_port_surface_event(
        AF_INET,
        IPPROTO_TCP,
        TCP_CLOSE,
        TCP_LISTEN
    ));
    assert!(is_port_surface_event(
        AF_INET,
        IPPROTO_TCP,
        TCP_LISTEN,
        TCP_CLOSE
    ));
    assert!(is_port_surface_event(
        AF_INET6,
        IPPROTO_TCP,
        TCP_CLOSE,
        TCP_LISTEN
    ));
}

#[test]
fn filter_drops_established_churn() {
    // The bound that makes the window cheap: SYN_SENT, ESTABLISHED,
    // CLOSE_WAIT, TIME_WAIT - none of it crosses the ring.
    let established = 1; // TCP_ESTABLISHED
    let syn_sent = 2; // TCP_SYN_SENT
    let close_wait = 8; // TCP_CLOSE_WAIT
    assert!(!is_port_surface_event(
        AF_INET,
        IPPROTO_TCP,
        syn_sent,
        established
    ));
    assert!(!is_port_surface_event(
        AF_INET,
        IPPROTO_TCP,
        established,
        close_wait
    ));
    assert!(!is_port_surface_event(
        AF_INET,
        IPPROTO_TCP,
        TCP_CLOSE,
        syn_sent
    ));
}

#[test]
fn filter_keeps_udp_close_only() {
    // A UDP socket exists whenever bound; its CLOSE is the change.
    assert!(is_port_surface_event(
        AF_INET,
        IPPROTO_UDP,
        TCP_CLOSE,
        TCP_CLOSE
    ));
    // A UDP "transition" to anything else is not a port-surface
    // truth (and does not happen on a real stack).
    assert!(!is_port_surface_event(
        AF_INET,
        IPPROTO_UDP,
        TCP_CLOSE,
        TCP_LISTEN
    ));
}

#[test]
fn filter_drops_non_inet_families_and_other_protocols() {
    // AF_UNIX (1) / AF_NETLINK (16) never ride this tracepoint; the
    // predicate refuses them anyway - defense in depth on both
    // sides of the ring.
    assert!(!is_port_surface_event(
        1,
        IPPROTO_TCP,
        TCP_CLOSE,
        TCP_LISTEN
    ));
    assert!(!is_port_surface_event(
        16,
        IPPROTO_UDP,
        TCP_CLOSE,
        TCP_CLOSE
    ));
    // A protocol that is neither TCP nor UDP is not this surface's
    // truth even on an INET socket.
    assert!(!is_port_surface_event(AF_INET, 132, TCP_CLOSE, TCP_CLOSE)); // SCTP
    assert!(!is_port_surface_event(AF_INET, 0, TCP_CLOSE, TCP_CLOSE));
}

#[test]
fn rolling_window_keeps_newest_and_drops_oldest() {
    // The synthetic mirror of the drain: fill past the cap, the
    // oldest die, the newest survive - the window is evidence-shaped
    // (recent), never log-shaped (complete).
    let cap = 4;
    let mut window: Vec<SockEvent> = Vec::new();
    for i in 0..6u64 {
        push_rolling(&mut window, event(i, 1000 + i as u16, 1), cap);
    }
    let sports: Vec<u16> = window.iter().map(|e| e.sport).collect();
    assert_eq!(sports, vec![1002, 1003, 1004, 1005]);
    assert!(window.len() <= cap);
}

#[test]
fn rolling_window_cap_matches_the_contract() {
    // 4096 entries: half the ring's 8192-record capacity - the
    // number the spec pinned, the number the drain honors.
    assert_eq!(ROLLING_CAP, 4096);
}

#[test]
fn rolling_window_never_grows_past_cap_one_at_a_time() {
    let mut window: Vec<SockEvent> = Vec::new();
    for i in 0..(ROLLING_CAP + 3) {
        push_rolling(&mut window, event(i as u64, 7, 1), ROLLING_CAP);
        assert!(window.len() <= ROLLING_CAP);
    }
    assert_eq!(window.len(), ROLLING_CAP);
    // The three oldest (0, 1, 2) were dropped; the newest is the
    // last push.
    assert_eq!(window[0].timestamp_ns, 3);
    assert_eq!(
        window.last().unwrap().timestamp_ns,
        (ROLLING_CAP + 2) as u64
    );
}

#[test]
fn drain_on_a_clean_host_reads_nothing() {
    // On a host with no attached chain the pin is absent and the
    // open names it - the honest diagnosis, not a generic failure.
    // (On a host WITH the chain attached this pin would race the
    // live ring, so it only asserts the clean-host shape.)
    if !std::path::Path::new(PIN_MAP_SOCK_EVENTS).exists() {
        // match, not expect_err: the Ok half (a live RingBuf) carries
        // no Debug, and the test only ever wants the refusal text.
        let err = match open_sock_ring() {
            Err(err) => err,
            Ok(_) => panic!("absent pin must not open"),
        };
        assert!(
            err.contains("sock_events"),
            "the error names the pin: {err}"
        );
    }
}

// ── The post-mortem exit record (night-improve-47) ────────────────

#[test]
fn proc_exit_event_is_exactly_32_bytes() {
    // The ring record size: the kernel side's output() call and the
    // host side's length check both carry this number - the same
    // pin the sock record carries, for the same reason.
    assert_eq!(PROCEXIT_EVENT_BYTES, 32);
    assert_eq!(std::mem::size_of::<ProcExitEvent>(), 32);
    assert_eq!(std::mem::align_of::<ProcExitEvent>(), 8);
}

#[test]
fn proc_exit_event_offsets_are_pinned() {
    // repr(C) natural alignment: the u64 first, the pid, the
    // explicit pad, the comm array last - every byte written by the
    // probe constructor (the 5.15-verifier lesson, the SockEvent
    // discipline).
    assert_eq!(offset_of!(ProcExitEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(ProcExitEvent, pid), 8);
    assert_eq!(offset_of!(ProcExitEvent, _pad), 12);
    assert_eq!(offset_of!(ProcExitEvent, comm), 16);
}

#[test]
fn proc_exit_drain_on_a_clean_host_names_the_pin() {
    // The post-mortem pump's clean-host refusal, mirroring the sock
    // reader's: an absent pin is a diagnosis that names itself.
    if !std::path::Path::new(PIN_MAP_PROC_EVENTS).exists() {
        let err = match drain_proc_exits() {
            Err(err) => err,
            Ok(_) => panic!("absent pin must not drain"),
        };
        assert!(
            err.contains("proc_events"),
            "the error names the pin: {err}"
        );
    }
}
