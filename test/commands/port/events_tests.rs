// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The event-row rendering pins (split from window_tests.rs with the
//! events.rs seam, the 600-LOC cap discipline): the transition and
//! protocol labels, the row shape (provenance tag, attribution, the
//! --no-pid token), the empty window's honesty, and the UDP-only
//! kernel-truth note. The grammar, capture, and snapshot pins stay
//! in window_tests.rs. Wired from src/commands/port/events.rs.

use super::*;

#[cfg(test)]
mod fixture {
    use crate::commands::port::model::PortOptions;
    use crate::commands::port::window::WINDOW_DEFAULT;

    pub fn options() -> PortOptions {
        PortOptions {
            port: None,
            tcp: false,
            udp: false,
            listen: false,
            all: false,
            numeric: false,
            group: false,
            no_pid: false,
            window: WINDOW_DEFAULT,
            events_only: false,
            snapshot_only: false,
        }
    }
}

mod live {
    use super::*;
    use crate::ebpf::events::{
        AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, SockEvent, TCP_CLOSE, TCP_LISTEN,
    };
    use std::time::Duration;

    pub(crate) fn live_event(
        pid: u32,
        sport: u16,
        protocol: u8,
        family: u16,
        oldstate: u8,
        newstate: u8,
    ) -> SockEvent {
        SockEvent {
            timestamp_ns: 0,
            skaddr: 0xffff_8880_0000_0000,
            family,
            protocol,
            oldstate,
            newstate,
            _pad: 0,
            sport,
            dport: 0,
            _pad2: 0,
            pid,
        }
    }

    fn self_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn transition_labels_name_the_three_truths() {
        assert_eq!(
            transition_label(IPPROTO_TCP, TCP_CLOSE, TCP_LISTEN),
            Some("ENTERED LISTEN")
        );
        assert_eq!(
            transition_label(IPPROTO_TCP, TCP_LISTEN, TCP_CLOSE),
            Some("LEFT LISTEN")
        );
        assert_eq!(
            transition_label(IPPROTO_UDP, TCP_CLOSE, TCP_CLOSE),
            Some("CLOSED")
        );
        assert_eq!(transition_label(IPPROTO_TCP, 2, 1), None); // ESTABLISHED churn
        assert_eq!(transition_label(132, TCP_CLOSE, TCP_CLOSE), None); // not TCP/UDP
    }

    #[test]
    fn protocol_tokens_carry_the_family() {
        assert_eq!(protocol_family_label(IPPROTO_TCP, AF_INET), Some("TCP4"));
        assert_eq!(protocol_family_label(IPPROTO_TCP, AF_INET6), Some("TCP6"));
        assert_eq!(protocol_family_label(IPPROTO_UDP, AF_INET), Some("UDP4"));
        assert_eq!(protocol_family_label(IPPROTO_UDP, AF_INET6), Some("UDP6"));
        assert_eq!(protocol_family_label(IPPROTO_TCP, 1), None); // AF_UNIX
    }

    #[test]
    fn event_rows_carry_provenance_and_attribution() {
        // One attributed event (this test process) and one whose pid
        // is gone: the row shape and the unaccounted count are the
        // contract. The time token rides the real clock - pinned
        // structurally (the " UTC " separator), never by value.
        let events = vec![
            live_event(
                self_pid(),
                8080,
                IPPROTO_TCP,
                AF_INET,
                TCP_CLOSE,
                TCP_LISTEN,
            ),
            live_event(
                999_999_999,
                5353,
                IPPROTO_UDP,
                AF_INET,
                TCP_CLOSE,
                TCP_CLOSE,
            ),
        ];
        let section = format_event_section(&events, Duration::from_secs(60), false);

        let lines: Vec<&str> = section.lines().collect();
        assert_eq!(lines[0], "Changes in the last 60s:");
        // header + row + blank + Unaccounted: + the two-line count +
        // the two-line disagreement note.
        assert_eq!(lines.len(), 8, "the section's shape: {section}");

        let row = lines[1];
        assert!(row.starts_with("[event]  "), "the provenance prefix: {row}");
        assert!(
            row.contains(" UTC  TCP4  *:8080  ENTERED LISTEN  PID "),
            "{row}"
        );
        assert!(row.contains(&format!("PID {}", self_pid())), "{row}");
        // The name comes from /proc/<pid>/status - this test binary.
        assert!(
            row.ends_with(&format!("({})", comm_of(self_pid()))),
            "{row}"
        );

        assert_eq!(lines[3], "Unaccounted:");
        assert!(lines[4].starts_with("  1 events in the window with no visible PID"));
        assert!(lines[4].contains("namespace boundary or"));
        assert!(lines[5].contains("exited before attribution"));
        assert!(lines[6].contains("Snapshot and event window can disagree"));
        assert!(lines[7].contains("snapshot is the state at this instant"));
    }

    fn comm_of(pid: u32) -> String {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find(|l| l.starts_with("Name:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    }

    #[test]
    fn empty_window_says_so_honestly() {
        let section = format_event_section(&[], Duration::from_secs(300), false);
        assert!(section.contains("Changes in the last 5m:"));
        assert!(section.contains("(no events in the window)"));
        assert!(section.contains("Unaccounted:"));
        assert!(section.contains("0 events in the window"));
    }

    #[test]
    fn no_pid_drops_the_pid_token_from_event_rows() {
        let events = vec![live_event(
            self_pid(),
            8080,
            IPPROTO_TCP,
            AF_INET,
            TCP_CLOSE,
            TCP_LISTEN,
        )];
        let section = format_event_section(&events, Duration::from_secs(60), true);
        // The PID token is dropped from the ROW - the unaccounted
        // block's prose still names the concept ("no visible PID"),
        // which is the point of the block.
        let row = section.lines().nth(1).unwrap();
        assert!(
            !row.contains("PID "),
            "the token is dropped, not the row: {row}"
        );
        assert!(row.contains("ENTERED LISTEN"), "{row}");
        assert!(row.contains("(zejtron") || row.ends_with(')'), "{row}");
    }
}

#[test]
fn udp_only_event_window_names_the_kernel_truth() {
    // night-improve-61, the micro-VM census: the sock probe's
    // tracepoint never fires for a UDP lifecycle, so a UDP-only
    // event window is empty by construction - and the note says so
    // instead of pretending the window listened and heard nothing.
    let mut udp_only = fixture::options();
    udp_only.udp = true;
    assert!(udp_events_only(&udp_only));

    let mut tcp_only = fixture::options();
    tcp_only.tcp = true;
    assert!(!udp_events_only(&tcp_only));

    let mut both = fixture::options();
    both.tcp = true;
    both.udp = true;
    assert!(!udp_events_only(&both));

    assert!(
        !udp_events_only(&fixture::options()),
        "the unfiltered window is not UDP-only"
    );

    assert_eq!(
        udp_event_lane_note(),
        "note: the kernel fires no lifecycle events for UDP sockets - this event lane is TCP-only; UDP sockets ride the snapshot"
    );
}
