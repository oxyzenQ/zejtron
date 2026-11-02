// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
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
        AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, ProcExitEvent, SockEvent, TCP_CLOSE,
        TCP_LISTEN,
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
        let section = format_event_section(&events, Duration::from_secs(60), false, None);

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
        let section = format_event_section(&[], Duration::from_secs(300), false, None);
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
        let section = format_event_section(&events, Duration::from_secs(60), true, None);
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

    /// One synthetic exit record: the comm rides as the kernel's
    /// bpf_get_current_comm would have written it, NUL-padded (the
    /// lane_tests fixture shape, local so both suites stay hermetic).
    fn exit_at(timestamp_ns: u64, pid: u32, comm: &str) -> ProcExitEvent {
        let mut bytes = [0u8; 16];
        bytes[..comm.len()].copy_from_slice(comm.as_bytes());
        ProcExitEvent {
            timestamp_ns,
            pid,
            _pad: 0,
            comm: bytes,
        }
    }

    fn dead_left_listen(pid: u32, event_ts: u64) -> SockEvent {
        let mut event = live_event(pid, 9999, IPPROTO_TCP, AF_INET, TCP_LISTEN, TCP_CLOSE);
        event.timestamp_ns = event_ts;
        event
    }

    #[test]
    fn a_left_listen_with_a_teardown_lag_exit_is_observed_with_the_note() {
        // The residual's first branch: the process died 87ms before
        // its socket's teardown recorded - the strict rule refuses
        // (the exit is BEFORE the event), the bounded lag fallback
        // names it, and the row rides [observed] with the measured
        // lag and the recorded actor.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 87_000_000, 4242, "shortlisten")];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&exits),
        );
        let row = section.lines().nth(1).unwrap();
        assert!(row.starts_with("[observed]  "), "the weaker tier: {row}");
        assert!(row.contains("TCP4  *:9999  LEFT LISTEN"), "{row}");
        assert!(row.contains("PID 4242"), "{row}");
        assert!(row.contains("(shortlisten)"), "{row}");
        assert!(
            row.contains(
                "attribution from post-mortem exit ring (socket teardown lag: exit fired 87ms before LEFT LISTEN)"
            ),
            "{row}"
        );
        // The unaccounted block carries zero: the event IS accounted.
        assert!(section.contains("0 events in the window"), "{section}");
        assert!(
            !section.contains("race window by kernel ordering"),
            "{section}"
        );
    }

    #[test]
    fn a_sub_millisecond_lag_reads_under_1ms() {
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 400_000, 4242, "fast")];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&exits),
        );
        assert!(
            section
                .lines()
                .nth(1)
                .unwrap()
                .contains("exit fired under 1ms before LEFT LISTEN"),
            "{section}"
        );
    }

    #[test]
    fn a_left_listen_the_ring_cannot_name_rides_the_race_note() {
        // The residual's second branch: no exit record names the
        // event at all - no invented actor, the race note says the
        // kernel's ordering plainly, and the count stays honest.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&[]),
        );
        let note = section
            .lines()
            .find(|l| l.contains("[unaccounted]") && l.contains("LEFT LISTEN"))
            .expect("the race note row: {section}");
        assert!(
            note.contains("no matching exit event (process exited before teardown; race window by kernel ordering)"),
            "{note}"
        );
        assert!(note.contains("TCP4  *:9999"), "{note}");
        // The count still counts it - one miss, named and counted.
        assert!(section.contains("  1 events in the window"), "{section}");
        // No [observed] row was invented.
        assert!(!section.contains("[observed]"), "{section}");
    }

    #[test]
    fn an_exit_beyond_the_envelope_is_a_prior_life_not_the_actor() {
        // 400ms before: outside the bounded envelope, the record is
        // a recycled pid's prior life again - the race note, not a
        // fabricated attribution.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 400_000_000, 4242, "oldlife")];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&exits),
        );
        assert!(!section.contains("[observed]"), "{section}");
        assert!(
            section.contains("race window by kernel ordering"),
            "{section}"
        );
    }

    #[test]
    fn the_teardown_lag_branch_belongs_to_left_listen_alone() {
        // The relaxation is LEFT LISTEN's alone: an ENTERED LISTEN
        // (and every other transition) keeps the strict at-or-after
        // rule - an exit stamped before the event stays unaccounted,
        // never [observed].
        let event_ts = 10_000_000_000;
        let mut entered = live_event(4242, 9999, IPPROTO_TCP, AF_INET, TCP_CLOSE, TCP_LISTEN);
        entered.timestamp_ns = event_ts;
        let events = vec![entered];
        let exits = vec![exit_at(event_ts - 87_000_000, 4242, "eager")];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&exits),
        );
        assert!(!section.contains("[observed]"), "{section}");
        assert!(section.contains("  1 events in the window"), "{section}");
    }

    #[test]
    fn an_exit_after_the_left_listen_stays_the_plain_event_row() {
        // The strict rule still owns the at-or-after case: the row
        // rides [event] (the strongest tier), no lag note - the lag
        // fallback never hijacks what night-improve-61 already
        // attributes.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts + 3_000_000, 4242, "slowclose")];
        let section = format_event_section_with_exits(
            &events,
            Duration::from_secs(30),
            false,
            None,
            Some(&exits),
        );
        let row = section.lines().nth(1).unwrap();
        assert!(row.starts_with("[event]  "), "{row}");
        assert!(!row.contains("[observed]"), "{row}");
        assert!(!section.contains("teardown lag"), "{section}");
        assert!(row.contains("(slowclose)"), "{row}");
    }

    #[test]
    fn the_header_names_the_window_it_describes() {
        // The one-shot window semantics residual: two sequential runs
        // watch two different windows, and the header says WHICH one
        // this section describes. The bounds are fixture stamps (the
        // capture's own shape: the wait runs the window long, the
        // drain costs the overhead); the rendered times ride the live
        // wall offset, so the pins are structural and arithmetic,
        // never by wall-clock value.
        let start = 30_000_123_456_789;
        let bounds = Some((start, start + 5 * 1_000_000_000 + 137_000_000));
        let section = format_event_section(&[], Duration::from_secs(5), false, bounds);
        let header = section.lines().next().unwrap();
        assert!(header.contains("Changes in the last 5s ("), "{header}");
        assert!(header.ends_with("):"), "{header}");
        // The range token: two HH:MM:SS UTC stamps around the arrow.
        let open = header.find('(').unwrap();
        let range = &header[open + 1..header.len() - 2];
        let stamps: Vec<&str> = range.split(" \u{2192} ").collect();
        assert_eq!(stamps.len(), 2, "start then end: {header}");
        let sod = |stamp: &str| -> u64 {
            let bare = stamp
                .strip_suffix(" UTC")
                .unwrap_or_else(|| panic!("HH:MM:SS UTC: {stamp}"));
            assert_eq!(bare.len(), 8, "HH:MM:SS: {bare}");
            assert_eq!(&bare[2..3], ":", "{bare}");
            assert_eq!(&bare[5..6], ":", "{bare}");
            let p: Vec<u64> = bare.split(':').map(|x| x.parse().unwrap()).collect();
            p[0] * 3600 + p[1] * 60 + p[2]
        };
        for stamp in &stamps {
            sod(stamp);
        }
        // The span pin: end - start ~= the 5s window (the tolerance
        // covers the fixture's own collection overhead and the
        // per-endpoint whole-second truncation; the wrap keeps a
        // midnight-crossing window honest).
        let span = (sod(stamps[1]) + 86_400 - sod(stamps[0])) % 86_400;
        assert!((4..=7).contains(&span), "end - start ~= 5s: {span}");
        // The empty line carries the same range - an empty window
        // still names itself.
        let empty = section.lines().nth(1).unwrap();
        assert!(empty.contains("(no events in the window: "), "{empty}");
        assert!(empty.ends_with(')'), "{empty}");
        assert!(empty.contains(" \u{2192} "), "{empty}");
    }

    #[test]
    fn the_header_without_bounds_keeps_the_locked_shape() {
        // No bounds (a failed clock read, or a caller without the
        // capture's stamps): the locked range-less shapes ride
        // unchanged - the honest absence, never a guessed boundary.
        let section = format_event_section(&[], Duration::from_secs(5), false, None);
        assert!(
            section.contains("Changes in the last 5s:\n  (no events in the window)"),
            "{section}"
        );
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
