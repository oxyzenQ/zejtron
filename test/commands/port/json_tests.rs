// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The port surface's JSON lane pins (night-badass-9). Lives under
//! the single test/ tree and is #[path]-wired from
//! src/commands/port/json.rs. The schema is the contract: the two
//! truths (snapshot table, event window), the lane honesty (the
//! unavailable window names its reason, never a fabricated event
//! list), and the absence law (nulls, not empty strings).

use super::*;

use crate::commands::port::model::Protocol;
use crate::ebpf::events::{AF_INET, IPPROTO_TCP, IPPROTO_UDP, TCP_CLOSE, TCP_LISTEN};
use std::collections::HashMap;
use std::time::Duration;

fn options(snapshot_only: bool) -> PortOptions {
    PortOptions {
        port: Some(9999),
        tcp: false,
        udp: false,
        listen: false,
        all: false,
        numeric: false,
        group: false,
        no_pid: false,
        window: Duration::from_secs(60),
        events_only: false,
        snapshot_only,
    }
}

fn socket() -> SocketEntry {
    SocketEntry {
        protocol: Protocol::Tcp,
        address: "0.0.0.0".to_owned(),
        port: 9999,
        remote_address: "0.0.0.0".to_owned(),
        remote_port: 0,
        state: Some("LISTEN".to_owned()),
        inode: 42,
    }
}

fn owners() -> OwnerMap {
    HashMap::from([(
        42u64,
        vec![super::super::model::ProcessInfo {
            pid: 2829,
            name: "python3".to_owned(),
            user: "root".to_owned(),
            cwd: None,
            cmdline: None,
            fd: Some(3),
        }],
    )])
}

fn live_event(pid: u32, oldstate: u8, newstate: u8) -> SockEvent {
    SockEvent {
        timestamp_ns: 0,
        skaddr: 0xffff_8880_0000_0000,
        family: AF_INET,
        protocol: IPPROTO_TCP,
        oldstate,
        newstate,
        _pad: 0,
        sport: 9999,
        dport: 0,
        _pad2: 0,
        pid,
    }
}

fn live_udp_event(pid: u32) -> SockEvent {
    SockEvent {
        protocol: IPPROTO_UDP,
        ..live_event(pid, TCP_CLOSE, TCP_CLOSE)
    }
}

#[test]
fn json_snapshot_shape_pins_the_two_truths() {
    let stats = ScanStats::default();
    let opts = options(true);
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None);
    // The subject pins the asked port; the mode is the honest
    // snapshot; the ports array carries the owner typed.
    assert!(out.starts_with("{\"subject\":\":9999\""));
    assert!(out.contains("\"mode\":\"snapshot\""));
    assert!(out.contains("\"window\":\"60s\""));
    assert!(out.contains(
        "\"ports\":[{\"protocol\":\"tcp\",\"local_addr\":\"0.0.0.0:9999\",\"state\":\"LISTEN\""
    ));
    assert!(out.contains("\"owners\":[{\"pid\":2829,\"process\":\"python3\",\"user\":\"root\"}]"));
    // The snapshot-only escape hatch names its own reason.
    assert!(out.contains("\"changes\":{\"available\":false,\"reason\":\"snapshot-only\""));
    assert!(out.contains("\"events\":[]"));
    assert!(out.contains("\"scan\":{\"unreadable_processes\":0,\"unreadable_fds\":0}"));
    assert!(!out.contains('\n'));
}

#[test]
fn json_snapshot_without_a_port_filter_has_a_null_subject() {
    let stats = ScanStats::default();
    let mut opts = options(true);
    opts.port = None;
    let out = super::port_report_json(&[], &HashMap::new(), &stats, &opts, None);
    assert!(out.starts_with("{\"subject\":null"));
}

#[test]
fn json_live_shape_carries_the_event_kinds() {
    let stats = ScanStats::default();
    let opts = options(false);
    let events = vec![
        live_event(std::process::id(), TCP_CLOSE, TCP_LISTEN),
        // The UDP closed transition: the third truth the window
        // grammar names.
        live_udp_event(std::process::id()),
        // A pid the kernel no longer shows: the unaccounted gap.
        live_event(4_000_000, TCP_CLOSE, TCP_LISTEN),
    ];
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, Some(&events));
    assert!(out.contains("\"mode\":\"live\""));
    assert!(out.contains("\"changes\":{\"available\":true,\"reason\":null"));
    // The transition vocabulary, as the jq-friendly kind tokens.
    assert!(out.contains("\"kind\":\"listened\""));
    assert!(out.contains("\"kind\":\"closed\""));
    assert!(out.contains("\"protocol\":\"tcp4\""));
    assert!(out.contains("\"protocol\":\"udp4\""));
    assert!(out.contains("\"port\":9999"));
    assert!(out.contains("\"unaccounted\":1"));
}

#[test]
fn json_lane_absence_names_the_reason_not_a_fake_window() {
    let stats = ScanStats::default();
    let opts = options(false);
    // The default shape with no captured window: the same snapshot
    // honesty as --snapshot-only, with the lane's own reason.
    let out = super::port_report_json(&[socket()], &owners(), &stats, &opts, None);
    assert!(out.contains("\"mode\":\"snapshot\""));
    assert!(out.contains("\"changes\":{\"available\":false,\"reason\":\"lane-not-attached\""));
}

/// The post-mortem parity pins (the night-dragon-lts-T1 JSON-lane
/// residual): the SAME synthetic event + exit-ring fixture through
/// BOTH renderers - the text section (format_event_section_with_exits)
/// and the JSON lane (port_report_json_with_exits, the exact string
/// `--print-json` prints) - asserting the two formats tell one
/// story. Hermetic by construction: the fixtures are synthetic, the
/// exit slice is injected through the seam forms, no kernel, no VM.
mod post_mortem {
    use super::*;
    use crate::commands::port::events::{LEFT_LISTEN_RACE_NOTE, format_event_section_with_exits};

    /// One synthetic exit record: the comm rides as the kernel's
    /// bpf_get_current_comm would have written it, NUL-padded (the
    /// events_tests fixture shape, local so both suites stay
    /// hermetic).
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

    /// A LEFT LISTEN recorded after its process is gone from /proc -
    /// the post-mortem candidate both lanes must agree on.
    fn dead_left_listen(pid: u32, event_ts: u64) -> SockEvent {
        let mut event = live_event(pid, TCP_LISTEN, TCP_CLOSE);
        event.timestamp_ns = event_ts;
        event
    }

    /// An ENTERED LISTEN for the same dead pid - the transition the
    /// teardown-lag envelope does NOT cover (strict rule only).
    fn dead_entered_listen(pid: u32, event_ts: u64) -> SockEvent {
        let mut event = live_event(pid, TCP_CLOSE, TCP_LISTEN);
        event.timestamp_ns = event_ts;
        event
    }

    fn both_formats(events: &[SockEvent], exits: &[ProcExitEvent]) -> (String, String) {
        let text =
            format_event_section_with_exits(events, Duration::from_secs(60), false, Some(exits));
        let stats = ScanStats::default();
        let opts = options(false);
        let json = super::super::port_report_json_with_exits(
            &[],
            &HashMap::new(),
            &stats,
            &opts,
            Some(events),
            Some(exits),
        );
        (text, json)
    }

    /// The hand parser (the lane writes JSON by hand; the pins parse
    /// it the same way - there is no serde in the tree): the value
    /// token of `key` inside one flat row object, quotes included
    /// for strings, bare for integers. `None` is the absence pin.
    fn json_value_token<'a>(row: &'a str, key: &str) -> Option<&'a str> {
        let marker = format!("\"{key}\":");
        let start = row.find(&marker)? + marker.len();
        let rest = &row[start..];
        let end = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.find('"')? + 2
        } else {
            rest.find([',', '}']).unwrap_or(rest.len())
        };
        Some(&rest[..end])
    }

    /// One flat event row from the full report, found by a marker
    /// and cut at its closing brace (event rows carry no nested
    /// objects, so the first brace ends the row).
    fn json_row(out: &str, marker: &str) -> String {
        let start = out
            .find(marker)
            .unwrap_or_else(|| panic!("the row {marker} exists in the report: {out}"));
        let rest = &out[start..];
        let end = rest.find('}').expect("flat rows end with }");
        rest[..=end].to_owned()
    }

    #[test]
    fn parity_when_the_teardown_lag_names_the_actor() {
        // The residual's first branch in both formats at once: the
        // process died 87ms before its socket's teardown recorded.
        // Text renders [observed] with the measured lag; JSON
        // renders attribution "post-mortem" with lag_ms 87 - and
        // the JSON number is pinned to the TEXT figure, not to a
        // private constant.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 87_000_000, 4242, "shortlisten")];
        let (text, json) = both_formats(&events, &exits);

        assert!(text.contains("[observed]"), "{text}");
        assert!(
            text.contains(
                "attribution from post-mortem exit ring (socket teardown lag: \
                 exit fired 87ms before LEFT LISTEN)"
            ),
            "{text}"
        );
        assert!(text.contains("(shortlisten)"), "{text}");
        assert!(text.contains("0 events in the window"), "{text}");

        let row = json_row(&json, "\"kind\":\"left-listen\"");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"post-mortem\""),
            "{row}"
        );
        assert_eq!(
            json_value_token(&row, "process"),
            Some("\"shortlisten\""),
            "{row}"
        );
        assert_eq!(json_value_token(&row, "pid"), Some("4242"), "{row}");
        // The parity cross-pin: the lag figure in JSON IS the figure
        // the text note renders.
        let lag_token = json_value_token(&row, "lag_ms").expect("the lag field rides the row");
        assert!(!lag_token.starts_with('"'), "lag_ms is an integer: {row}");
        let lag_ms: u64 = lag_token.parse().expect("integer lag_ms");
        assert_eq!(lag_ms, 87);
        assert!(
            text.contains(&format!("exit fired {lag_ms}ms before LEFT LISTEN")),
            "the text figure matches the JSON integer: {text}"
        );
        assert!(json.contains("\"unaccounted\":0"), "{json}");
        assert!(!row.contains("race_note"), "{row}");
    }

    #[test]
    fn parity_when_the_ring_cannot_name_the_actor() {
        // The residual's second branch in both formats: no exit
        // record names the event - the text renders the race note,
        // the JSON carries the same words typed as `race_note`,
        // byte-identical (parsed out of the JSON and matched
        // against the text note's own prose).
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let (text, json) = both_formats(&events, &[]);

        assert!(
            text.contains(&format!("LEFT LISTEN — {LEFT_LISTEN_RACE_NOTE}")),
            "{text}"
        );
        assert!(text.contains("  1 events in the window"), "{text}");
        assert!(!text.contains("[observed]"), "{text}");

        let row = json_row(&json, "\"kind\":\"left-listen\"");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"unaccounted\""),
            "{row}"
        );
        assert_eq!(json_value_token(&row, "process"), Some("null"), "{row}");
        let note = json_value_token(&row, "race_note").expect("the race note rides the row");
        // Byte-identical to the text lane's note (and to the shared
        // constant both formats speak).
        assert_eq!(
            note.trim_matches('"'),
            LEFT_LISTEN_RACE_NOTE,
            "the JSON note is the text note's own words: {row}"
        );
        assert!(text.contains(note.trim_matches('"')), "{text}");
        assert!(json.contains("\"unaccounted\":1"), "{json}");
        assert!(!row.contains("lag_ms"), "{row}");
    }

    #[test]
    fn parity_when_the_strict_rule_names_the_actor() {
        // The at-or-after branch in both formats: the exit landed
        // after the event - the strongest tier, [event] in text,
        // attribution "post-mortem" with NO lag_ms in JSON (the lag
        // note is the teardown branch's alone, never this one's).
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts + 3_000_000, 4242, "slowclose")];
        let (text, json) = both_formats(&events, &exits);

        assert!(text.contains("[event]"), "{text}");
        assert!(text.contains("(slowclose)"), "{text}");
        assert!(!text.contains("teardown lag"), "{text}");

        let row = json_row(&json, "\"kind\":\"left-listen\"");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"post-mortem\""),
            "{row}"
        );
        assert_eq!(
            json_value_token(&row, "process"),
            Some("\"slowclose\""),
            "{row}"
        );
        assert_eq!(json_value_token(&row, "lag_ms"), None, "{row}");
        assert_eq!(json_value_token(&row, "race_note"), None, "{row}");
        assert!(json.contains("\"unaccounted\":0"), "{json}");
    }

    #[test]
    fn json_teardown_lag_belongs_to_left_listen_alone() {
        // The envelope is LEFT LISTEN's alone in JSON, as in text:
        // an ENTERED LISTEN whose actor died 87ms before the event
        // stays unaccounted - the race note's teardown story would
        // not fit it, so no note rides the row.
        let event_ts = 10_000_000_000;
        let events = vec![dead_entered_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 87_000_000, 4242, "eager")];
        let (_, json) = both_formats(&events, &exits);

        let row = json_row(&json, "\"kind\":\"listened\"");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"unaccounted\""),
            "{row}"
        );
        assert_eq!(json_value_token(&row, "race_note"), None, "{row}");
        assert!(!json.contains("post-mortem"), "{json}");
        assert!(json.contains("\"unaccounted\":1"), "{json}");
    }

    #[test]
    fn json_beyond_the_envelope_is_unaccounted_in_both_formats() {
        // 400ms before: outside the bounded envelope - a recycled
        // pid's prior life, not the actor. Both formats refuse to
        // attribute: the race note in text, the typed verdict in
        // JSON.
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 400_000_000, 4242, "oldlife")];
        let (text, json) = both_formats(&events, &exits);

        assert!(!text.contains("[observed]"), "{text}");
        assert!(text.contains("race window by kernel ordering"), "{text}");
        let row = json_row(&json, "\"kind\":\"left-listen\"");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"unaccounted\""),
            "{row}"
        );
        assert_eq!(
            json_value_token(&row, "race_note"),
            Some(&*format!("\"{LEFT_LISTEN_RACE_NOTE}\"")),
            "{row}"
        );
        assert!(json.contains("\"unaccounted\":1"), "{json}");
    }

    #[test]
    fn json_sub_millisecond_lag_reads_zero_and_text_reads_under_1ms() {
        // The false-precision law, typed: 400 microseconds of lag is
        // "under 1ms" in the text note and the integer 0 in JSON -
        // the number without decimals, both formats from the same
        // arithmetic (lag_whole_ms).
        let event_ts = 10_000_000_000;
        let events = vec![dead_left_listen(4242, event_ts)];
        let exits = vec![exit_at(event_ts - 400_000, 4242, "fast")];
        let (text, json) = both_formats(&events, &exits);

        assert!(
            text.contains("exit fired under 1ms before LEFT LISTEN"),
            "{text}"
        );
        let row = json_row(&json, "\"kind\":\"left-listen\"");
        assert_eq!(json_value_token(&row, "lag_ms"), Some("0"), "{row}");
        assert_eq!(
            json_value_token(&row, "attribution"),
            Some("\"post-mortem\""),
            "{row}"
        );
    }

    #[test]
    fn json_clean_rows_stay_clean() {
        // The clean contract: a row the /proc read names live never
        // grows an attribution field - its absence IS the "not a
        // post-mortem case" verdict, and no field of the post-mortem
        // vocabulary may leak onto it.
        let events = vec![live_event(std::process::id(), TCP_CLOSE, TCP_LISTEN)];
        let (_, json) = both_formats(&events, &[]);

        assert!(!json.contains("\"attribution\""), "{json}");
        assert!(!json.contains("\"lag_ms\""), "{json}");
        assert!(!json.contains("\"race_note\""), "{json}");
        assert!(json.contains("\"unaccounted\":0"), "{json}");
    }

    #[test]
    fn json_post_mortem_schema_types_are_pinned() {
        // The schema pin over one parsed --print-json line: a
        // post-mortem row carries attribution as a string and lag_ms
        // as a bare integer; an unaccounted row carries attribution
        // and race_note as strings; the fields are absent where the
        // field laws say absent.
        let event_ts = 10_000_000_000;
        let lag_events = vec![dead_left_listen(4242, event_ts)];
        let lag_exits = vec![exit_at(event_ts - 87_000_000, 4242, "shortlisten")];
        let (_, json) = both_formats(&lag_events, &lag_exits);
        let lag_row = json_row(&json, "\"kind\":\"left-listen\"");
        for key in ["kind", "protocol", "attribution"] {
            let token = json_value_token(&lag_row, key).unwrap_or_else(|| panic!("{key} present"));
            assert!(
                token.starts_with('"') && token.ends_with('"'),
                "{key} is a JSON string: {lag_row}"
            );
        }
        let token = json_value_token(&lag_row, "lag_ms").expect("lag_ms present");
        assert!(
            !token.starts_with('"') && token.parse::<u64>().is_ok(),
            "lag_ms is a bare JSON integer: {lag_row}"
        );
        assert_eq!(json_value_token(&lag_row, "race_note"), None, "{lag_row}");

        let miss_events = vec![dead_left_listen(4243, event_ts)];
        let (_, json) = both_formats(&miss_events, &[]);
        let miss_row = json_row(&json, "\"kind\":\"left-listen\"");
        for key in ["attribution", "race_note"] {
            let token = json_value_token(&miss_row, key).unwrap_or_else(|| panic!("{key} present"));
            assert!(
                token.starts_with('"') && token.ends_with('"'),
                "{key} is a JSON string: {miss_row}"
            );
        }
        assert_eq!(json_value_token(&miss_row, "lag_ms"), None, "{miss_row}");
    }
}
