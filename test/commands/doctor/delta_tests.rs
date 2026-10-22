// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The delta engine's pins (night-improve-48): the parsers every
//! delta symptom rides on, pinned against synthetic /proc bytes -
//! the shape is the contract, not this host's own tables.

use super::*;
use std::collections::BTreeMap;

#[test]
fn the_sample_window_is_exactly_one_second() {
    // The spec's own number, stated once: 1.0s, never a loop.
    assert_eq!(SAMPLE_WINDOW, Duration::from_secs(1));
    assert_eq!(SAMPLE_WINDOW.as_millis(), 1000);
}

#[test]
fn the_overlay_window_is_two_seconds_with_its_label_beside_it() {
    assert_eq!(OVERLAY_WINDOW_SECS, 2);
    assert_eq!(OVERLAY_WINDOW_LABEL, "2s");
}

#[test]
fn the_cpu_line_parses_the_floor_kernel_shape() {
    let ticks = parse_cpu_line("cpu  100 20 30 4000 50 5 10 2").expect("floor shape parses");
    assert_eq!(ticks.user, 100);
    assert_eq!(ticks.nice, 20);
    assert_eq!(ticks.system, 30);
    assert_eq!(ticks.idle, 4000);
    assert_eq!(ticks.iowait, 50);
    assert_eq!(ticks.irq, 5);
    assert_eq!(ticks.softirq, 10);
    assert_eq!(ticks.steal, 2);
    assert_eq!(ticks.total(), 100 + 20 + 30 + 4000 + 50 + 5 + 10 + 2);
    assert_eq!(ticks.busy(), 100 + 20 + 30 + 5 + 10 + 2);
}

#[test]
fn the_cpu_line_tolerates_later_kernel_fields_without_reading_them() {
    // guest/guest_nice ride after steal on newer kernels and are
    // already accounted inside user - the parser reads exactly the
    // eight floor fields and no more.
    let ticks = parse_cpu_line("cpu  1 2 3 4 5 6 7 8 90 90").expect("appended fields parse");
    assert_eq!(ticks.steal, 8);
    assert_eq!(ticks.total(), 36);
}

#[test]
fn non_aggregate_cpu_lines_do_not_parse_as_the_aggregate() {
    assert!(parse_cpu_line("cpu0 1 2 3 4 5 6 7 8").is_none());
    assert!(parse_cpu_line("intr 1").is_none());
    assert!(parse_cpu_line("cpu 1 2 3").is_none());
    assert!(parse_cpu_line("").is_none());
}

#[test]
fn the_pid_stat_parser_takes_the_comm_between_the_outermost_parens() {
    // A comm with spaces is the parser's classic trap: field 2 can
    // be "(my yes app)", so the split is first '(' to LAST ')'.
    let stat = parse_pid_stat("1234 (my yes app) R 1 2 3 4 5 6 7 8 9 10 11 12")
        .expect("spaced comm parses");
    assert_eq!(stat.comm, "my yes app");
    assert_eq!(stat.state, 'R');
    assert_eq!(stat.cpu_ticks, 11 + 12);
}

#[test]
fn the_pid_stat_parser_sanitizes_hostile_comms_at_the_boundary() {
    // A process can rename itself to carry control bytes; the
    // zero-escape law holds at the parse boundary.
    let stat =
        parse_pid_stat("9 (evil\tname) S 1 2 3 4 5 6 7 8 9 10 11 12").expect("hostile comm parses");
    assert!(!stat.comm.chars().any(char::is_control), "{}", stat.comm);
    assert!(stat.comm.starts_with("evil"));
}

#[test]
fn the_pid_stat_parser_refuses_short_and_malformed_lines() {
    assert!(parse_pid_stat("1234 (yes) R 1 2").is_none());
    assert!(parse_pid_stat("no parens here").is_none());
    assert!(parse_pid_stat(") reversed (").is_none());
    assert!(parse_pid_stat("").is_none());
}

#[test]
fn the_pid_io_parser_keeps_only_the_block_backed_pair() {
    // rchar/wchar count cache hits and terminal writes; the symptom
    // rides read_bytes/write_bytes only.
    let io = parse_pid_io(
        "rchar: 999999\nwchar: 888888\nsyscr: 3\nsyscw: 2\nread_bytes: 400\n\
         write_bytes: 50\ncancelled_write_bytes: 0\n",
    );
    assert_eq!(io.read_bytes, 400);
    assert_eq!(io.write_bytes, 50);
    // Absent names stay zero - a race is not a guess.
    let empty = parse_pid_io("rchar: 5\n");
    assert_eq!(empty.read_bytes, 0);
    assert_eq!(empty.write_bytes, 0);
}

#[test]
fn the_mode_lines_name_all_three_lane_states_for_both_flavors() {
    // The delta flavor (cpu/disk/network) and the snapshot flavor
    // (gpu) - six pinned strings, one builder, no drift.
    assert_eq!(
        mode_line(&ExitLane::NotAttached, true),
        "Mode: snapshot delta (1.0s sample; eBPF not attached)"
    );
    assert_eq!(
        mode_line(&ExitLane::Drained(Vec::new()), true),
        "Mode: snapshot delta + post-mortem (1.0s sample; eBPF exits drained, last 2s)"
    );
    assert_eq!(
        mode_line(&ExitLane::DrainFailed("x".to_owned()), true),
        "Mode: snapshot delta + post-mortem (1.0s sample; the exit drain failed - named below)"
    );
    assert_eq!(
        mode_line(&ExitLane::NotAttached, false),
        "Mode: snapshot (eBPF not attached)"
    );
    assert_eq!(
        mode_line(&ExitLane::Drained(Vec::new()), false),
        "Mode: snapshot + post-mortem (eBPF exits drained, last 2s)"
    );
    assert_eq!(
        mode_line(&ExitLane::DrainFailed("x".to_owned()), false),
        "Mode: snapshot + post-mortem (the exit drain failed - named below)"
    );
}

#[test]
fn the_sampling_boundary_names_the_spec_sentence_when_not_attached() {
    let line = sampling_unaccounted(&ExitLane::NotAttached, SAMPLE_WINDOW_DESC);
    assert!(
        line.contains("processes that started and exited within the 1.0s sampling window"),
        "{line}"
    );
    assert!(
        line.contains("zejtron samples, it does not watch"),
        "the spec's own sentence rides: {line}"
    );
    assert!(line.contains("[unaccounted]"), "{line}");
}

#[test]
fn the_sampling_boundary_defers_to_the_overlay_when_drained() {
    let line = sampling_unaccounted(&ExitLane::Drained(Vec::new()), SAMPLE_WINDOW_DESC);
    assert!(
        line.contains("named [observed] in the exits section above"),
        "{line}"
    );
    assert!(line.contains("the eBPF drain holds the last 2s"), "{line}");
}

#[test]
fn the_sampling_boundary_names_the_drain_failure_verbatim() {
    let line = sampling_unaccounted(
        &ExitLane::DrainFailed("test refusal".to_owned()),
        "the moment",
    );
    assert!(
        line.contains("the eBPF exit drain failed: test refusal"),
        "{line}"
    );
}

#[test]
fn the_pid_sample_walker_is_a_map_plus_two_boundary_counters() {
    // The default shape: nothing read, nothing refused - the struct
    // the Unaccounted blocks name their counts from.
    let sample = PidSample::default();
    assert!(sample.stat.is_empty());
    assert!(sample.io.is_empty());
    assert_eq!(sample.io_permission_refused, 0);
    assert_eq!(sample.io_vanished, 0);
    let map: BTreeMap<u32, PidStat> = sample.stat;
    assert_eq!(map.len(), 0);
}
