// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! doctor [eBPF] section unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract) and is #[path]-wired
//! from src/commands/doctor/ebpf.rs. The section's live rendering
//! probes the host; what IS pinned here is the row shape (the pure
//! renderer) and the lane rows that do not depend on host state.

use super::*;

#[test]
fn section_shape_pins_every_row() {
    let section = format_section(
        "enabled (this binary)",
        "6.1.11",
        "present (/sys/kernel/btf/vmlinux exists)",
        "none",
        "CAP_BPF + CAP_PERFMON present",
        "live (attached, N=5 events since 2026-10-19 03:11:22 (UTC))",
        "sched_process_exec, inet_sock_set_state",
        "/sys/fs/bpf/zejtron (present: tap_link, sock_tap_link, tap, sock_tap, stats, sock_events)",
    );
    assert_eq!(
        section,
        "[eBPF]\n  \
         Feature:     enabled (this binary)\n  \
         Kernel:      6.1.11\n  \
         BTF:         present (/sys/kernel/btf/vmlinux exists)\n  \
         Lockdown:    none\n  \
         Caps:        CAP_BPF + CAP_PERFMON present\n  \
         Lane:        live (attached, N=5 events since 2026-10-19 03:11:22 (UTC))\n  \
         Tracepoints: sched_process_exec, inet_sock_set_state\n  \
         Pins:        /sys/fs/bpf/zejtron (present: tap_link, sock_tap_link, tap, sock_tap, stats, sock_events)"
    );
}

#[test]
fn live_section_renders_nine_lines() {
    // The live section (host-probing) still renders the contract
    // shape: the header plus exactly eight rows, whatever the host
    // says - a broken renderer cannot hide behind host variance.
    let section = section();
    let lines: Vec<&str> = section.lines().collect();
    assert_eq!(lines.len(), 9, "the section is the header + 8 rows");
    assert_eq!(lines[0], "[eBPF]");
    for row in &lines[1..] {
        assert!(row.starts_with("  "), "every row is indented: {row}");
    }
    assert_eq!(
        lines[7], "  Tracepoints: sched_process_exec, inet_sock_set_state",
        "the tracepoints row is the binary's contract, host-independent"
    );
}

#[test]
fn lane_rows_for_host_independent_verdicts() {
    assert_eq!(lane_row(&LaneVerdict::Live), "live (attach available)");
    assert_eq!(
        lane_row(&LaneVerdict::Snapshot(
            "kernel 5.10.1 is below the 5.15 floor".to_owned()
        )),
        "snapshot (kernel 5.10.1 is below the 5.15 floor)"
    );
    assert_eq!(
        lane_row(&LaneVerdict::Dormant),
        "dormant (built without the ebpf feature)"
    );
}

#[test]
fn lane_row_live_attached_is_honest_in_the_dormant_lane() {
    // In a featureless build the LiveAttached row is never reached
    // (the verdict is Dormant first), but the arm compiles and the
    // honest stub stands: the binary names what it cannot do.
    if !cfg!(feature = "ebpf") {
        assert_eq!(
            lane_row(&LaneVerdict::LiveAttached),
            "live (attached, counter unreadable (this binary was built \
             without the ebpf feature))"
        );
    }
    // In a feature build the row reads the live counter through the
    // pin - host state, exercised live by the owner's session, not
    // pinned here.
}

#[test]
fn feature_and_btf_rows_name_both_states() {
    assert_eq!(btf_row(true), "present (/sys/kernel/btf/vmlinux exists)");
    assert_eq!(btf_row(false), "absent");

    if cfg!(feature = "ebpf") {
        assert_eq!(feature_row(), "enabled (this binary)");
    } else {
        assert_eq!(feature_row(), "disabled (this binary)");
    }
}

#[test]
fn pins_row_lists_every_pin_in_planting_order() {
    // The present list names the whole set from ALL_PINS - the same
    // list attach prints, the same set detach removes. On a host
    // with no pins the row says absent; the pin-name source itself
    // is what this pins (the order, the spelling).
    let names = pin_names();
    assert_eq!(
        names,
        vec![
            "tap_link",
            "sock_tap_link",
            "tap",
            "sock_tap",
            "stats",
            "sock_events"
        ]
    );
}
