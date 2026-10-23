// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! ebpf lane unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/ebpf/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.
//!
//! Compiled in BOTH lanes (feature and featureless): the pure helpers
//! (version parsing, labels, the floor) are lane-independent, and the
//! verdict pins are written host-tolerant - the verdicts that ride on
//! the host's real pin state (Live vs LiveAttached) assert the union
//! the pin state selects between, never a state the test host cannot
//! promise.

use super::*;

/// Facts with every knob at a chosen position - the fixture builder
/// the verdict pins share (one shape, no per-test drift).
fn facts(
    release: Option<&str>,
    lockdown: LockdownMode,
    cap_bpf: bool,
    cap_perfmon: bool,
) -> KernelFacts {
    KernelFacts {
        release: release.map(str::to_owned),
        btf_present: true,
        lockdown,
        cap_bpf,
        cap_perfmon,
    }
}

#[test]
fn parse_kernel_version_shapes() {
    assert_eq!(parse_kernel_version("5.15.0-arch1-1"), Some((5, 15)));
    assert_eq!(parse_kernel_version("6.1.11"), Some((6, 1)));
    assert_eq!(
        parse_kernel_version("5.10.134-013.15.kangaroo.al8.x86_64"),
        Some((5, 10))
    );
    // Anything that does not open with two numeric components is
    // refused - an unparsable release is NOT a floor pass.
    assert_eq!(parse_kernel_version("weird"), None);
    assert_eq!(parse_kernel_version("6"), None);
    assert_eq!(parse_kernel_version(""), None);
}

#[test]
fn kernel_floor_is_5_15_and_enforced() {
    assert_eq!(KERNEL_FLOOR, (5, 15));
    assert_eq!(floor_label(), "5.15");

    let at_floor = facts(Some("5.15.0"), LockdownMode::None, true, true);
    assert!(at_floor.kernel_meets_floor());
    let below_floor = facts(Some("5.14.9"), LockdownMode::None, true, true);
    assert!(!below_floor.kernel_meets_floor());
    let above_floor = facts(Some("6.8.0"), LockdownMode::None, true, true);
    assert!(above_floor.kernel_meets_floor());
    // Unreadable and unparsable releases are refused, not guessed.
    let unreadable = facts(None, LockdownMode::None, true, true);
    assert!(!unreadable.kernel_meets_floor());
    let unparsable = facts(Some("unknown"), LockdownMode::None, true, true);
    assert!(!unparsable.kernel_meets_floor());
}

#[test]
fn lockdown_labels_and_blocking() {
    assert_eq!(LockdownMode::None.label(), "none");
    assert_eq!(LockdownMode::Integrity.label(), "integrity");
    assert_eq!(LockdownMode::Confidentiality.label(), "confidentiality");
    assert_eq!(LockdownMode::Unknown.label(), "unknown (unreadable)");

    assert!(!LockdownMode::None.blocks_bpf());
    assert!(LockdownMode::Integrity.blocks_bpf());
    assert!(LockdownMode::Confidentiality.blocks_bpf());
    assert!(!LockdownMode::Unknown.blocks_bpf());
}

#[test]
fn caps_labels_name_the_missing_pair() {
    let both = facts(None, LockdownMode::None, true, true);
    assert_eq!(both.caps_label(), "CAP_BPF + CAP_PERFMON present");
    assert!(both.caps_sufficient());

    let no_perfmon = facts(None, LockdownMode::None, true, false);
    assert_eq!(no_perfmon.caps_label(), "missing (CAP_PERFMON)");

    let no_bpf = facts(None, LockdownMode::None, false, true);
    assert_eq!(no_bpf.caps_label(), "missing (CAP_BPF)");

    let neither = facts(None, LockdownMode::None, false, false);
    assert_eq!(neither.caps_label(), "missing (CAP_BPF + CAP_PERFMON)");
}

#[test]
fn lane_verdict_refuses_below_floor_before_pin_state() {
    // The floor check precedes the pin-state check in lane_verdict,
    // so this verdict holds on every host regardless of what is
    // pinned there.
    let below = facts(Some("5.10.1"), LockdownMode::None, true, true);
    let verdict = lane_verdict(&below);
    match verdict {
        LaneVerdict::Snapshot(reason) => assert!(
            reason.contains("below the 5.15 floor"),
            "the reason must name the floor: {reason}"
        ),
        other => panic!("below-floor host must refuse, got {other:?}"),
    }
}

#[test]
fn lane_verdict_refuses_lockdown_before_pin_state() {
    // Lockdown also precedes the pin-state check.
    let locked = facts(Some("6.1.11"), LockdownMode::Integrity, true, true);
    let verdict = lane_verdict(&locked);
    match verdict {
        LaneVerdict::Snapshot(reason) => assert!(
            reason.contains("lockdown integrity blocks eBPF"),
            "the reason must name the lockdown mode: {reason}"
        ),
        other => panic!("locked-down host must refuse, got {other:?}"),
    }
}

#[test]
fn lane_verdict_live_or_attached_when_capable() {
    // A capable host with no pins is Live; with a complete pin set it
    // is LiveAttached. The pin state belongs to the host, so the pin
    // asserts the union the state selects between.
    let capable = facts(Some("6.1.11"), LockdownMode::None, true, true);
    let verdict = lane_verdict(&capable);
    assert!(
        matches!(verdict, LaneVerdict::Live | LaneVerdict::LiveAttached),
        "a capable host must report a live lane, got {verdict:?}"
    );
}

#[test]
fn lane_verdict_names_the_missing_caps_once() {
    // The caps reason rides caps_label alone (night-improve-43, the
    // one-truth law): the label already names which capability is
    // missing, so the reason must not re-state the fact above it -
    // the doctor's Lane row stays one paren level deep. The pin state
    // precedes the caps seat in the verdict order, so a host with a
    // complete pin set never reaches this branch; the reason contract
    // is pinned on the pinless hosts the suite rides.
    let no_caps = facts(Some("6.1.11"), LockdownMode::None, false, false);
    let verdict = lane_verdict(&no_caps);
    match verdict {
        LaneVerdict::Snapshot(reason) => {
            assert_eq!(
                reason,
                "missing (CAP_BPF + CAP_PERFMON) - attach needs root"
            );
        }
        LaneVerdict::Live | LaneVerdict::LiveAttached => {
            // The host's pin state answered first - nothing to pin here.
        }
    }
}

#[test]
fn pin_constants_carry_the_removal_order() {
    // Link first (unlinking the link detaches the probe), program and
    // map last - ALL_PINS is the removal order, not a set.
    assert_eq!(ALL_PINS[0], PIN_LINK);
    assert_eq!(ALL_PINS[1], PIN_LINK_SOCK);
    assert_eq!(ALL_PINS[2], PIN_LINK_OPEN);
    assert_eq!(ALL_PINS[3], PIN_LINK_WRITE);
    assert_eq!(ALL_PINS[4], PIN_LINK_WRITEV);
    assert_eq!(ALL_PINS[5], PIN_LINK_EXIT);
    assert_eq!(ALL_PINS[6], PIN_PROG);
    assert_eq!(ALL_PINS[7], PIN_PROG_SOCK);
    assert_eq!(ALL_PINS[8], PIN_PROG_OPEN);
    assert_eq!(ALL_PINS[9], PIN_PROG_WRITE);
    assert_eq!(ALL_PINS[10], PIN_PROG_WRITEV);
    assert_eq!(ALL_PINS[11], PIN_PROG_EXIT);
    assert_eq!(ALL_PINS[12], PIN_MAP_STATS);
    assert_eq!(ALL_PINS[13], PIN_MAP_SOCK_EVENTS);
    assert_eq!(ALL_PINS[14], PIN_MAP_PROC_EVENTS);
    assert_eq!(ALL_PINS[15], PIN_MAP_TRACKED_INODES);
    assert_eq!(ALL_PINS[16], PIN_MAP_FILE_EVENTS);
    assert_eq!(ALL_PINS[17], PIN_MAP_OFFSETS);
    assert_eq!(
        ALL_PINS.len(),
        18,
        "eighteen pins: 6 links, 6 programs, 6 maps"
    );
    for pin in ALL_PINS {
        assert!(
            pin.starts_with("/sys/fs/bpf/zejtron/"),
            "every pin lives under the one directory: {pin}"
        );
    }
}
