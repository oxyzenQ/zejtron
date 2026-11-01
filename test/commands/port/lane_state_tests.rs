// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The lane-state classification pins (the misleading-reason
//! residual). Split from window_tests.rs with the lane_state module
//! (the 600-LOC cap): the ladder speaks std::io::ErrorKind - the
//! exact shape the contract names - so every rung is pinned on
//! synthesized errors, no bpffs, no root, no fixture host needed.
//! Wired from src/commands/port/lane_state.rs.

/// The classification speaks `std::io::ErrorKind` - the exact
/// shape the task's contract names - so a test synthesizes the
/// error; no bpffs, no root, no fixture host needed.
fn kind_error(kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::new(kind, "synthetic probe failure")
}

#[test]
fn a_missing_pin_directory_is_not_attached_with_the_attach_hint() {
    // The task's own probe: metadata answers NotFound - the lane
    // is simply not there, and the hint is the healing command.
    let error = kind_error(std::io::ErrorKind::NotFound);
    let state = super::lane_state_before_window(Some(error.kind()), None);
    assert_eq!(state, Some(super::LaneUnavailable::NotAttached));
    let (reason, hint) = super::lane_reason(super::LaneUnavailable::NotAttached);
    assert_eq!(reason, "lane-not-attached");
    assert!(hint.contains("attach"), "the hint names the fix: {hint}");
    assert!(hint.contains("doctor --attach"), "the exact verb: {hint}");
}

#[test]
fn a_refused_directory_probe_is_unreadable_with_the_sudo_hint() {
    // The live evidence this residual closes: the pins exist
    // (a root attach session planted them) but this euid cannot
    // stat in - EACCES, not ENOENT, and the sudo hint, not an
    // attach instruction that never heals a permission wall.
    let error = kind_error(std::io::ErrorKind::PermissionDenied);
    let state = super::lane_state_before_window(Some(error.kind()), None);
    assert_eq!(state, Some(super::LaneUnavailable::Unreadable));
    let (reason, hint) = super::lane_reason(super::LaneUnavailable::Unreadable);
    assert_eq!(reason, "lane-unreadable");
    assert!(hint.contains("sudo"), "the hint names the fix: {hint}");
}

#[test]
fn a_refused_directory_walk_is_unreadable_too() {
    // The directory stat may pass on a hostile-to-euid bpffs
    // while the WALK refuses - the second probe of the ladder,
    // same verdict, same hint.
    let error = kind_error(std::io::ErrorKind::PermissionDenied);
    let state = super::lane_state_before_window(None, Some(error.kind()));
    assert_eq!(state, Some(super::LaneUnavailable::Unreadable));
}

#[test]
fn a_readable_directory_proceeds_to_the_chain_gate() {
    // Dir present, walk clean: no verdict from this rung - the
    // ladder continues (the pin-set integrity gate is next).
    assert_eq!(super::lane_state_before_window(None, None), None);
}

#[test]
fn an_exotic_directory_failure_keeps_the_blanket_token() {
    // An EIO on bpffs has no token of its own: the pre-fix
    // blanket rides (the doctor's [eBPF] section names the
    // exact cause), never a fabricated third story.
    let error = kind_error(std::io::ErrorKind::StorageFull);
    let state = super::lane_state_before_window(Some(error.kind()), None);
    assert_eq!(state, Some(super::LaneUnavailable::NotAttached));
}

#[test]
fn the_mid_window_detach_is_a_not_found_after_a_served_start() {
    // The lane existed at the start probe and the directory is
    // gone when the collection ended: the detach story. Any
    // other outcome - present, a different error, no probe at
    // all - keeps the window's own verdict.
    assert!(super::lane_detached_mid_window(Some(
        std::io::ErrorKind::NotFound
    )));
    assert!(!super::lane_detached_mid_window(None));
    assert!(!super::lane_detached_mid_window(Some(
        std::io::ErrorKind::PermissionDenied
    )));
    let (reason, hint) = super::lane_reason(super::LaneUnavailable::DetachedMidWindow);
    assert_eq!(reason, "lane-detached-mid-window");
    assert!(hint.contains("re-attach"), "the hint names the fix: {hint}");
}

#[test]
fn every_reason_token_is_stable_and_hinted() {
    // The automation lane gates on these tokens: the full
    // vocabulary, pinned, each with its own next action.
    let vocabulary = [
        (super::LaneUnavailable::NotAttached, "lane-not-attached"),
        (super::LaneUnavailable::Unreadable, "lane-unreadable"),
        (
            super::LaneUnavailable::DetachedMidWindow,
            "lane-detached-mid-window",
        ),
    ];
    for (lane, token) in vocabulary {
        let (reason, hint) = super::lane_reason(lane);
        assert_eq!(reason, token);
        assert!(!hint.is_empty(), "every token carries a hint");
    }
}

#[test]
fn on_a_pinned_host_the_real_ladder_names_a_real_state() {
    // The integration leg (skippable by construction): on a host
    // without pins - every CI runner - there is nothing to
    // assert, the leg returns. On a host WITH pins it walks the
    // real probes: a directory this euid can walk proceeds, one
    // it cannot is named unreadable - never "not attached", the
    // exact regression the live verification caught.
    let dir = std::path::Path::new(crate::ebpf::PIN_DIR);
    if !dir.exists() {
        return;
    }
    let dir_kind = super::dir_error_kind(std::fs::metadata(crate::ebpf::PIN_DIR));
    let listing_kind = super::pin_dir_listing_kind();
    let state = super::lane_state_before_window(dir_kind, listing_kind);
    match state {
        None => {
            assert!(dir_kind.is_none() && listing_kind.is_none());
        }
        Some(super::LaneUnavailable::Unreadable) => {
            assert!(
                dir_kind == Some(std::io::ErrorKind::PermissionDenied)
                    || listing_kind == Some(std::io::ErrorKind::PermissionDenied)
            );
        }
        Some(super::LaneUnavailable::NotAttached) => {
            assert!(dir_kind.is_some() && dir_kind != Some(std::io::ErrorKind::PermissionDenied));
        }
        Some(other) => panic!("the start ladder never detaches: {other:?}"),
    }
}
