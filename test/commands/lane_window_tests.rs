// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The event-window resolver's grammar pins (the lane_tests.rs
//! window half, moved with the resolver's pure move under the
//! 600-LOC cap): the 10s default, the surface grammar, the clamp
//! range, the refusal. All pure, no live kernel.

use super::*;
use std::time::Duration;

#[test]
fn the_default_window_is_ten_seconds() {
    assert_eq!(WINDOW_DEFAULT, Duration::from_secs(10));
}

#[test]
fn resolve_window_maps_the_grammar() {
    let (w, l) = resolve_window(None).unwrap();
    assert_eq!(w, Duration::from_secs(10));
    assert_eq!(l, "10s");

    let (w, l) = resolve_window(Some("60s")).unwrap();
    assert_eq!(w, Duration::from_secs(60));
    assert_eq!(l, "60s");

    let (w, l) = resolve_window(Some("5m")).unwrap();
    assert_eq!(w, Duration::from_secs(300));
    assert_eq!(l, "5m");

    let (w, l) = resolve_window(Some("1h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");
}

#[test]
fn resolve_window_clamps_the_same_range_as_port() {
    // 0s floors to 1s; 2h ceilings to 1h - one grammar, two surfaces.
    // The absurd ask (u64::MAX/1000 hours, the audit's own token)
    // saturates through the same ceiling: every window surface that
    // resolves through here truncates to the honest 1h maximum.
    let (w, l) = resolve_window(Some("0s")).unwrap();
    assert_eq!(w, Duration::from_secs(1));
    assert_eq!(l, "1s");

    let (w, l) = resolve_window(Some("2h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");

    let (w, l) = resolve_window(Some("999999h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");

    let (w, l) = resolve_window(Some("18446744073709551h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");
}

#[test]
fn resolve_window_refuses_the_non_grammar() {
    for bad in ["7x", "abc", "m", ""] {
        assert!(resolve_window(Some(bad)).is_err(), "{bad} must be refused");
    }
}
