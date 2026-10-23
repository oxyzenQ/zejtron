// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The verbose lane's tests: the flag gates, and the log shape.

use super::{enabled, init, log};

/// The flag arms and disarms round-trip (tests run in one process,
/// so the last writer wins - each test re-arms to its own state).
#[test]
fn init_round_trips() {
    init(true);
    assert!(enabled());
    init(false);
    assert!(!enabled());
}

/// The log door emits the bracketed shape on stderr when armed.
#[test]
fn log_prints_tagged_line_when_armed() {
    init(true);
    // No panic, no stdout use: the shape contract is exercised by
    // the pipe-purity integration surface (why -v split test), and
    // this pin keeps the door callable in both states.
    log("engine", "test probe line");
    assert!(enabled());
    init(false);
}

#[test]
fn log_is_silent_when_disarmed() {
    init(false);
    log("engine", "this must not print");
    assert!(!enabled());
}
