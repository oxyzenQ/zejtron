// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The verbose lane's tests: the flag gates, and the log shape.

use std::sync::{Mutex, OnceLock};

use super::{enabled, init, log};

/// The process-global VERBOSE flag is one AtomicBool shared by every
/// test thread (cargo runs tests in parallel), so the three pins
/// below must hold the flag exclusively for their whole body - an
/// interleaved init(false) from a neighbor thread between one test's
/// init(true) and its assert is exactly the race the low-specs host
/// leg lost once (657 passed, this one flipped). One mutex, all
/// three tests, the flag state is deterministic again.
fn flag_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Poison-safe guard: a panicked neighbor must not wedge the rest of
/// the suite.
fn lock_flag() -> std::sync::MutexGuard<'static, ()> {
    match flag_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The flag arms and disarms round-trip.
#[test]
fn init_round_trips() {
    let _flag = lock_flag();
    init(true);
    assert!(enabled());
    init(false);
    assert!(!enabled());
}

/// The log door emits the bracketed shape on stderr when armed.
#[test]
fn log_prints_tagged_line_when_armed() {
    let _flag = lock_flag();
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
    let _flag = lock_flag();
    init(false);
    log("engine", "this must not print");
    assert!(!enabled());
}
