// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The waiting indicator's tests: the gate's truth table, the one
//! line shape, the ceiling arithmetic, and the machine's byte-level
//! draw contract - carriage return, grey line, stable-width padding,
//! and the full clear - pinned through the test sink so the battery
//! stays silent and the pins hold on any terminal. The expected
//! bytes ride the same [`crate::output::grey_err`] wrapper the
//! machine paints through, so the pins are environment-independent
//! (the palette itself has its own pins in the output tests).

use std::time::{Duration, Instant};

use super::{Countdown, ceil_secs, countdown_line, gate, wait};

/// The gate's truth table: a terminal narrates, NO_COLOR silences,
/// a captured stream never draws - the owner's law in four rows.
#[test]
fn the_gate_needs_a_tty_and_silences_on_no_color() {
    assert!(gate(true, false));
    assert!(!gate(true, true));
    assert!(!gate(false, false));
    assert!(!gate(false, true));
}

/// The one line shape, pinned: the label, the ellipsis, the seconds
/// left, the brackets. One grammar, every surface.
#[test]
fn the_line_shape_is_bracketed_label_and_seconds() {
    assert_eq!(
        countdown_line("watching for events", 10),
        "[watching for events... 10s]"
    );
    assert_eq!(countdown_line("sampling", 1), "[sampling... 1s]");
    assert_eq!(
        countdown_line("watching for socket events", 60),
        "[watching for socket events... 60s]"
    );
}

/// The ceiling counts seconds LEFT: a fraction of a second is still
/// a second, and zero is only reached at zero.
#[test]
fn the_ceiling_counts_seconds_left() {
    assert_eq!(ceil_secs(Duration::from_secs_f64(10.0)), 10);
    assert_eq!(ceil_secs(Duration::from_secs_f64(9.2)), 10);
    assert_eq!(ceil_secs(Duration::from_secs_f64(9.0)), 9);
    assert_eq!(ceil_secs(Duration::from_secs_f64(0.2)), 1);
    assert_eq!(ceil_secs(Duration::ZERO), 0);
}

/// The inert machine draws nothing and grows no width: the piped
/// run's every method is a no-op, byte for byte.
#[test]
fn the_inert_countdown_never_draws() {
    super::test_clear_drawn();
    let mut countdown = Countdown {
        label: "watching for events",
        active: false,
        shown: None,
        width: 0,
    };
    countdown.update(Duration::from_secs(10));
    assert_eq!(countdown.shown, None);
    assert_eq!(countdown.width, 0);
    countdown.finish();
    assert!(super::test_drawn_bytes().is_empty());
}

/// The active machine draws once per whole-second change: carriage
/// return, the grey line, nothing else - and the identical second
/// across slices never redraws. The finish blanks the drawn width
/// and parks the cursor at column zero.
#[test]
fn the_active_countdown_draws_on_second_changes_only() {
    super::test_clear_drawn();
    let mut countdown = Countdown {
        label: "sampling",
        active: true,
        shown: None,
        width: 0,
    };
    countdown.update(Duration::from_secs_f64(3.0));
    assert_eq!(countdown.shown, Some(3));
    let three = crate::output::grey_err("[sampling... 3s]");
    assert_eq!(super::test_drawn_bytes(), format!("\r{three}"));
    countdown.update(Duration::from_secs_f64(2.5));
    assert_eq!(countdown.shown, Some(3), "the same second - no redraw");
    countdown.update(Duration::from_secs_f64(1.9));
    let two = crate::output::grey_err("[sampling... 2s]");
    assert_eq!(super::test_drawn_bytes(), format!("\r{three}\r{two}"));
    countdown.update(Duration::from_secs_f64(0.4));
    let one = crate::output::grey_err("[sampling... 1s]");
    assert_eq!(
        super::test_drawn_bytes(),
        format!("\r{three}\r{two}\r{one}")
    );
    countdown.finish();
    assert_eq!(
        super::test_drawn_bytes(),
        format!("\r{three}\r{two}\r{one}\r{}\r", " ".repeat(16))
    );
}

/// The width pin that justifies the padding: a two-digit second is
/// one column wider than a one-digit one - the redraw pads to the
/// wider width so the overwrite never leaves a stray tail, and the
/// clear blanks the same width.
#[test]
fn the_width_survives_the_two_digit_to_one_digit_flip() {
    super::test_clear_drawn();
    let mut countdown = Countdown {
        label: "watching for events",
        active: true,
        shown: None,
        width: 0,
    };
    let ten = crate::output::grey_err("[watching for events... 10s]");
    countdown.update(Duration::from_secs_f64(10.0));
    assert_eq!(countdown.width, "[watching for events... 10s]".len());
    countdown.update(Duration::from_secs_f64(9.9));
    assert_eq!(countdown.shown, Some(10), "9.9s left is still 10 to show");
    countdown.update(Duration::from_secs_f64(8.9));
    let nine = crate::output::grey_err("[watching for events... 9s]");
    assert_eq!(
        super::test_drawn_bytes(),
        format!("\r{ten}\r{nine} "),
        "the one-column pad keeps the overwrite stable"
    );
    countdown.finish();
    assert_eq!(
        super::test_drawn_bytes(),
        format!("\r{ten}\r{nine} \r{}\r", " ".repeat(28))
    );
}

/// The plain wait's floor and tripwire: the gate-off path is the
/// old sleep - at least the window, and no runaway loop above it.
/// (The test lane runs piped, so this exercises the exact path a
/// piped production run takes.)
#[test]
fn the_plain_wait_sleeps_the_window() {
    let start = Instant::now();
    wait(Duration::from_millis(150), "sampling");
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(150));
    assert!(
        elapsed < Duration::from_secs(5),
        "the wait overshot: {elapsed:?}"
    );
}
