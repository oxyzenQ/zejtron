// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The waiting indicator's tests: the gate's truth table, the one
//! line shape, the ceiling arithmetic, and the machine's byte-level
//! draw contract - carriage return, grey line, stable-width padding,
//! and the full clear - pinned through the test sink so the battery
//! stays silent and the pins hold on any terminal. The expected
//! bytes ride the same [`crate::output::grey_err`] wrapper the
//! machine paints through, so the pins are environment-independent
//! (the palette itself has its own pins in the output tests).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use super::{
    ASCII, Countdown, HELIX, Spinner, Style, SWEEP, WAVE, ceil_secs, countdown_line, frame_slot,
    frames_for, gate, render_slot, spinner_line, unicode_ok, wait,
};

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

// ── The loading lane (night-ux-orion-1) ─────────────────────────────

/// The helix table is the pin, not a computation: ten frames, every
/// frame pairing the sweep's i-th cell with its (9-i)-th - two
/// strands running the same walk in opposite directions - and the
/// strands never collide at any frame. Every frame in every table
/// shares one width, the stable-overwrite law.
#[test]
fn the_helix_table_is_ten_counter_phase_strands() {
    assert_eq!(HELIX.len(), 10);
    assert_eq!(WAVE.len(), 10);
    for i in 0..10 {
        let expected = format!("{}{}", SWEEP[i], SWEEP[9 - i]);
        assert_eq!(HELIX[i], expected, "frame {i}: forward x backward strand");
        let cells: Vec<char> = HELIX[i].chars().collect();
        assert_eq!(cells.len(), 2, "two strands, one cell each");
        assert_ne!(cells[0], cells[1], "frame {i}: the strands never collide");
    }
    assert!(HELIX.iter().all(|frame| frame.len() == HELIX[0].len()));
    assert!(WAVE.iter().all(|frame| frame.len() == WAVE[0].len()));
    assert!(ASCII.iter().all(|frame| frame.len() == ASCII[0].len()));
}

/// The style ladder: NO_COLOR or a locale without UTF-8 lands on the
/// ASCII floor, a UTF-8 terminal gets the seat the site claims - and
/// NO_COLOR wins over everything, because the unpainted dash is
/// still a visible wait, and a hang looks like a hang with or
/// without color.
#[test]
fn the_style_ladder_lands_on_the_ascii_floor() {
    let utf8 = Some("en_US.UTF-8");
    for locale in [None, Some("C"), Some("POSIX"), utf8] {
        for chosen in [Style::Helix, Style::Wave] {
            assert_eq!(frames_for(true, locale, chosen), &ASCII[..], "NO_COLOR: the dash, always");
        }
    }
    assert_eq!(frames_for(false, None, Style::Helix), &ASCII[..]);
    assert_eq!(frames_for(false, Some("C"), Style::Helix), &ASCII[..]);
    assert_eq!(frames_for(false, Some("C.UTF-8"), Style::Helix), &HELIX[..]);
    assert_eq!(frames_for(false, utf8, Style::Helix), &HELIX[..]);
    assert_eq!(frames_for(false, utf8, Style::Wave), &WAVE[..]);
}

/// The Unicode probe's spellings: the three usual UTF-8 forms pass,
/// the plain locales fail, and absence fails - an exotic spelling
/// degrades to the ASCII floor, never to garbage bytes.
#[test]
fn the_unicode_probe_knows_the_utf8_spellings() {
    assert!(unicode_ok(Some("en_US.UTF-8")));
    assert!(unicode_ok(Some("C.UTF-8")));
    assert!(unicode_ok(Some("id_ID.utf8")));
    assert!(!unicode_ok(Some("C")));
    assert!(!unicode_ok(Some("POSIX")));
    assert!(!unicode_ok(None));
}

/// The lazy slot clock: silence below the owner's 100 ms threshold,
/// then one slot per frame period, deterministic - a late redraw
/// repeats a frame instead of skipping the sequence.
#[test]
fn the_lazy_slot_clock_stays_silent_below_the_threshold() {
    assert_eq!(frame_slot(Duration::from_millis(0)), None);
    assert_eq!(frame_slot(Duration::from_millis(99)), None);
    assert_eq!(frame_slot(Duration::from_millis(100)), Some(0));
    assert_eq!(frame_slot(Duration::from_millis(150)), Some(0));
    assert_eq!(frame_slot(Duration::from_millis(199)), Some(0));
    assert_eq!(frame_slot(Duration::from_millis(200)), Some(1));
    assert_eq!(frame_slot(Duration::from_millis(1234)), Some(11));
}

/// The loading line rides the countdown's bracket grammar - the
/// frame where the seconds ride - and the slot render wraps the
/// table, so slot 12 of a ten-frame helix is frame 2.
#[test]
fn the_loading_line_rides_the_bracket_grammar() {
    assert_eq!(
        spinner_line("checking for updates", "⠋⠏"),
        "[checking for updates... ⠋⠏]"
    );
    assert_eq!(
        spinner_line("checking for updates", "-"),
        "[checking for updates... -]"
    );
    assert_eq!(
        render_slot("checking for updates", &HELIX, 12),
        spinner_line("checking for updates", HELIX[2]),
        "the table wraps"
    );
}

/// The inert machine: the test lane runs piped, so arm() takes the
/// gate's off arm - no thread, no width, and a finish that writes
/// nothing. A piped `--check-update` pays one gate probe and
/// nothing else, byte for byte.
#[test]
fn the_inert_spinner_never_draws_and_never_spawns() {
    super::test_clear_drawn();
    let spinner = Spinner::arm("checking for updates", Style::Helix);
    assert!(spinner.handle.is_none());
    assert_eq!(spinner.width, 0);
    spinner.finish();
    assert!(super::test_drawn_bytes().is_empty());
}

/// The finish clear, byte-pinned: the drawn width blanked with
/// spaces, the cursor parked at column zero - the same clear
/// grammar the countdown lane pins.
#[test]
fn the_finish_clear_blanks_the_drawn_width() {
    super::test_clear_drawn();
    let width = spinner_line("checking for updates", HELIX[0]).len();
    let spinner = Spinner {
        stop: Arc::new(AtomicBool::new(false)),
        handle: None,
        width,
    };
    spinner.finish();
    assert_eq!(
        super::test_drawn_bytes(),
        format!("\r{}\r", " ".repeat(width))
    );
}
