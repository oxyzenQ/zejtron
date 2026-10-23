// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The waiting indicator (night-hunter-6): the Lazy Camera's voice
//! while the shutter is open.
//!
//! The doctrine sleeps on purpose - the event window IS the
//! collection (the kprobes record into the ring while zejtron
//! waits), and the delta sample IS the measurement's denominator -
//! but a silent sleep is indistinguishable from a hang, and the
//! Ctrl+C a frozen-looking terminal invites is a bug of perception,
//! not of behavior. The wait sites narrate instead: a grey countdown
//! on stderr - "[watching for events... 10s]", "[sampling... 1s]" -
//! that redraws once per whole second and is erased entirely when
//! the wait ends, so the Evidence Ledger's stdout lands on a clean
//! terminal line and a pipe never sees the narration at all.
//!
//! The gate is the owner's plain-output law, stated verbatim: the
//! narration runs only when stderr is a terminal, and NO_COLOR
//! silences it entirely (no color, no narration - not an unpainted
//! countdown). Paint still rides the capability ladder through
//! [`crate::output::grey_err`]: grey wherever the stderr lane
//! paints, plain wherever the ladder lands Mono. A piped stderr is
//! silent no matter what else the environment promises - `why ...
//! > out.txt 2> err.txt` carries countdown bytes on neither stream.
//!
//! Two doors, one machine:
//!
//! - [`wait`] is the narrated sleep: exactly `window`, deadline-
//!   anchored. The wake slices are ONE window's chunks - the
//!   deadline is computed once, every slice sleeps toward it, and
//!   the total is the window itself - so the sampled windows stay
//!   exact and the delta spec's "no loop, no second window" law is
//!   untouched: the slices redraw a line, they never re-arm a
//!   window.
//! - [`Countdown`] is the bare state machine, for the one wait site
//!   that cannot ride [`wait`]: port's collection loop already wakes
//!   on its own cadence to drain the socket ring (a bounded ring
//!   must not sit undrained for a whole window), so it drives
//!   `start` / `update` / `finish` around its existing slices and
//!   keeps its drain contract byte for byte.
//!
//! The render is deliberately boring: one line, ASCII, the grammar
//! tier's grey - the stderr lane's first non-error seat, dimmer than
//! every ledger byte it annotates. The overwrite and the clear ride
//! carriage returns and spaces only (no CSI erase, no animation
//! frames), so they degrade honestly on any terminal that honors
//! \r. Labels are the crate's own ASCII constants; nothing external
//! ever reaches this lane. The 300 ms verify-write poll is below the
//! narration threshold on purpose: a verification retry is not a
//! wait the user asked about.
//!
//! One noise law: a failed narration write is swallowed, never a
//! panic (write_raw) - the indicator is decoration, and a stderr
//! that cannot take the line must not cost the run its ledger. The
//! test lane swaps the sink for a thread-local buffer, so the byte
//! contract is pinned exactly and the battery stays silent.

use std::io::IsTerminal;
#[cfg(not(test))]
use std::io::Write;
use std::time::{Duration, Instant};

/// The wake slice of [`wait`]'s countdown: short enough that the
/// displayed second flips within a quarter-second of the true
/// boundary, long enough that the wakeup cost is noise next to the
/// wait itself. Port's drain-driven loop keeps its own 100 ms
/// slice - that one exists for the ring, this one exists only for
/// the redraw.
const TICK: Duration = Duration::from_millis(250);

/// The gate, pure: narration runs when stderr is a terminal and
/// NO_COLOR is silent. The owner's law, in one row.
fn gate(stream_tty: bool, no_color: bool) -> bool {
    stream_tty && !no_color
}

/// The production gate: stderr's own TTY-ness, and NO_COLOR in the
/// capability module's exact shape (non-empty means set).
fn enabled() -> bool {
    gate(
        std::io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
    )
}

/// The narrated sleep: exactly `window`, with a grey countdown on
/// stderr while it lasts. The door the bare wait sites ride -
/// fileprobe's live file window and the delta symptoms' sample gap
/// replaced their plain `thread::sleep` with this call.
pub(crate) fn wait(window: Duration, label: &'static str) {
    let mut countdown = Countdown::start(label);
    if !countdown.active {
        // The gate's off arm: the plain sleep, byte for byte.
        std::thread::sleep(window);
        return;
    }
    let deadline = Instant::now() + window;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        countdown.update(deadline - now);
        // Re-derived after the draw: the redraw's own write time
        // never leaks into the window's total.
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(TICK));
    }
    countdown.finish();
}

/// One narration write, errors swallowed: `eprint!` panics when the
/// write fails, and the indicator must never be the reason a run
/// dies. stderr is unbuffered - one call, one landing.
#[cfg(not(test))]
fn write_raw(bytes: &str) {
    let _ = std::io::stderr().write_all(bytes.as_bytes());
}

/// The test lane's sink: the machine's exact bytes, per test thread.
/// The production path above is the only other writer - the tests
/// pin the draw contract without touching the battery's stderr.
#[cfg(test)]
fn write_raw(bytes: &str) {
    DRAWN.with(|buffer| buffer.borrow_mut().extend_from_slice(bytes.as_bytes()));
}

#[cfg(test)]
thread_local! {
    /// The bytes this test thread's machine drew since the last
    /// clear.
    static DRAWN: std::cell::RefCell<Vec<u8>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// The drawn bytes of this test thread, for the shape pins. The
/// machine's grammar is ASCII, so the bytes are always valid UTF-8.
#[cfg(test)]
fn test_drawn_bytes() -> String {
    DRAWN.with(|buffer| String::from_utf8_lossy(&buffer.borrow()).into_owned())
}

/// Clear the test sink between draws, per test.
#[cfg(test)]
fn test_clear_drawn() {
    DRAWN.with(|buffer| buffer.borrow_mut().clear());
}

/// The whole-second ceiling: a countdown says how many seconds are
/// LEFT, so 9.2s remaining says "10s" and the final fraction says
/// "1s" - the number reaches zero only when the wait does.
fn ceil_secs(remaining: Duration) -> u64 {
    remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)
}

/// The one line shape: "[watching for events... 10s]". One grammar,
/// every surface, no drift - the shape the test pins.
fn countdown_line(label: &str, secs: u64) -> String {
    format!("[{label}... {secs}s]")
}

/// The countdown state machine: one line, drawn when the whole-
/// second count changes, erased entirely at the end. [`wait`] drives
/// it around its deadline slices; port's collection loop drives it
/// around its drain slices. On the gate's off arm every method is a
/// no-op - a piped run pays one gate probe and nothing else.
pub(crate) struct Countdown {
    /// The narration's subject: one of the crate's own ASCII labels.
    label: &'static str,
    /// The gate's verdict, fixed at start.
    active: bool,
    /// The last whole-second count drawn (the ceiling). The next
    /// draw fires only when this changes - one line per second, no
    /// per-slice redraw spam.
    shown: Option<u64>,
    /// The widest line drawn so far: the stable overwrite width.
    /// Every draw pads to it and the clear blanks it, so a shrinking
    /// number never leaves a stray tail on the line.
    width: usize,
}

impl Countdown {
    /// Arm the countdown if the gate allows it, the inert state
    /// otherwise. One gate probe per wait site.
    pub(crate) fn start(label: &'static str) -> Countdown {
        Countdown {
            label,
            active: enabled(),
            shown: None,
            width: 0,
        }
    }

    /// Draw when the whole-second count changed. `remaining` is the
    /// caller's own view of the clock (wait's deadline remainder,
    /// port's loop remainder) - the machine never reads the clock
    /// itself, so the caller's contract over the window stays the
    /// caller's.
    pub(crate) fn update(&mut self, remaining: Duration) {
        if !self.active {
            return;
        }
        let secs = ceil_secs(remaining);
        if self.shown == Some(secs) {
            return;
        }
        let line = countdown_line(self.label, secs);
        self.width = self.width.max(line.len());
        let pad = " ".repeat(self.width - line.len());
        // One write per draw: carriage return, the grey line, then
        // the padding that keeps the overwrite stable.
        write_raw(&format!("\r{}{}", crate::output::grey_err(&line), pad));
        self.shown = Some(secs);
    }

    /// Erase the line entirely: the drawn width blanked with spaces,
    /// the cursor back at column zero, before any ledger prints.
    pub(crate) fn finish(self) {
        if !self.active || self.width == 0 {
            return;
        }
        write_raw(&format!("\r{}\r", " ".repeat(self.width)));
    }
}

#[cfg(test)]
#[path = "../../test/output/spinner_tests.rs"]
mod tests;
