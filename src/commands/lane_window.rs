// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The event-window resolver (night-witness-pids moved it here - a
//! PURE move under the 600-LOC cap, the lane_unaccounted.rs sibling
//! precedent): the one place a `--since` argument becomes the window
//! and its label, so every event-window surface resolves the same
//! grammar and the default can never drift between them.

use std::time::Duration;

/// The default window for holds/touch/why (the spec's lock): short
/// enough that the live lane's collection-over-duration stays quick,
/// long enough to catch the common "who just touched this".
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(10);

/// Resolve a `--since` argument into the window and its label: the
/// port surface's own grammar (`s`/`m`/`h`, clamped [1s, 1h] - one
/// grammar, two surfaces, imported rather than duplicated), with
/// the 10s default when the flag is absent. Every surface resolves
/// through here so the default can never drift between them. An
/// out-of-bounds ask - above the ceiling or below the floor - rides
/// one stderr warning (the clamp note, night-dragon-lts-T1
/// residual, both directions since night-total-hardening-1) and
/// never touches stdout.
pub fn resolve_window(since: Option<&str>) -> Result<(Duration, String), String> {
    use crate::commands::port::window::{
        clamp_window, parse_window, truncation_note, window_label,
    };
    let window = match since {
        Some(raw) => {
            let parsed = parse_window(raw).map_err(|e| format!("{e}"))?;
            if let Some(note) = truncation_note(raw, parsed) {
                eprintln!("{note}");
            }
            clamp_window(parsed)
        }
        None => WINDOW_DEFAULT,
    };
    let label = window_label(window);
    Ok((window, label))
}

#[cfg(test)]
#[path = "../../test/commands/lane_window_tests.rs"]
mod tests;
