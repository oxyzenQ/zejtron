// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The capability ladder - environment detection and the two lane
//! caches (a pure move out of the output root by night-weekly-
//! maintenance-2, the sibling's own split precedent: zelynic's
//! NIGHT-boost-5 moved the same machinery out of its output root for
//! the owner's LOC cap, and this file is zejtron's same move, same
//! law, zero behavior change).
//!
//! Capability ladder, the sibling's table sized honestly:
//!
//! | Capability | Detection | Encoding |
//! |---|---|---|
//! | TrueColor | `COLORTERM=truecolor/24bit`, `TERM` contains `-direct`/`-truecolor`, or `TERM` names a truecolor-native terminal (alacritty, kitty, ghostty, wezterm, foot, contour) | 24-bit RGB escape |
//! | Color256 | `TERM` contains `256color` | nearest xterm-256 cube index |
//! | Color16 | `CLICOLOR_FORCE=1` with `TERM=dumb`/unset/unrecognized - the forced lane's floor, never a probe verdict | classic ANSI slots, the sibling's netrunner SGRs (the palette renders back to VT100) |
//! | Mono | `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb`/unset, or stderr not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |
//!
//! There is still no probe-driven 16-color rung: an unrecognized
//! `TERM` would make a 16-color guess a lie on the very terminals
//! the rung claims to serve, and Mono (plain text) is the only
//! honest output there. The one Color16 seat is the forced lane's
//! floor (night-improve-37, the sibling's improve-73 law):
//! `CLICOLOR_FORCE=1` is a promise, and before this rung a
//! probe-dead `TERM` (dumb, empty, unrecognized) vetoed the promise
//! and landed the forced lane on Mono - the documented force
//! contract broken exactly where the sibling's had already been
//! fixed. The classic slots render on every terminal back to VT100,
//! so the forced lane never garbles and never lands Mono. The
//! ladder anchors on STDERR's TTY-ness (the sibling's rule): the
//! error lane's surfaces speak through stderr, and a
//! `zejtron ... | grep` pipe on stdout must not cost the error lane
//! its color. `CLICOLOR_FORCE=1` re-arms color for the wrapper
//! scripts and CI logs that capture stderr away from a terminal.
//!
//! Two lanes, one ladder (night-improve-37): zejtron renders through
//! two output streams, and each lane anchors the ladder on its own
//! stream. The STDERR lane (the labeled error blocks in main's gate)
//! keeps the original anchor: a `zejtron ... | grep` pipe on stdout
//! must not cost the error lane its color. The STDOUT lane (every
//! data surface: path, recent, port, proc, holds, touch, why, net,
//! doctor, -V, --check-update) anchors on stdout's TTY-ness through
//! [`stdout_capability`], so a piped stdout renders plain bytes even
//! when stderr keeps its lane - the zero-escape invariant holds on
//! both streams, in both piped combinations. `CLICOLOR_FORCE=1`
//! re-arms either lane for the wrapper scripts and CI logs that
//! capture a stream away from a terminal.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// The color capability this process renders with, detected once.
/// `Color16` is the forced lane's floor only (see the module doc): a
/// probe verdict never lands there, so a plain `TERM` stays Mono and
/// only `CLICOLOR_FORCE=1` over a probe-dead `TERM` reaches the
/// classic palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorCapability {
    TrueColor,
    Color256,
    Color16,
    Mono,
}

/// Pure capability classification: the ladder as data, testable
/// without env mutation. Production reads the real environment once
/// through [`capability`] (the stderr lane) and [`stdout_capability`]
/// (the stdout lane) - the stream's own TTY-ness is the only input
/// that differs between the two lanes.
pub(crate) fn classify(
    no_color: bool,
    clicolor_zero: bool,
    clicolor_force: bool,
    colorterm: Option<&str>,
    term: Option<&str>,
    stream_tty: bool,
) -> ColorCapability {
    if no_color {
        return ColorCapability::Mono;
    }
    if clicolor_zero {
        return ColorCapability::Mono;
    }
    if !clicolor_force && !stream_tty {
        return ColorCapability::Mono;
    }
    let term = term.unwrap_or("");
    if term == "dumb" || term.is_empty() {
        // The forced lane's floor (night-improve-37, the
        // sibling's improve-73 law): CLICOLOR_FORCE=1 promised
        // color, so a probe-dead TERM must not veto the promise.
        // The classic palette renders on every terminal back to
        // VT100 - the forced lane lands Color16, never Mono.
        if clicolor_force {
            return ColorCapability::Color16;
        }
        return ColorCapability::Mono;
    }
    let colorterm_truecolor =
        matches!(colorterm, Some(c) if c.eq_ignore_ascii_case("truecolor") || c == "24bit");
    let term_native_truecolor = [
        "alacritty",
        "kitty",
        "ghostty",
        "wezterm",
        "foot",
        "contour",
    ]
    .iter()
    .any(|name| term.contains(name));
    if colorterm_truecolor
        || term.contains("-direct")
        || term.contains("-truecolor")
        || term_native_truecolor
    {
        return ColorCapability::TrueColor;
    }
    if term.contains("256color") {
        return ColorCapability::Color256;
    }
    // Unrecognized non-dumb TERM: the non-forced ladder keeps the
    // documented Mono stance (a 16-color guess would be a lie on
    // the very terminals it claims to serve); the forced lane
    // takes the classic-palette floor instead.
    if clicolor_force {
        return ColorCapability::Color16;
    }
    ColorCapability::Mono
}

/// The detected capability, cached for the process lifetime. The
/// environment cannot change mid-run in any honest terminal session,
/// so one detection is one truth.
pub(crate) fn capability() -> ColorCapability {
    static CAPABILITY: OnceLock<ColorCapability> = OnceLock::new();
    *CAPABILITY.get_or_init(|| {
        let env_flag = |key: &str| std::env::var_os(key).is_some_and(|v| !v.is_empty());
        let env_value = |key: &str| std::env::var(key).ok();
        classify(
            env_flag("NO_COLOR"),
            env_flag("CLICOLOR") && std::env::var("CLICOLOR").is_ok_and(|v| v == "0"),
            color_forced(),
            env_value("COLORTERM").as_deref(),
            env_value("TERM").as_deref(),
            std::io::stderr().is_terminal(),
        )
    })
}

/// The detected capability for the STDOUT lane, cached for the
/// process lifetime. The data surfaces speak through stdout, so their
/// paint decisions anchor on stdout's own TTY-ness - the same env
/// ladder, the stream's own verdict (night-improve-37's two-lane
/// law). A piped stdout renders plain bytes even when stderr keeps
/// its lane, so piped output carries zero escape bytes regardless of
/// what stderr is doing.
pub(crate) fn stdout_capability() -> ColorCapability {
    static CAPABILITY: OnceLock<ColorCapability> = OnceLock::new();
    *CAPABILITY.get_or_init(|| {
        let env_flag = |key: &str| std::env::var_os(key).is_some_and(|v| !v.is_empty());
        let env_value = |key: &str| std::env::var(key).ok();
        classify(
            env_flag("NO_COLOR"),
            env_flag("CLICOLOR") && std::env::var("CLICOLOR").is_ok_and(|v| v == "0"),
            color_forced(),
            env_value("COLORTERM").as_deref(),
            env_value("TERM").as_deref(),
            std::io::stdout().is_terminal(),
        )
    })
}

/// The process-wide mono override (night-improve-37): an explicit
/// in-band ask for plain bytes - the proc surface's `--no-color`
/// flag - forces BOTH lanes Mono no matter what the ladders detected
/// or cached. The flag is a promise to the pipe, and a promise beats
/// a probe: paint points consult this switch before any tier opens.
static MONO_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// Force plain bytes for the rest of the process: every tier wrapper
/// on both lanes becomes the identity, and no paint gate reports
/// paintable. Idempotent; there is no re-arm (an explicit ask for
/// plain output stays plain).
pub(crate) fn disable_color() {
    MONO_OVERRIDE.store(true, Ordering::Relaxed);
}

/// The mono override's read side: the wrappers and the paint gate in
/// the output root consult this before any tier opens.
pub(crate) fn mono_overridden() -> bool {
    MONO_OVERRIDE.load(Ordering::Relaxed)
}

/// The CLICOLOR_FORCE contract: any non-empty value except "0".
/// One predicate, two consumers - the capability probe and the help
/// surface's stdout gate (the force flag promises color bytes even
/// when the stream is captured away from a terminal).
pub(crate) fn color_forced() -> bool {
    std::env::var("CLICOLOR_FORCE")
        .ok()
        .is_some_and(|v| !v.is_empty() && v != "0")
}
