// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The runtime color tier - capability detection and the branded
//! escape sequences every runtime surface renders: the labeled error
//! gate in main through the STDERR lane's red wrappers, and every
//! data surface (the doctor verdict rows, the update check's status
//! word, the version report, the evidence ledgers) through the STDOUT
//! lane's role wrappers below. The clap lane (help, usage, clap
//! errors, typo suggestions) is a separate surface with its own
//! module: [`crate::cli::styles`] paints what clap renders; this
//! module paints what zejtron renders itself. One palette across
//! both: the sibling contract.
//!
//! Owner color contract (the sibling project's output law): error
//! red #FF5A5A (255,90,90), warning yellow #FFEB3C (255,235,60),
//! status green #50FA7B (80,250,123). Brand purple #A855F7 rides the
//! clap heading tier via [`crate::cli::styles`] and has exactly one
//! runtime seat: the `-V` version-report header (the sibling's
//! masterclass layout) - nothing else on this lane paints purple.
//!
//! Capability ladder, the sibling's table sized honestly:
//!
//! | Capability | Detection | Encoding |
//! |---|---|---|
//! | TrueColor | `COLORTERM=truecolor/24bit`, `TERM` contains `-direct`/`-truecolor`, or `TERM` names a truecolor-native terminal (alacritty, kitty, ghostty, wezterm, foot, contour) | 24-bit RGB escape |
//! | Color256 | `TERM` contains `256color` | nearest xterm-256 cube index |
//! | Color16 | `CLICOLOR_FORCE=1` with `TERM=dumb`/unset/unrecognized - the forced lane's floor, never a probe verdict | classic ANSI bright slots (the palette renders back to VT100) |
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
//! fixed. The classic bright slots render on every terminal back to
//! VT100, so the forced lane never garbles and never lands Mono.
//! The ladder anchors on STDERR's TTY-ness (the sibling's rule):
//! this lane's surfaces speak through stderr, and a
//! `zejtron ... | grep` pipe on stdout must not cost the error lane
//! its color. `CLICOLOR_FORCE=1` re-arms color for the wrapper
//! scripts and CI logs that capture stderr away from a terminal.
//!
//! Every wrapper short-circuits Mono to the plain message - no
//! escape concatenation, no styled bytes that would never render,
//! piped output stays byte-clean for grep.
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
//! capture a stream away from a terminal. The white tier needs no
//! wrapper at all: values render in the terminal default, so the
//! data the user came for is the one thing this module never paints.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Error red RGB: #FF5A5A (255,90,90) - the owner's error tier.
/// 256-color fallback: index 203 (16 + 36*5 + 6*1 + 1, the closest
/// cube match: 255 sits on cube level 5, 90 on level 1).
///
/// cfg(test): the tier's production opens are the static strings
/// enumerated in [`Tier::open`] (const fn string building is not a
/// thing), so the constants exist as the documented source of truth
/// and the consistency test pins the literals to them - the sibling
/// module's pattern for exactly this situation.
#[cfg(test)]
const ERROR_RGB: (u8, u8, u8) = (255, 90, 90);
#[cfg(test)]
const ERROR_256: u8 = 203;

/// Warning yellow RGB: #FFEB3C (255,235,60) - the owner's warning
/// tier. 256-color fallback: index 227 (16 + 36*5 + 6*5 + 1; 235
/// sits exactly between cube levels 4 and 5 and the ladder takes the
/// brighter 5, keeping the tier's high-luminance intent).
#[cfg(test)]
const WARN_RGB: (u8, u8, u8) = (255, 235, 60);
#[cfg(test)]
const WARN_256: u8 = 227;

/// Status green RGB: #50FA7B (80,250,123) - affirmative verdicts.
/// 256-color fallback: index 84 (16 + 36*1 + 6*5 + 2), the same
/// index the sibling's ladder carries for this tier.
#[cfg(test)]
const OK_RGB: (u8, u8, u8) = (80, 250, 123);
#[cfg(test)]
const OK_256: u8 = 84;

/// Brand purple RGB: #A855F7 (168,85,247) - the one runtime seat is
/// the `-V` version-report header. 256-color fallback: index 135,
/// the exact cube index the sibling's default theme (Netrunner,
/// Slot::Brand) renders for the same RGB - one purple across the
/// family, same value on every rung.
#[cfg(test)]
const BRAND_RGB: (u8, u8, u8) = (168, 85, 247);
#[cfg(test)]
const BRAND_256: u8 = 135;

/// Calm grey RGB: #8B8B8B (139,139,139) - the grammar tier (the
/// sibling's flag-row law): typeable flag spellings on the help
/// surfaces ride this tier wherever they appear, dimmer than the
/// data they annotate. 256-color fallback: index 245 (the nearest
/// grey-ramp rung). Color16 floor: bright black (90), the palette's
/// only honest grey.
#[cfg(test)]
const GRAMMAR_RGB: (u8, u8, u8) = (139, 139, 139);
#[cfg(test)]
const GRAMMAR_256: u8 = 245;

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

/// The owner's color tiers on the runtime lane. Each tier carries its
/// RGB constant (the source of truth), its nearest 256-cube index,
/// and the static escape strings per capability - the consistency
/// test below pins them together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Error,
    Warn,
    Ok,
    Brand,
    Grammar,
}

impl Tier {
    /// Test-side accessors: the constants above are cfg(test), so
    /// these ride the same gate (the consistency test reads the
    /// source-of-truth values through them).
    #[cfg(test)]
    fn rgb(self) -> (u8, u8, u8) {
        match self {
            Tier::Error => ERROR_RGB,
            Tier::Warn => WARN_RGB,
            Tier::Ok => OK_RGB,
            Tier::Brand => BRAND_RGB,
            Tier::Grammar => GRAMMAR_RGB,
        }
    }

    #[cfg(test)]
    fn index_256(self) -> u8 {
        match self {
            Tier::Error => ERROR_256,
            Tier::Warn => WARN_256,
            Tier::Ok => OK_256,
            Tier::Brand => BRAND_256,
            Tier::Grammar => GRAMMAR_256,
        }
    }

    /// The foreground escape prefix for this tier at this capability,
    /// bold or regular. Enumerated as static strings - no runtime
    /// formatting, no allocation, and the RGB/256 constants above
    /// stay pinned to the literals by the consistency test.
    fn open(self, cap: ColorCapability, bold: bool) -> &'static str {
        match (cap, self, bold) {
            (ColorCapability::TrueColor, Tier::Error, false) => "\x1b[38;2;255;90;90m",
            (ColorCapability::TrueColor, Tier::Error, true) => "\x1b[1;38;2;255;90;90m",
            (ColorCapability::TrueColor, Tier::Warn, false) => "\x1b[38;2;255;235;60m",
            (ColorCapability::TrueColor, Tier::Warn, true) => "\x1b[1;38;2;255;235;60m",
            (ColorCapability::TrueColor, Tier::Ok, false) => "\x1b[38;2;80;250;123m",
            (ColorCapability::TrueColor, Tier::Ok, true) => "\x1b[1;38;2;80;250;123m",
            (ColorCapability::TrueColor, Tier::Brand, false) => "\x1b[38;2;168;85;247m",
            (ColorCapability::TrueColor, Tier::Brand, true) => "\x1b[1;38;2;168;85;247m",
            (ColorCapability::Color256, Tier::Error, false) => "\x1b[38;5;203m",
            (ColorCapability::Color256, Tier::Error, true) => "\x1b[1;38;5;203m",
            (ColorCapability::Color256, Tier::Warn, false) => "\x1b[38;5;227m",
            (ColorCapability::Color256, Tier::Warn, true) => "\x1b[1;38;5;227m",
            (ColorCapability::Color256, Tier::Ok, false) => "\x1b[38;5;84m",
            (ColorCapability::Color256, Tier::Ok, true) => "\x1b[1;38;5;84m",
            (ColorCapability::Color256, Tier::Brand, false) => "\x1b[38;5;135m",
            (ColorCapability::Color256, Tier::Brand, true) => "\x1b[1;38;5;135m",
            // The forced lane's floor (night-improve-37): the
            // classic bright slots, the aixterm additions every
            // VT100-era terminal speaks. No RGB here - a
            // probe-dead terminal's palette is unknown, and the
            // classic slots are the only encoding that never
            // garbles on one.
            (ColorCapability::Color16, Tier::Error, false) => "\x1b[91m",
            (ColorCapability::Color16, Tier::Error, true) => "\x1b[1;91m",
            (ColorCapability::Color16, Tier::Warn, false) => "\x1b[93m",
            (ColorCapability::Color16, Tier::Warn, true) => "\x1b[1;93m",
            (ColorCapability::Color16, Tier::Ok, false) => "\x1b[92m",
            (ColorCapability::Color16, Tier::Ok, true) => "\x1b[1;92m",
            (ColorCapability::Color16, Tier::Brand, false) => "\x1b[95m",
            (ColorCapability::Color16, Tier::Brand, true) => "\x1b[1;95m",
            // The grammar tier (night-improve-38, the sibling's
            // flag-row law): dimmer than the data it annotates,
            // bright black (90) at the Color16 floor - the
            // palette's only honest grey.
            (ColorCapability::TrueColor, Tier::Grammar, false) => "\x1b[38;2;139;139;139m",
            (ColorCapability::TrueColor, Tier::Grammar, true) => "\x1b[1;38;2;139;139;139m",
            (ColorCapability::Color256, Tier::Grammar, false) => "\x1b[38;5;245m",
            (ColorCapability::Color256, Tier::Grammar, true) => "\x1b[1;38;5;245m",
            (ColorCapability::Color16, Tier::Grammar, false) => "\x1b[90m",
            (ColorCapability::Color16, Tier::Grammar, true) => "\x1b[1;90m",
            (ColorCapability::Mono, _, _) => "",
        }
    }
}

/// Pure capability classification: the ladder as data, testable
/// without env mutation. Production reads the real environment once
/// through [`capability`] (the stderr lane) and [`stdout_capability`]
/// (the stdout lane) - the stream's own TTY-ness is the only input
/// that differs between the two lanes.
fn classify(
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

fn mono_overridden() -> bool {
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

/// The reset sequence: closes any open color/style. Empty in Mono so
/// piped output never carries stray escape bytes.
pub(crate) fn reset() -> &'static str {
    reset_for(capability())
}

/// The reset sequence for a known capability: the same bytes the lane
/// wrappers pair with their opens, so one capability governs the
/// whole painted segment. Empty in Mono and under the mono override.
fn reset_for(cap: ColorCapability) -> &'static str {
    match cap {
        ColorCapability::Mono => "",
        _ if mono_overridden() => "",
        _ => "\x1b[0m",
    }
}

/// Wrap `msg` in the tier's color (regular weight) on the STDERR
/// lane. Plain text when color is off.
fn wrap(msg: &str, tier: Tier) -> String {
    wrap_on(msg, tier, capability())
}

/// Wrap `msg` in the tier's color for a known capability - the one
/// paint point every lane's wrapper rides. Plain text in Mono and
/// under the mono override; the open and the reset always ride the
/// same capability, so a painted segment never mixes rungs.
fn wrap_on(msg: &str, tier: Tier, cap: ColorCapability) -> String {
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ if mono_overridden() => msg.to_owned(),
        _ => format!("{}{msg}{}", tier.open(cap, false), reset_for(cap)),
    }
}

/// True when the STDOUT lane may carry escape bytes: the capability
/// ladder says color for stdout AND the mono override is off. The one
/// shared paint gate of the stdout lane: the help surface's
/// self-painted regions (the Pro mode section, the example rows) and
/// every data surface answer to the same predicate, so one render
/// never mixes painted and plain halves.
pub(crate) fn stdout_paintable() -> bool {
    !mono_overridden() && stdout_capability() != ColorCapability::Mono
}

/// Wrap `msg` in error red (regular weight). Plain text when color
/// is off. The stderr lane's one regular-weight wrapper: the labeled
/// error block is the only regular-red seat on that lane.
pub(crate) fn error(msg: &str) -> String {
    wrap(msg, Tier::Error)
}

/// Wrap `msg` in bold error red. The label tier: the `error:` token
/// on the runtime error lane.
pub(crate) fn error_bold(msg: &str) -> String {
    let cap = capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ => format!("{}{msg}{}", Tier::Error.open(cap, true), reset()),
    }
}

// The stderr lane's affirmative/warning/brand wrappers rode out with
// night-improve-37's lane corrections: their last users (the doctor
// verdict rows, the update status word, the version header) speak
// through stdout and moved to the stdout-lane wrappers below, and a
// wrapper nobody calls is dead weight under -D warnings. The stderr
// lane keeps the red pair it uses ([`error`], [`error_bold`]); the
// green, grey, yellow, and purple seats all live on the stdout lane
// now, each anchored on the stream its surface speaks through.

// ── The stdout lane's tier wrappers (night-improve-37) ─────────────
//
// The data surfaces (path, recent, port, proc, holds, touch, why,
// net, doctor, -V, --check-update) speak through stdout, so their
// paint decisions anchor on [`stdout_capability`] - the same env
// ladder, the stream's own TTY-ness. In Mono (a piped stdout without
// the force flag, NO_COLOR, CLICOLOR=0) every wrapper here is the
// identity, byte-identical to the plain render the tests pin.
//
// The role law every surface applies: GREEN (the Ok tier) carries the
// primary content - section headers, field labels, verb names,
// verdict labels, the strongest provenance tags; GREY (the Grammar
// tier) carries the secondary content - mode lines, hints,
// timestamps, the weaker provenance tags, example lines, footer
// text, the "no events" line; WHITE is the terminal default and is
// NEVER wrapped - values (measurements, byte counts, PIDs, comm
// names, percentages) are the data the user came for. Errors keep
// their red seat (error_out) and warnings their yellow (warn_out)
// wherever a data surface carries one; the -V header keeps its one
// brand-purple seat (brand_out).

/// Wrap `msg` in status green for the stdout lane - section headers,
/// field labels, verdict labels, the strongest provenance tags.
pub(crate) fn ok_out(msg: &str) -> String {
    wrap_on(msg, Tier::Ok, stdout_capability())
}

/// Wrap `msg` in the calm-grey grammar tier for the stdout lane -
/// mode lines, hints, timestamps, tree glyphs, the weaker provenance
/// tags, footer text.
pub(crate) fn grey_out(msg: &str) -> String {
    wrap_on(msg, Tier::Grammar, stdout_capability())
}

/// Wrap `msg` in warning yellow for the stdout lane. Plain text when
/// color is off.
pub(crate) fn warn_out(msg: &str) -> String {
    wrap_on(msg, Tier::Warn, stdout_capability())
}

/// Wrap `msg` in error red for the stdout lane - the data surfaces'
/// error-shaped findings (the FAIL status label). The stderr error
/// lane keeps its own wrappers ([`error`], [`error_bold`]).
pub(crate) fn error_out(msg: &str) -> String {
    wrap_on(msg, Tier::Error, stdout_capability())
}

/// Wrap `msg` in brand purple for the stdout lane - the `-V`
/// version-report header, the tier's one runtime seat.
pub(crate) fn brand_out(msg: &str) -> String {
    wrap_on(msg, Tier::Brand, stdout_capability())
}

/// Print a labeled error block to stderr: `error: <msg>` with the
/// label bold red and the body red, line-aware. Every runtime error
/// that reaches main's gate flows through here, so all runtime
/// errors share one branded shape - the same `error:` label clap's
/// own surface already renders, in the same red the clap lane paints.
///
/// ASCII label only - icon glyphs render as tofu on some terminals
/// and the repo-wide gate forbids them anyway. Continuation lines
/// indent under the body so a multi-line error keeps one block shape.
pub(crate) fn eprintln_error_labeled(msg: &str) {
    let mut block = String::new();
    for (i, line) in msg.lines().enumerate() {
        if i == 0 {
            block.push_str(&format!("{} {}\n", error_bold("error:"), error(line)));
        } else {
            block.push_str(&format!("       {}\n", error(line)));
        }
    }
    let block = block.trim_end_matches('\n');
    eprintln!("{block}");
}

#[cfg(test)]
#[path = "../../test/output/output_tests.rs"]
mod tests;
