// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The runtime color tier - the branded escape sequences every
//! runtime surface renders: the labeled error
//! gate in main through the STDERR lane's red wrappers, and every
//! data surface (the doctor verdict rows, the update check's status
//! word, the version report, the evidence ledgers) through the STDOUT
//! lane's role wrappers below. The clap lane (help, usage, clap
//! errors, typo suggestions) is a separate surface with its own
//! module: [`crate::cli::styles`] paints what clap renders; this
//! module paints what zejtron renders itself. One palette across
//! both: the sibling contract. The capability ladder underneath -
//! the environment probe, the two lane caches, the mono override -
//! lives in [`capability`] (the sibling's own split law, one concern
//! per file).
//!
//! Owner color contract (the sibling project's output law): error
//! red #FF5A5A (255,90,90), warning yellow #FFEB3C (255,235,60),
//! status green #50FA7B (80,250,123). Brand purple #A855F7 rides the
//! clap heading tier via [`crate::cli::styles`]; on the runtime lane
//! it carries the report frame (night-weekly-maintenance-2, the
//! sibling's masterclass law): every report surface opens with the
//! `━━━ ... ━━━` banner in bold purple, and the `-V` version-report
//! header keeps its seat. The bold wrappers are the verdict seats
//! (the sibling doctor's law): status tokens and verdict words ride
//! the bold tiers, KV keys stay plain - keys are the frame, never
//! the paint.
//!
//! Every wrapper short-circuits Mono to the plain message - no
//! escape concatenation, no styled bytes that would never render,
//! piped output stays byte-clean for grep.

mod capability;

pub(crate) use capability::{
    ColorCapability, capability, disable_color, mono_overridden, stdout_capability,
};
// The pure ladder-as-data classifier is the output tests' probe; the
// production caches consume it inside the capability module.
#[cfg(test)]
pub(crate) use capability::classify;

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
/// tier. 256-color fallback: index 220, the sibling's exact Warn
/// rung (the visibility precedent: the saturated corner wins over
/// the exact match when the hue family holds - night-weekly-
/// maintenance-2 aligns every rung to the sibling's ladder).
#[cfg(test)]
const WARN_RGB: (u8, u8, u8) = (255, 235, 60);
#[cfg(test)]
const WARN_256: u8 = 220;

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
            (ColorCapability::Color256, Tier::Warn, false) => "\x1b[38;5;220m",
            (ColorCapability::Color256, Tier::Warn, true) => "\x1b[1;38;5;220m",
            (ColorCapability::Color256, Tier::Ok, false) => "\x1b[38;5;84m",
            (ColorCapability::Color256, Tier::Ok, true) => "\x1b[1;38;5;84m",
            (ColorCapability::Color256, Tier::Brand, false) => "\x1b[38;5;135m",
            (ColorCapability::Color256, Tier::Brand, true) => "\x1b[1;38;5;135m",
            // The forced lane's floor (night-improve-37), now the
            // sibling's exact SGR slots (night-weekly-maintenance-2,
            // the one-ladder law): brand rides magenta (35), ok
            // green (32), warn yellow (33), error red (31) - the
            // netrunner slots, regular weight, the same encoding the
            // sibling's 16-color rung renders for the same tiers.
            // Grey keeps its bright slot (90, the palette's only
            // honest grey) - the one bright seat the sibling also
            // carries. No RGB here - a probe-dead terminal's palette
            // is unknown, and the classic slots are the only encoding
            // that never garbles on one.
            (ColorCapability::Color16, Tier::Error, false) => "\x1b[31m",
            (ColorCapability::Color16, Tier::Error, true) => "\x1b[1;31m",
            (ColorCapability::Color16, Tier::Warn, false) => "\x1b[33m",
            (ColorCapability::Color16, Tier::Warn, true) => "\x1b[1;33m",
            (ColorCapability::Color16, Tier::Ok, false) => "\x1b[32m",
            (ColorCapability::Color16, Tier::Ok, true) => "\x1b[1;32m",
            (ColorCapability::Color16, Tier::Brand, false) => "\x1b[35m",
            (ColorCapability::Color16, Tier::Brand, true) => "\x1b[1;35m",
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
// their red seat on the data lane through the BOLD verdict wrapper
// ([`error_bold_out`], the doctor's FAIL seat) and on the stderr
// lane through the labeled pair; warnings their yellow (warn_out,
// warn_bold_out) wherever a data surface carries one; the -V header
// keeps its one brand-purple seat (brand_out).
//
// The report frame (night-weekly-maintenance-2, the sibling
// doctor's masterclass law, now shared verbatim): a report surface
// opens with [`banner`] - the `━━━ ... ━━━` title line in bold
// purple - and lays its facts out as KV rows whose KEYS stay plain
// (aligned to one column) while the VALUES carry the tiers. Verdict
// tokens (OK/WARN/FAIL, YES-style words, status words) ride the
// BOLD tiers ([`ok_bold_out`], [`warn_bold_out`],
// [`error_bold_out`]) exactly as the sibling doctor paints
// YES/NO/SUPPORTED; regular-weight tiers keep the seats they
// already hold on the tree and evidence surfaces.

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

// The regular-weight error wrapper rode out with night-weekly-
// maintenance-2: its last caller (the doctor's FAIL row) moved to
// the bold verdict seat ([`error_bold_out`], the sibling doctor's
// verdict law), and a wrapper nobody calls is dead weight under
// -D warnings - the same rule that retired the stderr lane's
// uncalled affirmative wrappers in night-improve-37. A future
// error-shaped finding on a data surface takes the bold seat.

/// Wrap `msg` in brand purple for the stdout lane - the `-V`
/// version-report header, the tier's one runtime seat.
pub(crate) fn brand_out(msg: &str) -> String {
    wrap_on(msg, Tier::Brand, stdout_capability())
}

// ── The bold verdict seats (night-weekly-maintenance-2) ────────────
//
// The sibling doctor paints its verdicts BOLD (YES in bold green,
// NO in bold red, the Warnings: label in bold yellow) - a verdict
// must out-shout the facts around it. These wrappers are zejtron's
// same seats on the stdout lane: the doctor's status tokens, the
// update check's status word, the [eBPF] section's verdict tokens.
// In Mono every wrapper is the identity, byte-identical to the
// pinned plain shapes.

/// Wrap `msg` in BOLD status green for the stdout lane - the
/// affirmative verdict token seat (the doctor's OK, the update
/// check's "up to date", the [eBPF] section's live/present/enabled).
pub(crate) fn ok_bold_out(msg: &str) -> String {
    let cap = stdout_capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ if mono_overridden() => msg.to_owned(),
        _ => format!("{}{msg}{}", Tier::Ok.open(cap, true), reset_for(cap)),
    }
}

/// Wrap `msg` in BOLD warning yellow for the stdout lane - the
/// attention verdict token seat (the doctor's WARN, a degraded
/// [eBPF] verdict, the Warnings-style label).
pub(crate) fn warn_bold_out(msg: &str) -> String {
    let cap = stdout_capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ if mono_overridden() => msg.to_owned(),
        _ => format!("{}{msg}{}", Tier::Warn.open(cap, true), reset_for(cap)),
    }
}

/// Wrap `msg` in BOLD error red for the stdout lane - the negative
/// verdict token seat (the doctor's FAIL).
pub(crate) fn error_bold_out(msg: &str) -> String {
    let cap = stdout_capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ if mono_overridden() => msg.to_owned(),
        _ => format!("{}{msg}{}", Tier::Error.open(cap, true), reset_for(cap)),
    }
}

/// Wrap `msg` in BOLD brand purple for the stdout lane - the report
/// banner seat. The banner is the family's report frame: one title
/// line, one purple, every report surface.
pub(crate) fn brand_bold_out(msg: &str) -> String {
    let cap = stdout_capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ if mono_overridden() => msg.to_owned(),
        _ => format!("{}{msg}{}", Tier::Brand.open(cap, true), reset_for(cap)),
    }
}

/// The report banner: the family's one title-line shape, the
/// sibling's `━━━ <title> ━━━` in bold purple. Every report surface
/// opens with this exact frame - doctor, the update check, every
/// future report - so the family reads as one family.
pub(crate) fn banner(title: &str) -> String {
    brand_bold_out(&format!("━━━ {title} ━━━"))
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
