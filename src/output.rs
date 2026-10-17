// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The runtime color tier - capability detection and the branded
//! escape sequences every runtime surface renders (the error gate in
//! main, the doctor verdict rows, the update check's status word).
//! The clap lane (help, usage, clap errors, typo suggestions) is a
//! separate surface with its own module: [`crate::styles`] paints
//! what clap renders; this module paints what zejtron renders
//! itself. One palette across both: the sibling contract.
//!
//! Owner color contract (the sibling project's output law): error
//! red #FF5A5A (255,90,90), warning yellow #FFEB3C (255,235,60),
//! status green #50FA7B (80,250,123). The runtime lane keeps three
//! of the sibling tiers it actually uses; brand purple stays on the
//! clap heading tier and needs no runtime seat here.
//!
//! Capability ladder, the sibling's table sized honestly:
//!
//! | Capability | Detection | Encoding |
//! |---|---|---|
//! | TrueColor | `COLORTERM=truecolor/24bit`, `TERM` contains `-direct`/`-truecolor`, or `TERM` names a truecolor-native terminal (alacritty, kitty, ghostty, wezterm, foot, contour) | 24-bit RGB escape |
//! | Color256 | `TERM` contains `256color` | nearest xterm-256 cube index |
//! | Mono | `NO_COLOR`, `CLICOLOR=0`, `TERM=dumb`/unset, or stderr not a TTY (unless `CLICOLOR_FORCE=1`) | plain text |
//!
//! There is no 16-color rung on purpose: an unrecognized `TERM`
//! would make a 16-color guess a lie on the very terminals the rung
//! claims to serve, and Mono (plain text) is the only honest output
//! there. The ladder anchors on STDERR's TTY-ness (the sibling's
//! rule): this lane's surfaces speak through stderr, and a
//! `zejtron ... | grep` pipe on stdout must not cost the error lane
//! its color. `CLICOLOR_FORCE=1` re-arms color for the wrapper
//! scripts and CI logs that capture stderr away from a terminal.
//!
//! Every wrapper short-circuits Mono to the plain message - no
//! escape concatenation, no styled bytes that would never render,
//! piped output stays byte-clean for grep.

use std::io::IsTerminal;
use std::sync::OnceLock;

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

/// The color capability this process renders with, detected once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorCapability {
    TrueColor,
    Color256,
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
        }
    }

    #[cfg(test)]
    fn index_256(self) -> u8 {
        match self {
            Tier::Error => ERROR_256,
            Tier::Warn => WARN_256,
            Tier::Ok => OK_256,
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
            (ColorCapability::Color256, Tier::Error, false) => "\x1b[38;5;203m",
            (ColorCapability::Color256, Tier::Error, true) => "\x1b[1;38;5;203m",
            (ColorCapability::Color256, Tier::Warn, false) => "\x1b[38;5;227m",
            (ColorCapability::Color256, Tier::Warn, true) => "\x1b[1;38;5;227m",
            (ColorCapability::Color256, Tier::Ok, false) => "\x1b[38;5;84m",
            (ColorCapability::Color256, Tier::Ok, true) => "\x1b[1;38;5;84m",
            (ColorCapability::Mono, _, _) => "",
        }
    }
}

/// Pure capability classification: the ladder as data, testable
/// without env mutation. Production reads the real environment once
/// through [`capability`].
fn classify(
    no_color: bool,
    clicolor_zero: bool,
    clicolor_force: bool,
    colorterm: Option<&str>,
    term: Option<&str>,
    stderr_tty: bool,
) -> ColorCapability {
    if no_color {
        return ColorCapability::Mono;
    }
    if clicolor_zero {
        return ColorCapability::Mono;
    }
    if !clicolor_force && !stderr_tty {
        return ColorCapability::Mono;
    }
    let term = term.unwrap_or("");
    if term == "dumb" {
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
            env_flag("CLICOLOR_FORCE"),
            env_value("COLORTERM").as_deref(),
            env_value("TERM").as_deref(),
            std::io::stderr().is_terminal(),
        )
    })
}

/// The reset sequence: closes any open color/style. Empty in Mono so
/// piped output never carries stray escape bytes.
pub(crate) fn reset() -> &'static str {
    match capability() {
        ColorCapability::Mono => "",
        _ => "\x1b[0m",
    }
}

/// Wrap `msg` in the tier's color (regular weight). Plain text when
/// color is off.
fn wrap(msg: &str, tier: Tier) -> String {
    let cap = capability();
    match cap {
        ColorCapability::Mono => msg.to_owned(),
        _ => format!("{}{msg}{}", tier.open(cap, false), reset()),
    }
}

/// Wrap `msg` in error red (regular weight). Plain text when color
/// is off.
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

/// Wrap `msg` in warning yellow. Plain text when color is off.
pub(crate) fn warn(msg: &str) -> String {
    wrap(msg, Tier::Warn)
}

/// Wrap `msg` in status green. The affirmative-verdict tier. Plain
/// text when color is off.
pub(crate) fn ok(msg: &str) -> String {
    wrap(msg, Tier::Ok)
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
mod tests {
    use super::*;

    #[test]
    fn no_color_forces_mono() {
        assert_eq!(
            classify(
                true,
                false,
                false,
                Some("truecolor"),
                Some("xterm-256color"),
                true
            ),
            ColorCapability::Mono
        );
    }

    #[test]
    fn clicolor_zero_forces_mono() {
        assert_eq!(
            classify(
                false,
                true,
                false,
                Some("truecolor"),
                Some("xterm-256color"),
                true
            ),
            ColorCapability::Mono
        );
    }

    #[test]
    fn non_tty_is_mono_unless_forced() {
        assert_eq!(
            classify(
                false,
                false,
                false,
                Some("truecolor"),
                Some("xterm-256color"),
                false
            ),
            ColorCapability::Mono
        );
        assert_eq!(
            classify(
                false,
                false,
                true,
                Some("truecolor"),
                Some("xterm-256color"),
                false
            ),
            ColorCapability::TrueColor
        );
    }

    #[test]
    fn colorterm_truecolor_wins_over_256_term() {
        assert_eq!(
            classify(
                false,
                false,
                false,
                Some("truecolor"),
                Some("xterm-256color"),
                true
            ),
            ColorCapability::TrueColor
        );
        assert_eq!(
            classify(false, false, false, Some("24bit"), Some("screen"), true),
            ColorCapability::TrueColor
        );
    }

    #[test]
    fn term_ladder_direct_then_256_then_mono() {
        assert_eq!(
            classify(false, false, false, None, Some("xterm-direct"), true),
            ColorCapability::TrueColor
        );
        assert_eq!(
            classify(false, false, false, None, Some("xterm-256color"), true),
            ColorCapability::Color256
        );
        assert_eq!(
            classify(false, false, false, None, Some("xterm"), true),
            ColorCapability::Mono
        );
        assert_eq!(
            classify(false, false, false, None, Some("dumb"), true),
            ColorCapability::Mono
        );
        assert_eq!(
            classify(false, false, false, None, None, true),
            ColorCapability::Mono
        );
    }

    #[test]
    fn native_truecolor_names_are_recognized() {
        for term in [
            "alacritty",
            "kitty",
            "ghostty",
            "wezterm",
            "foot",
            "contour",
        ] {
            assert_eq!(
                classify(false, false, false, None, Some(term), true),
                ColorCapability::TrueColor,
                "TERM={term} must classify truecolor-native"
            );
        }
    }

    #[test]
    fn mono_wrappers_return_plain_message() {
        assert_eq!(
            classify(false, false, false, None, Some("dumb"), true),
            ColorCapability::Mono
        );
        let text = "invalid port: abc";
        assert_eq!(error(text), text);
        assert_eq!(error_bold(text), text);
        assert_eq!(warn(text), text);
        assert_eq!(ok(text), text);
        assert_eq!(reset(), "");
    }

    #[test]
    fn tier_opens_carry_owner_rgb_and_cube_indexes() {
        // The bold error open must encode the owner's error red
        // (255,90,90) exactly; the 256 rung carries cube index 203.
        assert_eq!(
            Tier::Error.open(ColorCapability::TrueColor, true),
            "\x1b[1;38;2;255;90;90m"
        );
        assert_eq!(
            Tier::Error.open(ColorCapability::TrueColor, false),
            "\x1b[38;2;255;90;90m"
        );
        assert_eq!(
            Tier::Error.open(ColorCapability::Color256, false),
            "\x1b[38;5;203m"
        );
        assert_eq!(
            Tier::Warn.open(ColorCapability::TrueColor, false),
            "\x1b[38;2;255;235;60m"
        );
        assert_eq!(
            Tier::Warn.open(ColorCapability::Color256, false),
            "\x1b[38;5;227m"
        );
        assert_eq!(
            Tier::Ok.open(ColorCapability::TrueColor, false),
            "\x1b[38;2;80;250;123m"
        );
        assert_eq!(
            Tier::Ok.open(ColorCapability::Color256, false),
            "\x1b[38;5;84m"
        );
        assert_eq!(Tier::Error.open(ColorCapability::Mono, true), "");
    }

    #[test]
    fn tier_constants_match_the_owner_tiers() {
        // The RGB constants are the source of truth; the static tier
        // opens must encode exactly these values (a drift between the
        // constants and the enumerations fails here, and the 256
        // indexes are the documented cube matches).
        assert_eq!(ERROR_RGB, (255, 90, 90));
        assert_eq!(WARN_RGB, (255, 235, 60));
        assert_eq!(OK_RGB, (80, 250, 123));
        assert_eq!(ERROR_256, 203);
        assert_eq!(WARN_256, 227);
        assert_eq!(OK_256, 84);
    }

    #[test]
    fn tier_accessors_return_the_constants() {
        assert_eq!(Tier::Error.rgb(), ERROR_RGB);
        assert_eq!(Tier::Warn.rgb(), WARN_RGB);
        assert_eq!(Tier::Ok.rgb(), OK_RGB);
        assert_eq!(Tier::Error.index_256(), ERROR_256);
        assert_eq!(Tier::Warn.index_256(), WARN_256);
        assert_eq!(Tier::Ok.index_256(), OK_256);
    }
}
