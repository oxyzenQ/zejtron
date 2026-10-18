// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! output unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/output/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

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
    assert_eq!(
        Tier::Brand.open(ColorCapability::TrueColor, false),
        "\x1b[38;2;168;85;247m"
    );
    assert_eq!(
        Tier::Brand.open(ColorCapability::Color256, false),
        "\x1b[38;5;135m"
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
    assert_eq!(BRAND_256, 135);
}

#[test]
fn tier_accessors_return_the_constants() {
    assert_eq!(Tier::Error.rgb(), ERROR_RGB);
    assert_eq!(Tier::Warn.rgb(), WARN_RGB);
    assert_eq!(Tier::Ok.rgb(), OK_RGB);
    assert_eq!(Tier::Brand.rgb(), BRAND_RGB);
    assert_eq!(Tier::Error.index_256(), ERROR_256);
    assert_eq!(Tier::Warn.index_256(), WARN_256);
    assert_eq!(Tier::Ok.index_256(), OK_256);
    assert_eq!(Tier::Brand.index_256(), BRAND_256);
}

#[test]
fn forced_lane_takes_the_classic_palette_floor() {
    // night-improve-37: CLICOLOR_FORCE=1 must never land Mono - a
    // probe-dead TERM (dumb, empty, unrecognized) takes the Color16
    // floor (the sibling's improve-73 law), while a TERM that
    // advertises its true rung still classifies to that rung.
    assert_eq!(
        classify(false, false, true, None, Some("dumb"), false),
        ColorCapability::Color16
    );
    assert_eq!(
        classify(false, false, true, None, None, false),
        ColorCapability::Color16
    );
    assert_eq!(
        classify(false, false, true, None, Some("xterm"), false),
        ColorCapability::Color16
    );
    assert_eq!(
        classify(false, false, true, None, Some("xterm-256color"), false),
        ColorCapability::Color256
    );
    // zejtron's precedence: a dumb TERM vetoes even a COLORTERM
    // truecolor claim (the dumb check runs first), so the forced
    // lane takes its floor here, not the truecolor rung.
    assert_eq!(
        classify(false, false, true, Some("truecolor"), Some("dumb"), false),
        ColorCapability::Color16
    );
    // The non-forced ladder keeps the documented Mono stance for an
    // unrecognized TERM - the rung is the forced lane's floor only.
    assert_eq!(
        classify(false, false, false, None, Some("xterm"), true),
        ColorCapability::Mono
    );
}

#[test]
fn color16_opens_carry_the_classic_bright_slots() {
    // The forced lane's floor paints the aixterm bright slots - the
    // only encoding that never garbles on a probe-dead terminal.
    assert_eq!(
        Tier::Error.open(ColorCapability::Color16, false),
        "\x1b[91m"
    );
    assert_eq!(
        Tier::Error.open(ColorCapability::Color16, true),
        "\x1b[1;91m"
    );
    assert_eq!(Tier::Warn.open(ColorCapability::Color16, false), "\x1b[93m");
    assert_eq!(
        Tier::Warn.open(ColorCapability::Color16, true),
        "\x1b[1;93m"
    );
    assert_eq!(Tier::Ok.open(ColorCapability::Color16, false), "\x1b[92m");
    assert_eq!(Tier::Ok.open(ColorCapability::Color16, true), "\x1b[1;92m");
    assert_eq!(
        Tier::Brand.open(ColorCapability::Color16, false),
        "\x1b[95m"
    );
    assert_eq!(
        Tier::Brand.open(ColorCapability::Color16, true),
        "\x1b[1;95m"
    );
}

#[test]
fn grammar_tier_rides_the_documented_grey_rungs() {
    // night-improve-38: the grammar tier is the sibling's flag-row
    // grey - RGB 139/139/139 at the truecolor rung, cube index 245
    // at the 256 rung, bright black (90) at the Color16 floor.
    assert_eq!(
        Tier::Grammar.open(ColorCapability::TrueColor, false),
        "\x1b[38;2;139;139;139m"
    );
    assert_eq!(
        Tier::Grammar.open(ColorCapability::Color256, false),
        "\x1b[38;5;245m"
    );
    assert_eq!(
        Tier::Grammar.open(ColorCapability::Color16, false),
        "\x1b[90m"
    );
    assert_eq!(
        Tier::Grammar.open(ColorCapability::Color16, true),
        "\x1b[1;90m"
    );
    assert_eq!(Tier::Grammar.open(ColorCapability::Mono, false), "");
    assert_eq!(Tier::Grammar.rgb(), (139, 139, 139));
    assert_eq!(Tier::Grammar.index_256(), 245);
}

#[test]
fn grammar_grey_stays_plain_when_mono() {
    // The wrapper short-circuit: piped tests run Mono, so the
    // grammar wrap must return the plain message bytes.
    assert_eq!(grammar_grey("--limit"), "--limit");
}
