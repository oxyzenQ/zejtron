// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Clap brand styling — the one place clap's rendered surfaces
//! (help, usage, errors) pick up the brand palette. The runtime lane
//! (the error gate in main, the doctor verdict rows, the update
//! status word) paints through [`crate::output`], the sibling color
//! module; one palette across both surfaces.
//!
//! Purple brand identity: section headings (Usage, Commands, Options)
//! render in bold truecolor purple #A855F7 — the same RGB the sibling
//! project's brand layer speaks, so every purple element in -h/--help
//! and errors uses the exact same value.
//!
//! Grammar is grey: option flags and subcommand names are typeable
//! grammar, and grammar rides the calm-grey tier #8B8B8B wherever it
//! appears (the flag-spelling law). Value placeholders stay in the
//! terminal default color — values are content, not grammar.
//!
//! Style harmony: clap's default styles leave error labels plain red
//! and suggestion lines green — hues that disagree with an intentional
//! brand surface. These entries align clap's error rendering with the
//! brand palette (error red #FF5A5A, invalid yellow #FFEB3C, valid
//! grey #8B8B8B) so the clap-rendered surface looks deliberate.
//!
//! The styles set on the root command propagate to every subcommand
//! during clap's command build, so one attribute on the root
//! [`crate::cli::Cli`] styles the whole command tree.

use clap::builder::Styles;
use clap::builder::styling::{AnsiColor, Color, Effects, RgbColor, Style};

/// The brand clap styles: purple headings, grey grammar, aligned errors.
#[must_use]
pub(crate) fn clap_styles() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .usage(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(168, 85, 247)))),
        )
        .literal(Style::new().fg_color(Some(Color::Rgb(RgbColor(139, 139, 139)))))
        .placeholder(Style::new())
        .error(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Rgb(RgbColor(255, 90, 90)))),
        )
        .valid(Style::new().fg_color(Some(Color::Rgb(RgbColor(139, 139, 139)))))
        .invalid(Style::new().fg_color(Some(Color::Rgb(RgbColor(255, 235, 60)))))
}

/// The 16-color clap palette (night-improve-38, the sibling's bridge
/// law): the same brand shape one rung down the ladder, since clap
/// cannot speak RGB at a 16-color terminal and the brand purple
/// would garble. Brand purple falls to bold magenta, error red to
/// bold red, the grammar grey to bright black (90, the palette's
/// only honest grey), the invalid yellow to yellow. The branded
/// entries ([`crate::cli::parse_branded`], [`crate::cli::help_command`],
/// the ux bridge) swap these in when the capability ladder reports
/// Color16, so a forced 16-color terminal never receives RGB bytes
/// from any clap render.
#[must_use]
pub(crate) fn clap_styles_16() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Ansi(AnsiColor::Magenta))),
        )
        .usage(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Ansi(AnsiColor::Magenta))),
        )
        .literal(Style::new().effects(Effects::BOLD))
        .placeholder(Style::new())
        .error(
            Style::new()
                .effects(Effects::BOLD)
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack))))
        .invalid(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))))
}
