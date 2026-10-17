// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The CLI UX bridge (night-improve-19, the sibling's zelynic
//! contract sized for zejtron's read-only shape): parse errors stop
//! being clap's bare default render and get the mature treatment -
//! removed-subcommand redirects for the migration vocabulary, the
//! `help` muscle-memory rescue, the case-insensitive flag fallback,
//! the one-tip contract, and the brand styles applied at render time
//! through the same capability ladder every other surface answers to.
//!
//! Wiring: `main` parses with [`crate::cli::Cli::try_parse`] and hands
//! every error here. `DisplayHelp`/`DisplayVersion` still exit 0 on
//! stdout through clap's own path (the help flag is real); every
//! other kind is enriched, rendered with zejtron's clap styles, and
//! exits 2 (the clap usage-error code, unchanged) - runtime failures
//! keep exit 1 in `main`.
//!
//! Deliberate boundaries (the LTS-first cut): no shadowed-suggestion
//! rescue and no escape-hatch honesty probe - zejtron has no hidden
//! subcommands to leak and no value grammar complex enough to lie;
//! the one-tip contract below already keeps every rescued error at
//! exactly one tip.

use crate::cli::Cli;
use clap::builder::Command;
use clap::error::{ContextKind, ContextValue, Error, ErrorKind};
use std::fmt::Write as _;

/// Removed-subcommand redirects (the migration contract): the
/// pidnest/Zenlixem verbs zejtron consolidated (README origin table)
/// name their successor instead of dead-ending in a generic
/// unrecognized-subcommand error. Exact-match only: a redirect
/// overrides any fuzzy suggestion clap already attached - for an
/// exact retired name the successor is strictly more correct than a
/// near-miss candidate. `doctor` is deliberately absent: it parses
/// as zejtron's own readiness surface, so a Zenlixem operator's old
/// spelling lands on a real command, not a redirect.
const REMOVED_SUBCOMMAND_REDIRECTS: &[(&str, &str)] = &[
    ("whoholds", "holds"),
    ("lasttouch", "touch"),
    ("whyopen", "why"),
    ("envpath", "path"),
];

/// Subcommand spellings whose successor is a top-level FLAG, not
/// another subcommand. `help` is the muscle memory every clap tool
/// trains, and the auto-generated `help` subcommand has been
/// disabled since night-improve-15 (one help authority: -h/--help) -
/// without this row, `zejtron help` dies tip-less on the most
/// natural spelling in the vocabulary.
const SUBCOMMAND_FLAG_REDIRECTS: &[(&str, &str)] = &[("help", "zejtron --help")];

/// Long flags that parse at the TOP LEVEL only. A subcommand-scoped
/// typo of one of these gets the top-level spelling named - the
/// generic candidate pool at a subcommand never contains them, so
/// without this rescue the typo renders tip-less. `-V/--version` is
/// global since its landing and needs no rescue; `-h/--help` exists
/// at every level for the same reason.
const TOP_LEVEL_ONLY_FLAGS: &[(&str, &str)] = &[
    ("check-update", "--check-update"),
    ("check-updated", "--check-update"),
];

/// Jaro similarity (clap's own flag-suggestion metric),
/// case-insensitive. clap 4's did-you-mean engine scores flag
/// candidates with plain Jaro at a > 0.7 confidence threshold,
/// comparing case-SENSITIVELY - so `--ME` (zero matching chars
/// against `--me`) renders tip-less. Lowercasing both sides first
/// lets a case-variant spelling of a known flag still score; for
/// already-lowercase input the score is IDENTICAL to clap's own
/// engine, which is what makes the fallback safe: it only fires
/// where clap was silent, and never suggests a flag clap itself
/// would have rejected for the same lowercase input. Ported from the
/// sibling's suggestion engine verbatim.
fn jaro_ci(a: &str, b: &str) -> f64 {
    let lower = |s: &str| -> Vec<char> { s.chars().flat_map(char::to_lowercase).collect() };
    let a = lower(a);
    let b = lower(b);
    let (a_len, b_len) = (a.len(), b.len());
    if a_len == 0 && b_len == 0 {
        return 1.0;
    }
    if a_len == 0 || b_len == 0 {
        return 0.0;
    }
    if a_len == 1 && b_len == 1 {
        return if a[0] == b[0] { 1.0 } else { 0.0 };
    }
    let search_range = (a_len.max(b_len) / 2).saturating_sub(1);
    let mut b_consumed = vec![false; b_len];
    let mut matches = 0.0_f64;
    let mut transpositions = 0.0_f64;
    let mut b_match_index = 0_usize;
    for (i, &a_elem) in a.iter().enumerate() {
        let min_bound = i.saturating_sub(search_range);
        let max_bound = (b_len - 1).min(i + search_range);
        if min_bound > max_bound {
            continue;
        }
        for (j, &b_elem) in b.iter().enumerate() {
            if min_bound <= j && j <= max_bound && a_elem == b_elem && !b_consumed[j] {
                b_consumed[j] = true;
                matches += 1.0;
                if j < b_match_index {
                    transpositions += 1.0;
                }
                b_match_index = j;
                break;
            }
        }
    }
    if matches == 0.0 {
        0.0
    } else {
        (1.0 / 3.0)
            * ((matches / a_len as f64)
                + (matches / b_len as f64)
                + ((matches - transpositions) / matches))
    }
}

/// Closest long-flag name by case-insensitive Jaro (clap's > 0.7
/// confidence threshold), or `None`. Input and candidates are BARE
/// names (no leading dashes). Used only as the fallback when clap's
/// own case-sensitive engine found nothing. Ties resolve to the LAST
/// candidate in declaration order, mirroring clap's ascending-sort-
/// then-pop tie-break so the lowercase twin of a rescued typo
/// suggests the same flag clap would have.
fn closest_long_flag_ci(input: &str, candidates: &[&str]) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut best: Option<(String, f64)> = None;
    for candidate in candidates {
        let confidence = jaro_ci(trimmed, candidate);
        if confidence <= 0.7 {
            continue;
        }
        match &best {
            None => best = Some(((*candidate).to_string(), confidence)),
            Some((_, c)) if confidence >= *c => {
                best = Some(((*candidate).to_string(), confidence));
            }
            _ => {}
        }
    }
    best.map(|(name, _)| name)
}

/// The command the failing argument belongs to, found by walking argv
/// the way the parser descends: subcommand names at the current level
/// descend, everything else (flags, values, positionals) does not.
/// Good enough for suggestion candidates - the walk only feeds the
/// flag pool, never the verdict.
fn failing_command<'a>(cmd: &'a Command, argv: &[String]) -> &'a Command {
    let mut current = cmd;
    for token in argv {
        if token.starts_with('-') {
            continue;
        }
        if let Some(sub) = current.find_subcommand(token) {
            current = sub;
        }
    }
    current
}

/// Every visible long-flag spelling of `cmd` (primary longs and
/// visible aliases), bare (no dashes) for the matcher.
fn long_flag_candidates(cmd: &Command) -> Vec<&str> {
    cmd.get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .flat_map(|arg| arg.get_long_and_visible_aliases().unwrap_or_default())
        .collect()
}

/// Case-insensitive flag-suggestion fallback for UnknownArgument
/// errors: when clap was silent (its engine is case-sensitive), the
/// best case-insensitive match is injected as clap's OWN SuggestedArg
/// context, so the tip renders in clap's canonical position and
/// style - no custom printing, no second tip, no render surgery.
///
/// The top-level-authority rescue runs first: a subcommand-scoped
/// typo of a top-level-only flag names the top-level spelling. Every
/// injection drops clap's trailing escape-hatch tip first (the
/// "to pass as a value, use '--'" line clap attaches whenever the
/// failing command has positionals) - a suggestion beats the escape
/// hatch every time, and two tips violate the one-tip contract. No-op
/// for every other error kind, errors that already carry a
/// suggestion, and dashes-only or empty inputs.
fn enrich_unknown_arg_suggestion(e: &mut Error, cmd: &Command, argv: &[String]) {
    if e.kind() != ErrorKind::UnknownArgument {
        return;
    }
    if e.get(ContextKind::SuggestedArg).is_some() {
        return; // clap fired its own tip - usually the last word
    }
    let Some(ContextValue::String(typed)) = e.get(ContextKind::InvalidArg) else {
        return;
    };
    let typed = typed.trim_start_matches('-').to_string();
    if typed.is_empty() {
        return;
    }
    let authority = TOP_LEVEL_ONLY_FLAGS.iter().find(|(name, _)| *name == typed);
    if let Some((_, successor)) = authority {
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String((*successor).to_string()),
        );
        return;
    }
    let failing = failing_command(cmd, argv);
    let candidates = long_flag_candidates(failing);
    if let Some(best) = closest_long_flag_ci(&typed, &candidates) {
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedArg,
            ContextValue::String(format!("--{best}")),
        );
    }
}

/// Inject the successor for a removed subcommand as clap's OWN
/// SuggestedSubcommand context, overriding any fuzzy suggestion clap
/// already attached. No-op for every error kind except
/// InvalidSubcommand and every typed name outside the redirect table.
fn enrich_removed_subcommand_redirect(e: &mut Error) {
    if e.kind() != ErrorKind::InvalidSubcommand {
        return;
    }
    let Some(ContextValue::String(typed)) = e.get(ContextKind::InvalidSubcommand) else {
        return;
    };
    let successor = REMOVED_SUBCOMMAND_REDIRECTS
        .iter()
        .find(|(gone, _)| gone == typed)
        .map(|(_, successor)| *successor);
    if let Some(successor) = successor {
        e.remove(ContextKind::SuggestedSubcommand);
        e.remove(ContextKind::Suggested);
        e.insert(
            ContextKind::SuggestedSubcommand,
            ContextValue::String(successor.to_string()),
        );
    }
}

/// Inject the flag successor for a subcommand spelling in the flag
/// redirect table as a canonical `tip:` line. The plain `Suggested`
/// context is the only render slot that can carry a non-subcommand
/// successor at this position, and it renders in the command's
/// `valid` style - the same highlighted-command look every other tip
/// carries.
fn enrich_subcommand_flag_redirect(e: &mut Error, cmd: &Command) {
    if e.kind() != ErrorKind::InvalidSubcommand {
        return;
    }
    let Some(ContextValue::String(typed)) = e.get(ContextKind::InvalidSubcommand) else {
        return;
    };
    let Some(&(_, successor)) = SUBCOMMAND_FLAG_REDIRECTS
        .iter()
        .find(|(name, _)| name == typed)
    else {
        return;
    };
    e.remove(ContextKind::SuggestedSubcommand);
    e.remove(ContextKind::Suggested);
    let valid = cmd.get_styles().get_valid();
    let mut tip = clap::builder::StyledStr::new();
    let _ = write!(
        tip,
        "to see the reference, run '{valid}{successor}{valid:#}'"
    );
    e.insert(ContextKind::Suggested, ContextValue::StyledStrs(vec![tip]));
}

/// Render a clap parse error in the canonical zejtron shape and exit.
///
/// Help/version requests exit 0 on stdout through clap's own path;
/// every other kind gets the three enrichers (unknown-arg rescue,
/// removed-subcommand redirects, the `help` flag redirect), then the
/// brand styles applied at render time, then the bytes route through
/// the shared capability ladder - plain in Mono, clap's ANSI
/// otherwise - and the process exits 2 (the clap usage-error code).
/// Runtime failures keep exit 1 in `main`.
pub(crate) fn exit_clap_error(e: Error) -> ! {
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        e.exit(); // stdout + exit 0, clap's own path
    }
    let mut e = e;
    let mut cmd = Cli::command();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    enrich_unknown_arg_suggestion(&mut e, &cmd, &argv);
    enrich_removed_subcommand_redirect(&mut e);
    enrich_subcommand_flag_redirect(&mut e, &cmd);
    let e = e.format(&mut cmd);
    let rendered = e.render();
    // Broken pipe is swallowed (a downstream `| head` closing early
    // must not turn a usage error into a panic) - matching clap's own
    // exit() behavior and the sibling's bridge.
    use std::io::Write as _;
    let mut stderr = std::io::stderr();
    let _ = match crate::output::capability() {
        crate::output::ColorCapability::Mono => write!(stderr, "{rendered}"),
        _ => write!(stderr, "{}", rendered.ansi()),
    };
    let _ = stderr.flush();
    std::process::exit(2);
}

#[cfg(test)]
#[path = "../../test/cli/ux_tests.rs"]
mod tests;
