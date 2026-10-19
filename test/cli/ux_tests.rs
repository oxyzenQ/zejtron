// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! ux unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/cli/ux.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use crate::cli::Cli;
use clap::Parser;

fn parse_err(args: &[&str]) -> Error {
    Cli::try_parse_from(std::iter::once("zejtron").chain(args.iter().copied())).unwrap_err()
}

#[test]
fn jaro_ci_is_case_insensitive() {
    assert!(jaro_ci("verbos", "verbose") > 0.7);
    assert_eq!(jaro_ci("VERBOS", "verbose"), jaro_ci("verbos", "verbose"));
    assert_eq!(jaro_ci("", "verbose"), 0.0);
}

#[test]
fn closest_long_flag_ci_rescues_case_variants() {
    let candidates = ["me", "listen", "depth", "no-pid"];
    assert_eq!(
        closest_long_flag_ci("ME", &candidates).as_deref(),
        Some("me")
    );
    assert_eq!(
        closest_long_flag_ci("Depth", &candidates).as_deref(),
        Some("depth")
    );
    assert_eq!(closest_long_flag_ci("fortnight", &candidates), None);
}

#[test]
fn the_live_flag_is_unknown_and_stays_unknown() {
    // night-improve-34 removed `proc --live` (and its --watch alias)
    // with the whole lifecycle surface. There is no deprecation
    // alias: the flag is gone, and clap's unknown-argument error is
    // the honest answer. The pin holds so a future flag cannot
    // silently resurrect a watching surface under the same name.
    let err = parse_err(&["proc", "--live"]);
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    let err = parse_err(&["proc", "--watch"]);
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    // The --since window grammar was the lifecycle stream's own; it
    // is gone from proc with the stream (the --since windows on
    // holds/touch/why/port stay - they collect and report once).
    let err = parse_err(&["proc", "--since", "30s"]);
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
}

#[test]
fn migration_vocabulary_redirects_to_successors() {
    for (gone, successor) in REMOVED_SUBCOMMAND_REDIRECTS {
        let mut e = parse_err(&[gone]);
        assert_eq!(e.kind(), ErrorKind::InvalidSubcommand);
        enrich_removed_subcommand_redirect(&mut e);
        assert_eq!(
            e.get(ContextKind::SuggestedSubcommand),
            Some(&ContextValue::String((*successor).to_string())),
            "the retired verb {gone} must land on {successor}"
        );
    }
}

#[test]
fn non_table_typos_keep_claps_own_suggestion() {
    let mut e = parse_err(&["prco"]);
    enrich_removed_subcommand_redirect(&mut e);
    // clap's fuzzy engine already suggested 'proc'; the bridge
    // must not have overridden it (exact-match-only contract).
    assert!(e.get(ContextKind::SuggestedSubcommand).is_some());
}

#[test]
fn help_muscle_memory_lands_on_the_reference() {
    let mut e = parse_err(&["help"]);
    enrich_subcommand_flag_redirect(&mut e, &Cli::command());
    let Some(ContextValue::StyledStrs(tips)) = e.get(ContextKind::Suggested) else {
        panic!("the help redirect must inject a Suggested tip");
    };
    assert!(tips[0].to_string().contains("zejtron --help"));
}

#[test]
fn case_variant_flag_gets_the_ci_fallback() {
    let mut e = parse_err(&["proc", "--ME"]);
    assert_eq!(e.kind(), ErrorKind::UnknownArgument);
    assert!(e.get(ContextKind::SuggestedArg).is_none());
    let cmd = Cli::command();
    let argv: Vec<String> = ["proc"].iter().map(|s| s.to_string()).collect();
    enrich_unknown_arg_suggestion(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedArg),
        Some(&ContextValue::String("--me".to_string()))
    );
    // The one-tip contract: the escape hatch must not ride along.
    assert!(e.get(ContextKind::Suggested).is_none());
}

#[test]
fn top_level_only_flag_typo_names_the_top_level() {
    let mut e = parse_err(&["proc", "--check-updated"]);
    let cmd = Cli::command();
    let argv: Vec<String> = ["proc"].iter().map(|s| s.to_string()).collect();
    enrich_unknown_arg_suggestion(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedArg),
        Some(&ContextValue::String("--check-update".to_string()))
    );
}

#[test]
fn lowercase_typos_never_get_a_second_tip() {
    // clap fires its own suggestion for lowercase near-misses;
    // the fallback must stay silent (never duplicate).
    let mut e = parse_err(&["proc", "--depht"]);
    assert!(e.get(ContextKind::SuggestedArg).is_some());
    let cmd = Cli::command();
    let argv: Vec<String> = ["proc"].iter().map(|s| s.to_string()).collect();
    enrich_unknown_arg_suggestion(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedArg),
        Some(&ContextValue::String("--depth".to_string())),
        "clap's own tip must survive untouched"
    );
}
