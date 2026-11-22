// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

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
fn near_miss_vocabulary_names_both_status_surfaces() {
    // night-nearmiss-1: `stat` scores below every suggestion engine's
    // confidence (clap's Jaro and the CI fallback both stay silent),
    // yet the status muscle memory has real successors. The near-miss
    // table names both in one tip - sig and doctor - and the CI
    // fallback stays out of the way.
    let mut e = parse_err(&["stat"]);
    assert_eq!(e.kind(), ErrorKind::InvalidSubcommand);
    assert!(e.get(ContextKind::SuggestedSubcommand).is_none());
    enrich_near_miss_subcommand_hint(&mut e, &Cli::command());
    let Some(ContextValue::StyledStrs(tips)) = e.get(ContextKind::Suggested) else {
        panic!("the near-miss table must inject a Suggested tip");
    };
    assert_eq!(tips.len(), 1);
    assert!(tips[0].to_string().contains("sig"));
    assert!(tips[0].to_string().contains("(signature)"));
    assert!(tips[0].to_string().contains("doctor"));
    assert!(tips[0].to_string().contains("(status)"));
}

#[test]
fn status_spelling_rides_the_same_near_miss_tip() {
    // The longer form of the same muscle memory lands on the same
    // pair - the vocabulary the owner adjudicated, exact-match rows.
    let mut e = parse_err(&["status"]);
    enrich_near_miss_subcommand_hint(&mut e, &Cli::command());
    assert!(e.get(ContextKind::Suggested).is_some());
}

#[test]
fn near_miss_table_never_fires_on_unmapped_typos() {
    // Exact-match only: a typo outside the table passes through
    // untouched. clap may still speak for itself (its own engine
    // scores whohods against whoholds, and its escape-hatch tip
    // rides the Suggested slot) - the near-miss pair must not join
    // either lane.
    let mut e = parse_err(&["whohods"]);
    enrich_near_miss_subcommand_hint(&mut e, &Cli::command());
    if let Some(ContextValue::StyledStrs(tips)) = e.get(ContextKind::Suggested) {
        for tip in tips {
            assert!(!tip.to_string().contains("sig (signature)"));
        }
    }
    if let Some(ContextValue::String(named)) = e.get(ContextKind::SuggestedSubcommand) {
        assert_ne!(named, "sig");
        assert_ne!(named, "doctor");
    }
}

#[test]
fn case_variant_subcommand_gets_the_ci_fallback() {
    // clap's engine is case-sensitive: a case-variant verb spelling
    // renders tip-less, and the fallback names the real verb.
    let mut e = parse_err(&["PORT"]);
    assert_eq!(e.kind(), ErrorKind::InvalidSubcommand);
    assert!(e.get(ContextKind::SuggestedSubcommand).is_none());
    let cmd = Cli::command();
    let argv: Vec<String> = Vec::new();
    enrich_subcommand_ci_fallback(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedSubcommand),
        Some(&ContextValue::String("port".to_string()))
    );
}

#[test]
fn case_variant_retired_verb_lands_on_its_successor() {
    // The exact-match redirect table cannot rescue a case variant;
    // the CI fallback names the same successor the exact spelling
    // gets, through clap's own slot.
    let mut e = parse_err(&["WHOHOLDS"]);
    enrich_removed_subcommand_redirect(&mut e);
    assert!(e.get(ContextKind::SuggestedSubcommand).is_none());
    let cmd = Cli::command();
    let argv: Vec<String> = Vec::new();
    enrich_subcommand_ci_fallback(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedSubcommand),
        Some(&ContextValue::String("holds".to_string()))
    );
}

#[test]
fn subcommand_typos_clap_already_named_stay_untouched() {
    // The one-tip contract on the subcommand lane: clap's own fuzzy
    // suggestion is the last word, the fallback must stay silent.
    let mut e = parse_err(&["prco"]);
    let before = e.get(ContextKind::SuggestedSubcommand).cloned();
    assert!(before.is_some());
    let cmd = Cli::command();
    let argv: Vec<String> = Vec::new();
    enrich_subcommand_ci_fallback(&mut e, &cmd, &argv);
    assert_eq!(
        e.get(ContextKind::SuggestedSubcommand),
        before.as_ref(),
        "clap's own tip must survive untouched"
    );
}

#[test]
#[cfg(unix)]
fn argv_collection_survives_non_utf8_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let raw = [
        std::ffi::OsString::from_vec(vec![0xff]),
        std::ffi::OsString::from("proc"),
    ];
    let argv = argv_lossy(raw);
    assert_eq!(
        argv,
        vec![String::from("\u{FFFD}"), String::from("proc")],
        "the lossy walk must keep every element, replacement char in the invalid place"
    );
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
