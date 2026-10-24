// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The spec drift pin (night-improve-44): docs/EVIDENCE-LEDGER.md is
//! the citable contract - Evidence Ledger Specification v3 -
//! and this file is the clamp that keeps the document and the code
//! from drifting apart. The pin reads the spec's machine-readable
//! tier block (the fenced ```ledger-tiers``` section) and demands
//! exactly the four [`Provenance`] tags, in tier order.
//!
//! The count of four is not only a runtime assertion: the
//! `tier_index` match below carries NO wildcard arm, so a fifth
//! `Provenance` variant is a compile error in this file before it
//! can be a format break anywhere else. A new source class fits
//! inside the four (the spec's law) or the author writes
//! specification v4 - there is no silent third option.

use super::Provenance;

/// The spec document, compiled into the test binary: the pin reads
/// the exact bytes the repository ships, not a copy.
const SPEC_MD: &str = include_str!("../../docs/EVIDENCE-LEDGER.md");

/// The tier's seat in the vocabulary, by exhaustive match - no
/// wildcard arm. Adding a variant without updating this match (and
/// the spec) does not compile; the drift pin bites at build time.
fn tier_index(provenance: Provenance) -> usize {
    match provenance {
        Provenance::Observed => 0,
        Provenance::Measured => 1,
        Provenance::Inferred => 2,
        Provenance::Unaccounted => 3,
    }
}

/// The code's tier vocabulary in tier order: strongest perception
/// to named absence. The declaration order of the enum and this
/// array are the same fact; the spec block must agree with both.
fn code_tier_tags() -> Vec<String> {
    [
        Provenance::Observed,
        Provenance::Measured,
        Provenance::Inferred,
        Provenance::Unaccounted,
    ]
    .into_iter()
    .map(|p| format!("[{}]", p.tag()))
    .collect()
}

/// The spec's machine-readable tier block: the fenced
/// ```ledger-tiers``` section, one bracketed tag per line.
fn spec_tier_block() -> Vec<String> {
    let marker = "```ledger-tiers";
    let start = SPEC_MD.find(marker).unwrap_or_else(|| {
        panic!("the spec carries no {marker} tier block; the drift pin has nothing to read")
    });
    let after_marker = &SPEC_MD[start + marker.len()..];
    let end = after_marker
        .find("```")
        .expect("the spec's tier block is never closed");
    after_marker[..end]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_spec_declares_itself_v3() {
    assert!(
        SPEC_MD.contains("Evidence Ledger Specification v3"),
        "the spec's version line drifted - the citable contract is v3"
    );
    // The frozen versions stay citable history: the document names
    // each version it superseded, so a v1- or v2-pinned consumer
    // can find its contract.
    assert!(
        SPEC_MD.contains("v1 (Frozen)"),
        "the spec must keep naming the frozen v1 it supersedes"
    );
    assert!(
        SPEC_MD.contains("v2 (Frozen)"),
        "the spec must keep naming the frozen v2 it supersedes"
    );
}

#[test]
fn the_spec_block_and_the_code_agree_on_exactly_four_tags_in_order() {
    let block = spec_tier_block();
    assert_eq!(
        block.len(),
        4,
        "the vocabulary is exactly four tiers; the spec's block lists {}",
        block.len()
    );
    assert_eq!(
        block,
        code_tier_tags(),
        "the spec's tier block and the code's Provenance tags drifted apart"
    );
}

#[test]
fn every_code_tier_is_named_in_the_spec_prose() {
    for provenance in [
        Provenance::Observed,
        Provenance::Measured,
        Provenance::Inferred,
        Provenance::Unaccounted,
    ] {
        let tag = format!("[{}]", provenance.tag());
        assert!(
            SPEC_MD.contains(&tag),
            "the spec's prose never names {tag} - the definition is incomplete"
        );
        // The exhaustive-count pin rides along: tier_index refuses to
        // compile against a fifth variant, so this loop is where the
        // vocabulary's arity is enforced, not just asserted.
        let _ = tier_index(provenance);
    }
}

#[test]
fn the_code_round_trips_its_own_vocabulary() {
    // Every tag is distinct and every seat is where tier_index says:
    // the array order, the enum declaration order, and the spec's
    // tier order are one fact stated three ways.
    let tags = code_tier_tags();
    for (seat, provenance) in [
        Provenance::Observed,
        Provenance::Measured,
        Provenance::Inferred,
        Provenance::Unaccounted,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(tier_index(provenance), seat);
        assert_eq!(tags[seat], format!("[{}]", provenance.tag()));
    }
    let unique = tags.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 4, "two tiers render to the same tag");
}
