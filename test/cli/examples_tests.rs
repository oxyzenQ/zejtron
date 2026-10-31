// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pins for the examples layer (night-improve-35). The test harness
//! classifies Mono (captured streams), so every pin here reads the
//! exact plain bytes the Mono lane and every pipe render; the painted
//! lane's byte shapes ride the output ladder's own tier constants and
//! the render-time gate is the one shared predicate with the Pro mode
//! section.

use super::*;
use crate::cli::help_command;

fn rendered_help() -> String {
    help_command().render_help().to_string()
}

/// Every verb on the CLI carries its example row - a verb added to
/// the enum without a row in the examples table fails here, so the
/// table cannot go stale behind the grammar.
#[test]
fn every_verb_carries_an_example_row() {
    let help = rendered_help();
    for sub in help_command().get_subcommands() {
        let name = sub.get_name();
        assert!(
            help.contains(&format!("Example: zejtron {name}")),
            "the Commands list must carry an example row for verb '{name}'"
        );
    }
}

/// The example line aligns under its verb's about text column - the
/// continuation law of the two-column Commands list (the description
/// column, not the verb-name column).
#[test]
fn example_rows_align_with_the_about_column() {
    let help = rendered_help();
    let question_line = help
        .lines()
        .find(|l| l.ends_with("Where does a command come from?"))
        .expect("the path row's about line");
    let example_line = help
        .lines()
        .find(|l| l.trim_end().ends_with("Example: zejtron path sh"))
        .expect("the path row's example line");
    let about_column = question_line
        .find("Where does a command come from?")
        .expect("the about column");
    let example_indent = example_line.len() - example_line.trim_start().len();
    assert_eq!(
        example_indent, about_column,
        "the example line must align under the about column"
    );
}

/// The Quick examples block closes the render, after the Pro mode
/// section, with the five annotated pairs - the note line and its
/// command line, byte-adjacent.
#[test]
fn help_closes_with_quick_examples() {
    let help = rendered_help();
    let pro = help.find("Pro mode:").expect("Pro mode is pinned");
    let quick = help
        .find("Quick examples:")
        .expect("the Quick examples block must render");
    assert!(
        pro < quick,
        "Quick examples must close the render, after Pro mode"
    );
    for pair in [
        "# find a binary\n  zejtron path sh",
        "# who is listening on port 22?\n  zejtron port 22",
        "# what is running under my user?\n  zejtron proc --me",
        "# evidence report for a file\n  zejtron why /etc/passwd",
        "# why is everything slow?\n  zejtron doctor --symptom slow",
    ] {
        assert!(
            help.contains(pair),
            "Quick examples must carry the annotated pair {pair:?}"
        );
    }
    let tail = &help[quick..];
    assert!(
        !tail.contains("Commands:"),
        "no section may ride after the Quick examples block"
    );
}

/// The plain lane is escape-free: in the Mono classification of the
/// test harness the example rows are the exact plain bytes - the
/// same bytes a pipe renders (the painted lane embeds its tier codes
/// only when the shared gate opens, never in Mono).
#[test]
fn example_rows_render_plain_in_mono() {
    let help = rendered_help();
    let example_lines: Vec<&str> = help
        .lines()
        .filter(|l| l.contains("Example: zejtron"))
        .collect();
    assert_eq!(
        example_lines.len(),
        9,
        "one example line per verb, nine verbs on the CLI"
    );
    for line in example_lines {
        assert!(
            !line.contains('\x1b'),
            "the Mono example row must be plain bytes: {line:?}"
        );
    }
}

/// The invocation builder's plain shapes: the exact strings the pipe
/// lane renders, pinned at the unit level.
#[test]
fn plain_invocation_shapes() {
    assert_eq!(plain_invocation("path", "sh"), "zejtron path sh");
    assert_eq!(plain_invocation("net", ""), "zejtron net");
}
