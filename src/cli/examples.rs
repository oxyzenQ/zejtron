// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The Examples layer of the help surface (night-improve-35, the
//! sibling's teaching law): a help surface that lists grammar is a
//! reference, but a user reading it still has to guess what a whole
//! invocation looks like - so every verb carries one real example.
//! Two layers, one data table:
//!
//! 1. The Commands list of `-h`/`--help`: each verb's about grows a
//!    second line, `Example: zejtron <verb> <args>` - a real
//!    invocation with concrete values, never placeholders.
//! 2. The Quick examples section closing the help render: the
//!    annotated-pair shape the sibling's reference surface uses (the
//!    `#` note on its own line above, the command below), carrying
//!    the most useful invocations for a new user.
//!
//! Colors (the two-color intent, applied through the tree's tier
//! code - never raw ANSI): the verb token is the primary and rides
//! the status-green tier ([`crate::output::ok_out`]), the example line
//! around it is secondary and rides the calm-grey grammar tier
//! ([`crate::output::grey_out`]) - the STDOUT-lane wrappers, because
//! the help bytes speak through stdout and both the gate and the
//! wrappers must answer to the same lane (night-improve-37's two-lane
//! law). The capability law holds as everywhere on this surface: the
//! paint gate is [`crate::cli::pro_mode::stdout_paintable`] (the one
//! shared gate with the Pro mode section, the same two conditions
//! clap's own help gate answers to), so a piped stdout and a NO_COLOR
//! environment receive the exact plain bytes - the text survives, the
//! color drops.

use crate::cli::pro_mode::stdout_paintable;
use crate::output::{brand_bold_out, grey_out, ok_out};

/// One verb's example: the verb token and the argument spelling that
/// follows it - a verbatim invocation, no placeholders.
type VerbExample = (&'static str, &'static str);

/// The complete example estate: one row per top-level verb, matching
/// the [`crate::cli::Commands`] order. The single data table both
/// layers render from; a verb added to the CLI without a row here
/// fails the pins in test/cli/cli_tests.rs.
const VERB_EXAMPLES: &[VerbExample] = &[
    ("path", "sh"),
    ("recent", "--since 1h"),
    ("port", "--tcp"),
    ("proc", "--me"),
    ("holds", "/etc/resolv.conf"),
    ("touch", "/etc/hosts"),
    ("why", "/etc/passwd"),
    ("doctor", "--symptom ram"),
    ("net", ""),
];

/// The Quick examples: the annotated pairs a new user meets first -
/// the five most useful invocations of the toolkit, verbatim
/// commands with concrete values.
const QUICK_EXAMPLES: &[(&str, VerbExample)] = &[
    ("find a binary", ("path", "sh")),
    ("who is listening on port 22?", ("port", "22")),
    ("what is running under my user?", ("proc", "--me")),
    ("evidence report for a file", ("why", "/etc/passwd")),
    ("why is my RAM eaten?", ("doctor", "--symptom ram")),
];

/// One example invocation, unpainted: the exact plain bytes the Mono
/// lane (and every pipe) renders - the shape the tests pin.
fn plain_invocation(verb: &str, args: &str) -> String {
    if args.is_empty() {
        format!("zejtron {verb}")
    } else {
        format!("zejtron {verb} {args}")
    }
}

/// One example invocation, painted: the grey lead-in ("zejtron" or
/// the "Example: zejtron" row prefix) with the verb token in the
/// status-green tier and the argument spelling back on grey - the
/// two-color intent rendered through the output ladder's tiers.
fn painted_invocation(lead: &str, verb: &str, args: &str) -> String {
    let mut line = grey_out(lead);
    line.push_str(&ok_out(verb));
    if !args.is_empty() {
        line.push_str(&grey_out(&format!(" {args}")));
    }
    line
}

/// Stamp every top-level verb with its example row: the about line
/// (the verb's own wording, verbatim) plus the grey `Example:` line
/// under it - the whole line rides the grammar tier, the verb token
/// inside it the status-green tier. The verbs not present in the
/// table keep their plain about - and the completeness pin fails, so
/// the table cannot go stale behind a new verb.
pub(crate) fn paint_verbs(cmd: &mut clap::Command) {
    let paint = stdout_paintable();
    for sub in cmd.get_subcommands_mut() {
        let name = sub.get_name().to_owned();
        let Some((_, args)) = VERB_EXAMPLES.iter().find(|(v, _)| *v == name) else {
            continue;
        };
        let about = sub
            .get_about()
            .map(|styled| styled.to_string())
            .unwrap_or_default();
        let example = if paint {
            painted_invocation("Example: zejtron ", &name, args)
        } else {
            format!("Example: {}", plain_invocation(&name, args))
        };
        // clap's builder methods consume and return the command, so
        // the stamped about reassigns through the mutable borrow; the
        // clone is render-time-only and never on a hot path.
        *sub = sub.clone().about(format!("{about}\n{example}"));
    }
}

/// The Quick examples section: the annotated pairs (`#` note above,
/// command below, the sibling's pair shape) closing the help render.
/// The leading blank line separates the section from whatever rides
/// before it on the after_help surface; clap appends its own spacing
/// after the section, so the byte shape stays stable.
pub(crate) fn quick_section() -> String {
    let paint = stdout_paintable();
    // The section heading rides the sibling's heading law (night-
    // weekly-maintenance-2): help-surface section headings paint
    // brand purple bold, the same seat the Pro mode section's heading
    // takes. In Mono the wrapper is the identity, so the assembled
    // bytes stay identical to the pinned plain shape.
    let mut out = String::from("\n");
    out.push_str(&brand_bold_out("Quick examples:"));
    out.push('\n');
    for (i, (note, (verb, args))) in QUICK_EXAMPLES.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("  # {note}\n  "));
        if paint {
            out.push_str(&painted_invocation("zejtron ", verb, args));
        } else {
            out.push_str(&plain_invocation(verb, args));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[path = "../../test/cli/examples_tests.rs"]
mod tests;
