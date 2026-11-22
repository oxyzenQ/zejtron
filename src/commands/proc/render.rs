// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The proc text renderer (the no-mercy LOC law's pure move, the
//! same law that moved `forest.rs` out of the parent): the tree
//! render, the find/prune/depth shaping, the footer summary, and the
//! unreadable note - every function moved verbatim from
//! `commands/proc.rs`, not a byte of behavior touched. The parent
//! keeps the scan, the target grammar, and the JSON lane; this module
//! owns the drawing.

use super::forest::{build_forest, limit_depth, matching_process_ids, prune_for_matches};
use super::{ProcessForest, ScanReport, Subject, ViewOptions};
use std::fmt::Write as _;

pub(super) fn render_report(
    subject: &Subject,
    report: ScanReport,
    show_pid: bool,
    view: &ViewOptions,
) -> String {
    let mut forest = build_forest(report.processes);

    if let Some(pattern) = &view.find {
        let matches = matching_process_ids(&forest, pattern);
        if matches.is_empty() {
            // The empty-result line rides grey; the pattern is the
            // value and stays unwrapped.
            return format!(
                "{}{pattern}{}\n",
                crate::output::grey_out("No processes matched '"),
                crate::output::grey_out("'.")
            );
        }
        forest = prune_for_matches(&forest, &matches);
    }

    forest = limit_depth(&forest, view.max_depth);

    let mut output = render_forest(subject, &forest, show_pid);
    output.push('\n');

    if report.unreadable_statuses > 0 {
        output.push_str(&crate::output::grey_out(render_unreadable_note()));
        output.push('\n');
    }

    output.push_str(&render_summary(&forest));
    output.push('\n');

    output
}

pub(super) fn render_forest(subject: &Subject, forest: &ProcessForest, show_pid: bool) -> String {
    // The subject header rides green (the report's primary content);
    // the tree rows keep the roles render_process applies.
    let mut output = format!("{}\n", crate::output::ok_out(&subject.label()));

    // night-dragon-1: the recursive render_process is now an explicit
    // pre-order walk. Two bounds replace the call stack: the (pid,
    // is_last, prefix_len) stack cannot overflow on a pathological
    // 10,000-deep fork chain, and the prefix is one reusable buffer
    // truncated per node instead of an O(depth) format per node (the
    // recursive form rebuilt and re-formatted the full ancestor
    // prefix for every row). Children are pushed in reverse so pop()
    // yields the ascending order the recursive form drew, and each
    // stack entry carries its own prefix length, so interleaved
    // subtrees cannot corrupt one another's indentation. The bytes
    // are the recursive form's, row for row.
    let mut prefix = String::new();
    let mut stack: Vec<(u32, bool, usize)> = Vec::with_capacity(forest.processes.len());
    for (index, pid) in forest.roots.iter().enumerate() {
        stack.push((*pid, index + 1 == forest.roots.len(), 0));
    }
    stack.reverse();

    while let Some((pid, is_last, prefix_len)) = stack.pop() {
        let Some(process) = forest.processes.get(&pid) else {
            continue;
        };

        prefix.truncate(prefix_len);

        // Roles (night-improve-37): the tree glyph rides grey
        // (grammar), the comm name is the value and stays unwrapped,
        // the pid= and state= keys ride grey (inline annotations)
        // with their values unwrapped. In Mono every wrap is the
        // identity.
        let branch = if is_last { "└── " } else { "├── " };
        output.push_str(&crate::output::grey_out(&format!("{prefix}{branch}")));
        output.push_str(&process.name);

        if show_pid {
            output.push_str(&crate::output::grey_out(" pid="));
            let _ = write!(output, "{}", process.pid);
        }
        // Always show state — it's a single char and very high signal (Z = zombie!)
        output.push_str(&crate::output::grey_out(" state="));
        output.push_str(&process.state);

        output.push('\n');

        let Some(children) = forest.children.get(&pid) else {
            continue;
        };
        if children.is_empty() {
            continue;
        }

        // The children's prefix extends this node's own prefix with
        // this node's continuation segment, exactly the next_prefix
        // the recursive form built.
        prefix.push_str(if is_last { "    " } else { "│   " });
        let child_prefix_len = prefix.len();
        for (index, child_pid) in children.iter().enumerate().rev() {
            stack.push((*child_pid, index + 1 == children.len(), child_prefix_len));
        }
    }

    output
}

pub(super) fn render_summary(forest: &ProcessForest) -> String {
    // The footer line: the counts are the values (unwrapped, white),
    // the connecting words ride grey (footer text, the locked
    // scheme's secondary content).
    format!(
        "{} {} {} {}",
        forest.roots.len(),
        crate::output::grey_out("roots ·"),
        forest.processes.len(),
        crate::output::grey_out("processes")
    )
}

fn render_unreadable_note() -> &'static str {
    // The advice line rides grey (a hint, the locked scheme's
    // secondary content); the wrap is applied at the call site's
    // push through grey_out so the static stays plain.
    "note: some processes were not readable; try sudo for a complete tree"
}
