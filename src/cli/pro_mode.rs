// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The Pro mode section of the help surface (night-improve-25, the
//! sibling's zelynic shape): every flag of every verb, complete, on
//! the one reference surface - grouped by the verb that owns each
//! flag. The top-level Options block only ever shows the globals;
//! the per-verb flags lived scattered across thirteen per-verb help
//! renders, so the one surface a user reads end-to-end showed none
//! of them. Pro mode owns the whole estate: each spelling mirrors
//! the verb's own help string verbatim (one wording authority - the
//! CLI structs), the hidden aliases are disclosed next to the flags
//! they alias (--check-updated is the one that survives;
//! the lifecycle alias is gone with its surface, night-improve-34),
//! and the
//! layout rides one description column so the geometry cannot drift
//! per row.
//!
//! Rendering (night-improve-38, the sibling's flag-row law): the
//! spellings are typeable grammar, and grammar is grey wherever it
//! appears - each row paints its flag token through the output
//! ladder's grammar tier ([`crate::output::grey_out`]), while
//! value tokens (N, DURATION, SECONDS, PID, TEXT) stay in the
//! terminal default color: values are content, not grammar. The
//! capability law the runtime lane obeys holds here too: Mono (or a
//! non-terminal stdout without the force flag) renders the exact
//! plain bytes - piped output keeps its plain bytes and NO_COLOR
//! stays default; a color terminal gets the grey grammar.
//!
//! The section heading rides the sibling's heading law (night-weekly-
//! maintenance-2, the family's one-frame rule): help-surface section
//! headings paint brand purple bold - the same seat the sibling's
//! flag estate gives "Global flags:", "Rate formats:", and "Pro
//! mode:" ([`crate::output::brand_bold_out`], the stdout lane's bold
//! brand wrapper). The group labels under it ("net:", "proc:", ...)
//! stay plain - the sibling's Pro mode groups ride plain too, only
//! the section headings shout. In Mono the wrapper is the identity,
//! so the plain bytes the tests pin never move.

use crate::output::{brand_bold_out, grey_out};

/// One flag row: the spelling cell (flag token plus its value token,
/// verbatim from the CLI structs) and the description (verbatim from
/// the verb's own help string; an embedded newline carries the
/// description's wrapped continuation, re-indented to the column).
type Row = (&'static str, &'static str);

/// The complete flag estate, grouped by the verb that owns each flag.
/// The single wording authority for the section's rows; the renderer
/// computes the column, the data never encodes geometry.
const GROUPS: &[(&str, &[Row])] = &[
    (
        "recent:",
        &[
            ("--limit N", "Maximum files to show (default 20)"),
            (
                "--since DURATION",
                "Only show files modified since this duration",
            ),
        ],
    ),
    (
        "port:",
        &[
            ("--tcp", "Show TCP sockets"),
            ("--udp", "Show UDP sockets"),
            (
                "--listen",
                "Show listening or bound sockets (excludes --all)",
            ),
            ("--all", "Show all parsed sockets"),
            ("--numeric", "Use numeric addresses and ports"),
            ("--group", "Group repeated rendered socket rows"),
            ("--no-pid", "Hide process IDs in owner lines"),
            (
                "--since DURATION",
                "Event window width (s/m/h, default 60s, clamped to [1s, 1h])",
            ),
            ("--events-only", "Show only the event window (no snapshot)"),
            (
                "--snapshot-only",
                "Show only the snapshot (the phase-1 behavior)",
            ),
        ],
    ),
    (
        "proc:",
        &[
            ("--me", "Show processes owned by the current user"),
            ("--depth N", "Limit rendered tree depth"),
            (
                "--find PATTERN",
                "Show process families matching a case-insensitive name substring",
            ),
            ("--no-pid", "Hide pid=<PID> labels"),
            ("--no-color", "Disable ANSI color output"),
        ],
    ),
    (
        "holds:",
        &[(
            "--since DURATION",
            "Event window width (s/m/h, default 10s, clamped to [1s, 1h])",
        )],
    ),
    (
        "touch:",
        &[(
            "--since DURATION",
            "Event window width (s/m/h, default 10s, clamped to [1s, 1h])",
        )],
    ),
    (
        "why:",
        &[
            (
                "--since DURATION",
                "Event window width (s/m/h, default 10s, clamped to [1s, 1h])",
            ),
            (
                "--trace",
                "Append how zejtron knows each row (the explainability ladder)",
            ),
            (
                "--raw",
                "Append the raw kernel events as drained (drill-down)",
            ),
        ],
    ),
    (
        "doctor:",
        &[
            (
                "--attach",
                "Attach the eBPF probe (the privileged one-shot)",
            ),
            (
                "--detach",
                "Detach the eBPF probe (unpin everything, idempotent)",
            ),
            (
                "--symptom SYMPTOM",
                "Analyze a symptom instead of the readiness check (ram | cpu | disk | network | gpu | slow)",
            ),
            (
                "--raw",
                "With --symptom: append the raw /proc reads (drill-down)",
            ),
        ],
    ),
    (
        "global:",
        &[
            (
                "--check-update",
                "Alias: --check-updated (same surface, one check)",
            ),
            (
                "-V, --version",
                "Print complete version and build information",
            ),
            (
                "-v, --verbose",
                "Print engine diagnostics to stderr (stdout stays ledger-clean)",
            ),
        ],
    ),
];

/// The intro prose, verbatim (night-improve-25's wording) minus the
/// heading line: the heading renders separately so it can take its
/// brand-purple seat on a color terminal while the prose stays
/// default-colored, and the two reassemble into the exact bytes the
/// old single const carried (the Mono shape the tests pin).
const INTRO: &str = "\
  The complete flag estate - grouped by the verbs that own them.
  Each verb's own -h/--help shows its lane; this is the whole
  estate on one surface.

";

/// The row indent: two under the group's own two.
const ROW_INDENT: usize = 4;

/// True when the help surface may carry escape bytes: the capability
/// ladder says color AND the render destination can speak it - a
/// terminal stdout, or the force flag's piped promise (the same two
/// conditions clap's own help gate answers to, so the Pro mode
/// section and clap's Options block always agree). The gate now lives
/// in the output module (night-improve-37) beside the stdout lane it
/// governs - every data surface answers to the same predicate - and
/// this delegate keeps the help modules' one import path stable.
pub(crate) fn stdout_paintable() -> bool {
    crate::output::stdout_paintable()
}

/// Build the Pro mode section: grey grammar on a color stdout, the
/// exact plain bytes otherwise. The description column is computed
/// from the data (longest spelling cell + two), so the geometry
/// cannot drift per row and the plain render stays byte-identical
/// to the surface the tests pin.
#[must_use]
pub(crate) fn painted() -> String {
    let paint = stdout_paintable();
    let longest = GROUPS
        .iter()
        .flat_map(|group| group.1.iter())
        .map(|(spelling, _)| spelling.chars().count())
        .max()
        .unwrap_or(0);
    let column = ROW_INDENT + longest + 2;

    // The heading opens the section in bold brand purple (the
    // sibling's heading law); in Mono the wrapper is the identity,
    // so the assembled bytes stay identical to the pinned shape.
    let mut out = brand_bold_out("Pro mode:");
    out.push('\n');
    out.push_str(INTRO);
    for (group, rows) in GROUPS {
        out.push_str("  ");
        out.push_str(group);
        out.push('\n');
        for (spelling, desc) in rows.iter() {
            let pad = column - ROW_INDENT - spelling.chars().count();
            let flag_token = spelling.split(' ').next().unwrap_or(spelling);
            let value_token = &spelling[flag_token.len()..];
            out.push_str(&" ".repeat(ROW_INDENT));
            if paint {
                out.push_str(&grey_out(flag_token));
            } else {
                out.push_str(flag_token);
            }
            out.push_str(value_token);
            out.push_str(&" ".repeat(pad));
            let continuation = &" ".repeat(column);
            for (i, line) in desc.split('\n').enumerate() {
                if i > 0 {
                    out.push('\n');
                    out.push_str(continuation);
                }
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    // The trailing newline the frozen section carried stays: clap
    // appends its own spacing after the section, so the byte shape
    // of the whole help render stays identical to the old surface.
    out
}
