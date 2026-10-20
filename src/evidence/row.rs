// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The Evidence Ledger row (night-improve-3): one line of evidence.
//! The row grammar is locked - `<UTC timestamp>  <action>  <actor>
//! [<provenance>]` - and the four provenance tiers are the whole
//! vocabulary: no fifth tier, ever. A later pass that needs a new
//! source class must fit it INSIDE one of these four (the log lane
//! is \[inferred] however strong an audit record reads; the tag is
//! the truth about the source, not marketing).
//!
//! The timestamp is unix seconds; `None` renders `unknown` (an
//! absent fact stays absent, never guessed). The (UTC) suffix rule
//! lives in the renderer: the first timestamped row of the report
//! declares the column's clock, the rows after it stay bare.

/// The four provenance tiers - exactly four, the locked grammar.
/// \[observed] rows come from eBPF kernel events, \[measured] rows
/// from snapshot reads taken at the instant of the command,
/// \[inferred] rows from indirect evidence (the log lane: audit.log
/// and journalctl records, replayed), \[unaccounted] names what the
/// report cannot see (it lives in the Unaccounted block; the tier
/// exists so the vocabulary stays four).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Directly from an eBPF kernel event - the kernel recorded the
    /// action as it happened, with the pid.
    Observed,
    /// From a snapshot read (/proc, /sys, stat) at the instant of
    /// the command.
    Measured,
    /// From indirect evidence - a log replayed, an mtime implying a
    /// write.
    Inferred,
    /// The report cannot see this. Carried by the Unaccounted block
    /// rather than by rows in Phase 3; the variant holds the
    /// vocabulary's fourth seat so no later pass invents a fifth -
    /// the scoped allow is the honest count.
    #[allow(dead_code)]
    Unaccounted,
}

impl Provenance {
    /// The row tag - lowercase, bracketed, the last token on the
    /// line.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Measured => "measured",
            Self::Inferred => "inferred",
            Self::Unaccounted => "unaccounted",
        }
    }
}

/// One evidence row. The timestamp is the moment of the fact: the
/// scan instant for state rows, the event's own time for event rows,
/// the mtime for an mtime row. The actor is the acting identity
/// (`name (pid N, user)` for processes, `—` for pure state that has
/// no actor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Unix seconds of the fact; `None` renders `unknown`.
    pub unix_secs: Option<i64>,
    /// What happened or what holds - the fact itself.
    pub action: String,
    /// Who did it or who holds it; `—` when the row is pure state.
    pub actor: String,
    /// Exactly one tier.
    pub provenance: Provenance,
}

impl EvidenceRow {
    /// Build a row; the plain constructor the ledgers use.
    pub fn new(
        unix_secs: Option<i64>,
        action: impl Into<String>,
        actor: impl Into<String>,
        provenance: Provenance,
    ) -> Self {
        Self {
            unix_secs,
            action: action.into(),
            actor: actor.into(),
            provenance,
        }
    }

    /// Render the row line (no leading indent; the renderer adds
    /// it). `mark_utc` is true only for the first timestamped row of
    /// the report - it keeps the ` (UTC)` suffix the clock module
    /// emits; every row after it drops the suffix (the column was
    /// declared once).
    ///
    /// Roles (night-improve-37, the locked scheme): the timestamp
    /// column rides the grey tier (secondary content), the action and
    /// actor stay unwrapped (the values - the facts the user came
    /// for), and the provenance tag rides the strongest-evidence
    /// split: `[observed]` and `[measured]` are green (the strongest
    /// evidence), `[inferred]` and `[unaccounted]` grey (the weaker
    /// evidence). The tag is the last token on the line, exactly four
    /// tiers, unchanged. In Mono every wrap is the identity - the
    /// plain bytes the tests pin.
    pub fn render_line(&self, mark_utc: bool) -> String {
        let timestamp = match self.unix_secs {
            Some(secs) => {
                let full = crate::info::clock::format_unix_secs(secs);
                if mark_utc {
                    full
                } else {
                    full.strip_suffix(" (UTC)")
                        .map(str::to_owned)
                        .unwrap_or(full)
                }
            }
            None => "unknown".to_owned(),
        };
        let tag = format!("[{}]", self.provenance.tag());
        let tag = match self.provenance {
            Provenance::Observed | Provenance::Measured => crate::output::ok_out(&tag),
            Provenance::Inferred | Provenance::Unaccounted => crate::output::grey_out(&tag),
        };
        format!(
            "{}  {}  {}  {tag}",
            crate::output::grey_out(&timestamp),
            self.action,
            self.actor
        )
    }
}

#[cfg(test)]
#[path = "../../test/evidence/row_tests.rs"]
mod tests;
