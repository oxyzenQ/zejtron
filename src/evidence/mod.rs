// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The Evidence Ledger report type (night-improve-3, the flagship
//! pass): three surfaces - holds, touch, why - one grammar. Every
//! report names its subject, its mode and window, its rows (each
//! carrying exactly one provenance tag), what it cannot see, and a
//! two-line verdict. The format is feature-independent and pure std:
//! it compiles with or without the ebpf feature and renders the same
//! bytes for the same rows - the SOURCE of the rows is what differs
//! between builds, never the shape.
//!
//! The mode line's lane qualifier is the fallback ladder made
//! visible: `live` (the kernel lane ran), `snapshot (journal
//! fallback)` (the log lane served), `snapshot (no event lane
//! available)` (neither). `mixed` is reserved for a report that
//! draws rows from more than one lane at once - the Phase 3 ladder
//! is exclusive, so no surface emits it yet; the grammar carries it
//! so a later pass never has to break the format to say it.

use row::EvidenceRow;

pub mod render;
pub mod row;

/// The mode line's lane verdict, one variant per ladder step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The eBPF lane ran: `Mode: live (window Ns)`. Constructed only
    /// by the live lane (feature builds); the default build keeps the
    /// variant for the grammar - the allow is the honest count.
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    Live,
    /// The log lane served (audit.log or journalctl):
    /// `Mode: snapshot (window Ns, journal fallback)`.
    SnapshotJournal,
    /// Neither lane could serve:
    /// `Mode: snapshot (window Ns, no event lane available)`.
    SnapshotNoLane,
    /// Reserved (see the module doc): `Mode: mixed (window Ns)`.
    /// No Phase 3 surface emits it - the ladder is exclusive - so
    /// the variant carries the grammar, not a constructor; the
    /// scoped allow is the honest count.
    #[allow(dead_code)]
    Mixed,
}

impl Mode {
    /// The base word of the mode line.
    pub fn base(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::SnapshotJournal | Self::SnapshotNoLane => "snapshot",
            Self::Mixed => "mixed",
        }
    }

    /// The lane qualifier inside the window parentheses (empty for
    /// the lanes that need no qualifier).
    pub fn lane_qualifier(self) -> &'static str {
        match self {
            Self::Live | Self::Mixed => "",
            Self::SnapshotJournal => ", journal fallback",
            Self::SnapshotNoLane => ", no event lane available",
        }
    }
}

/// The Changes subsection of the Evidence block: the event rows,
/// plus the one bit of state the header line cannot carry - whether
/// the lane was absent at all (the honest unavailability line,
/// rendered instead of `(no events in the window)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangesSection {
    /// The event rows (\[observed] from the kernel lane, \[inferred]
    /// from the log lane), ascending by timestamp - the caller
    /// sorts; the renderer never reorders.
    pub rows: Vec<EvidenceRow>,
    /// True when no event lane could serve this run: the section
    /// renders the named unavailability line instead of an empty
    /// list. An absent lane and an empty window are different
    /// truths, and the report keeps them different.
    pub unavailable: bool,
}

/// One Unaccounted entry: `<N> <category> (<reason>)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnaccountedEntry {
    /// How many of whatever the entry names.
    pub count: usize,
    /// The category, lowercase and plural by convention (`opens`,
    /// `writes`, `processes`, `event window`).
    pub category: &'static str,
    /// The reason, naming the boundary honestly.
    pub reason: String,
}

impl UnaccountedEntry {
    /// Build an entry.
    pub fn new(count: usize, category: &'static str, reason: impl Into<String>) -> Self {
        Self {
            count,
            category,
            reason: reason.into(),
        }
    }

    /// Render the entry line (no leading indent).
    pub fn render_line(&self) -> String {
        format!("{} {} ({})", self.count, self.category, self.reason)
    }
}

/// The two-line verdict: what the evidence supports, and what it
/// cannot. Sparse evidence gets a sparse verdict that names the
/// sparseness - never a confident line the rows do not back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The supports line, without the "The evidence supports: "
    /// prefix (the renderer owns the prefix).
    pub supports: String,
    /// The cannot-support line, without its prefix.
    pub cannot_support: String,
}

/// The full report. Built by the surfaces, rendered by
/// [`render::render_report`].
#[derive(Clone, Debug)]
pub struct EvidenceReport {
    /// The subject line: the path, or `:port` for port targets - the
    /// same token the old outputs carried as their header.
    pub subject: String,
    /// The lane verdict for the mode line.
    pub mode: Mode,
    /// The window label (e.g. `10s`, `5m`) - computed by the caller
    /// from the window; the renderer interpolates it into the mode
    /// line and the Changes header so the two can never disagree.
    pub window_label: String,
    /// The state rows, \[measured], the snapshot's facts.
    pub measured: Vec<EvidenceRow>,
    /// The event rows and their lane state.
    pub changes: ChangesSection,
    /// What the report cannot see; empty renders `(none observed)`.
    pub unaccounted: Vec<UnaccountedEntry>,
    /// The two-line verdict.
    pub verdict: Verdict,
}

#[cfg(test)]
#[path = "../../test/evidence/report_tests.rs"]
mod tests;
