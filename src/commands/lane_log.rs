// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The live lane's LOG half (night-frontier-Z6 moved it here - a PURE
//! move under the 600-LOC no-mercy cap, the lane_unaccounted.rs
//! sibling precedent): the audit/journal assembly the ladder rides
//! when the camera cannot serve a window, plus the log actor and the
//! lane-present probe. One module, one concern - the log lane's own
//! assembly - so the live half (lane.rs) and the log half stop
//! competing for one file's line budget.

use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::commands::touch::TouchInfo;
use crate::commands::touch::audit::{try_audit_log, try_journalctl};
use crate::evidence::row::{EvidenceActor, EvidenceKind, EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, Mode, UnaccountedEntry};

use super::lane::LaneParts;
use super::lane::LaneQuery;

/// The log lane: audit first (real syscall records), journal
/// second (whatever mentioned the path). Whichever record comes
/// back is THE latest the lane has.
pub(crate) fn collect_log(query: &LaneQuery<'_>, window: Duration) -> LaneParts {
    let record: Option<(TouchInfo, bool)> =
        match try_audit_log(query.display_path, query.lookup_path, query.users) {
            Some(info) => {
                crate::output::verbose::vlog!("lane", "audit log record selected");
                Some((info, true))
            }
            None => match try_journalctl(query.display_path, query.lookup_path, query.users) {
                Some(info) => {
                    crate::output::verbose::vlog!("lane", "journal fallback selected");
                    Some((info, false))
                }
                None => {
                    crate::output::verbose::vlog!("lane", "no log record - metadata snapshot only");
                    None
                }
            },
        };

    let mut unaccounted = Vec::new();
    match record {
        Some((info, from_audit)) => {
            // In-window check: the record's time against the window.
            // An old record is not a lie about the window - it is a
            // fact the window excludes, and the Unaccounted block
            // names it with the actor the log did record.
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let record_secs = info
                .modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(-1);
            let cutoff = now.saturating_sub(window.as_secs() as i64);
            if record_secs >= cutoff && record_secs > 0 {
                // The action names the exact source: an audit record
                // is a real syscall record; a journal grep hit only
                // proves the journal mentioned the path. The kind is
                // the typed fact; the phrase is its text form.
                let kind = if from_audit {
                    EvidenceKind::Modified {
                        via: Some("audit log"),
                    }
                } else {
                    EvidenceKind::JournalMention
                };
                let actor = log_actor(&info);
                let mut changes = ChangesSection {
                    rows: Vec::new(),
                    unavailable: false,
                };
                changes.rows.push(EvidenceRow::new(
                    Some(record_secs),
                    kind,
                    actor,
                    Provenance::Inferred,
                ));
                return LaneParts {
                    mode: Mode::SnapshotJournal,
                    changes,
                    unaccounted,
                    raw: Vec::new(),
                };
            }
            // Outside the window: the row is not rendered; the
            // record (and its actor) is named in Unaccounted.
            let actor = log_actor(&info);
            unaccounted.push(UnaccountedEntry::new(
                1,
                "modification",
                format!(
                    "the log lane's latest record (by {actor}) is older than this window - \
                     extend --since to widen it"
                ),
            ));
            LaneParts {
                mode: Mode::SnapshotJournal,
                changes: ChangesSection {
                    rows: Vec::new(),
                    unavailable: false,
                },
                unaccounted,
                raw: Vec::new(),
            }
        }
        None => {
            // No record at all. Two different truths: the lane ran
            // and found nothing (an honest empty window), or no lane
            // exists on this host (the named unavailability). The
            // distinction is the mode line's to carry.
            if log_lane_present() {
                LaneParts {
                    mode: Mode::SnapshotJournal,
                    changes: ChangesSection {
                        rows: Vec::new(),
                        unavailable: false,
                    },
                    unaccounted,
                    raw: Vec::new(),
                }
            } else {
                unaccounted.push(UnaccountedEntry::new(
                    1,
                    "event window",
                    "unavailable - no live chain and no log lane; see zejtron doctor [eBPF]",
                ));
                LaneParts {
                    mode: Mode::SnapshotNoLane,
                    changes: ChangesSection {
                        rows: Vec::new(),
                        unavailable: true,
                    },
                    unaccounted,
                    raw: Vec::new(),
                }
            }
        }
    }
}

/// The log record's actor, in the holder rows' grammar: the typed
/// actor carrying the process when the log recorded one (the pid
/// when the record carried it) and the username it recorded either
/// way. The row renders it through Display; the JSON lane holds it
/// as the name/pid/user object.
pub(crate) fn log_actor(info: &TouchInfo) -> EvidenceActor {
    match &info.process {
        Some(process) => EvidenceActor::recorded(
            Some(process.name.clone()),
            process.pid,
            Some(info.actor.clone()),
        ),
        None => EvidenceActor::recorded(None, None, Some(info.actor.clone())),
    }
}

/// True when the log lane exists on this host at all: a readable
/// audit.log, or an invocable journalctl. Probed only on the
/// no-record path, so the common case pays nothing.
fn log_lane_present() -> bool {
    if Path::new("/var/log/audit/audit.log").exists() {
        return true;
    }
    std::process::Command::new("journalctl")
        .arg("--version")
        .output()
        .is_ok()
}
