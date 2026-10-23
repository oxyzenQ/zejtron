// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The fallback-lane collector (night-improve-3): the one place the
//! ladder lives, shared by holds, touch, and why. The ladder is
//! exclusive and every step is honest about its source:
//!
//! 1. eBPF attached (root, BTF, kernel 5.15+, feature enabled, probe
//!    live) - \[observed] rows from the kernel's own records;
//! 2. eBPF unavailable but the log lane present (audit.log or
//!    journalctl) - \[inferred] rows from the log, replayed;
//! 3. neither - no event rows, the named unavailability line, and
//!    the Unaccounted block names the missing window.
//!
//! The log lane's row actions are source-true whatever the surface:
//! an audit record is `modified (audit log)` (the parser only
//! matches modification syscalls), a journal grep hit is a
//! `journal mention` (the journal mentioned the path - it proves
//! neither an open nor a write). The log lane cannot distinguish
//! opens from writes; the actions say so. The kernel lane can, and
//! the per-surface OpFilter picks which class of event this surface
//! cares about (holds: opens; touch: writes; why: both).
//!
//! In the live lane the log is not consulted at all - the ladder is
//! exclusive, and the verdict (not a row) names that nothing older
//! than the window was looked for.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::evidence::row::{EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, Mode, UnaccountedEntry};

use crate::commands::touch::TouchInfo;
use crate::commands::touch::audit::{try_audit_log, try_journalctl};

/// The default window for holds/touch/why (the spec's lock): short
/// enough that the live lane's collection-over-duration stays quick,
/// long enough to catch the common "who just touched this".
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(10);

/// Resolve a `--since` argument into the window and its label: the
/// port surface's own grammar (`s`/`m`/`h`, clamped [1s, 1h] - one
/// grammar, two surfaces, imported rather than duplicated), with
/// the 10s default when the flag is absent. Every surface resolves
/// through here so the default can never drift between them.
pub fn resolve_window(since: Option<&str>) -> Result<(Duration, String), String> {
    use crate::commands::port::window::{clamp_window, parse_window, window_label};
    let window = match since {
        Some(raw) => clamp_window(parse_window(raw).map_err(|e| format!("{e}"))?),
        None => WINDOW_DEFAULT,
    };
    let label = window_label(window);
    Ok((window, label))
}

/// The canonical device token from a stat(2) st_dev value (the
/// userspace encoding glibc reports - the 12-bit-major packing, the
/// same split holds' dev_major_minor applies). st_dev and the kernel
/// s_dev are two encodings of one (major, minor) pair; this brings
/// both sides to the same canonical integer - the form the BPF side
/// carries in its records and its filter keys. Lives here (not in
/// the feature-gated events module) because the LaneQuery needs it
/// in every build; the six-line decode is duplicated from
/// holds/procfs.rs by hand (that parser is a locked snapshot
/// surface), and mirrored on the BPF side by
/// events::device_token_from_kernel.
pub fn device_token_from_stat(st_dev: u64) -> u64 {
    let major = ((st_dev & 0x0000_0000_000f_ff00) >> 8) | ((st_dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (st_dev & 0x0000_0000_0000_00ff) | ((st_dev & 0x0000_0000_fff0_0000) >> 12);
    (major << 20) | minor
}

/// Which class of live events this surface reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpFilter {
    /// Open events only (holds).
    Opens,
    /// Write events only (touch).
    Writes,
    /// Both (why).
    Both,
}

/// What the ladder produced for one window.
#[derive(Debug)]
pub struct LaneParts {
    /// The mode line's verdict.
    pub mode: Mode,
    /// The Changes subsection (rows + the unavailable bit).
    pub changes: ChangesSection,
    /// The entries the lane itself owes the Unaccounted block (the
    /// out-of-window log record, the unavailable window, the live
    /// events whose pid is no longer visible).
    pub unaccounted: Vec<UnaccountedEntry>,
    /// The raw kernel records of the live capture, as drained -
    /// every event the ring held for this file, before the surface
    /// filter and before attribution. Carried for `why --raw`; absent
    /// in default builds (no live lane exists to produce any).
    pub raw: Vec<crate::ebpf::events::FileEvent>,
}

/// The per-run context the log half needs; the live half needs only
/// the identity. One struct keeps the signature from growing flags.
pub struct LaneQuery<'a> {
    /// The path as the user wrote it (the log grep key).
    pub display_path: &'a Path,
    /// The path as the log grep should read it (absolute).
    pub lookup_path: &'a Path,
    /// The uid-to-name map (shared with the log parsers).
    pub users: &'a HashMap<u32, String>,
    /// The queried file's inode (full 64 bits). Read only by the live
    /// half; the default build writes it and never reads it (the
    /// allow is the honest count of that split).
    pub inode: u64,
    /// The queried file's canonical device token. Same split as
    /// `inode`.
    pub device: u64,
}

/// Walk the ladder for one window. `Err` only from the live half (a
/// chain that died mid-command is worth an error, never a silent
/// lane switch); the log half degrades honestly instead of failing.
pub fn collect(
    query: &LaneQuery<'_>,
    window: Duration,
    filter: OpFilter,
) -> Result<LaneParts, String> {
    {
        if crate::ebpf::all_pins_present() {
            return collect_live(query, window, filter);
        }
    }
    Ok(collect_log(query, window))
}

// ── The live half (feature builds only) ─────────────────────────────

fn collect_live(
    query: &LaneQuery<'_>,
    window: Duration,
    filter: OpFilter,
) -> Result<LaneParts, String> {
    let events = crate::ebpf::fileprobe::capture_file_window(query.inode, query.device, window)?;

    let mut rows: Vec<EvidenceRow> = Vec::new();
    let mut gone_opens: usize = 0;
    let mut gone_writes: usize = 0;
    for event in &events {
        let is_open = event.op == crate::ebpf::events::FILE_OP_OPEN;
        // Both write paths are writes: the plain write probe (op=2) and
        // the vectorized writev probe (op=4, night-improve-42). The
        // filter must never re-open the gap the second probe closed -
        // a Writes-only window that dropped writev rows would be the
        // false negative reborn one layer up.
        let is_write = event.op == crate::ebpf::events::FILE_OP_WRITE
            || event.op == crate::ebpf::events::FILE_OP_WRITEV;
        let wanted = match filter {
            OpFilter::Opens => is_open,
            OpFilter::Writes => is_write,
            OpFilter::Both => is_open || is_write,
        };
        if !wanted {
            continue;
        }
        // The row's actor: the /proc facts for the recorded pid,
        // resolved at render time - the same fields the snapshot's
        // holder rows carry. A pid with no visible /proc entry at
        // render time is unaccounted (a namespace boundary, or an
        // exit between the change and the query).
        let Some((name, user)) = pid_context(event.pid, query.users) else {
            if is_open {
                gone_opens += 1;
            } else {
                gone_writes += 1;
            }
            continue;
        };
        // The action names the write path that crossed: the writev
        // parenthetical is the whole point of op=4 - the operator
        // learns WHICH syscall family the writer used.
        let action = match event.op {
            crate::ebpf::events::FILE_OP_OPEN => "opened",
            crate::ebpf::events::FILE_OP_WRITEV => "wrote (writev)",
            _ => "wrote",
        };
        rows.push(EvidenceRow::new(
            crate::ebpf::fileprobe::event_unix_secs(event),
            action,
            format!("{name} (pid {}, {user})", event.pid),
            Provenance::Observed,
        ));
    }

    let mut unaccounted = Vec::new();
    if gone_opens > 0 {
        unaccounted.push(UnaccountedEntry::new(
            gone_opens,
            "opens",
            "no visible PID - namespace boundary or exited before attribution",
        ));
    }
    if gone_writes > 0 {
        unaccounted.push(UnaccountedEntry::new(
            gone_writes,
            "writes",
            "no visible PID - namespace boundary or exited before attribution",
        ));
    }
    // events arrive ascending from the capture; the filter keeps the
    // order. No re-sorting here - the renderer never reorders.
    Ok(LaneParts {
        mode: Mode::Live,
        changes: ChangesSection {
            rows,
            unavailable: false,
        },
        unaccounted,
        raw: events,
    })
}

/// The pid's Name and Uid (real) from /proc, resolved to a username.
/// `None` when the process is gone or hidden - the honest absence.
fn pid_context(pid: u32, users: &HashMap<u32, String>) -> Option<(String, String)> {
    use crate::commands::touch::uid_to_user;
    use crate::system::read_status_value;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let name = crate::system::read_status_name(&status)?;
    let uid = read_status_value(&status, "Uid").and_then(|value| {
        value
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u32>().ok())
    });
    let user = match uid {
        Some(uid) => uid_to_user(uid, users),
        None => "unknown".to_owned(),
    };
    Some((name, user))
}

// ── The log half (every build) ──────────────────────────────────────

fn collect_log(query: &LaneQuery<'_>, window: Duration) -> LaneParts {
    // The log lane: audit first (real syscall records), journal
    // second (whatever mentioned the path). Whichever record comes
    // back is THE latest the lane has.
    let record: Option<(TouchInfo, bool)> =
        match try_audit_log(query.display_path, query.lookup_path, query.users) {
            Some(info) => Some((info, true)),
            None => try_journalctl(query.display_path, query.lookup_path, query.users)
                .map(|info| (info, false)),
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
                // proves the journal mentioned the path.
                let action = if from_audit {
                    "modified (audit log)"
                } else {
                    "journal mention"
                };
                let actor = log_actor(&info);
                let mut changes = ChangesSection {
                    rows: Vec::new(),
                    unavailable: false,
                };
                changes.rows.push(EvidenceRow::new(
                    Some(record_secs),
                    action,
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

/// The log record's actor, in the holder rows' format: the process
/// when the log recorded one, the username it recorded either way.
fn log_actor(info: &TouchInfo) -> String {
    // The old tree's actor line, single-sourced: ProcessEvidence::label
    // is the one implementation ("name pid=N"); the row appends the
    // user the log recorded.
    match &info.process {
        Some(process) => match process.pid {
            Some(pid) => format!("{} (pid {pid}, {})", process.name, info.actor),
            None => format!("{} ({})", process.name, info.actor),
        },
        None => info.actor.clone(),
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

#[cfg(test)]
#[path = "../../test/commands/lane_tests.rs"]
mod tests;
