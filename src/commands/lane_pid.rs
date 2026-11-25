// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The live lane's recorded-pid attribution (night-frontier-Z11):
//! the one place a pid the kernel recorded is reconciled against the
//! /proc snapshot it is attributed from. The old attribution read
//! `/proc/<pid>/status` directly and shrugged when the read failed -
//! "no visible PID - namespace boundary or exited before
//! attribution" - one message for three different truths. The
//! recorded-pid compare splits them:
//!
//! 1. Recycled: the pid now names a process born AFTER the recorded
//!    event (the stat starttime against the event's CLOCK_MONOTONIC
//!    stamp). The /proc name is the new holder's, never the actor's -
//!    the record's own comm (night-frontier-Z8, D5) and the exit ring
//!    answer before the honest absence does, and the entry says what
//!    the recycled holder's name would have lied about.
//! 2. Hidden: the pid's own directory resolves (stat, status) but the
//!    namespace's directory listing does not name it - the getdents64
//!    view and the direct-lookup view of the same namespace disagree,
//!    the shape a stealth filter prints. The live lane runs with the
//!    pins open (root, or the attach session's owner), where a
//!    hidepid mount cannot explain the mismatch away; the entry still
//!    says cross-validate, never the rootkit word.
//! 3. Gone: no resolvable directory - the exited-or-namespace truth
//!    the old message named, and the only one it could.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::evidence::UnaccountedEntry;

/// How the recorded pid's /proc snapshot compares to the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PidVisibility {
    /// The pid resolves, is listed, and (when its birth is readable)
    /// predates the event: the live attribution stands.
    Live,
    /// The pid's directory resolves but the listing does not name it.
    Hidden,
    /// The pid now names a process born after the recorded event.
    Recycled,
    /// No resolvable directory: exited, or the lookup itself is gone.
    Gone,
}

/// One tick of the /proc stat ABI: USER_HZ is 100 on every
/// architecture Linux ships (include/uapi/asm-generic/param.h), so
/// the birth's own granularity is ten milliseconds - the slack the
/// recycle compare needs, because a jiffy boundary can read a birth
/// one tick late but never early.
const USER_HZ_TICK_NS: u64 = 10_000_000;

/// The pure truth table the recorded-pid compare runs: the /proc
/// snapshot's facts (status readable, the directory reachable by
/// direct lookup, the pid present in the namespace listing, the birth
/// stamp when the stat line gave one) against the recorded event's
/// CLOCK_MONOTONIC stamp. The recycle compare runs first - an
/// identity that names a later birth is the wrong identity, whatever
/// the listing says. Pure, so the table is pinnable without a live
/// kernel or a tampered namespace.
pub(crate) fn classify_pid(
    status_readable: bool,
    dir_reachable: bool,
    listed: bool,
    birth_boot_ns: Option<u64>,
    event_monotonic_ns: u64,
) -> PidVisibility {
    if status_readable {
        if let Some(birth) = birth_boot_ns
            && birth > event_monotonic_ns.saturating_add(USER_HZ_TICK_NS)
        {
            return PidVisibility::Recycled;
        }
        return match listed {
            true => PidVisibility::Live,
            false => PidVisibility::Hidden,
        };
    }
    // The status read failed: the direct lookup and the listing split
    // the two absences - a directory the lookup cannot resolve is the
    // exited-or-namespace truth, and one it resolves while the
    // listing does not name it is the hidden shape.
    match (dir_reachable, listed) {
        (true, false) => PidVisibility::Hidden,
        _ => PidVisibility::Gone,
    }
}

/// One readdir of the namespace's pid listing - the recorded-pid
/// compare's other half, shared by every event of one window (the
/// capture costs seconds; one getdents pass costs microseconds).
/// `None` when the listing itself is unreadable: the hidden check
/// then rides as listed - an unreadable listing is a named absence,
/// never a hidden verdict invented from it.
pub(crate) fn proc_listing() -> Option<HashSet<u32>> {
    let entries = std::fs::read_dir(Path::new("/proc")).ok()?;
    let mut pids = HashSet::new();
    for entry in entries.flatten() {
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            pids.insert(pid);
        }
    }
    Some(pids)
}

/// The recorded pid's attribution: the /proc reads the old
/// `pid_context` did, plus the two comparisons that split the honest
/// absence from the disagreement. Returns the /proc-learned actor
/// context ONLY when it is the recorded event's own - a recycled
/// holder's name is not the actor and rides `None` (the record's own
/// comm and the exit ring answer instead). `listing` is the window's
/// one readdir (see [`proc_listing`]); `None` degrades every pid to
/// listed, the honest default an unreadable listing earns.
pub(crate) fn attribute_pid(
    pid: u32,
    event_monotonic_ns: u64,
    users: &HashMap<u32, String>,
    listing: Option<&HashSet<u32>>,
) -> (Option<(String, String)>, PidVisibility) {
    use crate::commands::touch::uid_to_user;
    use crate::system::read_status_value;
    let Some(status) = std::fs::read_to_string(format!("/proc/{pid}/status")).ok() else {
        let dir_reachable = std::fs::metadata(format!("/proc/{pid}")).is_ok();
        let listed = listing.is_none_or(|set| set.contains(&pid));
        return (
            None,
            classify_pid(false, dir_reachable, listed, None, event_monotonic_ns),
        );
    };
    let name = crate::system::read_status_name(&status);
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
    let birth = crate::commands::proc::process_starttime_boot_ns(Path::new("/proc"), pid);
    let listed = listing.is_none_or(|set| set.contains(&pid));
    let visibility = classify_pid(true, true, listed, birth, event_monotonic_ns);
    let context = if visibility == PidVisibility::Recycled {
        None
    } else {
        name.map(|name| (name, user))
    };
    (context, visibility)
}

/// The event-versus-distinct split (night-witness-pids): the clause
/// appended to the count-backed pid entries. The entry's `count`
/// counts EVENTS (one per recorded event); `per_pid` holds each
/// distinct recorded pid's contribution, and the clause names up to
/// 32 of them in ascending pid order - the audit question "how many
/// processes is that, really" answered inside the entry instead of
/// left to a misread of the count. Pure, so the clause is pinnable
/// without a namespace.
pub(crate) fn pid_sample_clause(count: usize, per_pid: &BTreeMap<u32, usize>) -> String {
    const SAMPLE_CAP: usize = 32;
    let distinct = per_pid.len();
    let plural = if distinct == 1 { "" } else { "s" };
    let listed: Vec<String> = per_pid
        .iter()
        .take(SAMPLE_CAP)
        .map(|(pid, events)| format!("pid {pid} x{events}"))
        .collect();
    let mut clause = format!(" - the {count} events carry {distinct} distinct pid{plural}");
    if !listed.is_empty() {
        clause.push_str(&format!("; sample: {}", listed.join(", ")));
        if distinct > SAMPLE_CAP {
            clause.push_str(&format!(" (+{} more pids unlisted)", distinct - SAMPLE_CAP));
        }
    }
    clause
}

/// The hidden-pids boundary (night-frontier-Z11): the count-backed
/// entry for the recorded pids the namespace's own listing does not
/// show. The count counts events; the per-pid map rides the entry's
/// own clause (night-witness-pids) so the distinct-process question
/// is answered where the count is printed. Pure, so the wording is
/// pinnable without a tampered namespace.
pub(crate) fn hidden_pid_entry(count: usize, per_pid: &BTreeMap<u32, usize>) -> UnaccountedEntry {
    let clause = pid_sample_clause(count, per_pid);
    UnaccountedEntry::new(
        count,
        "hidden pids",
        format!(
            "the kernel resolved these pids' /proc directories, but the directory \
             listing does not show them - the listing and the direct lookup \
             disagree, the shape a getdents filter (stealth) or a hidepid-style \
             mount prints - cross-validate with sudo before trusting the process \
             table{clause}"
        ),
    )
}

/// The recycled-pids boundary (night-frontier-Z11): the count-backed
/// entry for the recorded pids whose /proc identity now belongs to a
/// process born after the event - the anti-false-positive arm. The
/// count counts events; the per-pid clause rides as above
/// (night-witness-pids). Pure, so the wording is pinnable without a
/// pid-recycling race.
pub(crate) fn recycled_pid_entry(count: usize, per_pid: &BTreeMap<u32, usize>) -> UnaccountedEntry {
    let clause = pid_sample_clause(count, per_pid);
    UnaccountedEntry::new(
        count,
        "recycled pids",
        format!(
            "these recorded pids now name processes born after the events - the \
             old holders exited and the numbers moved on; the rows render the \
             records' own actors, never the new holders' names{clause}"
        ),
    )
}

#[cfg(test)]
#[path = "../../test/commands/lane_pid_tests.rs"]
mod tests;
