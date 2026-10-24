// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The Evidence Ledger's JSON output lane (`--print-json`): a
//! std-only serializer for the report type. No serde, no
//! serde_json, no new crates - the dependency law (three runtime
//! crates, period) holds even for the enterprise surface. The
//! structure is simple enough to serialize by hand: arrays of rows,
//! strings, and the four tiers.
//!
//! One line, byte-deterministic, jq-ready: the same report renders
//! the same bytes on every host, text or JSON. The shape mirrors
//! render.rs's text grammar field for field:
//!
//! ```json
//! {"ledger_version":3,"subject":"/etc/resolv.conf","mode":"snapshot",
//!  "lane":"journal fallback","window":"10s","measured":[...],
//!  "changes":{"unavailable":false,"rows":[...]},
//!  "unaccounted":[{"count":1,"category":"opens","reason":"..."}],
//!  "verdict":{"supports":"...","cannot_support":"..."}}
//! ```
//!
//! Field laws:
//! - `mode` is the base word of the mode line (`live`, `snapshot`,
//!   `mixed`).
//! - `lane` is the mode line's lane qualifier without the comma
//!   (`journal fallback`, `no event lane available`) or `null` for
//!   the unqualified lanes (`live`, `mixed`) - the text mode line
//!   omits the qualifier there, and so does JSON.
//! - A row carries `unix_secs` (null when the fact is absent - the
//!   JSON-native form of the text renderer's `unknown`),
//!   `timestamp_utc` (the clock-rendered string, null with it), the
//!   TYPED evidence fields at the row root (night-badass-6: `kind`
//!   plus the kind's raw fields, the v2 nested `action` object is
//!   gone), `actor` (the typed actor object, null for pure state),
//!   and `provenance` (one of the four tier tags, the locked
//!   vocabulary).
//! - The row's `kind` token is one per variant of [`
//!   super::row::EvidenceKind`], the same vocabulary the text
//!   phrase renders ("size 884 bytes" is `"kind":"size",
//!   "bytes":884`), and the variant's raw data rides beside it at
//!   the same level: numbers stay numbers (bytes, uid, gid, inode,
//!   dev), strings stay strings (file_type, octal, the held-via
//!   label, the cwd path), and absent optional parts are JSON null
//!   (the cwd of an unreadable directory, a runs row's missing
//!   half). The flat shape is the enterprise lane's contract: jq
//!   filters `.measured[] | select(.kind=="size") | .bytes` in one
//!   descent, no nesting to walk.
//! - The `actor` is the typed acting identity (night-badass-6):
//!   `{"name":...,"pid":N,"user":...}` with JSON null for each
//!   part the source did not name, and JSON null for the whole
//!   actor when the row is pure state - the machine-native form of
//!   the text grammar's em-dash. jq selects `.actor.pid == 2985`
//!   without parsing a parenthesized string.
//! - `changes.unavailable` is the absent-lane truth; rows sit
//!   beside it, and an empty window with a present lane is
//!   `unavailable:false` with an empty `rows` array - the two
//!   different truths the text renderer keeps apart.
//! - `unaccounted` is always present (empty array when nothing is
//!   named), `verdict` always exactly its two lines.
//!
//! Escaping: quote and backslash take their two-character forms,
//! the named control bytes take `\b` `\f` `\n` `\r` `\t`, any other
//! control byte takes `\u00xx`, and every other scalar (including
//! all of UTF-8) passes through untouched - the ledger's em-dash
//! actors and non-ASCII paths survive verbatim, as valid JSON.

use std::fmt::Write as _;

use super::row::{EvidenceActor, EvidenceKind, EvidenceRow};
use super::{EvidenceReport, Mode};

/// The one version number the automation lane can pin against: the
/// Evidence Ledger Specification this module mirrors. v3
/// (night-badass-6) flattened the row - the typed evidence fields
/// moved from the nested `action` object to the row root - and
/// typed the actor (the name/pid/user object, null for pure
/// state); v2 (night-badass-5) had typed the action, v1 was the
/// string phrase. Every one of those changes is a breaking event,
/// named by the version.
const LEDGER_VERSION: u32 = 3;

/// Serialize the report to one line of JSON. Pure function of its
/// input: no clock reads, no environment reads, no map iteration -
/// the same rows in, the same bytes out.
pub fn report_json(report: &EvidenceReport) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"ledger_version\":");
    let _ = write!(out, "{LEDGER_VERSION}");
    out.push_str(",\"subject\":");
    write_string(&mut out, &report.subject);
    out.push_str(",\"mode\":");
    write_string(&mut out, mode_word(report.mode));
    out.push_str(",\"lane\":");
    match lane_name(report.mode) {
        Some(lane) => write_string(&mut out, lane),
        None => out.push_str("null"),
    }
    out.push_str(",\"window\":");
    write_string(&mut out, &report.window_label);
    out.push_str(",\"measured\":");
    write_rows(&mut out, &report.measured);
    out.push_str(",\"changes\":{\"unavailable\":");
    out.push_str(if report.changes.unavailable {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"rows\":");
    write_rows(&mut out, &report.changes.rows);
    out.push_str("},\"unaccounted\":");
    write_unaccounted(&mut out, &report.unaccounted);
    out.push_str(",\"verdict\":{\"supports\":");
    write_string(&mut out, &report.verdict.supports);
    out.push_str(",\"cannot_support\":");
    write_string(&mut out, &report.verdict.cannot_support);
    out.push_str("}}");
    out
}

/// The base word of the mode line, the text grammar's own words.
fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Live => "live",
        Mode::SnapshotJournal | Mode::SnapshotNoLane => "snapshot",
        Mode::Mixed => "mixed",
    }
}

/// The lane qualifier without the comma; `None` for the unqualified
/// lanes (live, mixed), serialized as JSON null.
fn lane_name(mode: Mode) -> Option<&'static str> {
    match mode {
        Mode::Live | Mode::Mixed => None,
        Mode::SnapshotJournal => Some("journal fallback"),
        Mode::SnapshotNoLane => Some("no event lane available"),
    }
}

fn write_rows(out: &mut String, rows: &[EvidenceRow]) {
    out.push('[');
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_row(out, row);
    }
    out.push(']');
}

fn write_row(out: &mut String, row: &EvidenceRow) {
    out.push_str("{\"unix_secs\":");
    match row.unix_secs {
        Some(secs) => {
            let _ = write!(out, "{secs}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"timestamp_utc\":");
    match row.unix_secs {
        Some(secs) => write_string(out, &crate::info::clock::format_unix_secs(secs)),
        None => out.push_str("null"),
    }
    // The flat row (night-badass-6): the kind token and its raw
    // fields sit at the row root - the text column's own order
    // (timestamp, action, actor, tag) with no nesting to walk.
    out.push_str(",\"kind\":");
    write_string(out, row.kind.kind_word());
    write_kind_fields(out, &row.kind);
    out.push_str(",\"actor\":");
    write_actor(out, &row.actor);
    out.push_str(",\"provenance\":");
    write_string(out, row.provenance.tag());
    out.push('}');
}

/// Serialize the typed action's raw fields (night-badass-6, the
/// flattened v2 writer): one fragment per variant of [`EvidenceKind`],
/// each field carrying its own leading comma (the `kind` token was
/// written by the caller) - numbers as numbers, absent optional
/// parts as JSON null. The field names are the contract the
/// automation lane pins.
fn write_kind_fields(out: &mut String, kind: &EvidenceKind) {
    use EvidenceKind as K;
    match kind {
        K::Type { file_type } => {
            out.push_str(",\"file_type\":");
            write_string(out, file_type);
        }
        K::SymlinkTarget { target } => {
            out.push_str(",\"target\":");
            write_string(out, target);
        }
        K::Size { bytes } => {
            out.push_str(",\"bytes\":");
            let _ = write!(out, "{bytes}");
        }
        K::Owner {
            user,
            group,
            uid,
            gid,
        } => {
            out.push_str(",\"user\":");
            write_string(out, user);
            out.push_str(",\"group\":");
            write_string(out, group);
            out.push_str(",\"uid\":");
            let _ = write!(out, "{uid}");
            out.push_str(",\"gid\":");
            let _ = write!(out, "{gid}");
        }
        K::Permissions { octal } => {
            out.push_str(",\"octal\":");
            write_string(out, octal);
        }
        K::Inode { id, dev } => {
            out.push_str(",\"id\":");
            let _ = write!(out, "{id}");
            out.push_str(",\"dev\":");
            let _ = write!(out, "{dev}");
        }
        K::Modified { via } => {
            out.push_str(",\"via\":");
            match via {
                Some(source) => write_string(out, source),
                None => out.push_str("null"),
            }
        }
        K::Accessed | K::Changed => {}
        K::Held { via } => {
            out.push_str(",\"via\":");
            write_string(out, via);
        }
        K::Cwd { path } => {
            out.push_str(",\"path\":");
            match path {
                Some(path) => write_string(out, path),
                None => out.push_str("null"),
            }
        }
        K::Runs { cmd, unit } => {
            out.push_str(",\"cmd\":");
            match cmd {
                Some(cmd) => write_string(out, cmd),
                None => out.push_str("null"),
            }
            out.push_str(",\"unit\":");
            match unit {
                Some(unit) => write_string(out, unit),
                None => out.push_str("null"),
            }
        }
        K::Opened => {}
        K::Wrote { via } => {
            out.push_str(",\"via\":");
            match via {
                Some(family) => write_string(out, family),
                None => out.push_str("null"),
            }
        }
        K::JournalMention => {}
    }
}

/// Serialize the typed actor (night-badass-6): the name/pid/user
/// object with JSON null for each part the source did not name, and
/// JSON null for the whole actor when the row is pure state - the
/// machine-native form of the text grammar's em-dash. jq selects
/// `.actor.pid == 2985` without parsing a phrase.
fn write_actor(out: &mut String, actor: &EvidenceActor) {
    if actor.name.is_none() && actor.pid.is_none() && actor.user.is_none() {
        out.push_str("null");
        return;
    }
    out.push_str("{\"name\":");
    match &actor.name {
        Some(name) => write_string(out, name),
        None => out.push_str("null"),
    }
    out.push_str(",\"pid\":");
    match actor.pid {
        Some(pid) => {
            let _ = write!(out, "{pid}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"user\":");
    match &actor.user {
        Some(user) => write_string(out, user),
        None => out.push_str("null"),
    }
    out.push('}');
}

pub(crate) fn write_unaccounted(out: &mut String, entries: &[super::UnaccountedEntry]) {
    out.push('[');
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"count\":");
        let _ = write!(out, "{}", entry.count);
        out.push_str(",\"category\":");
        write_string(out, entry.category);
        out.push_str(",\"reason\":");
        write_string(out, &entry.reason);
        out.push('}');
    }
    out.push(']');
}

/// Write a JSON string literal with every control byte named:
/// quote and backslash take their two-character forms, the named
/// controls take `\b` `\f` `\n` `\r` `\t`, any other control byte
/// takes `\u00xx`, and every other scalar (including all of UTF-8)
/// passes through untouched.
pub(crate) fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            _ if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            _ => out.push(character),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[path = "../../test/evidence/json_tests.rs"]
mod tests;
