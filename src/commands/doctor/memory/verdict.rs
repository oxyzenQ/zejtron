// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory verdict's lines (night-badass-5): the largest single
//! consumer, the conditional findings (the stale tmpfs file, the
//! deleted-but-open total, the residual above the heuristic
//! threshold), and the named absence. One builder, two surfaces -
//! the text ledger seats the lines under its Verdict header, the
//! JSON lane carries them in verdict.lines.

use super::MemorySample;
use super::fds::deleted_unique;
use super::ledger::{fmt_bytes, kib_to_bytes};
use super::residual_kib;

/// 500 MiB: the threshold above which an unheld tmpfs file or a
/// deleted-but-open total is anomalous enough for the verdict to
/// name it. The 15 percent residual threshold rides the same idea:
/// a named boundary, not a mood.
const ANOMALY_BYTES: u64 = 500 * 1024 * 1024;
const RESIDUAL_PCT_THRESHOLD: u64 = 15;

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane
/// (night-badass-5). The bool is the absence flag: when no finding
/// fired, the last line is the "No anomalous consumer detected."
/// sentence, which the text renderer seats in the grey tier.
pub(crate) fn verdict_parts(sample: &MemorySample) -> (Vec<String>, bool) {
    let mut lines: Vec<String> = Vec::new();

    // Line 1: the largest single consumer, always named when the
    // data allowed one. The verdict text is the report's content.
    match sample.pss.first() {
        Some(top) => lines.push(format!(
            "The largest single consumer is {} ({} PSS).",
            top.name,
            fmt_bytes(kib_to_bytes(top.pss_kib))
        )),
        None => lines.push(
            "No process PSS was readable (permission boundary); the largest \
             consumer cannot be named."
                .to_owned(),
        ),
    }

    // The conditional findings - each names a fact with its boundary,
    // never an action.
    let mut findings = 0usize;

    // The tmpfs file with no holders above the threshold: the exact
    // case htop cannot show. The condition is the user's to verify -
    // the touch surface names the file's actual holders and mtime.
    if let Some(file) = sample
        .tmpfs_files
        .iter()
        .find(|f| f.size_bytes >= ANOMALY_BYTES && f.holders.is_empty())
    {
        lines.push(format!(
            "The tmpfs file {} holds {} and no process in this namespace holds it \
             (a stale write, or a holder this user cannot see). It can be removed only \
             if nothing needs it - verify with `zejtron touch {}` first, which names \
             the file's actual holders and mtime.",
            file.path,
            fmt_bytes(file.size_bytes),
            file.path,
        ));
        findings += 1;
    }

    // Deleted-but-open total above the threshold: never "safe to
    // remove" - the holder process is the only way those pages free.
    // night-dragon-lts-4: the total counts each FILE once (dev, ino)
    // through the fd walk's identity accounting - the pre-fix sum
    // counted one row per holder, so a shared deleted file or memfd
    // riding N processes inflated the number the verdict leans on.
    let (_deleted_unique_files, deleted_total) = deleted_unique(&sample.deleted);
    if deleted_total >= ANOMALY_BYTES {
        lines.push(format!(
            "{} is held by deleted files still open in live processes. These cannot \
             be removed without closing the holder. Named above.",
            fmt_bytes(deleted_total)
        ));
        findings += 1;
    }

    // The residual above the heuristic threshold. checked arithmetic:
    // a zero or unreadable total yields no percent, never a panic or
    // a division-by-zero guess.
    if let (Some(mem), Some(residual)) = (&sample.meminfo, residual_kib(sample)) {
        let pct = u64::checked_mul(residual, 100).and_then(|n| n.checked_div(mem.total_kib));
        if let Some(pct) = pct.filter(|pct| *pct > RESIDUAL_PCT_THRESHOLD) {
            lines.push(format!(
                "The unaccounted remainder ({pct}%) is above the \
                 {RESIDUAL_PCT_THRESHOLD}% heuristic threshold - this is unusual; \
                 investigate with `zejtron doctor --symptom ram --raw` (raw dump of \
                 the underlying /proc reads)."
            ));
            findings += 1;
        }
    }

    let absence = findings == 0;
    if absence {
        lines.push("No anomalous consumer detected.".to_owned());
    }
    (lines, absence)
}
