// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory symptom's Evidence Ledger (night-improve-4, Part B):
//! the Phase 3 grammar - mode, sections, Unaccounted, Verdict, the
//! four provenance tiers - rendered for RAM. Every row is
//! \[measured] (a /proc read taken at the instant of the command);
//! the residual is \[unaccounted] by design. The verdict names
//! facts, never actions: "can be removed only if nothing needs it"
//! is a condition the user verifies, never an instruction.
//! zejtron remains read-only; the user decides.

use super::{MemorySample, TmpfsFile, holders_label, residual_kib};

/// 500 MiB: the threshold above which an unheld tmpfs file or a
/// deleted-but-open total is anomalous enough for the verdict to
/// name it. The 15 percent residual threshold rides the same idea:
/// a named boundary, not a mood.
const ANOMALY_BYTES: u64 = 500 * 1024 * 1024;
const RESIDUAL_PCT_THRESHOLD: u64 = 15;

/// The top-N rows each section renders.
const TOP_N: usize = 10;

pub(crate) fn render(sample: &MemorySample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("Evidence report: memory / ram".to_owned());
    lines.push("Mode: snapshot (this symptom does not need eBPF)".to_owned());
    lines.push(String::new());
    render_memory_header(sample, &mut lines);
    render_pss(sample, &mut lines);
    render_tmpfs(sample, &mut lines);
    render_deleted(sample, &mut lines);
    render_memfds(sample, &mut lines);
    render_kernel_buckets(sample, &mut lines);
    render_slab(sample, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

/// Adaptive size label: GiB above one gibibyte (one decimal), MiB
/// above one mebibyte, KiB above one kibibyte, raw bytes below.
/// One number, one unit, no scientific notation.
pub(crate) fn fmt_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

/// Pad a row's first column to the section's label width so the
/// sizes line up like the locked shape shows - computed from the
/// report's own rows, never from a terminal width.
fn pad(label: &str, width: usize) -> String {
    let visible = label.chars().count();
    if visible >= width {
        format!("{label} ")
    } else {
        format!("{label}{}", " ".repeat(width - visible))
    }
}

fn label_width(labels: &[String], floor: usize, cap: usize) -> usize {
    labels
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(floor)
        .clamp(floor, cap)
}

fn render_memory_header(sample: &MemorySample, lines: &mut Vec<String>) {
    let Some(mem) = &sample.meminfo else {
        lines.push("Memory total: unknown (/proc/meminfo unreadable)".to_owned());
        lines.push(String::new());
        return;
    };
    let total = kib_to_bytes(mem.total_kib);
    let used = kib_to_bytes(mem.total_kib.saturating_sub(mem.available_kib));
    let avail = kib_to_bytes(mem.available_kib);
    let pct = if mem.total_kib == 0 {
        0
    } else {
        (used as f64 / total as f64 * 100.0).round() as u64
    };
    lines.push(format!("Memory total: {}", fmt_bytes(total)));
    lines.push(format!(
        "Memory used:  {}  ({pct}% of total)",
        fmt_bytes(used)
    ));
    lines.push(format!("Memory avail: {}", fmt_bytes(avail)));
    lines.push(String::new());
}

fn render_pss(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Per-process PSS (top 10):".to_owned());
    let rows: Vec<&super::ProcessPss> = sample
        .pss
        .iter()
        .filter(|p| p.pss_kib > 0)
        .take(TOP_N)
        .collect();
    if rows.is_empty() {
        lines.push("  (none observed)".to_owned());
        lines.push(String::new());
        return;
    }
    let labels: Vec<String> = rows
        .iter()
        .map(|p| format!("PID {} ({})", p.pid, p.name))
        .collect();
    let width = label_width(&labels, 24, 44);
    for row in &rows {
        lines.push(format!(
            "  {}PSS {}  (anon {}, shmem {}, file {})  [measured]",
            pad(&format!("PID {} ({})", row.pid, row.name), width),
            fmt_bytes(kib_to_bytes(row.pss_kib)),
            fmt_bytes(kib_to_bytes(row.anon_kib)),
            fmt_bytes(kib_to_bytes(row.shmem_kib)),
            fmt_bytes(kib_to_bytes(row.file_kib)),
        ));
    }
    lines.push(String::new());
}

fn render_tmpfs(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Tmpfs (files in RAM, top 10):".to_owned());
    let with_size: Vec<&TmpfsFile> = sample
        .tmpfs_files
        .iter()
        .filter(|f| f.size_bytes > 0)
        .take(TOP_N)
        .collect();
    if with_size.is_empty() {
        lines.push("  (none observed)".to_owned());
        if sample.tmpfs_unreadable_dirs > 0 {
            lines.push(format!(
                "  {} tmpfs directories were unreadable (permission) and are not represented",
                sample.tmpfs_unreadable_dirs
            ));
        }
        lines.push(String::new());
        return;
    }
    let labels: Vec<String> = with_size.iter().map(|f| f.path.clone()).collect();
    let width = label_width(&labels, 24, 60);
    for file in &with_size {
        lines.push(format!(
            "  {}{}  {}  [measured]",
            pad(&file.path, width),
            fmt_bytes(file.size_bytes),
            holders_label(file),
        ));
    }
    if sample.tmpfs_unreadable_dirs > 0 {
        lines.push(format!(
            "  {} tmpfs directories were unreadable (permission) and are not represented",
            sample.tmpfs_unreadable_dirs
        ));
    }
    lines.push(String::new());
}

fn render_deleted(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Deleted-but-open files:".to_owned());
    if sample.deleted.is_empty() {
        lines.push("  (none observed)".to_owned());
        lines.push(String::new());
        return;
    }
    let rows: Vec<&super::DeletedOpenFile> = sample.deleted.iter().take(TOP_N).collect();
    let labels: Vec<String> = rows
        .iter()
        .map(|f| format!("PID {} ({})", f.pid, f.name))
        .collect();
    let width = label_width(&labels, 24, 44);
    for file in &rows {
        let size = match file.size_bytes {
            Some(bytes) => fmt_bytes(bytes),
            None => "unknown".to_owned(),
        };
        lines.push(format!(
            "  {}{}  {}  [measured]",
            pad(&format!("PID {} ({})", file.pid, file.name), width),
            size,
            file.path,
        ));
    }
    if sample.deleted.len() > TOP_N {
        lines.push(format!(
            "  ({} more deleted-but-open files, not rendered)",
            sample.deleted.len() - TOP_N
        ));
    }
    lines.push(String::new());
}

fn render_memfds(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Memfd files:".to_owned());
    if sample.memfds.is_empty() {
        lines.push("  (none observed)".to_owned());
        lines.push(String::new());
        return;
    }
    let rows: Vec<&super::MemfdFile> = sample.memfds.iter().take(TOP_N).collect();
    let labels: Vec<String> = rows
        .iter()
        .map(|f| format!("PID {} ({})", f.pid, f.name))
        .collect();
    let width = label_width(&labels, 24, 44);
    for file in &rows {
        let size = match file.size_bytes {
            Some(bytes) => fmt_bytes(bytes),
            None => "unknown".to_owned(),
        };
        lines.push(format!(
            "  {}{}  {}  [measured]",
            pad(&format!("PID {} ({})", file.pid, file.name), width),
            size,
            file.target,
        ));
    }
    lines.push(String::new());
}

fn render_kernel_buckets(sample: &MemorySample, lines: &mut Vec<String>) {
    let Some(mem) = &sample.meminfo else {
        return;
    };
    let page_cache = fmt_bytes(kib_to_bytes(mem.cached_kib.saturating_sub(mem.shmem_kib)));
    // The three kernel-level buckets render flush-left, exactly as
    // the locked shape shows them - they are totals, not rows under
    // a header, and the reclaimable story is the point of the line.
    lines.push(format!(
        "Page cache (reclaimable):        {page_cache}  [measured]"
    ));
    lines.push(format!(
        "Buffers:                         {}  [measured]",
        fmt_bytes(kib_to_bytes(mem.buffers_kib))
    ));
    lines.push(format!(
        "Shmem:                           {}  [measured]",
        fmt_bytes(kib_to_bytes(mem.shmem_kib))
    ));
    lines.push(String::new());
}

fn render_slab(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Slab:".to_owned());
    if !sample.slab_readable {
        lines.push(
            "  unavailable (/proc/slabinfo is not readable by this user; the \
             reclaimable/unreclaimable totals above still carry the slab total)"
                .to_owned(),
        );
    } else if sample.slab.is_empty() {
        lines.push("  (none observed)".to_owned());
    } else {
        let labels: Vec<String> = sample.slab.iter().map(|r| r.cache.clone()).collect();
        let width = label_width(&labels, 12, 44);
        for row in &sample.slab {
            lines.push(format!(
                "  {}{}  [measured]",
                pad(&row.cache, width),
                fmt_bytes(kib_to_bytes(row.size_kib)),
            ));
        }
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Unaccounted:".to_owned());
    match residual_kib(sample) {
        Some(residual) => {
            lines.push(format!(
                "  {} not attributable to the categories above (kernel, drivers, \
                 page tables, reserved regions)  [unaccounted]",
                fmt_bytes(kib_to_bytes(residual))
            ));
        }
        None => {
            lines.push(
                "  the residual is unknown (/proc/meminfo unreadable)  [unaccounted]".to_owned(),
            );
        }
    }
    // The permission boundaries, named always - a report that only
    // mentions them when they fired would read as "everything was
    // visible" on the runs where they did not fire.
    if sample.pss_permission_refused > 0 {
        lines.push(format!(
            "  {} processes' smaps_rollup unreadable (permission) - their memory \
             rides the residual above",
            sample.pss_permission_refused
        ));
    }
    if sample.pss_vanished > 0 {
        lines.push(format!(
            "  {} processes exited or emptied mid-scan - their memory rides the \
             residual above",
            sample.pss_vanished
        ));
    }
    if sample.fd_permission_refused > 0 {
        lines.push(format!(
            "  {} processes' fd tables unreadable (permission) - the tmpfs holder \
             list names only the holders visible to this user",
            sample.fd_permission_refused
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push("Verdict:".to_owned());

    // Line 1: the largest single consumer, always named when the
    // data allowed one.
    match sample.pss.first() {
        Some(top) => lines.push(format!(
            "  The largest single consumer is {} ({} PSS).",
            top.name,
            fmt_bytes(kib_to_bytes(top.pss_kib))
        )),
        None => lines.push(
            "  No process PSS was readable (permission boundary); the largest \
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
            "  The tmpfs file {} holds {} and no process in this namespace holds it \
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
    let deleted_total: u64 = sample
        .deleted
        .iter()
        .map(|f| f.size_bytes.unwrap_or(0))
        .sum();
    if deleted_total >= ANOMALY_BYTES {
        lines.push(format!(
            "  {} is held by deleted files still open in live processes. These cannot \
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
                "  The unaccounted remainder ({pct}%) is above the \
                 {RESIDUAL_PCT_THRESHOLD}% heuristic threshold - this is unusual; \
                 investigate with `zejtron doctor --symptom ram --raw` (raw dump of \
                 the underlying /proc reads)."
            ));
            findings += 1;
        }
    }

    if findings == 0 {
        lines.push("  No anomalous consumer detected.".to_owned());
    }
}

/// The drill-down: the verbatim /proc reads the report rode on.
/// Appended after the verdict; never rendered unless asked.
fn render_raw(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push("Raw /proc reads (drill-down):".to_owned());
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(contents) => {
            lines.push("  /proc/meminfo:".to_owned());
            for line in contents.lines() {
                lines.push(format!("    {line}"));
            }
        }
        Err(e) => lines.push(format!("  /proc/meminfo: unreadable ({e})")),
    }
    lines.push("  /proc/<pid>/smaps_rollup (top 10 by Pss, verbatim):".to_owned());
    for row in sample.pss.iter().take(TOP_N) {
        lines.push(format!("    == PID {} ({}) ==", row.pid, row.name));
        match std::fs::read_to_string(format!("/proc/{}/smaps_rollup", row.pid)) {
            Ok(contents) => {
                for line in contents.lines() {
                    lines.push(format!("      {line}"));
                }
            }
            Err(e) => lines.push(format!("      unreadable at render time ({e})")),
        }
    }
    lines.push("  /proc/mounts (tmpfs entries):".to_owned());
    match std::fs::read_to_string("/proc/mounts") {
        Ok(contents) => {
            let entries = super::parse_tmpfs_mounts_entries(&contents);
            if entries.is_empty() {
                lines.push("    (no tmpfs mounts observed)".to_owned());
            } else {
                for entry in entries {
                    lines.push(format!("    {entry}"));
                }
            }
        }
        Err(e) => lines.push(format!("    /proc/mounts unreadable ({e})")),
    }
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_ledger_tests.rs"]
mod tests;
