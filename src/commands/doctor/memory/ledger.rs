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

use super::exits::EXIT_WINDOW_LABEL;
use super::exits::ExitLane;
use super::{MemorySample, TmpfsFile, holders_label, residual_kib};

/// 500 MiB: the threshold above which an unheld tmpfs file or a
/// deleted-but-open total is anomalous enough for the verdict to
/// name it. The 15 percent residual threshold rides the same idea:
/// a named boundary, not a mood.
const ANOMALY_BYTES: u64 = 500 * 1024 * 1024;
const RESIDUAL_PCT_THRESHOLD: u64 = 15;

/// The top-N rows each section renders (the exits section shares
/// it - one row cap for the whole report).
pub(crate) const TOP_N: usize = 10;

pub(crate) fn render(sample: &MemorySample, raw: bool) -> String {
    // Roles (night-improve-37): the section headers and field labels
    // ride green, the mode line / hints / annotations ride grey, the
    // provenance tags ride the evidence split (green for [measured]
    // and [observed], grey for [unaccounted]), and the values
    // (sizes, PIDs, comms, percentages) stay unwrapped - white, the
    // terminal default. In Mono every wrap is the identity,
    // byte-identical to the pinned shape.
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} memory / ram",
        crate::output::ok_out("Evidence report:")
    ));
    lines.push(crate::output::grey_out(mode_line(&sample.exit_lane)));
    lines.push(String::new());
    render_memory_header(sample, &mut lines);
    render_pss(sample, &mut lines);
    render_tmpfs(sample, &mut lines);
    render_deleted(sample, &mut lines);
    render_memfds(sample, &mut lines);
    render_kernel_buckets(sample, &mut lines);
    render_slab(sample, &mut lines);
    super::exits::render_section(&sample.exit_lane, &mut lines, EXIT_WINDOW_LABEL);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

/// The mode line, driven by the exit lane's state (night-improve-47):
/// the post-mortem half is named only when it actually ran - and a
/// failed drain says so instead of claiming the lane. One line,
/// three truths, no drift with the section below.
fn mode_line(lane: &ExitLane) -> &'static str {
    match lane {
        ExitLane::NotAttached => "Mode: snapshot (eBPF not attached - recent exits are invisible)",
        ExitLane::Drained(_) => "Mode: snapshot + post-mortem (eBPF exit lane drained, last 5s)",
        ExitLane::DrainFailed(_) => {
            "Mode: snapshot + post-mortem (the exit drain failed - named below)"
        }
    }
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
        // The absence line rides grey (the "no events" class).
        lines.push(crate::output::grey_out(
            "Memory total: unknown (/proc/meminfo unreadable)",
        ));
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
    // Field labels ride green; the sizes are the values and stay
    // unwrapped; the parenthesized percentage keeps its number
    // unwrapped with the surrounding words grey.
    lines.push(format!(
        "{} {}",
        crate::output::ok_out("Memory total:"),
        fmt_bytes(total)
    ));
    lines.push(format!(
        "{}  {}{}{}{}",
        crate::output::ok_out("Memory used:"),
        fmt_bytes(used),
        crate::output::grey_out("  ("),
        pct,
        crate::output::grey_out("% of total)")
    ));
    lines.push(format!(
        "{} {}",
        crate::output::ok_out("Memory avail:"),
        fmt_bytes(avail)
    ));
    lines.push(String::new());
}

fn render_pss(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Per-process PSS (top 10):"));
    let rows: Vec<&super::ProcessPss> = sample
        .pss
        .iter()
        .filter(|p| p.pss_kib > 0)
        .take(TOP_N)
        .collect();
    if rows.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    let labels: Vec<String> = rows
        .iter()
        .map(|p| format!("PID {} ({})", p.pid, p.name))
        .collect();
    let width = label_width(&labels, 24, 44);
    for row in &rows {
        // The padded actor cell is the value (white, unwrapped); the
        // PSS/anon/shmem/file keys ride grey with their sizes
        // unwrapped; the [measured] tag rides green (the strongest
        // evidence). Pad first, color second. The separators ride
        // inside the grey key tokens (the leading comma-space of the
        // shmem/file keys), so the Mono bytes stay identical to the
        // locked shape - no doubled commas, no moved spaces.
        lines.push(format!(
            "  {}{}{}  ({}{}{}{}{}{})  {}",
            pad(&format!("PID {} ({})", row.pid, row.name), width),
            crate::output::grey_out("PSS "),
            fmt_bytes(kib_to_bytes(row.pss_kib)),
            crate::output::grey_out("anon "),
            fmt_bytes(kib_to_bytes(row.anon_kib)),
            crate::output::grey_out(", shmem "),
            fmt_bytes(kib_to_bytes(row.shmem_kib)),
            crate::output::grey_out(", file "),
            fmt_bytes(kib_to_bytes(row.file_kib)),
            crate::output::ok_out("[measured]"),
        ));
    }
    lines.push(String::new());
}

fn render_tmpfs(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Tmpfs (files in RAM, top 10):"));
    let with_size: Vec<&TmpfsFile> = sample
        .tmpfs_files
        .iter()
        .filter(|f| f.size_bytes > 0)
        .take(TOP_N)
        .collect();
    if with_size.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        if sample.tmpfs_unreadable_dirs > 0 {
            lines.push(grey_unreadable_dirs(sample.tmpfs_unreadable_dirs));
        }
        lines.push(String::new());
        return;
    }
    let labels: Vec<String> = with_size.iter().map(|f| f.path.clone()).collect();
    let width = label_width(&labels, 24, 60);
    for file in &with_size {
        // The path and size are the values (white, unwrapped); the
        // holders label rides grey (an annotation); the [measured]
        // tag rides green.
        lines.push(format!(
            "  {}{}  {}  {}",
            pad(&file.path, width),
            fmt_bytes(file.size_bytes),
            crate::output::grey_out(&holders_label(file)),
            crate::output::ok_out("[measured]"),
        ));
    }
    if sample.tmpfs_unreadable_dirs > 0 {
        lines.push(grey_unreadable_dirs(sample.tmpfs_unreadable_dirs));
    }
    lines.push(String::new());
}

/// The unreadable-directories note, rendered grey (a hint, the
/// locked scheme's secondary content). One builder, two call sites.
fn grey_unreadable_dirs(count: usize) -> String {
    crate::output::grey_out(&format!(
        "  {count} tmpfs directories were unreadable (permission) and are not represented"
    ))
}

fn render_deleted(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Deleted-but-open files:"));
    if sample.deleted.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
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
        // The actor cell, size, and path are the values (white,
        // unwrapped); the [measured] tag rides green.
        lines.push(format!(
            "  {}{}  {}  {}",
            pad(&format!("PID {} ({})", file.pid, file.name), width),
            size,
            file.path,
            crate::output::ok_out("[measured]"),
        ));
    }
    if sample.deleted.len() > TOP_N {
        lines.push(crate::output::grey_out(&format!(
            "  ({} more deleted-but-open files, not rendered)",
            sample.deleted.len() - TOP_N
        )));
    }
    lines.push(String::new());
}

fn render_memfds(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Memfd files:"));
    if sample.memfds.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
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
            "  {}{}  {}  {}",
            pad(&format!("PID {} ({})", file.pid, file.name), width),
            size,
            file.target,
            crate::output::ok_out("[measured]"),
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
    // The labels ride green (field labels), the sizes are the values
    // (unwrapped), the [measured] tags ride green.
    lines.push(format!(
        "{}{page_cache}  {}",
        crate::output::ok_out("Page cache (reclaimable):        "),
        crate::output::ok_out("[measured]")
    ));
    lines.push(format!(
        "{}{}  {}",
        crate::output::ok_out("Buffers:                         "),
        fmt_bytes(kib_to_bytes(mem.buffers_kib)),
        crate::output::ok_out("[measured]")
    ));
    lines.push(format!(
        "{}{}  {}",
        crate::output::ok_out("Shmem:                           "),
        fmt_bytes(kib_to_bytes(mem.shmem_kib)),
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_slab(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Slab:"));
    if !sample.slab_readable {
        lines.push(crate::output::grey_out(
            "  unavailable (/proc/slabinfo is not readable by this user; the \
             reclaimable/unreclaimable totals above still carry the slab total)",
        ));
    } else if sample.slab.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
    } else {
        let labels: Vec<String> = sample.slab.iter().map(|r| r.cache.clone()).collect();
        let width = label_width(&labels, 12, 44);
        for row in &sample.slab {
            lines.push(format!(
                "  {}{}  {}",
                pad(&row.cache, width),
                fmt_bytes(kib_to_bytes(row.size_kib)),
                crate::output::ok_out("[measured]"),
            ));
        }
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    match residual_kib(sample) {
        Some(residual) => {
            // The residual size is the value (unwrapped); the boundary
            // text and the [unaccounted] tag ride grey (the weaker
            // evidence, the locked scheme's secondary content).
            lines.push(format!(
                "  {} {}  {}",
                fmt_bytes(kib_to_bytes(residual)),
                crate::output::grey_out(
                    "not attributable to the categories above (kernel, drivers, \
                     page tables, reserved regions)"
                ),
                crate::output::grey_out("[unaccounted]"),
            ));
        }
        None => {
            lines.push(format!(
                "  {}  {}",
                crate::output::grey_out("the residual is unknown (/proc/meminfo unreadable)"),
                crate::output::grey_out("[unaccounted]"),
            ));
        }
    }
    // The post-exit attribution boundary, named by lane state
    // (night-improve-47 reworks night-improve-34's static line): the
    // exit lane either named the recent exits [observed] in its own
    // section, or names exactly why it cannot - the not-attached
    // sentence is the spec's own. Grey text, grey [unaccounted] tag
    // (a boundary note, the weakest evidence).
    match &sample.exit_lane {
        ExitLane::NotAttached => lines.push(format!(
            "  {}  {}",
            crate::output::grey_out(
                "eBPF is not attached - processes that exited before this \
                 snapshot are invisible"
            ),
            crate::output::grey_out("[unaccounted]"),
        )),
        ExitLane::Drained(_) => lines.push(format!(
            "  {}  {}",
            crate::output::grey_out(
                "processes that exited before the 5-second eBPF window: \
                 not named (the drain above holds the last 5 seconds only)"
            ),
            crate::output::grey_out("[unaccounted]"),
        )),
        ExitLane::DrainFailed(e) => lines.push(format!(
            "  {}  {}",
            crate::output::grey_out(&format!(
                "the eBPF exit drain failed ({e}) - exited processes are \
                 invisible to this report"
            )),
            crate::output::grey_out("[unaccounted]"),
        )),
    }
    // The permission boundaries, named always - a report that only
    // mentions them when they fired would read as "everything was
    // visible" on the runs where they did not fire. The text rides
    // grey (boundary notes); the counts stay unwrapped - the values.
    if sample.pss_permission_refused > 0 {
        lines.push(format!(
            "  {} {}",
            sample.pss_permission_refused,
            crate::output::grey_out(
                "processes' smaps_rollup unreadable (permission) - their memory \
                 rides the residual above"
            )
        ));
    }
    if sample.pss_vanished > 0 {
        lines.push(format!(
            "  {} {}",
            sample.pss_vanished,
            crate::output::grey_out(
                "processes exited or emptied mid-scan - their memory rides the \
                 residual above"
            )
        ));
    }
    if sample.fd_permission_refused > 0 {
        lines.push(format!(
            "  {} {}",
            sample.fd_permission_refused,
            crate::output::grey_out(
                "processes' fd tables unreadable (permission) - the tmpfs holder \
                 list names only the holders visible to this user"
            )
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));

    // Line 1: the largest single consumer, always named when the
    // data allowed one. The verdict text is the report's content and
    // stays unwrapped (white, the values it is composed of).
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
        // The absence verdict rides grey (the "no events" class -
        // the same honesty an empty window gets).
        lines.push(crate::output::grey_out("  No anomalous consumer detected."));
    }
}

/// The drill-down: the verbatim /proc reads the report rode on.
/// Appended after the verdict; never rendered unless asked.
fn render_raw(sample: &MemorySample, lines: &mut Vec<String>) {
    lines.push(String::new());
    // The drill-down header rides green (the section header); the
    // section keys ride grey (secondary content) and the verbatim
    // kernel lines stay unwrapped - they are the bytes the report
    // rode on, quoted, never repainted.
    lines.push(crate::output::ok_out("Raw /proc reads (drill-down):"));
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(contents) => {
            lines.push(crate::output::grey_out("  /proc/meminfo:"));
            for line in contents.lines() {
                lines.push(format!("    {line}"));
            }
        }
        Err(e) => lines.push(crate::output::grey_out(&format!(
            "  /proc/meminfo: unreadable ({e})"
        ))),
    }
    lines.push(crate::output::grey_out(
        "  /proc/<pid>/smaps_rollup (top 10 by Pss, verbatim):",
    ));
    for row in sample.pss.iter().take(TOP_N) {
        lines.push(crate::output::grey_out(&format!(
            "    == PID {} ({}) ==",
            row.pid, row.name
        )));
        match std::fs::read_to_string(format!("/proc/{}/smaps_rollup", row.pid)) {
            Ok(contents) => {
                for line in contents.lines() {
                    lines.push(format!("      {line}"));
                }
            }
            Err(e) => lines.push(crate::output::grey_out(&format!(
                "      unreadable at render time ({e})"
            ))),
        }
    }
    lines.push(crate::output::grey_out("  /proc/mounts (tmpfs entries):"));
    match std::fs::read_to_string("/proc/mounts") {
        Ok(contents) => {
            let entries = super::parse_tmpfs_mounts_entries(&contents);
            if entries.is_empty() {
                lines.push(crate::output::grey_out("    (no tmpfs mounts observed)"));
            } else {
                for entry in entries {
                    lines.push(format!("    {entry}"));
                }
            }
        }
        Err(e) => lines.push(crate::output::grey_out(&format!(
            "    /proc/mounts unreadable ({e})"
        ))),
    }
}

#[cfg(test)]
#[path = "../../../../test/commands/doctor/memory_ledger_tests.rs"]
mod tests;
