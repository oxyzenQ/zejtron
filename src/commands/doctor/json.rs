// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's JSON lane (`--print-json`, night-badass-5): the
//! readiness report and every symptom, as one line of typed JSON.
//! Std-only by the dependency law - the serializer is hand-written,
//! the string escaper is the Evidence Ledger's own (one escaping
//! law, every surface). The shape mirrors the text ledgers field
//! for field: the same facts the operator reads, held as data -
//! numbers stay numbers, absent optional facts are JSON null, and
//! the named boundaries ride `unaccounted` as the same
//! `{count, category, reason}` entries the Evidence Ledger speaks.
//!
//! ```json
//! {"ledger_version":1,"mode":"readiness","user":{"uid":0,"class":
//!  "privileged"},"checks":[...],"summary":{...},"ebpf":{...}}
//! {"ledger_version":1,"mode":"symptom","symptom":"ram","memory":
//!  {"total_bytes":N,"used_bytes":N,"available_bytes":N,"used_pct":
//!  N},"processes":[...],"unaccounted":[...],"verdict":{"lines":[...]}}
//! ```
//!
//! The verdicts are prose by nature - the fact sentence the report
//! names - so they ride as `verdict.lines`; everything a machine
//! wants to filter on (percentages, bytes, pids, states) is a typed
//! field beside it. One line, byte-deterministic: pure functions of
//! their sample, no clock reads, no map iteration.

use std::fmt::Write as _;

use super::cpu::{CpuRow, CpuSample};
use super::disk::DiskSample;
use super::ebpf;
use super::gpu::GpuSample;
use super::memory::exits::ExitLane;
use super::memory::{MemorySample, residual_kib};
use super::network::NetworkSample;
use super::{CheckResult, Summary};
use crate::evidence::UnaccountedEntry;
use crate::evidence::json::{write_string, write_unaccounted};

/// The one version number the doctor's automation lane pins: the
/// JSON surface's own contract line, v1.
const LEDGER_VERSION: u32 = 1;

// ── Shared writers ────────────────────────────────────────────────

/// KiB to bytes, saturating - the memory ledger's own arithmetic.
fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

/// One fixed-point number with one decimal, the text ledger's own
/// percentage shape ("47.2") - deterministic bytes, no float drift.
fn write_pct(out: &mut String, pct: f64) {
    let _ = write!(out, "{pct:.1}");
}

/// The array framing every writer below rides on: `[a,b,c]` with
/// the closure emitting each element (the index is passed so the
/// caller owns the comma).
fn write_array(out: &mut String, items: usize, emit: impl Fn(&mut String, usize)) {
    out.push('[');
    for index in 0..items {
        if index > 0 {
            out.push(',');
        }
        emit(out, index);
    }
    out.push(']');
}

/// The string array: `["a","b"]`.
fn write_str_array(out: &mut String, items: &[&str]) {
    write_array(out, items.len(), |out, index| {
        write_string(out, items[index]);
    });
}

/// The optional number: the value, or JSON null - the absent fact
/// stays absent, never zero.
fn write_opt_u64(out: &mut String, value: Option<u64>) {
    match value {
        Some(value) => {
            let _ = write!(out, "{value}");
        }
        None => out.push_str("null"),
    }
}

/// The optional fixed-point number, or JSON null.
fn write_opt_pct(out: &mut String, value: Option<f64>) {
    match value {
        Some(pct) => write_pct(out, pct),
        None => out.push_str("null"),
    }
}

/// The verdict block: `{"lines":[...]}` - the prose the report
/// names, one line per element.
fn write_verdict(out: &mut String, lines: &[String]) {
    out.push_str(",\"verdict\":{\"lines\":");
    write_array(out, lines.len(), |out, index| {
        write_string(out, &lines[index]);
    });
    out.push('}');
}

/// The Unaccounted block: the Evidence Ledger's own entries, the
/// same writer the evidence surfaces speak.
fn write_unaccounted_entries(out: &mut String, entries: &[UnaccountedEntry]) {
    out.push_str(",\"unaccounted\":");
    write_unaccounted(out, entries);
}

/// The exits overlay object (night-improve-47's three truths): the
/// lane state, the drained rows (the render's own TOP_N cap and
/// overflow count), or the drain failure verbatim.
fn write_exits(out: &mut String, lane: &ExitLane, window_label: &str) {
    out.push_str(",\"exits\":{\"lane\":");
    match lane {
        ExitLane::NotAttached => out.push_str("\"not-attached\"}"),
        ExitLane::DrainFailed(error) => {
            out.push_str("\"drain-failed\",\"error\":");
            write_string(out, error);
            out.push('}');
        }
        ExitLane::Drained(rows) => {
            out.push_str("\"drained\",\"window_label\":");
            write_string(out, window_label);
            out.push_str(",\"rows\":");
            let shown = rows.len().min(super::memory::ledger::TOP_N);
            write_array(out, shown, |out, index| {
                let row = &rows[index];
                out.push_str("{\"pid\":");
                let _ = write!(out, "{}", row.pid);
                out.push_str(",\"comm\":");
                write_string(out, &row.comm);
                out.push_str(",\"at\":");
                write_string(
                    out,
                    &crate::info::clock::time_of_day_from_monotonic_ns(row.timestamp_ns),
                );
                out.push_str(",\"timestamp_ns\":");
                let _ = write!(out, "{}", row.timestamp_ns);
                out.push('}');
            });
            out.push_str(",\"overflow\":");
            let _ = write!(
                out,
                "{}",
                rows.len().saturating_sub(super::memory::ledger::TOP_N)
            );
            out.push('}');
        }
    }
}

// ── The readiness report ─────────────────────────────────────────

/// The readiness report as JSON: the user context, every check
/// (name, lowercase status, the message the text row carries), the
/// summary counts, and the eBPF section's structured facts.
pub(super) fn readiness_json(
    checks: &[CheckResult],
    summary: &Summary,
    uid: Option<u32>,
) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("{\"ledger_version\":");
    let _ = write!(out, "{LEDGER_VERSION}");
    out.push_str(",\"mode\":\"readiness\"");
    out.push_str(",\"user\":{\"uid\":");
    match uid {
        Some(uid) => {
            let _ = write!(out, "{uid}");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"class\":");
    write_string(
        &mut out,
        if uid == Some(0) {
            "privileged"
        } else {
            "unprivileged"
        },
    );
    out.push_str("},\"checks\":");
    write_array(&mut out, checks.len(), |out, index| {
        let check = &checks[index];
        out.push_str("{\"name\":");
        write_string(out, check.check);
        out.push_str(",\"status\":");
        write_string(out, check.status.label().to_ascii_lowercase().as_str());
        out.push_str(",\"message\":");
        write_string(out, &check.message);
        out.push('}');
    });
    out.push_str(",\"summary\":{\"ok\":");
    let _ = write!(out, "{}", summary.ok);
    out.push_str(",\"warn\":");
    let _ = write!(out, "{}", summary.warn);
    out.push_str(",\"fail\":");
    let _ = write!(out, "{}", summary.fail);
    out.push_str("},\"ebpf\":");
    write_ebpf_facts(&mut out, &ebpf::facts_json());
    out.push('}');
    out
}

/// The eBPF section's typed facts - the nine text rows held as
/// data, the pin set's state named beside its names.
fn write_ebpf_facts(out: &mut String, facts: &ebpf::EbpfFactsJson) {
    out.push_str("{\"feature\":");
    write_string(out, facts.feature);
    out.push_str(",\"kernel\":");
    write_string(out, &facts.kernel);
    out.push_str(",\"btf\":");
    write_string(out, facts.btf);
    out.push_str(",\"lockdown\":");
    write_string(out, facts.lockdown);
    out.push_str(",\"caps\":");
    write_string(out, &facts.caps);
    out.push_str(",\"lane\":");
    write_string(out, facts.lane);
    out.push_str(",\"lane_attached\":");
    out.push_str(if facts.lane_attached { "true" } else { "false" });
    out.push_str(",\"lane_detail\":");
    write_string(out, &facts.lane_detail);
    out.push_str(",\"camera\":");
    write_string(out, &facts.camera);
    out.push_str(",\"probes\":");
    write_str_array(out, &facts.probes);
    out.push_str(",\"pins_state\":");
    write_string(out, facts.pins_state);
    out.push_str(",\"pins\":");
    write_str_array(out, &facts.pins);
    out.push_str(",\"pins_missing\":");
    write_str_array(out, &facts.pins_missing);
    out.push('}');
}

// ── The symptom envelope ─────────────────────────────────────────

/// The symptom envelope's opening: ledger_version, mode, symptom,
/// the sample stamp, and the window (null for the snapshot lanes
/// that carry none).
fn symptom_header(out: &mut String, symptom: &str, window: Option<&str>) {
    out.push_str("{\"ledger_version\":");
    let _ = write!(out, "{LEDGER_VERSION}");
    out.push_str(",\"mode\":\"symptom\",\"symptom\":");
    write_string(out, symptom);
    out.push_str(",\"window\":");
    match window {
        Some(window) => write_string(out, window),
        None => out.push_str("null"),
    }
}

/// The `slow` deferral as JSON - the named absence, the same
/// honesty the text line carries: not implemented, and the list of
/// what is.
pub(super) fn slow_json(implemented: &[&str]) -> String {
    let mut out = String::with_capacity(128);
    symptom_header(&mut out, "slow", None);
    out.push_str(",\"implemented\":false,\"implemented_symptoms\":");
    write_str_array(&mut out, implemented);
    out.push('}');
    out
}

// ── ram ──────────────────────────────────────────────────────────

/// The ram symptom as JSON: the memory header as three byte counts
/// and the percent, the per-process PSS rows the text renders (top
/// of the readable set), the tmpfs/deleted/memfd views, the kernel
/// buckets, the slab census, the exit lane, the residual as a
/// number, and the Unaccounted block's boundary entries.
pub(super) fn json_ram(sample: &MemorySample) -> String {
    let mut out = String::with_capacity(1024);
    symptom_header(&mut out, "ram", None);
    // The memory header: null when /proc/meminfo was unreadable -
    // the absent fact stays absent.
    match &sample.meminfo {
        Some(mem) => {
            let total = kib_to_bytes(mem.total_kib);
            let used = kib_to_bytes(mem.total_kib.saturating_sub(mem.available_kib));
            let available = kib_to_bytes(mem.available_kib);
            let pct = if mem.total_kib == 0 {
                0
            } else {
                (used as f64 / total as f64 * 100.0).round() as u64
            };
            out.push_str(",\"memory\":{\"total_bytes\":");
            let _ = write!(out, "{total}");
            out.push_str(",\"used_bytes\":");
            let _ = write!(out, "{used}");
            out.push_str(",\"available_bytes\":");
            let _ = write!(out, "{available}");
            out.push_str(",\"used_pct\":");
            let _ = write!(out, "{pct}");
            out.push('}');
        }
        None => out.push_str(",\"memory\":null"),
    }
    // The per-process PSS rows: the text's own top-10-of-positive
    // slice, with the readable-set total and the two boundary
    // counts beside it.
    let pss_rows: Vec<&super::memory::ProcessPss> = sample
        .pss
        .iter()
        .filter(|p| p.pss_kib > 0)
        .take(super::memory::ledger::TOP_N)
        .collect();
    out.push_str(",\"processes\":");
    write_array(&mut out, pss_rows.len(), |out, index| {
        let p = pss_rows[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", p.pid);
        out.push_str(",\"comm\":");
        write_string(out, &p.name);
        out.push_str(",\"pss_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(p.pss_kib));
        out.push_str(",\"anon_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(p.anon_kib));
        out.push_str(",\"file_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(p.file_kib));
        out.push_str(",\"shmem_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(p.shmem_kib));
        out.push_str(",\"rss_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(p.rss_kib));
        out.push('}');
    });
    out.push_str(",\"processes_total\":");
    let _ = write!(out, "{}", sample.pss.len());
    out.push_str(",\"pss_permission_refused\":");
    let _ = write!(out, "{}", sample.pss_permission_refused);
    out.push_str(",\"pss_vanished\":");
    let _ = write!(out, "{}", sample.pss_vanished);
    // The tmpfs view: the text's top files (size > 0) and the
    // mounts they ride on.
    let tmpfs_files: Vec<&super::memory::TmpfsFile> = sample
        .tmpfs_files
        .iter()
        .filter(|f| f.size_bytes > 0)
        .take(super::memory::ledger::TOP_N)
        .collect();
    out.push_str(",\"tmpfs\":{\"mounts\":");
    write_array(&mut out, sample.tmpfs_mounts.len(), |out, index| {
        write_string(out, &sample.tmpfs_mounts[index]);
    });
    out.push_str(",\"files\":");
    write_array(&mut out, tmpfs_files.len(), |out, index| {
        let f = tmpfs_files[index];
        out.push_str("{\"path\":");
        write_string(out, &f.path);
        out.push_str(",\"size_bytes\":");
        let _ = write!(out, "{}", f.size_bytes);
        out.push_str(",\"holders\":");
        write_array(out, f.holders.len(), |out, hindex| {
            let _ = write!(out, "{}", f.holders[hindex]);
        });
        out.push('}');
    });
    out.push_str(",\"unreadable_dirs\":");
    let _ = write!(out, "{}", sample.tmpfs_unreadable_dirs);
    out.push('}');
    // The deleted-but-open and memfd views.
    let deleted: Vec<&super::memory::DeletedOpenFile> = sample
        .deleted
        .iter()
        .take(super::memory::ledger::TOP_N)
        .collect();
    out.push_str(",\"deleted_open\":");
    write_array(&mut out, deleted.len(), |out, index| {
        let f = deleted[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", f.pid);
        out.push_str(",\"comm\":");
        write_string(out, &f.name);
        out.push_str(",\"path\":");
        write_string(out, &f.path);
        out.push_str(",\"size_bytes\":");
        write_opt_u64(out, f.size_bytes);
        out.push('}');
    });
    let memfds: Vec<&super::memory::MemfdFile> = sample
        .memfds
        .iter()
        .take(super::memory::ledger::TOP_N)
        .collect();
    out.push_str(",\"memfds\":");
    write_array(&mut out, memfds.len(), |out, index| {
        let f = memfds[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", f.pid);
        out.push_str(",\"comm\":");
        write_string(out, &f.name);
        out.push_str(",\"target\":");
        write_string(out, &f.target);
        out.push_str(",\"size_bytes\":");
        write_opt_u64(out, f.size_bytes);
        out.push('}');
    });
    // The kernel-level buckets and the slab census.
    match &sample.meminfo {
        Some(mem) => {
            out.push_str(",\"kernel_buckets\":{\"page_cache_bytes\":");
            let _ = write!(
                out,
                "{}",
                kib_to_bytes(mem.cached_kib.saturating_sub(mem.shmem_kib))
            );
            out.push_str(",\"buffers_bytes\":");
            let _ = write!(out, "{}", kib_to_bytes(mem.buffers_kib));
            out.push_str(",\"shmem_bytes\":");
            let _ = write!(out, "{}", kib_to_bytes(mem.shmem_kib));
            out.push('}');
        }
        None => out.push_str(",\"kernel_buckets\":null"),
    }
    out.push_str(",\"slab\":{\"readable\":");
    out.push_str(if sample.slab_readable {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"top\":[");
    for (index, row) in sample.slab.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"cache\":");
        write_string(&mut out, &row.cache);
        out.push_str(",\"size_bytes\":");
        let _ = write!(out, "{}", kib_to_bytes(row.size_kib));
        out.push('}');
    }
    out.push_str("]}");
    out.push_str(",\"residual_bytes\":");
    write_opt_u64(&mut out, residual_kib(sample).map(kib_to_bytes));
    write_exits(
        &mut out,
        &sample.exit_lane,
        super::memory::exits::EXIT_WINDOW_LABEL,
    );
    write_unaccounted_entries(&mut out, &ram_unaccounted(sample));
    write_verdict(&mut out, &super::memory::ledger::verdict_parts(sample).0);
    out.push('}');
    out
}

/// The ram Unaccounted block as entries: the residual is a number
/// beside it (residual_bytes), the boundaries here are the ones the
/// text block names - the exit lane's visibility, the permission
/// and vanished-process counts.
fn ram_unaccounted(sample: &MemorySample) -> Vec<UnaccountedEntry> {
    let mut entries = Vec::new();
    match &sample.exit_lane {
        ExitLane::NotAttached => {
            entries.push(UnaccountedEntry::new(
                1,
                "exited processes",
                "eBPF is not attached - processes that exited before this snapshot are invisible",
            ));
        }
        ExitLane::Drained(_) => {
            entries.push(UnaccountedEntry::new(
                1,
                "exited processes",
                "processes that exited before the 5-second eBPF window: not named (the drain above holds the last 5 seconds only)",
            ));
        }
        ExitLane::DrainFailed(error) => {
            entries.push(UnaccountedEntry::new(
                1,
                "exited processes",
                format!(
                    "the eBPF exit drain failed ({error}) - exited processes are invisible to this report"
                ),
            ));
        }
    }
    if sample.pss_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.pss_permission_refused,
            "processes",
            "smaps_rollup unreadable (permission) - their memory rides the residual above",
        ));
    }
    if sample.pss_vanished > 0 {
        entries.push(UnaccountedEntry::new(
            sample.pss_vanished,
            "processes",
            "exited or emptied mid-scan - their memory rides the residual above",
        ));
    }
    if sample.fd_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.fd_permission_refused,
            "fd tables",
            "unreadable (permission) - the tmpfs holder list names only the holders visible to this user",
        ));
    }
    entries
}

// ── cpu ──────────────────────────────────────────────────────────

/// The cpu symptom as JSON: the window's busy share and load
/// average, the ranked consumers (the pct the text renders, as a
/// number), the R/D state counts, the boundary counts, the exit
/// lane, and the Unaccounted block.
pub(super) fn json_cpu(sample: &CpuSample) -> String {
    let mut out = String::with_capacity(768);
    symptom_header(&mut out, "cpu", Some("1.0s"));
    out.push_str(",\"ncpu\":");
    let _ = write!(out, "{}", sample.ncpu);
    out.push_str(",\"loadavg_1min\":");
    write_opt_pct(&mut out, sample.loadavg_1min);
    out.push_str(",\"busy_pct\":");
    write_opt_pct(&mut out, sample.busy_pct);
    out.push_str(",\"total_ticks_delta\":");
    let _ = write!(out, "{}", sample.total_ticks_delta);
    out.push_str(",\"top\":");
    write_array(&mut out, sample.top.len(), |out, index| {
        write_cpu_row(out, &sample.top[index]);
    });
    out.push_str(",\"running\":");
    let _ = write!(out, "{}", sample.running);
    out.push_str(",\"stuck\":");
    write_array(&mut out, sample.stuck.len(), |out, index| {
        let row = &sample.stuck[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", row.pid);
        out.push_str(",\"comm\":");
        write_string(out, &row.comm);
        out.push('}');
    });
    out.push_str(",\"stuck_overflow\":");
    let _ = write!(out, "{}", sample.stuck_overflow);
    out.push_str(",\"started_in_window\":");
    let _ = write!(out, "{}", sample.started_in_window);
    out.push_str(",\"vanished_between_reads\":");
    let _ = write!(out, "{}", sample.vanished_between_reads);
    write_exits(
        &mut out,
        &sample.exit_lane,
        super::delta::OVERLAY_WINDOW_LABEL,
    );
    write_unaccounted_entries(&mut out, &cpu_unaccounted(sample));
    write_verdict(&mut out, &super::cpu::verdict_lines(sample));
    out.push('}');
    out
}

/// One ranked CPU row: the pid, the comm, the window share as a
/// number, the raw tick delta beside it.
fn write_cpu_row(out: &mut String, row: &CpuRow) {
    out.push_str("{\"pid\":");
    let _ = write!(out, "{}", row.pid);
    out.push_str(",\"comm\":");
    write_string(out, &row.comm);
    out.push_str(",\"pct\":");
    write_pct(out, row.pct);
    out.push_str(",\"ticks\":");
    let _ = write!(out, "{}", row.ticks);
    out.push('}');
}

/// The cpu Unaccounted block as entries: the sampling boundary (the
/// lane's own truth), the started-in-window and vanished counts.
fn cpu_unaccounted(sample: &CpuSample) -> Vec<UnaccountedEntry> {
    let mut entries = vec![sampling_entry(&sample.exit_lane)];
    if sample.started_in_window > 0 {
        entries.push(UnaccountedEntry::new(
            sample.started_in_window,
            "processes",
            "started inside the window: no baseline to delta against, not ranked",
        ));
    }
    if sample.vanished_between_reads > 0 {
        entries.push(UnaccountedEntry::new(
            sample.vanished_between_reads,
            "processes",
            "vanished between the reads: their window share is not carried",
        ));
    }
    entries
}

/// The sampling-boundary entry, the delta lanes' shared sentence -
/// the same three truths the shared text builder phrases.
fn sampling_entry(lane: &ExitLane) -> UnaccountedEntry {
    match lane {
        ExitLane::NotAttached => UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the 1.0s sampling window: not attributed (zejtron samples, it does not watch)",
        ),
        ExitLane::Drained(_) => UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the 1.0s sampling window: named [observed] in the exits section above (the eBPF drain holds the last 2s)",
        ),
        ExitLane::DrainFailed(error) => UnaccountedEntry::new(
            1,
            "process lifecycles",
            format!(
                "processes that started and exited within the 1.0s sampling window: not attributed (the eBPF exit drain failed: {error})"
            ),
        ),
    }
}

// ── disk ─────────────────────────────────────────────────────────

/// The disk symptom as JSON: the iowait share, the ranked block I/O
/// consumers as raw byte deltas, the boundary counts, the exit lane,
/// and the Unaccounted block.
pub(super) fn json_disk(sample: &DiskSample) -> String {
    let mut out = String::with_capacity(768);
    symptom_header(&mut out, "disk", Some("1.0s"));
    out.push_str(",\"iowait_pct\":");
    write_opt_pct(&mut out, sample.iowait_pct);
    out.push_str(",\"total_ticks_delta\":");
    let _ = write!(out, "{}", sample.total_ticks_delta);
    out.push_str(",\"top\":");
    write_array(&mut out, sample.top.len(), |out, index| {
        let row = &sample.top[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", row.pid);
        out.push_str(",\"comm\":");
        write_string(out, &row.comm);
        out.push_str(",\"read_bytes\":");
        let _ = write!(out, "{}", row.read_delta);
        out.push_str(",\"write_bytes\":");
        let _ = write!(out, "{}", row.write_delta);
        out.push('}');
    });
    out.push_str(",\"io_permission_refused\":");
    let _ = write!(out, "{}", sample.io_permission_refused);
    out.push_str(",\"started_in_window\":");
    let _ = write!(out, "{}", sample.started_in_window);
    out.push_str(",\"vanished_between_reads\":");
    let _ = write!(out, "{}", sample.vanished_between_reads);
    write_exits(
        &mut out,
        &sample.exit_lane,
        super::delta::OVERLAY_WINDOW_LABEL,
    );
    write_unaccounted_entries(&mut out, &disk_unaccounted(sample));
    write_verdict(&mut out, &super::disk::verdict_lines(sample));
    out.push('}');
    out
}

/// The disk Unaccounted block as entries: the sampling boundary,
/// the io permission refusals, the started and vanished counts.
fn disk_unaccounted(sample: &DiskSample) -> Vec<UnaccountedEntry> {
    let mut entries = vec![sampling_entry(&sample.exit_lane)];
    if sample.io_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.io_permission_refused,
            "processes",
            "/proc/<pid>/io unreadable (permission - root or the owning user only): their I/O share is not carried",
        ));
    }
    if sample.started_in_window > 0 {
        entries.push(UnaccountedEntry::new(
            sample.started_in_window,
            "processes",
            "started inside the window: no baseline to delta against, not ranked",
        ));
    }
    if sample.vanished_between_reads > 0 {
        entries.push(UnaccountedEntry::new(
            sample.vanished_between_reads,
            "processes",
            "vanished between the reads: their window share is not carried",
        ));
    }
    entries
}

// ── network ──────────────────────────────────────────────────────

/// The network symptom as JSON: the interface deltas as raw byte
/// and packet counts, the socket-state census, the top socket
/// holders, the boundary count, the exit lane, and the Unaccounted
/// block.
pub(super) fn json_network(sample: &NetworkSample) -> String {
    let mut out = String::with_capacity(768);
    symptom_header(&mut out, "network", Some("1.0s"));
    out.push_str(",\"interfaces\":");
    write_array(&mut out, sample.interfaces.len(), |out, index| {
        let row = &sample.interfaces[index];
        out.push_str("{\"name\":");
        write_string(out, &row.name);
        out.push_str(",\"rx_bytes\":");
        let _ = write!(out, "{}", row.rx_bytes);
        out.push_str(",\"rx_packets\":");
        let _ = write!(out, "{}", row.rx_packets);
        out.push_str(",\"tx_bytes\":");
        let _ = write!(out, "{}", row.tx_bytes);
        out.push_str(",\"tx_packets\":");
        let _ = write!(out, "{}", row.tx_packets);
        out.push('}');
    });
    out.push_str(",\"sockets\":{\"total\":");
    let _ = write!(out, "{}", sample.sockets.total);
    out.push_str(",\"established\":");
    let _ = write!(out, "{}", sample.sockets.established);
    out.push_str(",\"time_wait\":");
    let _ = write!(out, "{}", sample.sockets.time_wait);
    out.push_str(",\"close_wait\":");
    let _ = write!(out, "{}", sample.sockets.close_wait);
    out.push('}');
    out.push_str(",\"holders\":");
    write_array(&mut out, sample.holders.len(), |out, index| {
        let row = &sample.holders[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", row.pid);
        out.push_str(",\"comm\":");
        write_string(out, &row.comm);
        out.push_str(",\"sockets\":");
        let _ = write!(out, "{}", row.sockets);
        out.push('}');
    });
    out.push_str(",\"fd_permission_refused\":");
    let _ = write!(out, "{}", sample.fd_permission_refused);
    write_exits(
        &mut out,
        &sample.exit_lane,
        super::delta::OVERLAY_WINDOW_LABEL,
    );
    write_unaccounted_entries(&mut out, &network_unaccounted(sample));
    write_verdict(&mut out, &super::network::verdict_lines(sample));
    out.push('}');
    out
}

/// The network Unaccounted block as entries: the sampling boundary
/// and the fd permission refusals.
fn network_unaccounted(sample: &NetworkSample) -> Vec<UnaccountedEntry> {
    let mut entries = vec![sampling_entry(&sample.exit_lane)];
    if sample.fd_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.fd_permission_refused,
            "fd tables",
            "unreadable (permission) - the holder list names only the holders visible to this user",
        ));
    }
    entries
}

// ── gpu ──────────────────────────────────────────────────────────

/// The gpu symptom as JSON: the device holders with their device
/// lists, the AMD/amdgpu VRAM rows as byte pairs, the NVIDIA marker,
/// the boundary count, the exit lane, and the Unaccounted block.
pub(super) fn json_gpu(sample: &GpuSample) -> String {
    let mut out = String::with_capacity(768);
    symptom_header(&mut out, "gpu", None);
    out.push_str(",\"holders\":");
    write_array(&mut out, sample.holders.len(), |out, index| {
        let row = &sample.holders[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", row.pid);
        out.push_str(",\"comm\":");
        write_string(out, &row.comm);
        out.push_str(",\"devices\":");
        write_array(out, row.devices.len(), |out, dindex| {
            write_string(out, &row.devices[dindex]);
        });
        out.push('}');
    });
    out.push_str(",\"vram\":");
    write_array(&mut out, sample.vram.len(), |out, index| {
        let row = &sample.vram[index];
        out.push_str("{\"card\":");
        write_string(out, &row.card);
        out.push_str(",\"used_bytes\":");
        let _ = write!(out, "{}", row.used);
        out.push_str(",\"total_bytes\":");
        let _ = write!(out, "{}", row.total);
        out.push('}');
    });
    out.push_str(",\"nvidia_detected\":");
    out.push_str(if sample.nvidia_detected {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"fd_permission_refused\":");
    let _ = write!(out, "{}", sample.fd_permission_refused);
    write_exits(
        &mut out,
        &sample.exit_lane,
        super::delta::OVERLAY_WINDOW_LABEL,
    );
    write_unaccounted_entries(&mut out, &gpu_unaccounted(sample));
    write_verdict(&mut out, &super::gpu::verdict_lines(sample));
    out.push('}');
    out
}

/// The gpu Unaccounted block as entries: the snapshot boundary (the
/// moment phrasing gpu passes its text builder), the NVIDIA
/// external-dependency marker, and the fd permission refusals.
fn gpu_unaccounted(sample: &GpuSample) -> Vec<UnaccountedEntry> {
    let mut entries = Vec::new();
    match &sample.exit_lane {
        ExitLane::NotAttached => entries.push(UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the moment before this snapshot: not attributed (zejtron samples, it does not watch)",
        )),
        ExitLane::Drained(_) => entries.push(UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the moment before this snapshot: named [observed] in the exits section above (the eBPF drain holds the last 2s)",
        )),
        ExitLane::DrainFailed(error) => entries.push(UnaccountedEntry::new(
            1,
            "process lifecycles",
            format!(
                "processes that started and exited within the moment before this snapshot: not attributed (the eBPF exit drain failed: {error})"
            ),
        )),
    }
    if sample.nvidia_detected {
        entries.push(UnaccountedEntry::new(
            1,
            "vram",
            "NVIDIA proprietary driver detected: VRAM requires nvidia-smi (an external tool zejtron does not run) - the card's memory is not measured here",
        ));
    }
    if sample.fd_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.fd_permission_refused,
            "fd tables",
            "unreadable (permission) - the holder list names only the holders visible to this user",
        ));
    }
    entries
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "../../../test/commands/doctor/json_tests.rs"]
mod tests;
