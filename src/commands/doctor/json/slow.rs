// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The umbrella symptom's JSON lane (night-dragon-lts-2): the four
//! lanes' headline facts as compact sub-objects, the ranked
//! findings with their severity classes, and the verdict - the same
//! sample the text ledger renders, one collection, two renderings.
//! Split out of json/symptoms.rs at birth (the 600-line LOC cap,
//! the no-mercy law) - a pure move, the parent's shared writers and
//! the sampling-boundary entry staying where they were.

use super::super::delta::OVERLAY_WINDOW_LABEL;
use super::super::slow::{SlowSample, rank_findings, verdict_lines as slow_verdict_lines};
use super::{
    kib_to_bytes, sampling_entry, symptom_header, write_array, write_exits, write_opt_pct,
    write_opt_u64, write_pct, write_unaccounted_entries, write_verdict,
};
use crate::evidence::UnaccountedEntry;
use crate::evidence::json::write_string;
use std::fmt::Write as _;

/// The umbrella symptom as JSON (night-dragon-lts-2): the four
/// lanes' headline facts as compact sub-objects (the full per-lane
/// documents live on their own `--symptom <lane>` lanes - the
/// umbrella is the triage, not the concatenation), the ranked
/// findings with their severity classes, the exit lane, the
/// Unaccounted block, and the verdict - the same sample the text
/// ledger renders, one collection, two renderings.
pub(in crate::commands::doctor) fn json_slow(sample: &SlowSample) -> String {
    let mut out = String::with_capacity(1024);
    symptom_header(&mut out, "slow", Some("1.0s"));
    // The cpu compact: the headline shares plus the top consumer
    // (the full ranked table rides the cpu lane's own document).
    out.push_str(",\"cpu\":{\"ncpu\":");
    let _ = write!(out, "{}", sample.cpu.ncpu);
    out.push_str(",\"loadavg_1min\":");
    write_opt_pct(&mut out, sample.cpu.loadavg_1min);
    out.push_str(",\"busy_pct\":");
    write_opt_pct(&mut out, sample.cpu.busy_pct);
    out.push_str(",\"running\":");
    let _ = write!(out, "{}", sample.cpu.running);
    out.push_str(",\"d_state\":");
    let _ = write!(out, "{}", sample.cpu.stuck.len());
    out.push_str(",\"top_pid\":");
    match sample.cpu.top.first() {
        Some(top) => {
            let _ = write!(out, "{}", top.pid);
            out.push_str(",\"top_comm\":");
            write_string(&mut out, &top.comm);
            out.push_str(",\"top_pct\":");
            write_pct(&mut out, top.pct);
        }
        None => out.push_str("null"),
    }
    out.push('}');
    // The memory compact: the headline byte counts, the percent, the
    // swap totals and the window's swap rate - the rate is the
    // fact that says "slow now".
    out.push_str(",\"memory\":");
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
            out.push_str("{\"total_bytes\":");
            let _ = write!(out, "{total}");
            out.push_str(",\"used_bytes\":");
            let _ = write!(out, "{used}");
            out.push_str(",\"available_bytes\":");
            let _ = write!(out, "{available}");
            out.push_str(",\"used_pct\":");
            let _ = write!(out, "{pct}");
            out.push_str(",\"swap_total_bytes\":");
            write_opt_u64(&mut out, sample.swap_total_kib.map(kib_to_bytes));
            out.push_str(",\"swap_free_bytes\":");
            write_opt_u64(&mut out, sample.swap_free_kib.map(kib_to_bytes));
            out.push_str(",\"swap_in_pages\":");
            let _ = write!(out, "{}", sample.swap_in_pages);
            out.push_str(",\"swap_out_pages\":");
            let _ = write!(out, "{}", sample.swap_out_pages);
            out.push('}');
        }
        None => out.push_str("null"),
    }
    // The disk compact: the iowait share and the top consumer.
    out.push_str(",\"disk\":{\"iowait_pct\":");
    write_opt_pct(&mut out, sample.disk.iowait_pct);
    out.push_str(",\"top_pid\":");
    match sample.disk.top.first() {
        Some(top) => {
            let _ = write!(out, "{}", top.pid);
            out.push_str(",\"top_comm\":");
            write_string(&mut out, &top.comm);
            out.push_str(",\"top_read_bytes\":");
            let _ = write!(out, "{}", top.read_delta);
            out.push_str(",\"top_write_bytes\":");
            let _ = write!(out, "{}", top.write_delta);
        }
        None => out.push_str("null"),
    }
    out.push('}');
    // The network compact: the busiest interface and the census.
    out.push_str(",\"network\":");
    match sample.network.interfaces.first() {
        Some(top) => {
            out.push_str("{\"busiest_interface\":");
            write_string(&mut out, &top.name);
            out.push_str(",\"rx_bytes\":");
            let _ = write!(out, "{}", top.rx_bytes);
            out.push_str(",\"tx_bytes\":");
            let _ = write!(out, "{}", top.tx_bytes);
        }
        None => out.push_str("{\"busiest_interface\":null"),
    }
    out.push_str(",\"established\":");
    let _ = write!(out, "{}", sample.network.sockets.established);
    out.push_str(",\"time_wait\":");
    let _ = write!(out, "{}", sample.network.sockets.time_wait);
    out.push_str(",\"close_wait\":");
    let _ = write!(out, "{}", sample.network.sockets.close_wait);
    out.push('}');
    // The ranked findings: the severity class beside the sentence.
    let findings = rank_findings(sample);
    out.push_str(",\"findings\":");
    write_array(&mut out, findings.len(), |out, index| {
        let finding = &findings[index];
        out.push_str("{\"rank\":");
        let _ = write!(out, "{}", index + 1);
        out.push_str(",\"class\":");
        write_string(out, finding.class);
        out.push_str(",\"text\":");
        write_string(out, &finding.text);
        out.push('}');
    });
    write_exits(&mut out, &sample.exit_lane, OVERLAY_WINDOW_LABEL);
    write_unaccounted_entries(&mut out, &slow_unaccounted(sample));
    write_verdict(&mut out, &slow_verdict_lines(sample));
    out.push('}');
    out
}

/// The umbrella Unaccounted block as entries: the sampling
/// boundary, the meminfo absence, the per-lane permission
/// refusals, and the gpu exclusion - a fact not carried is named,
/// never silently dropped.
pub(super) fn slow_unaccounted(sample: &SlowSample) -> Vec<UnaccountedEntry> {
    let mut entries = vec![sampling_entry(&sample.exit_lane)];
    if sample.meminfo.is_none() {
        entries.push(UnaccountedEntry::new(
            1,
            "meminfo",
            "/proc/meminfo unreadable: the memory share is not carried",
        ));
    }
    if sample.disk.io_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.disk.io_permission_refused,
            "processes",
            "/proc/<pid>/io unreadable (permission - root or the owning user only): their I/O share is not carried",
        ));
    }
    if sample.network.fd_permission_refused > 0 {
        entries.push(UnaccountedEntry::new(
            sample.network.fd_permission_refused,
            "fd tables",
            "unreadable (permission) - the holder list names only the holders visible to this user",
        ));
    }
    entries.push(UnaccountedEntry::new(
        1,
        "gpu lane",
        "rides outside this triage - 'zejtron doctor --symptom gpu' is its dedicated report",
    ));
    entries
}
