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
//! {"ledger_version":2,"mode":"readiness","os":"linux","kernel":
//!  "...","distro":"...","ebpf_lane":"live","user":{"uid":0,
//!  "class":"privileged"},"checks":[...],"summary":{...},"ebpf":{...}}
//! {"ledger_version":2,"mode":"symptom","symptom":"ram","memory":
//!  {"total_bytes":N,"used_bytes":N,"available_bytes":N,"used_pct":
//!  N},"processes":[...],"unaccounted":[...],"verdict":{"lines":[...]}}
//! ```
//!
//! The standard names (night-badass-6): every array of process
//! records is `processes` (the ranked consumers, the socket and
//! device holders, the drained exit rows), the interface deltas are
//! `interfaces`, the per-holder device lists are `devices`, the
//! slab census is `caches` - an SRE writes the jq path from the
//! noun, not from this document. The readiness report carries the
//! host's critical facts at the root (`os`, `kernel`, `distro`,
//! `ebpf_lane`) beside the detailed `checks` array - the five-second
//! query does not descend.
//!
//! The verdicts are prose by nature - the fact sentence the report
//! names - so they ride as `verdict.lines`; everything a machine
//! wants to filter on (percentages, bytes, pids, states) is a typed
//! field beside it. One line, byte-deterministic: pure functions of
//! their sample, no clock reads, no map iteration.

use std::fmt::Write as _;

use super::ebpf;
use super::memory::exits::ExitLane;
use super::{CheckResult, Summary};
use crate::evidence::UnaccountedEntry;
use crate::evidence::json::{write_string, write_unaccounted};

/// The one version number the doctor's automation lane pins: the
/// JSON surface's own contract line. v2 (night-badass-6) moved the
/// readiness host facts to the root and standardized the array
/// names (`processes`, `interfaces`, `devices`, `caches`) - a
/// breaking shape change, named by the version.
const LEDGER_VERSION: u32 = 2;

// ── Shared writers ────────────────────────────────────────────────

/// KiB to bytes, saturating - the memory ledger's own arithmetic.
fn kib_to_bytes(kib: u64) -> u64 {
    kib.saturating_mul(1024)
}

/// One fixed-point number with one decimal, the text ledger's own
/// percentage shape ("47.2") - deterministic bytes, no float drift.
///
/// JSON-validity guard (night-dragon-maintenance-T1): a non-finite
/// f64 (NaN, +/-inf) formats as `NaN`/`inf` - three letters that
/// are NOT JSON - and every consumer (jq, python json.loads) would
/// reject the whole document. The guard degrades a non-finite value
/// to JSON null instead, the lane's own typed-absence law ("the
/// absent fact stays absent, never zero"): a reading that is not a
/// finite number is not a reading. Today every caller guards its
/// arithmetic (division-by-zero `.then()` gates); the guard exists
/// so ONE future caller cannot ship an invalid document.
fn write_pct(out: &mut String, pct: f64) {
    if pct.is_finite() {
        let _ = write!(out, "{pct:.1}");
    } else {
        out.push_str("null");
    }
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
/// lane state, the drained rows under the standard `processes` name
/// (night-badass-6; the render's own TOP_N cap and the overflow
/// count beside them), or the drain failure verbatim.
fn write_exits(out: &mut String, lane: &ExitLane, window_label: &str) {
    out.push_str(",\"exits\":{\"lane\":");
    match lane {
        ExitLane::NotAttached => out.push_str("\"not-attached\"}"),
        ExitLane::DrainFailed(error) => {
            out.push_str("\"drain-failed\",\"error\":");
            write_string(out, error);
            out.push('}');
        }
        ExitLane::Drained(rows, observer_excluded) => {
            out.push_str("\"drained\",\"window_label\":");
            write_string(out, window_label);
            out.push_str(",\"processes\":");
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
            // The observer's own invocations the lane excluded from
            // the rows (night-dragon-lts-4) - named in the schema so
            // a JSON consumer can tell a quiet window from the
            // watch-loop's self-exits.
            out.push_str(",\"observer_excluded\":");
            let _ = write!(out, "{}", observer_excluded);
            out.push('}');
        }
    }
}

// ── The readiness report ─────────────────────────────────────────

/// The readiness report as JSON: the host's critical facts at the
/// root (the OS word, the kernel release, the distro, and the eBPF
/// lane, each the same value its check row speaks, probed once), the
/// user context, every check (name, lowercase status, the message
/// the text row carries), the summary counts, and the eBPF
/// section's structured facts.
pub(super) fn readiness_json(
    checks: &[CheckResult],
    summary: &Summary,
    uid: Option<u32>,
) -> String {
    let facts = ebpf::facts_json();
    let mut out = String::with_capacity(1024);
    out.push_str("{\"ledger_version\":");
    let _ = write!(out, "{LEDGER_VERSION}");
    out.push_str(",\"mode\":\"readiness\"");
    // The root facts (night-badass-6): the five-second query's
    // answers, each the same value its check row or eBPF section
    // speaks - the OS word is the compile-time constant, the kernel
    // and distro ride the shared probes, and the lane is the eBPF
    // facts' own. An unreadable fact is JSON null, never a guess.
    out.push_str(",\"os\":");
    write_string(&mut out, std::env::consts::OS);
    out.push_str(",\"kernel\":");
    match super::checks::kernel_release() {
        Some(release) => write_string(&mut out, &release),
        None => out.push_str("null"),
    }
    out.push_str(",\"distro\":");
    match super::checks::distro_name() {
        Some(name) => write_string(&mut out, &name),
        None => out.push_str("null"),
    }
    out.push_str(",\"ebpf_lane\":");
    write_string(&mut out, facts.lane);
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
    write_ebpf_facts(&mut out, &facts);
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

mod slow;
mod symptoms;

pub(super) use slow::json_slow;
#[cfg(test)]
use symptoms::{cpu_unaccounted, gpu_unaccounted};
pub(super) use symptoms::{json_cpu, json_disk, json_gpu, json_network, json_ram};

/// The sampling-boundary entry, the delta lanes' shared sentence -
/// the same three truths the shared text builder phrases. Lives in
/// the parent (night-dragon-lts-2) so the per-lane Unaccounted
/// builders and the umbrella's slow/slow.rs both import the one
/// source - a child can always see its parent's own items.
fn sampling_entry(lane: &ExitLane) -> UnaccountedEntry {
    match lane {
        ExitLane::NotAttached => UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the 1.0s sampling window: not attributed (zejtron samples, it does not watch)",
        ),
        ExitLane::Drained(..) => UnaccountedEntry::new(
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

#[cfg(test)]
#[path = "../../../../test/commands/doctor/json_tests.rs"]
mod tests;
