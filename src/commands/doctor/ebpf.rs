// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's \[eBPF\] section (night-improve-1). ALWAYS present and
//! ALWAYS honest, in every build: a featureless binary reports the
//! dormant lane by name, never a fake live one, and a feature binary
//! on an incapable host reports the snapshot lane with the reason.
//! The rows are the contract:
//!
//! ```text
//! [eBPF]
//!   Feature:   enabled (this binary)
//!   Kernel:    6.1.11
//!   BTF:       present (/sys/kernel/btf/vmlinux exists)
//!   Lockdown:  none
//!   Caps:      CAP_BPF + CAP_PERFMON present
//!   Lane:      live (attached, N=5 events since 2026-10-19 03:11:22 (UTC))
//!   Pins:      /sys/fs/bpf/zejtron (present: tap, tap_link, stats)
//! ```
//!
//! One probe feeds every row (the same `probe_kernel` + `lane_verdict`
//! the attach preflight reads - one truth, no drift between the two
//! surfaces), and the attached Lane row carries the live counter and
//! the attach moment, read through the pin: the read side needs no
//! capabilities, only the bpffs walk.

use std::path::Path;

use crate::ebpf::{self, LaneVerdict};

/// Render the live section: probe once, classify once, print the
/// seven rows. Feature builds additionally read the counter and the
/// attach moment when (and only when) the tap is attached.
pub(super) fn section() -> String {
    let facts = ebpf::probe_kernel();
    let verdict = ebpf::lane_verdict(&facts);
    format_section(
        &feature_row(),
        facts.release_label(),
        &btf_row(facts.btf_present),
        facts.lockdown.label(),
        &facts.caps_label(),
        &lane_row(&verdict),
        &pins_row(),
    )
}

/// The Feature row: what THIS binary can do, by compile-time fact.
fn feature_row() -> String {
    if cfg!(feature = "ebpf") {
        "enabled (this binary)".to_owned()
    } else {
        "disabled (this binary)".to_owned()
    }
}

/// The BTF row: the vmlinux BTF file, present or absent.
fn btf_row(present: bool) -> String {
    if present {
        "present (/sys/kernel/btf/vmlinux exists)".to_owned()
    } else {
        "absent".to_owned()
    }
}

/// The Lane row from the verdict. The attached shape carries the live
/// counter and the attach moment (see [`attached_detail`]).
fn lane_row(verdict: &LaneVerdict) -> String {
    match verdict {
        LaneVerdict::Live => "live (attach available)".to_owned(),
        LaneVerdict::LiveAttached => format!("live (attached, {})", attached_detail()),
        LaneVerdict::Snapshot(reason) => format!("snapshot ({reason})"),
        LaneVerdict::Dormant => "dormant (built without the ebpf feature)".to_owned(),
    }
}

/// The attached Lane detail: the counter and the attach moment, read
/// through the pins. Feature builds read them live; a featureless
/// build can never reach this row (its verdict is Dormant before the
/// pin state is even consulted), and the honest stub below keeps that
/// arm compiling in both lanes.
#[cfg(feature = "ebpf")]
fn attached_detail() -> String {
    let count = ebpf::readback::read_events_counter()
        .map(|n| format!("N={n} events"))
        .unwrap_or_else(|e| format!("counter unreadable ({e})"));
    let since = ebpf::readback::attach_moment()
        .map(crate::info::clock::format_system_time)
        .unwrap_or_else(|| "unknown".to_owned());
    format!("{count} since {since}")
}

#[cfg(not(feature = "ebpf"))]
fn attached_detail() -> String {
    "counter unreadable (this binary was built without the ebpf feature)".to_owned()
}

/// The Pins row: the whole pin set, a partial set named honestly (a
/// crashed attach is diagnosed, not papered over), or absent.
fn pins_row() -> String {
    if ebpf::all_pins_present() {
        format!("{} (present: tap, tap_link, stats)", ebpf::PIN_DIR)
    } else if ebpf::any_pin_present() {
        let missing: Vec<&str> = ebpf::ALL_PINS
            .iter()
            .filter(|p| !Path::new(*p).exists())
            .map(|p| {
                Path::new(p)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(p)
            })
            .collect();
        format!(
            "{} (partial - missing: {})",
            ebpf::PIN_DIR,
            missing.join(", ")
        )
    } else {
        format!("{} (absent)", ebpf::PIN_DIR)
    }
}

/// The pure row renderer - separated from [`section`] so the shape is
/// unit-pinnable without probing the host. The alignment matches the
/// doctor's table discipline: fixed label column, plain text, no
/// color (the section is facts, not verdicts).
fn format_section(
    feature: &str,
    kernel: &str,
    btf: &str,
    lockdown: &str,
    caps: &str,
    lane: &str,
    pins: &str,
) -> String {
    let mut out = String::from("[eBPF]\n");
    out.push_str(&format!("  Feature:   {feature}\n"));
    out.push_str(&format!("  Kernel:    {kernel}\n"));
    out.push_str(&format!("  BTF:       {btf}\n"));
    out.push_str(&format!("  Lockdown:  {lockdown}\n"));
    out.push_str(&format!("  Caps:      {caps}\n"));
    out.push_str(&format!("  Lane:      {lane}\n"));
    out.push_str(&format!("  Pins:      {pins}"));
    out
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/ebpf_section_tests.rs"]
mod tests;
