// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's \[eBPF\] section (night-improve-1). ALWAYS present and
//! ALWAYS honest: the eBPF support is unconditional
//! (night-weekly-maintenance-1), so the verdict is the host's alone -
//! an incapable host reports the snapshot lane with the reason, an
//! attached one reports the live pins.
//! The rows are the contract (night-improve-2 added the Tracepoints
//! row): night-improve-42 seats the header on the two-space KV
//! indent one blank line below the check rows, so the section reads
//! as the separated sub-report it is, and night-improve-46 seats the
//! Lazy Camera's Mode row between Lane and Probes (the doctrine's
//! own posture line - docs/EBPF_LIFECYCLE.md owns the prose):
//!
//! ```text
//!
//!   [eBPF]
//!   Feature:     enabled (this binary)
//!   Kernel:      6.1.11
//!   BTF:         present (/sys/kernel/btf/vmlinux exists)
//!   Lockdown:    none
//!   Caps:        CAP_BPF + CAP_PERFMON present
//!   Lane:        live (attached, N=5 events since 2026-10-19 03:11:22 (UTC))
//!   Mode:        Lazy Camera (Kernel: recording | CLI: asleep)
//!   Probes:      sched_process_exec, inet_sock_set_state, vfs_open, vfs_write, vfs_writev
//!   Pins:        /sys/fs/bpf/zejtron (present: tap, tap_link, stats, sock_tap, sock_tap_link, sock_events)
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
/// nine rows. Feature builds additionally read the counter and the
/// attach moment when (and only when) the tap is attached.
pub(super) fn section() -> String {
    let facts = ebpf::probe_kernel();
    let verdict = ebpf::lane_verdict(&facts);
    format_section(
        &feature_row(),
        facts.release_label(),
        &btf_row(facts.btf_present),
        &lockdown_row(facts.lockdown.label()),
        &facts.caps_label(),
        &lane_row(&verdict),
        &mode_row(&verdict),
        &probes_row(),
        &pins_row(),
    )
}

/// The Feature row: what THIS binary can do, by compile-time fact.
/// The eBPF support is unconditional (night-weekly-maintenance-1) -
/// every binary carries the full lane, so the row is a constant.
/// The verdict token rides the bold green seat (night-weekly-
/// maintenance-2, the sibling doctor's verdict law).
fn feature_row() -> String {
    format!("{} (this binary)", crate::output::ok_bold_out("enabled"))
}

/// The lockdown row: the verdict token rides the bold tiers - none
/// is the affirmative seat (bold green), every degraded mode is the
/// attention seat (bold yellow). The label fn is the single source
/// of the tokens; this row only paints them.
fn lockdown_row(label: &str) -> String {
    if label == "none" {
        crate::output::ok_bold_out(label)
    } else {
        crate::output::warn_bold_out(label)
    }
}

/// The BTF row: the vmlinux BTF file, present or absent. Present is
/// the affirmative verdict (bold green); absent degrades the lane
/// (bold yellow) - the sibling doctor's YES/NO painting.
fn btf_row(present: bool) -> String {
    if present {
        format!(
            "{} (/sys/kernel/btf/vmlinux exists)",
            crate::output::ok_bold_out("present")
        )
    } else {
        crate::output::warn_bold_out("absent")
    }
}

/// The Lane row from the verdict. The attached shape carries the live
/// counter and the attach moment (see [`attached_detail`]). The
/// verdict token rides the bold tiers: live is the affirmative seat,
/// a snapshot lane the degraded one (night-weekly-maintenance-2).
fn lane_row(verdict: &LaneVerdict) -> String {
    match verdict {
        LaneVerdict::Live => {
            format!("{} (attach available)", crate::output::ok_bold_out("live"))
        }
        LaneVerdict::LiveAttached => format!(
            "{} (attached, {})",
            crate::output::ok_bold_out("live"),
            attached_detail()
        ),
        LaneVerdict::Snapshot(reason) => {
            format!("{} ({reason})", crate::output::warn_bold_out("snapshot"))
        }
    }
}

/// The attached Lane detail: the counter and the attach moment, read
/// through the pins.
fn attached_detail() -> String {
    let count = ebpf::readback::read_events_counter()
        .map(|n| format!("N={n} events"))
        .unwrap_or_else(|e| format!("counter unreadable ({e})"));
    let since = ebpf::readback::attach_moment()
        .map(crate::info::clock::format_system_time)
        .unwrap_or_else(|| "unknown".to_owned());
    format!("{count} since {since}")
}

/// The Mode row (night-improve-46, the Lazy Camera doctrine): the
/// camera's own posture, and the one row that says what the lane IS
/// rather than what the host allows. The attached shape is the
/// doctrine's own sentence - "Kernel: recording | CLI: asleep" -
/// and every other verdict gets the honest negative: the CLI half
/// is the standing truth either way (between invocations there is
/// no CLI at all), and the kernel half follows the verdict so the
/// row can never claim a recording that is not happening. The row
/// rides unwrapped - like Kernel, Probes, and Pins, it is prose,
/// not a painted verdict token.
fn mode_row(verdict: &LaneVerdict) -> String {
    match verdict {
        LaneVerdict::LiveAttached => "Lazy Camera (Kernel: recording | CLI: asleep)".to_owned(),
        LaneVerdict::Live | LaneVerdict::Snapshot(_) => {
            "Lazy Camera (Kernel: not recording | CLI: asleep)".to_owned()
        }
    }
}

/// The Probes row (night-improve-2 opened it as Tracepoints,
/// night-improve-3 renames it to carry the file taps,
/// night-improve-42 adds the vectorized-write tap): the events the
/// tap listens to, by name - the binary's contract, not host state
/// (the tap object carries all five programs whatever the host
/// allows).
fn probes_row() -> String {
    "sched_process_exec, inet_sock_set_state, vfs_open, vfs_write, vfs_writev".to_owned()
}

/// The Pins row: the whole pin set, a partial set named honestly (a
/// crashed attach is diagnosed, not papered over), or absent. The
/// present list names every pin in planting order - the same list
/// attach prints and the same set detach removes.
fn pins_row() -> String {
    if ebpf::all_pins_present() {
        format!("{} (present: {})", ebpf::PIN_DIR, pin_names().join(", "))
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

/// The pin base names in ALL_PINS order (tap_link, sock_tap_link,
/// tap, sock_tap, stats, sock_events) - one source of truth for the
/// present list, shared by every future row that names the set.
fn pin_names() -> Vec<&'static str> {
    ebpf::ALL_PINS
        .iter()
        .map(|p| {
            Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(p)
        })
        .collect()
}

/// The pure row renderer - separated from [`section`] so the shape is
/// unit-pinnable without probing the host. The alignment is the KV
/// discipline: fixed label column. Roles (night-weekly-maintenance-2,
/// the family law): the section header rides green, the row labels
/// are the KEYS and stay PLAIN (the family paints values, never
/// keys), the verdict tokens inside the values ride the bold tiers
/// their rows paint, and the remaining facts stay unwrapped (white).
/// In Mono every wrap is the identity - the plain bytes the shape
/// shipped with. Nine rows is the contract; the allow is the honest
/// count, not an escape hatch.
#[allow(clippy::too_many_arguments)]
fn format_section(
    feature: &str,
    kernel: &str,
    btf: &str,
    lockdown: &str,
    caps: &str,
    lane: &str,
    mode: &str,
    probes: &str,
    pins: &str,
) -> String {
    let mut out = String::new();
    // The separated sub-report (night-improve-42): one blank line
    // splits the section from the check rows above it, and the
    // header rides the same two-space KV indent as its rows.
    out.push('\n');
    out.push_str(&crate::output::ok_out("  [eBPF]"));
    out.push('\n');
    for (label, value) in [
        ("  Feature:     ", feature),
        ("  Kernel:      ", kernel),
        ("  BTF:         ", btf),
        ("  Lockdown:    ", lockdown),
        ("  Caps:        ", caps),
        ("  Lane:        ", lane),
        ("  Mode:        ", mode),
        ("  Probes:      ", probes),
        ("  Pins:        ", pins),
    ] {
        out.push_str(label);
        out.push_str(value);
        out.push('\n');
    }
    // The last row carries no trailing newline (the caller prints
    // `{report}\n{section}`), so the loop's newline is trimmed.
    out.truncate(out.len() - 1);
    out
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/ebpf_section_tests.rs"]
mod tests;
