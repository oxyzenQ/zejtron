// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The gpu symptom (night-improve-48): "who is holding the GPU?"
//! answered honestly on a fragmented Linux landscape. This is the
//! one symptom that takes NO delta - the question is who holds the
//! device open, and /proc/<pid>/fd answers it at the instant of the
//! command. The scan reads:
//!
//! - /proc/<pid>/fd link targets: a process holding /dev/dri/card*,
//!   /dev/dri/renderD*, or /dev/nvidia* IS a GPU process - named
//!   with every device it holds, [measured];
//! - /sys/class/drm/card*/device/mem_info_vram_{used,total}: the
//!   AMD/amdgpu VRAM pair, read when the driver exports it;
//! - /proc/driver/nvidia/gpus: the proprietary NVIDIA marker. When
//!   it exists the VRAM truth lives behind nvidia-smi - an external
//!   tool zejtron does not run, so the card's memory is named
//!   [unaccounted], never guessed.
//!
//! No GPU process means exactly that: the spec's own sentence,
//! printed, exit 0.

use super::delta;
use super::memory::exits::ExitLane;
use super::memory::pid_dirs;
use std::collections::BTreeSet;
use std::time::SystemTime;

/// One GPU-holding process: the pid, its comm, and every GPU
/// device fd it holds (sorted, deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HolderRow {
    pub pid: u32,
    pub comm: String,
    pub devices: Vec<String>,
}

/// One AMD/amdgpu card's VRAM facts, in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VramRow {
    pub card: String,
    pub used: u64,
    pub total: u64,
}

/// The whole gpu sample: everything the report rode on.
#[derive(Debug, Clone, Default)]
pub(crate) struct GpuSample {
    pub sampled_at: String,
    /// GPU device holders, ascending by pid.
    pub holders: Vec<HolderRow>,
    /// The AMD/amdgpu VRAM rows, ascending by card name.
    pub vram: Vec<VramRow>,
    /// The proprietary NVIDIA driver marker (/proc/driver/nvidia/gpus
    /// exists) - the [unaccounted] external dependency.
    pub nvidia_detected: bool,
    /// Other users' fd tables this invocation may not read.
    pub fd_permission_refused: usize,
    pub exit_lane: ExitLane,
}

/// Classify one fd link target: a GPU device fd or not. The device
/// set is the union the scan cares about - the DRI nodes (card and
/// render) and the NVIDIA character devices.
pub(crate) fn is_gpu_device(target: &str) -> bool {
    target.starts_with("/dev/dri/card")
        || target.starts_with("/dev/dri/renderD")
        || target.starts_with("/dev/nvidia")
}

/// Walk one pid's fd table and collect its GPU device link targets.
/// Returns (devices, refused) - a permission refusal is a named
/// absence, not an empty set.
fn gpu_devices_of(pid: u32) -> (BTreeSet<String>, bool) {
    let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(e) => {
            return (
                BTreeSet::new(),
                e.kind() == std::io::ErrorKind::PermissionDenied,
            );
        }
    };
    let mut devices = BTreeSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let target = target.to_string_lossy().to_string();
            if is_gpu_device(&target) {
                devices.insert(target);
            }
        }
    }
    (devices, false)
}

/// Read the AMD/amdgpu VRAM pair for every cardN under
/// /sys/class/drm (renderD* siblings are skipped - they are the
/// same card's render node, and the memory belongs to the card).
pub(crate) fn read_vram() -> Vec<VramRow> {
    let mut rows = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/drm") else {
        return rows;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("card") || !name[4..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let base = entry.path().join("device");
        let read = |field: &str| -> Option<u64> {
            std::fs::read_to_string(base.join(field))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        if let (Some(used), Some(total)) = (read("mem_info_vram_used"), read("mem_info_vram_total"))
        {
            rows.push(VramRow {
                card: name,
                used,
                total,
            });
        }
    }
    rows.sort_by(|left, right| left.card.cmp(&right.card));
    rows
}

/// Collect the gpu sample: one fd walk, one sysfs VRAM read, one
/// NVIDIA marker check - an instant, no window, no loop.
pub(crate) fn collect() -> GpuSample {
    let mut holders = Vec::new();
    let mut refused = 0usize;
    for pid in pid_dirs(std::path::Path::new("/proc")) {
        let (devices, was_refused) = gpu_devices_of(pid);
        if was_refused {
            refused += 1;
            continue;
        }
        if devices.is_empty() {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|contents| delta::parse_pid_stat(&contents).map(|stat| stat.comm))
            .unwrap_or_else(|| "unknown".to_owned());
        holders.push(HolderRow {
            pid,
            comm,
            devices: devices.into_iter().collect(),
        });
    }
    holders.sort_by_key(|row| row.pid);

    GpuSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        holders,
        vram: read_vram(),
        nvidia_detected: std::path::Path::new("/proc/driver/nvidia/gpus").exists(),
        fd_permission_refused: refused,
        exit_lane: delta::collect_exits_overlay(),
    }
}

/// The report: collect, render, one String, exit. The snapshot
/// flavor - gpu has no sampling window of its own to name, so the
/// boundary text says the moment, not the window.
pub(crate) fn report(raw: bool) -> String {
    render(&collect(), raw)
}

/// The pure render - separated from [`collect`] so the shape is
/// unit-pinnable with synthetic samples, the memory ledger's own
/// discipline: the report is the contract, not the host.
pub(crate) fn render(sample: &GpuSample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} symptom - gpu",
        crate::output::ok_out("Evidence report:")
    ));
    lines.push(crate::output::grey_out(delta::mode_line(
        &sample.exit_lane,
        false,
    )));
    lines.push(crate::output::grey_out(&format!(
        "Sampled: {}",
        sample.sampled_at
    )));
    lines.push(String::new());
    render_holders(sample, &mut lines);
    render_vram(sample, &mut lines);
    delta::render_exits_overlay(&sample.exit_lane, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(sample, &mut lines);
    }
    lines.join("\n")
}

fn render_holders(sample: &GpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("GPU device holders:"));
    if sample.holders.is_empty() {
        // The spec's own sentence, verbatim - the honest empty
        // scene, riding grey (the "no events" class).
        lines.push(format!(
            "  {}",
            crate::output::grey_out("No active GPU processes observed.")
        ));
        lines.push(String::new());
        return;
    }
    for row in &sample.holders {
        lines.push(format!(
            "  PID {} ({})  {}  {}",
            row.pid,
            row.comm,
            row.devices.join(", "),
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_vram(sample: &GpuSample, lines: &mut Vec<String>) {
    // The AMD/amdgpu pair renders only when the driver exports it -
    // an absent section is the honest no-fact, not a zero.
    if sample.vram.is_empty() {
        return;
    }
    lines.push(crate::output::ok_out("VRAM (AMD/amdgpu):"));
    for row in &sample.vram {
        lines.push(format!(
            "  {}  {} used of {}  {}",
            row.card,
            fmt_bytes(row.used),
            fmt_bytes(row.total),
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &GpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    lines.push(delta::sampling_unaccounted(
        &sample.exit_lane,
        "the moment before this snapshot",
    ));
    if sample.nvidia_detected {
        lines.push(format!(
            "  {}  {}",
            crate::output::grey_out(
                "NVIDIA proprietary driver detected: VRAM requires nvidia-smi (an external \
                 tool zejtron does not run) - the card's memory is not measured here"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    if sample.fd_permission_refused > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.fd_permission_refused,
            crate::output::grey_out(
                "processes' fd tables unreadable (permission) - the holder list names \
                 only the holders visible to this user"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &GpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    match sample.holders.first() {
        Some(top) => lines.push(format!(
            "  The GPU is held by {} (PID {}, devices: {}).",
            top.comm,
            top.pid,
            top.devices.join(", ")
        )),
        None => lines.push("  No process holds the GPU device (the scene is idle).".to_owned()),
    }
}

/// The drill-down: the holders' fd link targets verbatim - the
/// link targets ARE the raw evidence, named once more, unpainted.
fn render_raw(sample: &GpuSample, lines: &mut Vec<String>) {
    if sample.holders.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(crate::output::ok_out("Raw device links (drill-down):"));
    for row in &sample.holders {
        lines.push(crate::output::grey_out(&format!("  PID {}:", row.pid)));
        for device in &row.devices {
            lines.push(format!("    {device}"));
        }
    }
}

/// The adaptive size label - the memory ledger's own, one source
/// for the whole symptom family.
fn fmt_bytes(bytes: u64) -> String {
    super::memory::ledger::fmt_bytes(bytes)
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/gpu_tests.rs"]
mod tests;
