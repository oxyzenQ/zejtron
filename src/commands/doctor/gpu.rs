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
use crate::output::noun_for;
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

/// One process's drm fdinfo memory facts, in KiB
/// (Documentation/gpu/drm-usage-stats.rst: the drm-memory-* keys
/// count buffer bytes in KiB, summed over every GPU device fd the
/// process holds). Ranked by VRAM descending - the answer to "who
/// is eating the GPU memory", which the holder list alone never
/// carried (night-dragon-lts-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GpuMemoryRow {
    pub pid: u32,
    pub comm: String,
    pub vram_kib: u64,
    pub gtt_kib: u64,
}

/// The whole gpu sample: everything the report rode on.
#[derive(Debug, Clone, Default)]
pub(crate) struct GpuSample {
    pub sampled_at: String,
    /// GPU device holders, ascending by pid.
    pub holders: Vec<HolderRow>,
    /// The per-process drm fdinfo memory rows, VRAM descending -
    /// empty when no driver exports the keys (the honest absence,
    /// never a zero written as measured).
    pub gpu_memory: Vec<GpuMemoryRow>,
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

/// The drm fdinfo memory keys one file carries, in KiB:
/// drm-memory-vram and drm-memory-gtt, the amdgpu pair the usage
/// stats spec defines. None when neither key rides the file - a
/// driver that does not export the lane (i915 without the memory
/// keys, the proprietary NVIDIA node) is an absent fact, never a
/// zero dressed up as measured.
pub(crate) fn parse_fdinfo_drm_memory(contents: &str) -> Option<(u64, u64)> {
    let mut vram = None;
    let mut gtt = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("drm-memory-vram:") {
            vram = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("drm-memory-gtt:") {
            gtt = rest.trim().parse().ok();
        }
    }
    match (vram, gtt) {
        (Some(v), Some(g)) => Some((v, g)),
        (Some(v), None) => Some((v, 0)),
        (None, Some(g)) => Some((0, g)),
        (None, None) => None,
    }
}

/// One holder's drm fdinfo memory sums (KiB): every GPU device
/// fd's fdinfo parsed for the drm-memory keys. A driver that
/// exports none yields (0, 0) and the holder stays out of the
/// memory ranking - the holder list above still names it.
fn drm_memory_of(pid: u32) -> (u64, u64) {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return (0, 0);
    };
    let mut vram = 0u64;
    let mut gtt = 0u64;
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        if !is_gpu_device(&target.to_string_lossy()) {
            continue;
        }
        let fdinfo = format!("/proc/{pid}/fdinfo/{}", entry.file_name().to_string_lossy());
        if let Ok(contents) = std::fs::read_to_string(fdinfo)
            && let Some((v, g)) = parse_fdinfo_drm_memory(&contents)
        {
            vram += v;
            gtt += g;
        }
    }
    (vram, gtt)
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

    // The per-process memory ranking (night-dragon-lts-4): one
    // fdinfo pass per holder - the few pids that hold the device,
    // not the whole pid walk - and only the rows the driver's own
    // accounting produced.
    let mut gpu_memory = Vec::new();
    for holder in &holders {
        let (vram_kib, gtt_kib) = drm_memory_of(holder.pid);
        if vram_kib > 0 || gtt_kib > 0 {
            gpu_memory.push(GpuMemoryRow {
                pid: holder.pid,
                comm: holder.comm.clone(),
                vram_kib,
                gtt_kib,
            });
        }
    }
    gpu_memory.sort_by(|left, right| {
        right
            .vram_kib
            .cmp(&left.vram_kib)
            .then(left.pid.cmp(&right.pid))
    });

    GpuSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        holders,
        gpu_memory,
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
    render_gpu_memory(sample, &mut lines);
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

/// The per-process GPU memory ranking: rendered only when the
/// driver's own fdinfo accounting produced rows - an absent
/// section is the honest no-fact, not a zero (night-dragon-lts-4).
fn render_gpu_memory(sample: &GpuSample, lines: &mut Vec<String>) {
    if sample.gpu_memory.is_empty() {
        return;
    }
    lines.push(crate::output::ok_out(
        "Per-process GPU memory (drm fdinfo, VRAM descending):",
    ));
    for row in sample.gpu_memory.iter().take(super::memory::ledger::TOP_N) {
        lines.push(format!(
            "  PID {} ({})  VRAM {}  GTT {}  {}",
            row.pid,
            row.comm,
            fmt_bytes(row.vram_kib.saturating_mul(1024)),
            fmt_bytes(row.gtt_kib.saturating_mul(1024)),
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
            crate::output::grey_out(&format!(
                "{} with unreadable fd tables (permission) - the holder list names \
                 only the holders visible to this user",
                noun_for(sample.fd_permission_refused, "process", "processes")
            )),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &GpuSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    for line in verdict_lines(sample) {
        lines.push(format!("  {line}"));
    }
}

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane
/// (night-badass-5). night-dragon-lts-4 rebuilds the ladder: the
/// first line names the largest GPU memory consumer when the
/// driver's fdinfo accounting produced one (the question the
/// symptom exists to answer), the holder count phrasing
/// attributing nothing it cannot measure otherwise, and the VRAM
/// pressure finding rides behind - the sharpest fact a GPU report
/// can carry, previously unranked and unnamed while the verdict
/// said "The GPU is held by systemd (PID 1)" on every desktop
/// (systemd holds the card node by design; holding is not
/// consuming).
pub(crate) fn verdict_lines(sample: &GpuSample) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(top) = sample.gpu_memory.first() {
        lines.push(format!(
            "The largest GPU memory consumer is {} (PID {}, {} VRAM).",
            top.comm,
            top.pid,
            fmt_bytes(top.vram_kib.saturating_mul(1024))
        ));
    } else if let Some(top) = sample.holders.first() {
        lines.push(format!(
            "{} {} the GPU device open (lowest PID {}, {}) - holding a device node is \
             not memory use; no driver exported per-process memory here.",
            sample.holders.len(),
            noun_for(sample.holders.len(), "process has", "processes have"),
            top.pid,
            top.comm
        ));
    } else {
        lines.push("No process holds the GPU device (the scene is idle).".to_owned());
    }
    // The VRAM pressure finding (night-dragon-lts-4): 85 percent
    // of the card's own total, the threshold the memory verdict's
    // residual heuristic rides - named with its boundary, never
    // an instruction.
    for row in &sample.vram {
        if let Some(pct) = row
            .used
            .saturating_mul(100)
            .checked_div(row.total)
            .filter(|pct| *pct >= 85)
        {
            lines.push(format!(
                "{} VRAM is at {}% of its {} - pressure the per-process table \
                 above ranks.",
                row.card,
                pct,
                fmt_bytes(row.total)
            ));
        }
    }
    lines
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
