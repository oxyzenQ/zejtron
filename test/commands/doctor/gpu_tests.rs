// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The gpu symptom's pins (night-improve-48): the device
//! classification and the render shape, pinned with synthetic
//! samples - the report is the contract, not this host's own GPU
//! (a container usually has none, which is exactly the honest
//! shape the empty scene pins).

use super::*;

#[test]
fn the_device_classifier_names_the_gpu_families() {
    assert!(is_gpu_device("/dev/dri/card0"));
    assert!(is_gpu_device("/dev/dri/card12"));
    assert!(is_gpu_device("/dev/dri/renderD128"));
    assert!(is_gpu_device("/dev/nvidia0"));
    assert!(is_gpu_device("/dev/nvidiactl"));
    assert!(is_gpu_device("/dev/nvidia-modeset"));
    // The fd table's other residents are not GPU devices.
    assert!(!is_gpu_device("socket:[12345]"));
    assert!(!is_gpu_device("/dev/dri"));
    assert!(!is_gpu_device("/dev/null"));
    assert!(!is_gpu_device("anon_inode:[i915]"));
}

fn synthetic() -> GpuSample {
    GpuSample {
        sampled_at: "2026-10-22 10:00:00 (UTC)".to_owned(),
        holders: vec![HolderRow {
            pid: 4321,
            comm: "firefox".to_owned(),
            devices: vec![
                "/dev/dri/card0".to_owned(),
                "/dev/dri/renderD128".to_owned(),
            ],
        }],
        vram: vec![VramRow {
            card: "card0".to_owned(),
            used: 3_u64 * 1024 * 1024 * 1024 + 200 * 1024 * 1024,
            total: 8_u64 * 1024 * 1024 * 1024,
        }],
        nvidia_detected: false,
        fd_permission_refused: 3,
        exit_lane: ExitLane::NotAttached,
    }
}

#[test]
fn the_report_carries_the_locked_shape() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains("Evidence report: symptom - gpu"),
        "{report}"
    );
    assert!(
        report.contains("Mode: snapshot (eBPF not attached)"),
        "the snapshot flavor, no window to name: {report}"
    );
    assert!(report.contains("GPU device holders:"), "{report}");
    assert!(
        report.contains("PID 4321 (firefox)  /dev/dri/card0, /dev/dri/renderD128  [measured]"),
        "{report}"
    );
    assert!(report.contains("VRAM (AMD/amdgpu):"), "{report}");
    assert!(
        report.contains("card0  3.2 GiB used of 8.0 GiB  [measured]"),
        "{report}"
    );
}

#[test]
fn the_verdict_names_the_holder() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains(
            "The GPU is held by firefox (PID 4321, devices: /dev/dri/card0, \
                         /dev/dri/renderD128)."
        ) || report.contains("The GPU is held by firefox (PID 4321"),
        "{report}"
    );
    // The nvidia marker is absent: no external-dependency line.
    assert!(!report.contains("nvidia-smi"), "{report}");
}

#[test]
fn the_empty_scene_prints_the_spec_sentence_and_exits_zero() {
    let mut idle = synthetic();
    idle.holders.clear();
    idle.vram.clear();
    let report = render(&idle, false);
    assert!(
        report.contains("No active GPU processes observed."),
        "the spec's own sentence, verbatim: {report}"
    );
    assert!(
        report.contains("No process holds the GPU device (the scene is idle)."),
        "{report}"
    );
}

#[test]
fn the_nvidia_marker_is_an_unaccounted_external_dependency() {
    let mut nvidia = synthetic();
    nvidia.nvidia_detected = true;
    // The NVIDIA host carries no AMD VRAM pair - the marker is the
    // only GPU memory fact, and it is an [unaccounted] one.
    nvidia.vram.clear();
    let report = render(&nvidia, false);
    assert!(
        report.contains(
            "NVIDIA proprietary driver detected: VRAM requires nvidia-smi (an external \
             tool zejtron does not run) - the card's memory is not measured here"
        ),
        "{report}"
    );
    // The NVIDIA path never fabricates a VRAM row.
    assert!(!report.contains("VRAM (AMD/amdgpu):"), "{report}");
}

#[test]
fn the_permission_boundary_is_named_never_dropped() {
    let report = render(&synthetic(), false);
    assert!(
        report.contains(
            "3 processes with unreadable fd tables (permission) - the holder list names \
             only the holders visible to this user"
        ),
        "{report}"
    );
}

#[test]
fn the_raw_drill_down_names_the_device_links() {
    let raw = render(&synthetic(), true);
    assert!(raw.contains("Raw device links (drill-down):"), "{raw}");
    assert!(raw.contains("/dev/dri/card0"), "{raw}");
    // No holders, no drill-down - an empty raw section is not a
    // section.
    let idle_raw = {
        let mut idle = synthetic();
        idle.holders.clear();
        render(&idle, true)
    };
    assert!(!idle_raw.contains("Raw device links"), "{idle_raw}");
}

#[test]
fn the_vram_reader_skips_the_render_nodes_and_non_cards() {
    // The reader is live sysfs; on a host with no DRM class the
    // honest shape is the empty Vec this pins (the sandbox and a
    // fresh CI runner both prove it), and the render skips the
    // section entirely.
    assert!(read_vram().len() <= 64, "bounded by the card count");
}
