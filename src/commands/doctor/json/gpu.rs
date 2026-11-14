// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The gpu symptom's JSON lane (night-frontier-Z1 moved it here - a
//! PURE move under the 600-LOC cap, the json/slow.rs sibling
//! precedent: one lane, one file). The device holders under the
//! standard `processes` name (night-badass-6) with their `devices`
//! lists, the AMD/amdgpu VRAM rows as byte pairs, the NVIDIA marker,
//! the boundary count, the exit lane, and the Unaccounted block -
//! serialized from the same sample the text ledger renders (the
//! shared writers live in the parent).

use std::fmt::Write as _;

use super::super::delta::OVERLAY_WINDOW_LABEL;
use super::super::gpu::{GpuSample, verdict_lines as gpu_verdict_lines};
use super::super::memory::exits::ExitLane;
use super::{
    symptom_header, write_array, write_exits, write_string, write_unaccounted_entries,
    write_verdict,
};
use crate::evidence::UnaccountedEntry;

/// The gpu symptom as JSON: the device holders under the standard
/// `processes` name (night-badass-6) with their `devices` lists,
/// the AMD/amdgpu VRAM rows as byte pairs, the NVIDIA marker, the
/// boundary count, the exit lane, and the Unaccounted block.
pub(in crate::commands::doctor) fn json_gpu(sample: &GpuSample) -> String {
    let mut out = String::with_capacity(768);
    symptom_header(&mut out, "gpu", None);
    out.push_str(",\"processes\":");
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
    out.push_str(",\"gpu_memory\":");
    write_array(&mut out, sample.gpu_memory.len(), |out, index| {
        let row = &sample.gpu_memory[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", row.pid);
        out.push_str(",\"comm\":");
        write_string(out, &row.comm);
        out.push_str(",\"vram_bytes\":");
        let _ = write!(out, "{}", row.vram_kib.saturating_mul(1024));
        out.push_str(",\"gtt_bytes\":");
        let _ = write!(out, "{}", row.gtt_kib.saturating_mul(1024));
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
    write_exits(&mut out, &sample.exit_lane, OVERLAY_WINDOW_LABEL);
    write_unaccounted_entries(&mut out, &gpu_unaccounted(sample));
    write_verdict(&mut out, &gpu_verdict_lines(sample));
    out.push('}');
    out
}

/// The gpu Unaccounted block as entries: the snapshot boundary (the
/// moment phrasing gpu passes its text builder), the NVIDIA
/// external-dependency marker, and the fd permission refusals.
pub(super) fn gpu_unaccounted(sample: &GpuSample) -> Vec<UnaccountedEntry> {
    let mut entries = Vec::new();
    match &sample.exit_lane {
        ExitLane::NotAttached => entries.push(UnaccountedEntry::new(
            1,
            "process lifecycles",
            "processes that started and exited within the moment before this snapshot: not attributed (zejtron samples, it does not watch)",
        )),
        ExitLane::Drained(..) => entries.push(UnaccountedEntry::new(
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
