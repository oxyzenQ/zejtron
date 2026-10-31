// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The doctor JSON lane's tests (night-badass-5, repinned by
//! night-badass-6): the readiness envelope with its root facts, the
//! ram and cpu byte pins, the standard array names (`processes`,
//! `caches`), the absent-fact null law, the exit lane's three
//! truths, the deferral's JSON honesty, and the one-line law.
//! Wired from src/commands/doctor/json.rs.

use super::super::CheckStatus;
use super::super::cpu::{CpuRow, CpuSample};
use super::super::disk::DiskSample;
use super::super::gpu::GpuSample;
use super::super::memory::exits::ExitRow;
use super::super::memory::{MemInfo, MemorySample, ProcessPss, SlabRow, TmpfsFile};
use super::super::network::NetworkSample;
use super::*;

// ── Fixtures ─────────────────────────────────────────────────────

fn ram_sample() -> MemorySample {
    MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 1024,
            free_kib: 512,
            available_kib: 768,
            cached_kib: 128,
            buffers_kib: 16,
            shmem_kib: 8,
            s_reclaimable_kib: 32,
            s_unreclaim_kib: 4,
        }),
        pss: vec![ProcessPss {
            pid: 42,
            name: "brave".to_owned(),
            pss_kib: 400,
            anon_kib: 100,
            file_kib: 200,
            shmem_kib: 4,
            rss_kib: 512,
        }],
        pss_permission_refused: 2,
        pss_vanished: 1,
        pss_kernel_threads: 5,
        tmpfs_files: vec![TmpfsFile {
            path: "/dev/shm/x".to_owned(),
            size_bytes: 2048,
            holders: vec![42],
        }],
        tmpfs_unreadable_dirs: 0,
        tmpfs_mounts: vec!["/dev/shm".to_owned()],
        deleted: Vec::new(),
        memfds: Vec::new(),
        fd_permission_refused: 3,
        slab: vec![SlabRow {
            cache: "kmalloc-1k".to_owned(),
            size_kib: 64,
        }],
        slab_readable: true,
        exit_lane: ExitLane::NotAttached,
    }
}

fn cpu_sample() -> CpuSample {
    CpuSample {
        sampled_at: "2026-01-01 00:00:00 (UTC)".to_owned(),
        ncpu: 8,
        loadavg_1min: Some(1.5),
        busy_pct: Some(47.2),
        total_ticks_delta: 1000,
        top: vec![CpuRow {
            pid: 2985,
            comm: "brave".to_owned(),
            pct: 47.2,
            ticks: 472,
        }],
        running: 1,
        stuck: Vec::new(),
        stuck_overflow: 0,
        started_in_window: 0,
        vanished_between_reads: 0,
        exit_lane: ExitLane::NotAttached,
        raw_stat_a: String::new(),
        raw_stat_b: String::new(),
        raw_loadavg: String::new(),
    }
}

// ── The envelope laws ────────────────────────────────────────────

#[test]
fn every_json_lane_is_one_line() {
    for line in [
        readiness_prefix(),
        json_ram(&ram_sample()),
        json_cpu(&cpu_sample()),
        json_disk(&DiskSample::default()),
        json_network(&NetworkSample::default()),
        json_gpu(&GpuSample::default()),
        slow_json(&["ram", "cpu"]),
    ] {
        assert!(
            !line.contains('\n'),
            "the JSON lane is one line, got {line}"
        );
    }
}

#[test]
fn the_symptom_envelope_carries_its_identity() {
    let line = json_gpu(&GpuSample::default());
    assert!(line.starts_with(
        "{\"ledger_version\":2,\"mode\":\"symptom\",\"symptom\":\"gpu\",\"window\":null"
    ));
    let line = json_cpu(&cpu_sample());
    assert!(line.contains("\"symptom\":\"cpu\",\"window\":\"1.0s\""));
}

#[test]
fn the_slow_json_names_the_absence_never_a_fake_report() {
    let line = slow_json(&super::super::symptom::IMPLEMENTED);
    assert_eq!(
        line,
        "{\"ledger_version\":2,\"mode\":\"symptom\",\"symptom\":\"slow\",\"window\":null,\
\"implemented\":false,\"implemented_symptoms\":[\"ram\",\"cpu\",\"disk\",\"network\",\"gpu\"]}"
    );
}

// ── The readiness report ─────────────────────────────────────────

fn readiness_prefix() -> String {
    let checks = vec![
        CheckResult {
            status: CheckStatus::Ok,
            check: "os",
            message: "linux".to_owned(),
        },
        CheckResult {
            status: CheckStatus::Warn,
            check: "journalctl",
            message: "unreadable".to_owned(),
        },
    ];
    let summary = Summary {
        ok: 1,
        warn: 1,
        fail: 0,
    };
    readiness_json(&checks, &summary, Some(0))
}

#[test]
fn the_readiness_json_pins_its_envelope() {
    let line = readiness_prefix();
    // The envelope opens with the root host facts (night-badass-6):
    // the OS word is the compile-time constant, the kernel and
    // distro ride the host's probes, the lane is the eBPF facts'
    // own - so the pin takes the deterministic prefix and the rest
    // rides contains assertions. The detailed check rows, the
    // summary, and the ebpf object follow.
    assert!(
        line.starts_with(
            "{\"ledger_version\":2,\"mode\":\"readiness\",\"os\":\"linux\",\"kernel\":"
        )
    );
    assert!(line.contains(
        "\"user\":{\"uid\":0,\"class\":\"privileged\"},\"checks\":[{\"name\":\"os\",\"status\":\"ok\",\
\"message\":\"linux\"},{\"name\":\"journalctl\",\"status\":\"warn\",\
\"message\":\"unreadable\"}],\"summary\":{\"ok\":1,\"warn\":1,\"fail\":0},\
\"ebpf\":{\"feature\":\"enabled\""
    ));
    assert!(line.contains("\"distro\":"));
    assert!(line.contains("\"ebpf_lane\":"));
    assert!(line.contains("\"pins_state\":"));
    assert!(line.contains("\"probes\":["));
}

#[test]
fn the_readiness_user_names_the_unprivileged_class() {
    let checks = Vec::new();
    let summary = Summary {
        ok: 0,
        warn: 0,
        fail: 0,
    };
    let line = readiness_json(&checks, &summary, Some(1000));
    assert!(line.contains("\"user\":{\"uid\":1000,\"class\":\"unprivileged\"}"));
}

// ── ram ──────────────────────────────────────────────────────────

#[test]
fn the_ram_json_pins_its_shape() {
    let line = json_ram(&ram_sample());
    assert_eq!(
        line,
        "{\"ledger_version\":2,\"mode\":\"symptom\",\"symptom\":\"ram\",\"window\":null,\
\"memory\":{\"total_bytes\":1048576,\"used_bytes\":262144,\"available_bytes\":786432,\
\"used_pct\":25},\
\"processes\":[{\"pid\":42,\"comm\":\"brave\",\"pss_bytes\":409600,\"anon_bytes\":102400,\
\"file_bytes\":204800,\"shmem_bytes\":4096,\"rss_bytes\":524288}],\
\"processes_total\":1,\"pss_permission_refused\":2,\"pss_vanished\":1,\"pss_kernel_threads\":5,\
\"tmpfs\":{\"mounts\":[\"/dev/shm\"],\"files\":[{\"path\":\"/dev/shm/x\",\
\"size_bytes\":2048,\"holders\":[42]}],\"unreadable_dirs\":0},\
\"deleted_open\":[],\"memfds\":[],\
\"kernel_buckets\":{\"page_cache_bytes\":122880,\"buffers_bytes\":16384,\
\"shmem_bytes\":8192},\
\"slab\":{\"readable\":true,\"caches\":[{\"cache\":\"kmalloc-1k\",\"size_bytes\":65536}]},\
\"residual_bytes\":155648,\"exits\":{\"lane\":\"not-attached\"},\
\"unaccounted\":[{\"count\":1,\"category\":\"exited processes\",\"reason\":\"eBPF is not \
attached - processes that exited before this snapshot are invisible\"},\
{\"count\":2,\"category\":\"processes\",\"reason\":\"smaps_rollup unreadable (permission) - \
their memory rides the residual above\"},\
{\"count\":1,\"category\":\"processes\",\"reason\":\"exited or truncated mid-scan - their \
memory rides the residual above\"},\
{\"count\":5,\"category\":\"processes\",\"reason\":\"carry no memory map (kernel threads, \
zombies) - no user memory to attribute; their kernel-side memory rides the residual \
above\"},\
{\"count\":3,\"category\":\"fd tables\",\"reason\":\"unreadable (permission) - the tmpfs \
holder list names only the holders visible to this user\"}],\
\"verdict\":{\"lines\":[\"The largest single consumer is brave (400 KiB PSS).\",\
\"No anomalous consumer detected.\"]}}"
    );
}

#[test]
fn the_absent_facts_stay_absent_never_zero() {
    // A sample nobody filled: the memory header, the kernel buckets,
    // and the residual are null; the arrays are empty; the exit lane
    // names its state. Zero would be a lie; null is the truth.
    let line = json_ram(&MemorySample::default());
    assert!(line.contains("\"memory\":null"));
    assert!(line.contains("\"kernel_buckets\":null"));
    assert!(line.contains("\"residual_bytes\":null"));
    assert!(line.contains("\"processes\":[],\"processes_total\":0"));
    assert!(line.contains("\"exits\":{\"lane\":\"not-attached\"}"));
    assert!(line.contains("\"slab\":{\"readable\":false,\"caches\":[]}"));
}

// ── cpu ──────────────────────────────────────────────────────────

#[test]
fn the_cpu_json_pins_its_shape() {
    let line = json_cpu(&cpu_sample());
    assert_eq!(
        line,
        "{\"ledger_version\":2,\"mode\":\"symptom\",\"symptom\":\"cpu\",\"window\":\"1.0s\",\
\"ncpu\":8,\"loadavg_1min\":1.5,\"busy_pct\":47.2,\"total_ticks_delta\":1000,\
\"processes\":[{\"pid\":2985,\"comm\":\"brave\",\"pct\":47.2,\"ticks\":472}],\
\"running\":1,\"stuck\":[],\"stuck_overflow\":0,\"started_in_window\":0,\
\"vanished_between_reads\":0,\"exits\":{\"lane\":\"not-attached\"},\
\"unaccounted\":[{\"count\":1,\"category\":\"process lifecycles\",\"reason\":\"processes \
that started and exited within the 1.0s sampling window: not attributed (zejtron samples, \
it does not watch)\"}],\
\"verdict\":{\"lines\":[\"The largest CPU consumer is brave (47.2% of total CPU in the \
window).\"]}}"
    );
}

#[test]
fn numbers_stay_numbers_in_the_json_lane() {
    // The night-badass-5 law the owner named: no stringly-typed
    // numbers - the pct and the ticks carry no quotes.
    let line = json_cpu(&cpu_sample());
    assert!(line.contains("\"busy_pct\":47.2,\"total_ticks_delta\":1000"));
    assert!(line.contains("\"pct\":47.2,\"ticks\":472"));
    assert!(!line.contains("\"busy_pct\":\""));
}

/// night-dragon-maintenance-T1, the JSON-validity guard: a
/// non-finite f64 must never reach the document as the three
/// letters `NaN`/`inf` - they are not JSON, and one such token
/// makes every consumer (jq, python json.loads) reject the WHOLE
/// document. write_pct degrades a non-finite value to JSON null
/// (the typed-absence law: a reading that is not a finite number
/// is not a reading), and the document-level pin proves a poisoned
/// sample still renders a document a strict parser accepts.
#[test]
fn non_finite_percentages_degrade_to_json_null_never_invalid_tokens() {
    // The emission guard, pinned directly through the private
    // writer the module owns (the tests ride super::*).
    for poisoned in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut out = String::new();
        write_pct(&mut out, poisoned);
        assert_eq!(out, "null", "a non-finite pct must serialize as null");
    }
    let mut finite = String::new();
    write_pct(&mut finite, 47.25);
    assert_eq!(finite, "47.2", "the finite shape is unchanged");

    // The document-level guard: a sample whose top row carries a
    // NaN pct (the kind a future unguarded division could produce)
    // still renders one valid JSON line - the pct field degrades
    // to null and no NaN/Inf token rides the bytes.
    let mut sample = cpu_sample();
    sample.top[0].pct = f64::NAN;
    sample.busy_pct = Some(f64::INFINITY);
    let line = json_cpu(&sample);
    assert!(
        !line.contains("NaN"),
        "NaN token must never ride the JSON: {line}"
    );
    assert!(
        !line.contains("inf"),
        "inf token must never ride the JSON: {line}"
    );
    assert!(
        line.contains("\"pct\":null,"),
        "the poisoned row's pct degrades to typed null: {line}"
    );
    assert!(
        line.contains("\"busy_pct\":null,"),
        "the poisoned busy_pct degrades to typed null: {line}"
    );
}

// ── The exit lane's three truths ─────────────────────────────────

#[test]
fn the_drained_lane_names_its_processes_and_the_overflow() {
    let lane = ExitLane::Drained(vec![
        ExitRow {
            pid: 7,
            comm: "gone".to_owned(),
            timestamp_ns: 2_000_000_000,
        },
        ExitRow {
            pid: 8,
            comm: "also-gone".to_owned(),
            timestamp_ns: 3_000_000_000,
        },
    ]);
    let mut out = String::new();
    write_exits(&mut out, &lane, "5s");
    assert!(out.starts_with(
        ",\"exits\":{\"lane\":\"drained\",\"window_label\":\"5s\",\"processes\":\
[{\"pid\":7,\"comm\":\"gone\",\"at\":"
    ));
    assert!(out.contains("\"timestamp_ns\":2000000000}"));
    assert!(out.contains("]"));
    assert!(out.ends_with("\"overflow\":0}"));
}

#[test]
fn the_drain_failure_rides_verbatim() {
    let lane = ExitLane::DrainFailed("the ring refused".to_owned());
    let mut out = String::new();
    write_exits(&mut out, &lane, "5s");
    assert_eq!(
        out,
        ",\"exits\":{\"lane\":\"drain-failed\",\"error\":\"the ring refused\"}"
    );
}

// ── The boundary mirroring ───────────────────────────────────────

#[test]
fn the_delta_boundaries_mirror_the_text_block() {
    // The started-in-window and vanished counts become the same
    // entries the text Unaccounted block names - count, category,
    // reason - so the JSON block and the text block cannot drift.
    let mut sample = cpu_sample();
    sample.started_in_window = 3;
    sample.vanished_between_reads = 4;
    let entries = cpu_unaccounted(&sample);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].count, 3);
    assert_eq!(entries[1].category, "processes");
    assert_eq!(
        entries[1].reason,
        "started inside the window: no baseline to delta against, not ranked"
    );
    assert_eq!(entries[2].count, 4);
    assert_eq!(
        entries[2].reason,
        "vanished between the reads: their window share is not carried"
    );
}

#[test]
fn the_gpu_boundaries_name_the_nvidia_truth() {
    let sample = GpuSample {
        nvidia_detected: true,
        ..Default::default()
    };
    let entries = gpu_unaccounted(&sample);
    assert!(
        entries
            .iter()
            .any(|entry| entry.category == "vram" && entry.reason.contains("nvidia-smi"))
    );
}
