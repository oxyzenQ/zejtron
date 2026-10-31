// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The umbrella symptom's tests (night-dragon-lts-2): the vmstat
//! swap parser's byte pins, the severity ladder's every rung (each
//! signature fires on a synthetic sample, and only on it), the
//! ladder's ordering, the quiet-host verdict that restates the four
//! headlines as numbers, and the render's section shape. Wired from
//! src/commands/doctor/slow.rs.

use super::*;
use crate::commands::doctor::cpu::{CpuRow, CpuSample, StuckRow};
use crate::commands::doctor::disk::{DiskRow, DiskSample};
use crate::commands::doctor::network::{IfRow, NetworkSample, SocketStates};

// ── Fixtures ─────────────────────────────────────────────────────

fn quiet_sample() -> SlowSample {
    SlowSample {
        sampled_at: "2026-01-01 00:00:00 (UTC)".to_owned(),
        cpu: CpuSample {
            sampled_at: String::new(),
            ncpu: 4,
            loadavg_1min: Some(0.5),
            busy_pct: Some(12.5),
            total_ticks_delta: 400,
            top: vec![CpuRow {
                pid: 7,
                comm: "worker".to_owned(),
                pct: 10.0,
                ticks: 40,
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
        },
        disk: DiskSample {
            sampled_at: String::new(),
            iowait_pct: Some(1.0),
            total_ticks_delta: 400,
            top: Vec::new(),
            started_in_window: 0,
            vanished_between_reads: 0,
            io_permission_refused: 0,
            exit_lane: ExitLane::NotAttached,
        },
        network: NetworkSample {
            sampled_at: String::new(),
            interfaces: vec![IfRow {
                name: "eth0".to_owned(),
                rx_bytes: 4096,
                rx_packets: 8,
                tx_bytes: 2048,
                tx_packets: 4,
            }],
            sockets: SocketStates {
                total: 20,
                established: 10,
                time_wait: 3,
                close_wait: 0,
            },
            holders: Vec::new(),
            fd_permission_refused: 0,
            exit_lane: ExitLane::NotAttached,
        },
        meminfo: Some(MemInfo {
            total_kib: 1_048_576,
            free_kib: 500_000,
            available_kib: 700_000,
            cached_kib: 200_000,
            buffers_kib: 16_384,
            shmem_kib: 8_192,
            s_reclaimable_kib: 4_096,
            s_unreclaim_kib: 2_048,
        }),
        swap_total_kib: Some(1_048_576),
        swap_free_kib: Some(1_048_576),
        swap_in_pages: 0,
        swap_out_pages: 0,
        exit_lane: ExitLane::NotAttached,
        raw_meminfo: String::new(),
        raw_vmstat_a: String::new(),
        raw_vmstat_b: String::new(),
    }
}

// ── The vmstat swap parser ───────────────────────────────────────

#[test]
fn the_vmstat_swap_parser_reads_both_counters() {
    let swap = parse_vmstat_swap("pswpin 123\npswpout 456\npgfault 999\n");
    assert_eq!(swap.pswpin, 123);
    assert_eq!(swap.pswpout, 456);
}

#[test]
fn absent_vmstat_swap_counters_count_zero() {
    // A kernel that has never swapped still writes the fields on
    // every modern host, but the parse never guesses: absent is
    // zero, malformed is zero, empty is zero.
    let swap = parse_vmstat_swap("");
    assert_eq!((swap.pswpin, swap.pswpout), (0, 0));
    let swap = parse_vmstat_swap("pswpin not-a-number\npswpout 1\n");
    assert_eq!((swap.pswpin, swap.pswpout), (0, 1));
    // The prefix is anchored: a counter named like another does not
    // feed the swap pair.
    let swap = parse_vmstat_swap("pswpin_zero 5\n");
    assert_eq!(swap.pswpin, 0);
}

// ── The severity ladder ──────────────────────────────────────────

#[test]
fn the_quiet_host_fires_no_finding() {
    let findings = rank_findings(&quiet_sample());
    assert!(
        findings.is_empty(),
        "a quiet window crosses no boundary: {findings:?}"
    );
}

#[test]
fn swap_rate_outranks_everything() {
    let mut sample = quiet_sample();
    sample.swap_in_pages = 512;
    sample.cpu.busy_pct = Some(95.0);
    sample.disk.iowait_pct = Some(40.0);
    let findings = rank_findings(&sample);
    assert_eq!(findings[0].class, "swap_pressure");
    assert!(findings[0].text.contains("swapping"));
    assert!(findings[0].text.contains("512 pages in"));
}

#[test]
fn d_state_processes_fire_stuck_io() {
    let mut sample = quiet_sample();
    sample.cpu.stuck = vec![StuckRow {
        pid: 99,
        comm: "dd".to_owned(),
    }];
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "stuck_io");
    assert!(findings[0].text.contains("dd (PID 99)"));
}

#[test]
fn load_above_cores_with_a_quiet_cpu_fires_stuck_io() {
    let mut sample = quiet_sample();
    sample.cpu.loadavg_1min = Some(9.5);
    sample.cpu.busy_pct = Some(4.0);
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "stuck_io");
    assert!(findings[0].text.contains("waiting on I/O"));
}

#[test]
fn high_iowait_fires_io_wait_with_its_consumer() {
    let mut sample = quiet_sample();
    sample.disk.iowait_pct = Some(31.0);
    sample.disk.top = vec![DiskRow {
        pid: 55,
        comm: "tar".to_owned(),
        read_delta: 4096,
        write_delta: 0,
    }];
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "io_wait");
    assert!(findings[0].text.contains("31.0%"));
    assert!(findings[0].text.contains("tar (PID 55)"));
}

#[test]
fn a_thin_available_margin_fires_memory_pressure() {
    let mut sample = quiet_sample();
    sample.meminfo = Some(MemInfo {
        total_kib: 1_000_000,
        free_kib: 10_000,
        available_kib: 90_000,
        cached_kib: 80_000,
        buffers_kib: 1_000,
        shmem_kib: 500,
        s_reclaimable_kib: 250,
        s_unreclaim_kib: 250,
    });
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "memory_pressure");
    assert!(
        findings[0]
            .text
            .contains("9.0% of memory is still available")
    );
}

#[test]
fn a_saturated_cpu_fires_cpu_saturation_with_its_consumer() {
    let mut sample = quiet_sample();
    sample.cpu.busy_pct = Some(88.0);
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "cpu_saturation");
    assert!(findings[0].text.contains("88.0%"));
    assert!(findings[0].text.contains("worker (10.0% of total CPU)"));
}

#[test]
fn an_oversubscribed_runnable_queue_fires() {
    let mut sample = quiet_sample();
    sample.cpu.running = 6;
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "runnable_queue");
    assert!(
        findings[0]
            .text
            .contains("6 processes are running on 4 cores")
    );
}

#[test]
fn time_wait_and_close_wait_piles_fire_socket_churn() {
    let mut sample = quiet_sample();
    sample.network.sockets.time_wait = 2000;
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "socket_churn");
    assert!(findings[0].text.contains("2000"));

    let mut sample = quiet_sample();
    sample.network.sockets.close_wait = 40;
    let findings = rank_findings(&sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].class, "socket_churn");
    assert!(findings[0].text.contains("40 sockets sit in CLOSE_WAIT"));
}

#[test]
fn the_ladder_orders_its_rungs_by_severity() {
    // Every signature at once: the order is the contract.
    let mut sample = quiet_sample();
    sample.swap_out_pages = 8;
    sample.cpu.stuck = vec![StuckRow {
        pid: 1,
        comm: "kworker".to_owned(),
    }];
    sample.disk.iowait_pct = Some(25.0);
    sample.meminfo = None;
    sample.cpu.busy_pct = Some(85.0);
    sample.cpu.running = 9;
    sample.network.sockets.time_wait = 5000;
    sample.network.sockets.close_wait = 64;
    let ladder: Vec<&str> = rank_findings(&sample)
        .iter()
        .map(|finding| finding.class)
        .collect();
    assert_eq!(
        ladder,
        [
            "swap_pressure",
            "stuck_io",
            "io_wait",
            "cpu_saturation",
            "runnable_queue",
            "socket_churn",
            "socket_churn",
        ],
        "the severity ladder's order is the contract"
    );
}

#[test]
fn the_unreadable_meminfo_does_not_fire_memory_pressure() {
    // None is an absence, not a zero: an unreadable meminfo must not
    // read as "no memory available".
    let mut sample = quiet_sample();
    sample.meminfo = None;
    let findings = rank_findings(&sample);
    assert!(
        findings.is_empty(),
        "an unreadable meminfo is not a finding: {findings:?}"
    );
}

// ── The verdict ──────────────────────────────────────────────────

#[test]
fn the_quiet_verdict_restates_the_four_headlines() {
    let lines = verdict_lines(&quiet_sample());
    assert_eq!(
        lines[0],
        "Nothing measurable is dragging this host in the 1.0s window: CPU 12.5% busy, \
         iowait 1.0%, swap 0/0 pages, 683.6 MiB available."
    );
    assert!(
        lines[1].contains("does not live inside one 1.0s window"),
        "the second line names the window's own limit: {lines:?}"
    );
}

#[test]
fn the_finding_verdict_carries_the_top_rung() {
    let mut sample = quiet_sample();
    sample.swap_in_pages = 10;
    let lines = verdict_lines(&sample);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("swapping"));
}

// ── The render ───────────────────────────────────────────────────

#[test]
fn the_render_carries_every_section_in_order() {
    let text = render(&quiet_sample(), false);
    let header = text
        .find("Evidence report: symptom - slow")
        .expect("header");
    let mode = text
        .find("Mode: snapshot delta (1.0s sample")
        .expect("mode line");
    let cpu = text.find("CPU (window 1.0s):").expect("cpu section");
    let memory = text.find("Memory:").expect("memory section");
    let disk = text.find("Disk (window 1.0s):").expect("disk section");
    let network = text
        .find("Network (window 1.0s):")
        .expect("network section");
    let findings = text
        .find("Findings (ranked by severity):")
        .expect("findings");
    let unaccounted = text.find("Unaccounted:").expect("unaccounted");
    let verdict = text.find("Verdict:").expect("verdict");
    for (a, b) in [
        (header, mode),
        (mode, cpu),
        (cpu, memory),
        (memory, disk),
        (disk, network),
        (network, findings),
        (findings, unaccounted),
        (unaccounted, verdict),
    ] {
        assert!(a < b, "the section order is the contract");
    }
    assert!(text.contains("no lane crossed its named boundary"));
    assert!(text.contains("[measured]"));
}

#[test]
fn the_render_names_the_gpu_exclusion_in_unaccounted() {
    let text = render(&quiet_sample(), false);
    assert!(
        text.contains("the gpu lane rides outside this triage"),
        "a fact not carried is named: {text}"
    );
}

#[test]
fn the_compact_lanes_carry_their_headline_numbers() {
    let text = render(&quiet_sample(), false);
    assert!(text.contains("busy 12.5% of total ticks"));
    assert!(text.contains("load 0.50 across 4 cores"));
    assert!(text.contains("swap in 0 pages, out 0 pages in window"));
    assert!(text.contains("iowait 1.0% of total ticks"));
    assert!(text.contains("eth0 RX 4 KiB TX 2 KiB"));
    assert!(text.contains("10 ESTABLISHED  3 TIME_WAIT  0 CLOSE_WAIT"));
}

#[test]
fn the_raw_drill_down_reprints_the_sampled_bytes() {
    let mut sample = quiet_sample();
    sample.raw_meminfo = "MemTotal:  100 kB\nMemFree:  1 kB\n".to_owned();
    sample.raw_vmstat_a = "pswpin 0\npswpout 0".to_owned();
    sample.raw_vmstat_b = "pswpin 3\npswpout 0".to_owned();
    let text = render(&sample, true);
    assert!(text.contains("Raw /proc reads (drill-down):"));
    assert!(text.contains("MemTotal:  100 kB"));
    assert!(text.contains("vmstat swap lines, sample A:"));
    assert!(text.contains("pswpin 3"));
}

#[test]
fn the_unreadable_vmstat_renders_its_absence() {
    let sample = quiet_sample();
    let text = render(&sample, true);
    assert!(text.contains("(unreadable at sample time)"));
}
