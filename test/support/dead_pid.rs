// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The dead-pid fixture guard (the port post-mortem fixtures'
//! hermeticity law): the post-mortem verdict reads the host's REAL
//! `/proc/<pid>` at render time to decide whether a process is gone,
//! so a fixture pid is only honest when the process table cannot hold
//! it. Hardcoded pids (the 4242 shape) raced the CI runner's own pid
//! allocation - a runner process holding the fixture's pid flipped
//! the rows from post-mortem to live, the attribution field vanished,
//! and the schema pins failed on exactly the hosts that happened to
//! collide (the supermassive low-specs leg's 2026-11-02 red run, and
//! the check-all leg's single-test failure on the same day).
//!
//! The helper scans upward from 40_000: above the kernel's classic
//! 32768 pid_max default, where any such pid is structurally
//! impossible on a host that did not raise the ceiling; on hosts with
//! the raised 4194304 limit the walk simply skips past the realistic
//! process count. The scan is fresh on every call (nothing cached):
//! it re-probes microseconds before the render, so a pid the host
//! allocated mid-run is never handed to the next test. A generous
//! bound fails loudly instead of looping forever.

use std::path::Path;

/// The scan floor: above the kernel's classic pid_max default
/// (32768) - structurally impossible on every host that did not
/// raise the ceiling; above every realistic process count on hosts
/// that did.
const SCAN_FLOOR: u32 = 40_000;

/// The scan bound: one million candidates past the floor - a host
/// holding every pid in that range is not a CI runner, and the loud
/// failure names the condition instead of hanging the suite.
const SCAN_BOUND: u32 = SCAN_FLOOR + 1_000_000;

/// A pid the host's process table cannot currently hold: the first
/// pid at or above [`SCAN_FLOOR`] with no `/proc/<pid>` entry. Test
/// code only - the production surfaces never guess a pid, they read
/// one from the kernel.
pub(crate) fn dead_pid() -> u32 {
    (SCAN_FLOOR..SCAN_BOUND)
        .find(|pid| !Path::new(&format!("/proc/{pid}")).exists())
        .expect("no free pid above the scan floor - is this a host or a datacenter?")
}
