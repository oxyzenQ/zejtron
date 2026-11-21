// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-datapath-1 (the proven datapath): the proof-harness
//! package's root. The pure cores compile here from their own files
//! (#[path] wirings - the fuzz harnesses' include law), and the two
//! instruments attach as cfg-gated modules:
//!
//!  * `property_tests` - #[cfg(test)]: proptest exhaustion of the
//!    cores' laws on stable (the standing lane: `cargo test`).
//!  * `kani_cores` - #[cfg(kani)]: the totality theorems, for all
//!    inputs within each harness's domain (`cargo kani --lib`).
//!
//! The loom instrument was examined and returned a signed census NO
//! (the manifest comment carries the record; the loom-census job in
//! proofs.yml enforces the absence standing). zejtron's proof-carrying
//! cores are pure functions - no shared mutable state for an
//! interleaving checker to explore.
//!
//! The cores are law libraries: each instrument uses the slice of
//! each core its theorem names, so dead-code silence is the honest
//! crate posture here (every unused fn is pinned by another tree).
#![allow(dead_code)]

// -- The included law files (the SAME bytes the binary builds -
// wired the fuzz-harness way, one inclusion per file per binary).
// The harness modules consume these, never their own copies.

/// The layout contract between the BPF program and the userspace
/// reader: the event records, the filter-key packing, the port
/// decision table, the offset slot domain. Plain core Rust, no aya.
#[path = "../../src/ebpf/events.rs"]
mod events_core;

/// The civil clock: Hinnant's civil_from_days arithmetic, the unix
/// seconds formatting and its SystemTime round trip. std plus the
/// libc pair (the monotonic helper the binary carries).
#[path = "../../src/info/clock.rs"]
mod clock_core;

// -- The instruments (each cfg-gated; see the module docs).

#[cfg(test)]
#[path = "property_tests.rs"]
mod property_tests;

#[cfg(kani)]
#[path = "kani_cores.rs"]
mod kani_cores;
