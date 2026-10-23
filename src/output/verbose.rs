// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The diagnostic trace lane (night-hunter-4): a global
//! `-v/--verbose` flag that gives the engine a voice on stderr while
//! the Evidence Ledger keeps stdout perfectly clean. The contract is
//! the pipe law: `zejtron why /etc/passwd -v > out.txt 2> err.txt`
//! must leave `out.txt` holding ONLY the ledger bytes, with every
//! `[engine]` / `[btf]` / `[lane]` trace confined to `err.txt`.
//!
//! This module lives in the output group because the trace lane IS
//! an output lane: the stderr sibling of the color tiers this module
//! group owns - same one-door discipline, same stream anchoring.
//!
//! Design: one static [`AtomicBool`], set once by main from the CLI
//! parse, read everywhere through [`enabled`]. The [`vlog`] macro
//! short-circuits on the flag BEFORE any formatting work, so a
//! silent run pays a single relaxed atomic load per call site - the
//! read-only command paths keep their zero-allocation shape. Logs
//! are factual and boring by law: one line, one bracketed tag
//! naming the subsystem (`engine` = the loader and attach chain,
//! `btf` = the struct-offset parser, `lane` = the snapshot/live
//! decision), no emojis, no hype, stderr only.

use std::sync::atomic::{AtomicBool, Ordering};

/// The verbose switch. Relaxed ordering is sufficient: the flag is
/// written once at startup, before any worker surface runs, and the
/// only contract is eventual visibility within one process lifetime.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Arm the diagnostic lane. Called exactly once, by main, straight
/// after the CLI parse - every later call site only reads.
pub fn init(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}

/// True when `-v/--verbose` armed the diagnostic lane.
pub fn enabled() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// The one logging door: print `[tag] message` to stderr when the
/// lane is armed, do nothing (and format nothing) when it is not.
/// Call sites use the [`vlog`] macro, which guards on [`enabled`]
/// before evaluating its format arguments.
pub fn log(tag: &str, msg: &str) {
    if enabled() {
        eprintln!("[{tag}] {msg}");
    }
}

/// The diagnostic trace macro: `vlog!("engine", "loading {} bytes", n)`
/// prints `[engine] loading N bytes` on stderr under `-v`, and costs
/// one atomic load when the lane is silent. Arguments are NOT
/// evaluated when the lane is off (the guard sits in front of the
/// format machinery), so logging never allocates on a quiet run.
macro_rules! vlog {
    ($tag:expr, $($arg:tt)*) => {
        if $crate::output::verbose::enabled() {
            $crate::output::verbose::log($tag, &format!($($arg)*));
        }
    };
}

pub(crate) use vlog;

#[cfg(test)]
#[path = "../../test/output/verbose_tests.rs"]
mod tests;
