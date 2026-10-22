// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the /proc and /etc raw parser grammar (night-improve-43).
//!
//! Every parser in this lane reads a file a local process or a
//! corrupted host controls byte for byte, and must answer with a
//! value or a refusal, never a panic. The harness drives the shared
//! parsers in `src/system/mod.rs`:
//!
//! - [`system::parse_cmdline_bytes`], the one /proc surface read as
//!   raw bytes (`/proc/<pid>/cmdline`, NUL-separated argv) - the real
//!   byte grammar the kernel serves, hostile NUL edge cases included;
//! - the string grammars behind the fs readers: passwd lines
//!   ([`system::parse_passwd_users`]), status fields
//!   ([`system::read_status_value`], [`system::read_status_name`]),
//!   and cgroup unit extraction
//!   ([`system::extract_systemd_unit`]) - driven through the same
//!   UTF-8 gate the real readers sit behind (`read_to_string`
//!   refuses non-UTF-8 before a parser ever sees the bytes).
//!
//! The source is path-included, not copied (see fuzz/Cargo.toml for
//! the full rationale): the harness compiles the same bytes the
//! binary ships, so the guarantee the lane proves is the guarantee
//! the binary carries.

#![no_main]

#[path = "../../src/system/mod.rs"]
mod system;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The raw /proc byte grammar: cmdline is the one /proc file the
    // readers take as bytes (NUL-separated argv, process-controlled).
    let _ = system::parse_cmdline_bytes(data);

    // The raw string grammars, behind the same UTF-8 gate the fs
    // readers sit behind.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = system::parse_passwd_users(text);
        let _ = system::read_status_value(text, "Name");
        let _ = system::read_status_value(text, "Uid");
        let _ = system::read_status_name(text);
        let _ = system::extract_systemd_unit(text);
    }
});
