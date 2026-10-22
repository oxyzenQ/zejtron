// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target: the terminal-safety neutralizer (night-improve-43).
//!
//! [`system::sanitize_display`] is the one gate between hostile text
//! (process names a local process sets byte for byte via prctl,
//! cmdlines, cgroup units, symlink targets) and the rendered row. Its
//! contract is two properties, and the harness asserts both on every
//! input the fuzzer invents:
//!
//! 1. Terminal safety (the CWE-150 class): NO control character -
//!    C0, DEL, C1 - survives into the output. An escape sequence that
//!    reaches the terminal can forge the evidence stream zejtron
//!    exists to report; a violation here is a fuzzer crash, libFuzzer
//!    saves the input, and CI fails.
//! 2. Honest-data fidelity: input carrying no control characters
//!    comes back byte-identical (the fast path's contract).
//!
//! The `&str` type system refuses non-UTF-8 before this function
//! runs (the fs readers' `read_to_string` and the cmdline
//! `from_utf8` gate sit upstream), so the harness drives the same
//! UTF-8 gate the real callers sit behind. The source is
//! path-included, not copied (see fuzz/Cargo.toml for the full
//! rationale): the harness compiles the same bytes the binary ships.

#![no_main]

#[path = "../../src/system/mod.rs"]
mod system;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let sanitized = system::sanitize_display(text);

        assert!(
            !sanitized.chars().any(char::is_control),
            "terminal injection: sanitize_display let a control character \
             through (input {text:?}, output {sanitized:?})"
        );

        if !text.chars().any(char::is_control) {
            assert_eq!(
                sanitized, text,
                "sanitize_display mutated honest data (input {text:?})"
            );
        }
    }
});
