// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The `sig` surface (night-signature-1, alias `signature`): the
//! depth-matrix self-check. The verb collects the four depths from
//! the running binary (see [`crate::info::signature`]) and renders
//! the matrix - human text or one JSON line - then maps the verdict
//! to the exit code: AUTHENTIC exits 0 (the partial-authentic arm
//! included, the unavailable depths named in the verdict), REFUSED
//! exits 1 as a runtime failure with the labeled error line. Usage
//! errors stay exit 2 above this module, help/version stay 0 - the
//! estate's exit-code law is untouched.

use std::error::Error;

pub fn run(print_json: bool) -> Result<(), Box<dyn Error>> {
    let matrix = crate::info::signature::collect();
    // The verb's own diagnostic lane (night-total-hardening-1): the
    // verdict rides stderr only, the report lane stays clean.
    crate::output::verbose::vlog!("sig", "depth matrix collected: {}", matrix.verdict_text());
    if print_json {
        println!("{}", crate::info::signature::matrix_json(&matrix));
    } else {
        println!("{}", crate::info::signature::matrix_report(&matrix));
    }
    match matrix.refused {
        None => Ok(()),
        Some((depth, reason)) => Err(format!("SIGNATURE: REFUSED ({depth}: {reason})").into()),
    }
}
