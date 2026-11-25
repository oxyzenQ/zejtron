// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The `sig` surface (night-signature-1, alias `signature`): the
//! depth-matrix self-check. The verb collects the six depths from
//! the running binary (see [`crate::info::signature`]) and renders
//! the matrix - human text or one JSON line - then maps the verdict
//! class to the exit code (night-hit-2): AUTHENTIC exits 0 (the
//! partial-authentic arm included, the unavailable depths named in
//! the verdict); UNSIGNED and TAMPERED both exit 1 as a runtime
//! failure with the labeled error line - the unsigned class names
//! the missing provenance link (5/6 depths verified, the integrity
//! depths all green), the tamper class names the contradicting
//! depth. Usage errors stay exit 2 above this module,
//! help/version stay 0 - the estate's exit-code law is untouched.

use std::error::Error;

use crate::info::signature::SigVerdict;

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
    // The exit law rides its named predicate: only the authentic
    // class exits 0. The match below names the failing class's own
    // truth - the unreachable authentic arm stays a named string,
    // never a panic (the estate's named-error law).
    if !matrix.is_authentic() {
        let error: String = match matrix.verdict {
            SigVerdict::Unsigned => format!(
                "SIGNATURE: UNSIGNED ({}/6 depths verified) - a missing provenance link, \
                 not a modification; releases still bind to signed commits/tags",
                matrix.verified
            ),
            SigVerdict::Tampered => match matrix.refused {
                Some((depth, reason)) => format!("SIGNATURE: TAMPERED ({depth}: {reason})"),
                None => "SIGNATURE: TAMPERED (no depth named - report the shape)".to_owned(),
            },
            SigVerdict::Authentic => "SIGNATURE: AUTHENTIC reached the error surface".to_owned(),
        };
        Err(error.into())
    } else {
        Ok(())
    }
}
