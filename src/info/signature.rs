// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth-matrix signature (night-signature-1): the binary's own
//! anti-theft / anti-fake-claim verification. The estate already
//! states its identity (the -V `Signature:` line, the trademark and
//! licensing layers); this module makes the claim CHECKABLE, at four
//! depths, by the binary itself and by anyone holding the artifact:
//!
//! - **D0 runtime identity** - the owner's claim,
//!   `rezky_nightky (oxyzenQ) 2026`, rides the -V report as the
//!   `Depth-sig:` line beside the anchor over it.
//! - **D1 embedded marker** - a `ZJNS1|identity|commit|build-time|anchor`
//!   line is burned into the binary image (see
//!   [`NZ_SIG_MARKER`]); `grep -a ZJNS1 <binary>` reads it off the
//!   artifact without executing it - the estate's own read-only
//!   discipline, pointed at the binary itself.
//! - **D2 anchor integrity** - the runtime recomputes the BLAKE3
//!   anchor over the shared payload (`build/sig.rs`, the one format
//!   both the build lane and this module include) and refuses on any
//!   mismatch - a hand-patched -V line or a rebuild claiming someone
//!   else's build facts breaks the chain.
//! - **D3 binary self-hash** - BLAKE3 over the running image
//!   (`/proc/self/exe`), b3sum-verifiable outside the binary: the
//!   owner pins one hash per release and any hacked or
//!   rebuilt artifact answers for the bytes it actually carries.
//!
//! The honesty law runs through every depth: an unverifiable depth is
//! `unavailable` with the reason named, a contradicting depth is
//! `refused`, and the verdict never claims more than it proved.

// The shared payload format (night-signature-1) - one definition,
// included here and by build.rs. The anchor the build lane stamped
// and the anchor this module recomputes can never disagree about the
// FORMAT, only about the bytes - which is exactly what D2 checks.
// pub(crate): the info test file pins SIG_IDENTITY's exact bytes too.
#[path = "../../build/sig.rs"]
pub(crate) mod sig;

// The same std-only BLAKE3 the build lane and the prebuilt manifest
// lane use (build/blake3.rs). One hash family across the object pin,
// the release checksums, and the depth matrix - the estate standard,
// zero new dependencies.
#[path = "../../build/blake3.rs"]
mod blake3;

/// The embedded marker: the signature line build.rs staged into
/// OUT_DIR, riding the binary image as static rodata. `#[used]` and
/// the D1 reference below keep it in the object; being referenced
/// data (not symbol metadata) it survives the release lane's
/// `strip = true`. This is the D1 fact the runtime verifies against
/// its own on-disk image.
#[used]
static NZ_SIG_MARKER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/nz_sig.bin"));

/// The honest unstamped arm of the Depth-sig line (the guard-arm
/// discipline of `SIGNATURE_UNSTAMPED_LINE`): a build the estate
/// build script never drove carries no anchor, and the report says so
/// instead of rendering an empty claim. ONE contiguous literal - the
/// release lanes byte-grep claims lines out of `strings` output.
const DEPTH_SIG_UNSTAMPED_LINE: &str =
    "Depth-sig: unstamped — the anchor was never stamped (a build outside the estate build script)";

/// The exact Depth-sig line the -V report carries. Stamped builds
/// render the identity claim plus the anchor over the payload (`b3:`
/// prefix, 64 lowercase hex); unstamped builds render the honest
/// guard line above. The identity, commit, and build-time ingredients
/// of the payload are the report's own adjacent lines - the recipe in
/// docs/VERIFY_RELEASE.md rebuilds the payload from the report alone.
pub(crate) fn depth_sig_line() -> String {
    match option_env!("ZEJTRON_SIG_ANCHOR") {
        Some(anchor) if !anchor.is_empty() => {
            format!("Depth-sig: {} b3:{anchor}", sig::SIG_IDENTITY)
        }
        _ => DEPTH_SIG_UNSTAMPED_LINE.to_owned(),
    }
}

/// One depth's verdict on this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepthStatus {
    /// The depth verified against this binary.
    Pass,
    /// The depth cannot run here - named, never guessed.
    Unavailable,
    /// The depth ran and contradicted the claim - the fake-build arm.
    Refused,
}

impl DepthStatus {
    fn word(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Unavailable => "unavailable",
            Self::Refused => "refused",
        }
    }
}

/// One row of the matrix: the depth id, its name, the status, and the
/// one-line fact or reason the row renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DepthRow {
    pub id: &'static str,
    pub name: &'static str,
    pub status: DepthStatus,
    pub detail: String,
}

/// The collected matrix - the data both renderers speak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigMatrix {
    pub rows: Vec<DepthRow>,
    pub identity: &'static str,
    pub commit: String,
    pub build_time: String,
    /// The stamped anchor (`None` on an unstamped build).
    pub anchor: Option<&'static str>,
    /// The D3 self-hash of the running image (`None` when the image
    /// lane is unavailable).
    pub binary_self_hash: Option<String>,
    /// The first refused depth, when the verdict is REFUSED.
    pub refused: Option<(&'static str, String)>,
    /// The unavailable depth ids, in row order.
    pub unavailable_ids: Vec<&'static str>,
    /// How many of the four depths verified.
    pub verified: usize,
}

/// Read the running executable's own bytes. Linux-only by the
/// estate's shape; every other target names the unavailability
/// instead of pretending.
fn read_self_image() -> Result<Vec<u8>, &'static str> {
    if !cfg!(target_os = "linux") {
        return Err("non-linux host - the self-image lane is linux-only");
    }
    std::fs::read("/proc/self/exe").map_err(|_| "the running image could not be read")
}

/// True when one parsed marker line agrees with the runtime's own
/// compile-time facts (the stamps build.rs laid down).
fn marker_matches_runtime(
    fields: &sig::SigMarkerFields<'_>,
    identity: &str,
    commit: &str,
    build_time: &str,
    anchor: &str,
) -> bool {
    fields.identity == identity
        && fields.commit == commit
        && fields.build_time == build_time
        && fields.anchor == anchor
}

/// Collect the four depths from this running binary. One image read
/// feeds D1 and D3; D0 and D2 are pure compile-time fact checks.
pub(crate) fn collect() -> SigMatrix {
    let identity = sig::SIG_IDENTITY;
    let commit = super::build_hash();
    let build_time = super::build_time();
    let anchor = option_env!("ZEJTRON_SIG_ANCHOR").filter(|a| !a.is_empty());

    // D0 - the runtime identity surface. The const IS the claim; the
    // test suite pins its exact bytes, the row renders them.
    let rows = vec![DepthRow {
        id: "D0",
        name: "runtime-identity",
        status: DepthStatus::Pass,
        detail: identity.to_owned(),
    }];

    let image = read_self_image();

    // D1 - the embedded marker. Two seats, both must hold: the
    // compile-time embedded copy parses (the build lane burned it),
    // and the on-disk image carries a marker agreeing with the
    // runtime's own stamps (the artifact was not stripped, rebuilt,
    // or patched after the fact).
    let d1 = match &image {
        Err(reason) => (DepthStatus::Unavailable, (*reason).to_owned()),
        Ok(bytes) => {
            let embedded = sig::parse_sig_marker(NZ_SIG_MARKER);
            let found = sig::parse_sig_marker(bytes);
            let anchor_cmp = anchor.unwrap_or("");
            match (embedded, found) {
                (Some(e), Some(f)) => {
                    if marker_matches_runtime(&e, identity, commit, build_time, anchor_cmp)
                        && marker_matches_runtime(&f, identity, commit, build_time, anchor_cmp)
                    {
                        (
                            DepthStatus::Pass,
                            "the image marker matches the compile-time stamps".to_owned(),
                        )
                    } else {
                        (
                            DepthStatus::Refused,
                            "the image marker disagrees with the compile-time stamps".to_owned(),
                        )
                    }
                }
                (Some(_), None) => (
                    DepthStatus::Refused,
                    "the running image carries no intact ZJNS1 marker - stripped, rebuilt, or tampered"
                        .to_owned(),
                ),
                (None, _) => (
                    DepthStatus::Refused,
                    "the embedded marker does not parse - corrupted or rebuilt without the estate build"
                        .to_owned(),
                ),
            }
        }
    };
    let rows = push_row(rows, "D1", "embedded-marker", d1);

    // D2 - the anchor integrity. The runtime recomputes the anchor
    // over the shared payload from its own stamped facts; a mismatch
    // means the facts were edited after the anchor was computed (the
    // fake-claim arm), an empty anchor means the estate build script
    // never ran.
    let d2 = match anchor {
        None => (
            DepthStatus::Refused,
            "the anchor is unstamped - a build outside the estate build script".to_owned(),
        ),
        Some(stamped) => {
            let recomputed = blake3::blake3_hex(sig::sig_payload(commit, build_time).as_bytes());
            if recomputed == stamped {
                (
                    DepthStatus::Pass,
                    "blake3 recomputes the anchor from the payload".to_owned(),
                )
            } else {
                (
                    DepthStatus::Refused,
                    "the payload does not recompute the anchor - tampered or fake build".to_owned(),
                )
            }
        }
    };
    let rows = push_row(rows, "D2", "anchor-integrity", d2);

    // D3 - the binary self-hash. The fact a verifier pins: the same
    // BLAKE3 family as the release checksum files, over the exact
    // bytes this process runs from.
    let mut binary_self_hash = None;
    let d3 = match image {
        Err(reason) => (DepthStatus::Unavailable, (*reason).to_owned()),
        Ok(bytes) => {
            let hash = blake3::blake3_hex(&bytes);
            binary_self_hash = Some(hash.clone());
            (DepthStatus::Pass, format!("b3:{hash}"))
        }
    };
    let rows = push_row(rows, "D3", "binary-self-hash", d3);

    let refused = rows.iter().find_map(|row| match row.status {
        DepthStatus::Refused => Some((row.id, row.detail.clone())),
        _ => None,
    });
    let unavailable_ids: Vec<&'static str> = rows
        .iter()
        .filter(|row| row.status == DepthStatus::Unavailable)
        .map(|row| row.id)
        .collect();
    let verified = rows
        .iter()
        .filter(|row| row.status == DepthStatus::Pass)
        .count();

    SigMatrix {
        rows,
        identity,
        commit: commit.to_owned(),
        build_time: build_time.to_owned(),
        anchor,
        binary_self_hash,
        refused,
        unavailable_ids,
        verified,
    }
}

fn push_row(
    rows: Vec<DepthRow>,
    id: &'static str,
    name: &'static str,
    (status, detail): (DepthStatus, String),
) -> Vec<DepthRow> {
    let mut rows = rows;
    rows.push(DepthRow {
        id,
        name,
        status,
        detail,
    });
    rows
}

impl SigMatrix {
    /// The verdict line's tail: AUTHENTIC with the verified count
    /// (naming the unavailable depths when the image lane cannot run
    /// here), or REFUSED naming the first contradicting depth.
    pub(crate) fn verdict_text(&self) -> String {
        match &self.refused {
            Some((id, reason)) => {
                let name = self
                    .rows
                    .iter()
                    .find(|row| row.id == *id)
                    .map(|row| row.name)
                    .unwrap_or("unknown");
                format!("SIGNATURE: REFUSED ({id} {name} — {reason})")
            }
            None => {
                let mut line = format!("SIGNATURE: AUTHENTIC ({}/4 depths verified", self.verified);
                if !self.unavailable_ids.is_empty() {
                    line.push_str(&format!(
                        "; {} unavailable on this host",
                        self.unavailable_ids.join(", ")
                    ));
                }
                line.push(')');
                line
            }
        }
    }

    /// True when every depth that could run here verified and none
    /// refused. The sig surface maps this to the exit code.
    pub(crate) fn is_authentic(&self) -> bool {
        self.refused.is_none()
    }
}

/// The human matrix. Byte-deterministic: fixed row labels, fixed
/// padding, the facts block, and the verdict as the last line.
pub(crate) fn matrix_report(matrix: &SigMatrix) -> String {
    let mut out = crate::output::banner("zejtron signature — depth matrix");
    out.push('\n');
    for row in &matrix.rows {
        out.push_str(&format!("{:<21}", format!("{} {}", row.id, row.name)));
        out.push_str(&format!("{} — {}\n", row.status.word(), row.detail));
    }
    out.push('\n');
    out.push_str(&format!("{:<12}{}\n", "identity", matrix.identity));
    out.push_str(&format!("{:<12}{}\n", "commit", matrix.commit));
    out.push_str(&format!("{:<12}{}\n", "build-time", matrix.build_time));
    let anchor_text = match matrix.anchor {
        Some(anchor) => format!("b3:{anchor}"),
        None => "unstamped".to_owned(),
    };
    out.push_str(&format!("{:<12}{}\n", "anchor", anchor_text));
    out.push('\n');
    out.push_str(&format!("verdict: {}", matrix.verdict_text()));
    out
}

/// The one-line JSON lane (the universal JSON law: the text matrix's
/// facts, one typed line, hand-written serializer - the runtime graph
/// stays at three crates). Absent facts ride JSON null, never an
/// empty string.
pub(crate) fn matrix_json(matrix: &SigMatrix) -> String {
    use crate::evidence::json::{write_opt_string, write_string};
    let mut out = String::with_capacity(1024);
    out.push_str("{\"identity\":");
    write_string(&mut out, matrix.identity);
    out.push_str(",\"commit\":");
    write_string(&mut out, &matrix.commit);
    out.push_str(",\"build_time\":");
    write_string(&mut out, &matrix.build_time);
    out.push_str(",\"payload_tag\":");
    write_string(&mut out, sig::SIG_PAYLOAD_TAG);
    out.push_str(",\"anchor\":");
    write_opt_string(&mut out, matrix.anchor);
    out.push_str(",\"binary_self_hash\":");
    match &matrix.binary_self_hash {
        Some(hash) => write_string(&mut out, hash),
        None => out.push_str("null"),
    }
    out.push_str(",\"depths\":[");
    for (index, row) in matrix.rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"depth\":");
        write_string(&mut out, row.id);
        out.push_str(",\"name\":");
        write_string(&mut out, row.name);
        out.push_str(",\"status\":");
        write_string(&mut out, row.status.word());
        out.push_str(",\"detail\":");
        write_string(&mut out, &row.detail);
        out.push('}');
    }
    out.push_str("],\"verdict\":");
    write_string(
        &mut out,
        if matrix.is_authentic() {
            "AUTHENTIC"
        } else {
            "REFUSED"
        },
    );
    out.push_str(",\"verified\":");
    write_string(&mut out, &format!("{}/4", matrix.verified));
    out.push('}');
    out
}

#[cfg(test)]
#[path = "../../test/info/signature_tests.rs"]
mod tests;
