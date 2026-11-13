// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The depth-matrix signature (night-signature-1, the masked
//! night-signature-advanced-1 upgrade): the binary's own anti-theft /
//! anti-fake-claim verification. The estate already states its
//! identity (the -V `Copyright:` line, the trademark and licensing
//! layers); this module makes the claim CHECKABLE, at four depths, by
//! the binary itself and by anyone holding the artifact:
//!
//! - **D0 runtime identity** - the masked manifest materializes to
//!   the owner's claim, `rezky_nightky (oxyzenQ) 2026` (see
//!   [`super::provenance`]); at rest the claim exists only as opaque
//!   masked words, so a grep over the artifact finds nothing.
//! - **D1 embedded marker** - the masked authors layer materializes
//!   and binds to the manifest identity (the coherent-pair check):
//!   two independent encodings of one identity, patching one still
//!   leaves the other reconstructing the owner.
//! - **D2 anchor integrity** - the runtime recomputes the BLAKE3
//!   anchor over the framed masked payload and the FNV-64
//!   fingerprints over both layers; any mismatch - a hand-patched
//!   -V line, a patched word, an incoherent layer pair - breaks the
//!   chain and the verdict refuses by name.
//! - **D3 binary self-hash** - BLAKE3 over the running image
//!   (`/proc/self/exe`), b3sum-verifiable outside the binary: the
//!   owner pins one hash per release and any hacked or rebuilt
//!   artifact answers for the bytes it actually carries.
//!
//! The honesty law runs through every depth: an unverifiable depth is
//! `unavailable` with the reason named, a contradicting depth is
//! `refused`, and the verdict never claims more than it proved.

use super::provenance;

// The estate's std-only BLAKE3, included once in the provenance
// module; the D3 self-hash reaches it through there.
use provenance::blake3;

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

/// The collected matrix - the data both renderers speak. The identity
/// facts ride the materialized masked layers (one unmask pass per
/// call site; see the provenance module's single-pass invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigMatrix {
    pub rows: Vec<DepthRow>,
    /// The owner's claim as the manifest materializes it.
    pub identity: String,
    /// The authors string as the masked layer materializes it.
    pub authors: String,
    /// The embedded manifest fingerprint (the `fp=` value).
    pub fingerprint: u64,
    pub commit: String,
    pub build_time: String,
    /// The runtime-recomputed anchor hex (equals the embedded
    /// `DEPTH_ANCHOR` exactly when the layers verify).
    pub anchor: String,
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

/// Collect the four depths from this running binary. One unmask pass
/// (inside the provenance view) feeds D0, D1, and D2; one image read
/// feeds D3.
pub(crate) fn collect() -> SigMatrix {
    let view = provenance::provenance_view();
    let commit = super::build_hash();
    let build_time = super::build_time();

    // D0 - the runtime identity surface. The masked manifest
    // materialized and still carries the marker/year shape; the row
    // renders the owner claim it reconstructs.
    let d0 = if view.identity_shape_ok {
        (DepthStatus::Pass, view.identity.clone())
    } else {
        (
            DepthStatus::Refused,
            "the manifest no longer carries the identity shape - tampered".to_owned(),
        )
    };
    let rows = vec![DepthRow {
        id: "D0",
        name: "runtime-identity",
        status: d0.0,
        detail: d0.1,
    }];

    // D1 - the embedded marker. The masked authors layer materialized
    // and binds to the manifest identity: two independent encodings
    // of one identity must agree, so a single-layer rebrand refuses
    // by name.
    let d1 = if view.binding_ok {
        (
            DepthStatus::Pass,
            "the masked authors layer binds to the manifest identity".to_owned(),
        )
    } else {
        (
            DepthStatus::Refused,
            "the authors layer does not bind to the manifest identity - incoherent rebrand"
                .to_owned(),
        )
    };
    let rows = push_row(rows, "D1", "embedded-marker", d1);

    // D2 - the anchor integrity. The runtime recomputes the anchor
    // over the framed masked payload from the SAME bytes the rows
    // display (the single-pass invariant); a mismatch means the layers
    // were edited after the anchor was embedded (the fake-claim arm).
    let d2 = if view.anchor_ok {
        (
            DepthStatus::Pass,
            format!("b3:{} recomputes from the masked payload", view.anchor_hex),
        )
    } else if view.fingerprints_ok {
        (
            DepthStatus::Refused,
            "the masked payload does not recompute the anchor - tampered or fake build".to_owned(),
        )
    } else {
        (
            DepthStatus::Refused,
            "the fingerprint fold disagrees with the compile-time digests - the masked layers are tampered"
                .to_owned(),
        )
    };
    let rows = push_row(rows, "D2", "anchor-integrity", d2);

    // D3 - the binary self-hash. The fact a verifier pins: the same
    // BLAKE3 family as the release checksum files, over the exact
    // bytes this process runs from.
    let mut binary_self_hash = None;
    let d3 = match read_self_image() {
        Err(reason) => (DepthStatus::Unavailable, reason.to_owned()),
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
        identity: view.identity,
        authors: view.authors,
        fingerprint: provenance::manifest_fingerprint(),
        commit: commit.to_owned(),
        build_time: build_time.to_owned(),
        anchor: view.anchor_hex,
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
/// padding, the facts block, and the verdict plus the self-hash note
/// as the closing lines.
pub(crate) fn matrix_report(matrix: &SigMatrix) -> String {
    let mut out = crate::output::banner("zejtron signature — depth matrix");
    out.push('\n');
    for row in &matrix.rows {
        out.push_str(&format!("{:<21}", format!("{} {}", row.id, row.name)));
        out.push_str(&format!("{} — {}\n", row.status.word(), row.detail));
    }
    out.push('\n');
    out.push_str(&format!("{:<12}{}\n", "identity", matrix.identity));
    out.push_str(&format!(
        "{:<12}fp={:016x} (fnv1a64, dual-layer)\n",
        "fingerprint", matrix.fingerprint
    ));
    out.push_str(&format!("{:<12}b3:{}\n", "anchor", matrix.anchor));
    out.push_str(&format!("{:<12}{}\n", "commit", matrix.commit));
    out.push_str(&format!("{:<12}{}\n", "build-time", matrix.build_time));
    out.push('\n');
    out.push_str(&format!("verdict: {}", matrix.verdict_text()));
    out.push('\n');
    out.push_str("note: the self-hash is a fingerprint to compare against a\n");
    out.push_str("published release hash; it cannot embed its own digest.\n");
    let trimmed = out.trim_end_matches('\n');
    trimmed.to_owned()
}

/// The one-line JSON lane (the universal JSON law: the text matrix's
/// facts, one typed line, hand-written serializer - the runtime graph
/// stays at three crates). Absent facts ride JSON null, never an
/// empty string.
pub(crate) fn matrix_json(matrix: &SigMatrix) -> String {
    use crate::evidence::json::write_string;
    let mut out = String::with_capacity(1024);
    out.push_str("{\"identity\":");
    write_string(&mut out, &matrix.identity);
    out.push_str(",\"authors\":");
    write_string(&mut out, &matrix.authors);
    out.push_str(",\"commit\":");
    write_string(&mut out, &matrix.commit);
    out.push_str(",\"build_time\":");
    write_string(&mut out, &matrix.build_time);
    out.push_str(",\"payload_tag\":");
    write_string(
        &mut out,
        std::str::from_utf8(provenance::ANCHOR_DOMAIN).unwrap_or(""),
    );
    out.push_str(",\"fingerprint\":");
    write_string(&mut out, &format!("{:016x}", matrix.fingerprint));
    out.push_str(",\"anchor\":");
    write_string(&mut out, &matrix.anchor);
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
