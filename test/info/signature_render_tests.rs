// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The render-surface pins for the depth-matrix signature: the
//! verdict classes' arms (the hand-built matrices - Authentic,
//! Unsigned, Tampered, night-hit-2), the human matrix's byte shape,
//! and the JSON lane's keys and absence arms. The sibling of the
//! engine pins in signature_tests.rs - one module, two files (the
//! btf.rs two-sibling precedent), split at the render boundary when
//! the 600-line no-mercy gate drew the line.
//!
//! The oracle literals ride the engine sibling as pub(crate) consts
//! and are imported here - one oracle source, two consumers, zero
//! drift.

use super::*;
use super::tests::{AUTHORS_ORACLE, DEPTH_ANCHOR_HEX_ORACLE, MANIFEST_FINGERPRINT_ORACLE};

/// The verdict's honest-partial arm: unavailable depths are named in
/// the verdict line, the verified count drops, and the verdict stays
/// AUTHENTIC (an unavailable lane is named, not faked, never refused).
#[test]
fn verdict_text_names_the_unavailable_depths() {
    let matrix = SigMatrix {
        rows: vec![
            DepthRow {
                id: "D0",
                name: "runtime-identity",
                status: DepthStatus::Pass,
                detail: "rezky_nightky (oxyzenQ)".to_owned(),
            },
            DepthRow {
                id: "D1",
                name: "embedded-marker",
                status: DepthStatus::Unavailable,
                detail: "non-linux host".to_owned(),
            },
            DepthRow {
                id: "D2",
                name: "anchor-integrity",
                status: DepthStatus::Pass,
                detail: "b3:00 recomputes from the masked payload".to_owned(),
            },
            DepthRow {
                id: "D3",
                name: "binary-self-hash",
                status: DepthStatus::Unavailable,
                detail: "the running image could not be read".to_owned(),
            },
        ],
        identity: "rezky_nightky (oxyzenQ)".to_owned(),
        contact: "oxyzenQ@proton.me".to_owned(),
        authors: AUTHORS_ORACLE.to_owned(),
        fingerprint: MANIFEST_FINGERPRINT_ORACLE,
        commit: "127c6ed".to_owned(),
        build_time: "2026-11-13 09:41Z".to_owned(),
        anchor: DEPTH_ANCHOR_HEX_ORACLE.to_owned(),
        binary_self_hash: None,
        refused: None,
        verdict: SigVerdict::Authentic,
        unavailable_ids: vec!["D1", "D3"],
        verified: 2,
    };
    assert!(matrix.is_authentic());
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: AUTHENTIC (2/6 depths verified; D1, D3 unavailable on this host)"
    );
}

/// The tamper arm (night-hit-2): an integrity depth contradicted the
/// claim, so the verdict reads TAMPERED naming the first
/// contradicting depth, and is_authentic flips the exit-code mapping
/// in the sig surface.
#[test]
fn verdict_text_names_the_tampered_depth() {
    let matrix = SigMatrix {
        rows: vec![
            DepthRow {
                id: "D0",
                name: "runtime-identity",
                status: DepthStatus::Pass,
                detail: "rezky_nightky (oxyzenQ)".to_owned(),
            },
            DepthRow {
                id: "D1",
                name: "embedded-marker",
                status: DepthStatus::Pass,
                detail: "the masked authors layer binds to the manifest identity".to_owned(),
            },
            DepthRow {
                id: "D2",
                name: "anchor-integrity",
                status: DepthStatus::Refused,
                detail: "the masked payload does not recompute the anchor - tampered or fake build"
                    .to_owned(),
            },
            DepthRow {
                id: "D3",
                name: "binary-self-hash",
                status: DepthStatus::Pass,
                detail: "b3:9f8e7d6c".to_owned(),
            },
        ],
        identity: "rezky_nightky (oxyzenQ)".to_owned(),
        contact: "oxyzenQ@proton.me".to_owned(),
        authors: AUTHORS_ORACLE.to_owned(),
        fingerprint: MANIFEST_FINGERPRINT_ORACLE,
        commit: "127c6ed".to_owned(),
        build_time: "2026-11-13 09:41Z".to_owned(),
        anchor: DEPTH_ANCHOR_HEX_ORACLE.to_owned(),
        binary_self_hash: Some("9f8e7d6c".to_owned()),
        refused: Some((
            "D2",
            "the masked payload does not recompute the anchor - tampered or fake build".to_owned(),
        )),
        verdict: SigVerdict::Tampered,
        unavailable_ids: vec![],
        verified: 2,
    };
    assert!(!matrix.is_authentic());
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: TAMPERED (D2 anchor-integrity — the masked payload does not recompute the anchor - tampered or fake build)"
    );
}

/// The unsigned arm (night-hit-2, the zelynic night-dragon-fly-4
/// shape): the commit-signature depth is the ONE refusal and the
/// stamp state says `unsigned`, so the verdict reads UNSIGNED with
/// the verified count - a missing provenance link, not a
/// modification - and the report carries the class's own note while
/// the exit law stays 1.
#[test]
fn verdict_text_names_the_unsigned_class() {
    let matrix = SigMatrix {
        rows: vec![
            DepthRow {
                id: "D0",
                name: "runtime-identity",
                status: DepthStatus::Pass,
                detail: "rezky_nightky (oxyzenQ)".to_owned(),
            },
            DepthRow {
                id: "D5",
                name: "commit-signature",
                status: DepthStatus::Refused,
                detail: "commit 6e0e3dd carries NO GPG signature - the provenance \
                         chain stops at an unbound commit; bind releases to signed \
                         commits/tags"
                    .to_owned(),
            },
        ],
        identity: "rezky_nightky (oxyzenQ)".to_owned(),
        contact: "oxyzenQ@proton.me".to_owned(),
        authors: AUTHORS_ORACLE.to_owned(),
        fingerprint: MANIFEST_FINGERPRINT_ORACLE,
        commit: "6e0e3dd".to_owned(),
        build_time: "2026-11-25 14:33Z".to_owned(),
        anchor: DEPTH_ANCHOR_HEX_ORACLE.to_owned(),
        binary_self_hash: Some("b851fa50".to_owned()),
        refused: Some(("D5", "the unbound commit".to_owned())),
        verdict: SigVerdict::Unsigned,
        unavailable_ids: vec![],
        verified: 5,
    };
    assert!(!matrix.is_authentic());
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: UNSIGNED (5/6 depths verified)"
    );
    let report = matrix_report(&matrix);
    assert!(
        report.contains("a missing provenance link, not a"),
        "the unsigned note rides the report: {report}"
    );
    assert!(
        report.contains("releases"),
        "the note names the release law: {report}"
    );
}

/// The human matrix's byte shape: the banner opens, the four rows
/// render with their labels, the facts block carries identity,
/// fingerprint, anchor, commit, build-time, and the verdict plus the
/// self-hash note close the report. The harness captures stdout (the
/// Mono lane), so the bytes are plain.
#[test]
#[cfg(target_os = "linux")]
fn matrix_report_shape_is_pinned() {
    let matrix = collect();
    let report = matrix_report(&matrix);
    let lines: Vec<&str> = report.lines().collect();
    assert!(
        lines[0].contains("zejtron signature — depth matrix"),
        "the banner opens the matrix: {}",
        lines[0]
    );
    for label in [
        "D0 runtime-identity",
        "D1 embedded-marker",
        "D2 anchor-integrity",
        "D3 binary-self-hash",
        "D4 camera-object",
        "D5 commit-signature",
    ] {
        let count = lines.iter().filter(|l| l.starts_with(label)).count();
        assert_eq!(count, 1, "row label must appear exactly once: {label}");
    }
    assert!(!report.contains('\x1b'), "the mono render is plain bytes");
    assert!(report.contains("identity    rezky_nightky (oxyzenQ)\ncontact     oxyzenQ@proton.me"));
    assert!(report.contains(&format!(
        "fingerprint fp={:016x} (fnv1a64, dual-layer)",
        MANIFEST_FINGERPRINT_ORACLE
    )));
    assert!(report.contains(&format!("anchor      b3:{}", DEPTH_ANCHOR_HEX_ORACLE)));
    assert!(report.contains(&format!("commit      {}", matrix.commit)));
    assert!(report.contains(&format!("build-time  {}", matrix.build_time)));
    // The verdict rides the build's own D5 truth (the honesty law
    // pinned by collect_verifies_the_running_test_binary_authentic):
    // a signed HEAD renders AUTHENTIC 6/6, an unsigned HEAD renders
    // the UNSIGNED class with its note (night-hit-2: a missing
    // provenance link, not a modification) - both are the pristine
    // shape.
    if matrix.is_authentic() {
        assert!(report.contains("verdict: SIGNATURE: AUTHENTIC (6/6 depths verified)"));
    } else {
        assert!(report.contains("verdict: SIGNATURE: UNSIGNED (5/6 depths verified)"));
        assert!(
            report.contains("note: an unsigned commit is a missing provenance link, not a"),
            "the unsigned note rides the report"
        );
    }
    // The self-hash note closes the report (the honest-limits law).
    assert!(
        report.contains("note: the self-hash is a fingerprint to compare against a\npublished release hash; it cannot embed its own digest."),
        "the note block closes the matrix:\n{report}"
    );
}

/// The JSON lane: one line, the facts beside the depths array, the
/// verdict and the verified count closing it. The hash facts ride
/// JSON null when absent (the absence law), never empty strings.
#[test]
#[cfg(target_os = "linux")]
fn matrix_json_is_one_line_with_the_documented_keys() {
    let matrix = collect();
    let json = matrix_json(&matrix);
    assert!(!json.contains('\n'), "one line, jq-ready: {json}");
    for key in [
        "\"identity\":\"rezky_nightky (oxyzenQ)\"",
        "\"contact\":\"oxyzenQ@proton.me\"",
        "\"authors\":\"rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>\"",
        "\"commit\":",
        "\"build_time\":",
        "\"payload_tag\":\"zejtron/depth-matrix/v1\"",
        "\"fingerprint\":\"7e9ff677aac06508\"",
        "\"anchor\":\"",
        "\"binary_self_hash\":\"",
        "\"depths\":[",
        "\"verdict\":\"",
    ] {
        assert!(json.contains(key), "the JSON lane must carry {key}: {json}");
    }
    // Six depths always ride the array; the D5 row's status rides
    // the build's own commit-signature truth (the honesty law), so
    // the pass count and the verdict follow it.
    assert_eq!(json.matches("\"depth\":").count(), 6);
    let sig_verified = crate::info::vcs_commit_sig()
        .strip_prefix("verified:")
        .is_some_and(|fpr| fpr == crate::info::commit_sig::PINNED_MAINTAINER_KEY_FPR);
    if sig_verified {
        assert!(json.contains("\"verdict\":\"AUTHENTIC\""), "{json}");
        assert!(json.contains("\"verified\":\"6/6\""), "{json}");
        assert_eq!(json.matches("\"status\":\"pass\"").count(), 6);
    } else {
        assert!(json.contains("\"verdict\":\"UNSIGNED\""), "{json}");
        assert!(json.contains("\"verified\":\"5/6\""), "{json}");
        assert!(json.contains("\"depth\":\"D5\""), "{json}");
        assert_eq!(json.matches("\"status\":\"pass\"").count(), 5);
    }
}

/// The JSON lane's absence arm, synthesized: an unavailable image
/// lane rides null for binary_self_hash, and a TAMPERED verdict is
/// spelled exactly so.
#[test]
fn matrix_json_absence_and_tamper_arms() {
    let mut matrix = SigMatrix {
        rows: vec![DepthRow {
            id: "D3",
            name: "binary-self-hash",
            status: DepthStatus::Unavailable,
            detail: "non-linux host".to_owned(),
        }],
        identity: "rezky_nightky (oxyzenQ)".to_owned(),
        contact: String::new(),
        authors: AUTHORS_ORACLE.to_owned(),
        fingerprint: MANIFEST_FINGERPRINT_ORACLE,
        commit: "127c6ed".to_owned(),
        build_time: "2026-11-13 09:41Z".to_owned(),
        anchor: DEPTH_ANCHOR_HEX_ORACLE.to_owned(),
        binary_self_hash: None,
        refused: None,
        verdict: SigVerdict::Authentic,
        unavailable_ids: vec!["D3"],
        verified: 0,
    };
    let json = matrix_json(&matrix);
    assert!(json.contains("\"binary_self_hash\":null"));
    assert!(json.contains("\"contact\":null"));
    // The tamper arm: a contradicting depth flips the class to
    // TAMPERED, named in the one-line JSON.
    matrix.refused = Some(("D2", "mismatch".to_owned()));
    matrix.verdict = SigVerdict::Tampered;
    assert!(matrix_json(&matrix).contains("\"verdict\":\"TAMPERED\""));
}
