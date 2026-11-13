// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the depth-matrix signature (night-signature-1). The
//! module is #[path]-wired from src/info/signature.rs, so `super::`
//! reaches the engine exactly like the sibling test files do. The
//! cargo-test binary is itself a build.rs-driven build, so the
//! stamped arms execute for real here - the suite verifies the test
//! binary's OWN signature end to end.

use super::*;

/// A well-formed 64-hex anchor shape for the synthesized matrices (a
/// const, not a leaked String - the Miri leak detector's law).
const TEST_ANCHOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The identity claim is the owner's text, verbatim - D0's fact, the
/// Depth-sig line's lead, and the marker's first field.
#[test]
fn identity_is_the_owner_claim_verbatim() {
    assert_eq!(sig::SIG_IDENTITY, "rezky_nightky (oxyzenQ) 2026");
}

/// The Depth-sig line's stamped arm: identity claim, then the anchor
/// as 64 lowercase hex behind the `b3:` marker. The unstamped arm
/// rides the contiguous guard literal (the claims discipline).
#[test]
fn depth_sig_line_shape_is_pinned() {
    let line = depth_sig_line();
    match option_env!("ZEJTRON_SIG_ANCHOR") {
        Some(anchor) if !anchor.is_empty() => {
            assert_eq!(
                line,
                format!("Depth-sig: {} b3:{anchor}", sig::SIG_IDENTITY)
            );
            let hex = line.rsplit("b3:").next().expect("the b3: tail");
            assert_eq!(hex.len(), 64, "the anchor is 64 hex: {line}");
            assert!(
                hex.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "the anchor is lowercase hex: {line}"
            );
        }
        _ => {
            assert_eq!(
                line,
                "Depth-sig: unstamped — the anchor was never stamped (a build outside the estate build script)"
            );
        }
    }
}

/// The crown pin: the anchor stamped at build time recomputes from
/// exactly the values the -V report renders (commit, build-time) -
/// the external recipe in docs/VERIFY_RELEASE.md depends on this
/// equality, so the runtime suite holds it, not just the build lane.
#[test]
fn anchor_recomputes_from_the_report_visible_payload() {
    let Some(anchor) = option_env!("ZEJTRON_SIG_ANCHOR").filter(|a| !a.is_empty()) else {
        return; // unstamped build: the guard arm is pinned above
    };
    let recomputed = blake3::blake3_hex(
        sig::sig_payload(super::super::build_hash(), super::super::build_time()).as_bytes(),
    );
    assert_eq!(recomputed, anchor, "the payload must recompute the anchor");
}

/// The collected matrix on a linux host: all four depths pass, the
/// rows ride in D0..D3 order, the image hash is present, and the
/// verdict is the full 4/4 line. The test binary verifies itself.
#[test]
#[cfg(target_os = "linux")]
fn collect_verifies_the_running_test_binary_authentic() {
    let matrix = collect();
    assert!(matrix.refused.is_none(), "no depth may refuse: {matrix:?}");
    assert!(matrix.is_authentic());
    let ids: Vec<&str> = matrix.rows.iter().map(|row| row.id).collect();
    assert_eq!(ids, vec!["D0", "D1", "D2", "D3"]);
    for row in &matrix.rows {
        assert_eq!(row.status, DepthStatus::Pass, "row {} refused", row.id);
    }
    assert_eq!(matrix.verified, 4);
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: AUTHENTIC (4/4 depths verified)"
    );
    assert!(
        matrix.anchor.is_some(),
        "a cargo-test build is always stamped"
    );
    let hash = matrix
        .binary_self_hash
        .as_ref()
        .expect("the image lane is available on linux");
    assert_eq!(hash.len(), 64);
    assert_eq!(matrix.commit, super::super::build_hash());
    assert_eq!(matrix.build_time, super::super::build_time());
}

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
                detail: sig::SIG_IDENTITY.to_owned(),
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
                detail: "blake3 recomputes the anchor from the payload".to_owned(),
            },
            DepthRow {
                id: "D3",
                name: "binary-self-hash",
                status: DepthStatus::Unavailable,
                detail: "the running image could not be read".to_owned(),
            },
        ],
        identity: sig::SIG_IDENTITY,
        commit: "127c6ed".to_owned(),
        build_time: "11/13/2026 09:41 (UTC)".to_owned(),
        anchor: Some(TEST_ANCHOR),
        binary_self_hash: None,
        refused: None,
        unavailable_ids: vec!["D1", "D3"],
        verified: 2,
    };
    assert!(matrix.is_authentic());
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: AUTHENTIC (2/4 depths verified; D1, D3 unavailable on this host)"
    );
}

/// The refusal arm: the first contradicting depth names itself in the
/// verdict, and is_authentic flips the exit-code mapping in the sig
/// surface.
#[test]
fn verdict_text_names_the_refused_depth() {
    let matrix = SigMatrix {
        rows: vec![
            DepthRow {
                id: "D0",
                name: "runtime-identity",
                status: DepthStatus::Pass,
                detail: sig::SIG_IDENTITY.to_owned(),
            },
            DepthRow {
                id: "D1",
                name: "embedded-marker",
                status: DepthStatus::Pass,
                detail: "the image marker matches the compile-time stamps".to_owned(),
            },
            DepthRow {
                id: "D2",
                name: "anchor-integrity",
                status: DepthStatus::Refused,
                detail: "the payload does not recompute the anchor - tampered or fake build"
                    .to_owned(),
            },
            DepthRow {
                id: "D3",
                name: "binary-self-hash",
                status: DepthStatus::Pass,
                detail: "b3:9f8e7d6c".to_owned(),
            },
        ],
        identity: sig::SIG_IDENTITY,
        commit: "127c6ed".to_owned(),
        build_time: "11/13/2026 09:41 (UTC)".to_owned(),
        anchor: Some(TEST_ANCHOR),
        binary_self_hash: Some("9f8e7d6c".to_owned()),
        refused: Some((
            "D2",
            "the payload does not recompute the anchor - tampered or fake build".to_owned(),
        )),
        unavailable_ids: vec![],
        verified: 2,
    };
    assert!(!matrix.is_authentic());
    assert_eq!(
        matrix.verdict_text(),
        "SIGNATURE: REFUSED (D2 anchor-integrity — the payload does not recompute the anchor - tampered or fake build)"
    );
}

/// The human matrix's byte shape: the banner opens, the four rows
/// render with their labels, the facts block carries identity,
/// commit, build-time, anchor, and the verdict is the last line. The
/// harness captures stdout (the Mono lane), so the bytes are plain.
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
    ] {
        let count = lines.iter().filter(|l| l.starts_with(label)).count();
        assert_eq!(count, 1, "row label must appear exactly once: {label}");
    }
    assert!(!report.contains('\x1b'), "the mono render is plain bytes");
    assert!(report.contains("identity    rezky_nightky (oxyzenQ) 2026"));
    assert!(report.contains(&format!("commit      {}", matrix.commit)));
    assert!(report.contains(&format!("build-time  {}", matrix.build_time)));
    let anchor = matrix.anchor.expect("stamped build");
    assert!(report.contains(&format!("anchor      b3:{anchor}")));
    assert_eq!(
        *lines.last().expect("the verdict closes the matrix"),
        format!("verdict: {}", matrix.verdict_text())
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
        "\"identity\":",
        "\"commit\":",
        "\"build_time\":",
        "\"payload_tag\":\"ns1\"",
        "\"anchor\":\"",
        "\"binary_self_hash\":\"",
        "\"depths\":[",
        "\"verdict\":\"AUTHENTIC\"",
        "\"verified\":\"4/4\"",
    ] {
        assert!(json.contains(key), "the JSON lane must carry {key}: {json}");
    }
    assert_eq!(json.matches("\"depth\":").count(), 4);
    assert_eq!(json.matches("\"status\":\"pass\"").count(), 4);
}

/// The JSON lane's absence arm, synthesized: an unavailable image
/// lane rides null for binary_self_hash, and a REFUSED verdict is
/// spelled exactly so.
#[test]
fn matrix_json_absence_and_refusal_arms() {
    let mut matrix = SigMatrix {
        rows: vec![DepthRow {
            id: "D3",
            name: "binary-self-hash",
            status: DepthStatus::Unavailable,
            detail: "non-linux host".to_owned(),
        }],
        identity: sig::SIG_IDENTITY,
        commit: "127c6ed".to_owned(),
        build_time: "11/13/2026 09:41 (UTC)".to_owned(),
        anchor: None,
        binary_self_hash: None,
        refused: None,
        unavailable_ids: vec!["D3"],
        verified: 0,
    };
    let json = matrix_json(&matrix);
    assert!(json.contains("\"anchor\":null"));
    assert!(json.contains("\"binary_self_hash\":null"));
    matrix.refused = Some(("D2", "mismatch".to_owned()));
    assert!(matrix_json(&matrix).contains("\"verdict\":\"REFUSED\""));
}
