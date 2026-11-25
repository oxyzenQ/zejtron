// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! Pins for the depth-matrix signature (night-signature-1, the masked
//! night-signature-advanced-1 upgrade). The module is #[path]-wired
//! from src/info/signature.rs, so `super::` reaches the engine exactly
//! like the sibling test files do; the masked layers live one door
//! over at [`crate::info::provenance`]. The cargo-test binary is
//! itself a build.rs-driven build, so the suite verifies the test
//! binary's OWN signature end to end.
//!
//! The oracle literals below are the exact plaintext truths the masked
//! words must materialize. They live ONLY in the test build - they are
//! the one legitimate plaintext carrier in the suite, because a test
//! that cannot name its expected output proves nothing. cfg(test) is
//! stripped from the release artifact.

use super::*;
use crate::info::provenance;

// The oracle literals ride pub(crate): the render-surface sibling
// (signature_render_tests.rs, the two-sibling module shape) imports
// them instead of restating them - one oracle source, zero drift.
/// The manifest layer's plaintext truth (the generator's MANIFEST,
/// night-ux-orion-3: the year tail left the claim - 41 bytes).
pub(crate) const MANIFEST_ORACLE: &str = "Official Build by rezky_nightky (oxyzenQ)";
/// The authors layer's plaintext truth (the generator's AUTHORS).
pub(crate) const AUTHORS_ORACLE: &str = "rezky_nightky (oxyzenQ) <oxyzenQ@proton.me>";
/// Generator cross-check values (scripts/release/
/// generate-provenance-words.py prints them). If these diverge from
/// the const eval, the generator and the Rust mirror have drifted.
pub(crate) const MANIFEST_FINGERPRINT_ORACLE: u64 = 0x7E9F_F677_AAC0_6508;
const AUTHORS_FINGERPRINT_ORACLE: u64 = 0x6677_1E5F_273B_9CAE;
/// The generator's printed anchor cross-check (blake3 over the framed
/// payload). The Python mirror and the estate's std-only BLAKE3 were
/// proven byte-identical on this value at integration time.
pub(crate) const DEPTH_ANCHOR_HEX_ORACLE: &str =
    "239ea10bff2d93384177924255d6fb4642707873c9da6a4a05f7e5bff8a2b1a5";

/// The manifest layer materializes to its oracle.
#[test]
fn manifest_layer_materializes_to_the_oracle() {
    let view = provenance::provenance_view();
    assert_eq!(view.manifest, MANIFEST_ORACLE);
    assert_eq!(view.identity, "rezky_nightky (oxyzenQ)");
    assert!(view.identity_shape_ok);
}

/// The authors layer materializes to its oracle, and the contact
/// fact rides out of it: the address after the identity core, the
/// bracket form stripped (night-remake-2).
#[test]
fn authors_layer_materializes_to_the_oracle() {
    let view = provenance::provenance_view();
    assert_eq!(view.authors, AUTHORS_ORACLE);
    assert_eq!(view.contact, "oxyzenQ@proton.me");
}

/// The at-rest invisibility contract, pinned mechanically:
/// strings(1) reports runs of four or more printable ASCII bytes.
/// Every byte of every masked word (both layers) must stay below
/// that floor, so a thief's grep over the artifact finds nothing.
#[test]
fn masked_words_are_strings_invisible() {
    let manifest_words = [
        0xE59B1C1BDA3108F2u64,
        0xC90A33081BCF84E1,
        0x13A79DF58DB876EE,
        0xFF6CFBC5F57230BE,
        0xF58451DB56EACEF4,
        0xD07E63E3FC073D34,
    ];
    let authors_words = [
        0x2A7EFE86C8EAB911u64,
        0x86FB41B2039A978D,
        0xC993BBE0C57ED58B,
        0xAAEBE032E1A10655u64,
        0x4CBBC30342076BF3,
        0xCD36A7F499287BD5,
    ];
    // The words above are the generator's committed output; the pin
    // walks their little-endian bytes exactly as the artifact's
    // rodata carries them.
    for words in [&manifest_words[..], &authors_words[..]] {
        for word in words {
            let bytes = word.to_le_bytes();
            let mut run = 0usize;
            for byte in bytes {
                if (0x20..=0x7E).contains(&byte) {
                    run += 1;
                    assert!(run < 4, "masked word {word:#x} leaks an ASCII run");
                } else {
                    run = 0;
                }
            }
        }
    }
}

/// The generator's printed cross-check values must equal the Rust
/// const eval - otherwise the Python mask mirror and the Rust const
/// mirror have drifted and the block is corrupt.
#[test]
fn const_fingerprints_match_generator_oracles() {
    assert_eq!(
        provenance::manifest_fingerprint(),
        MANIFEST_FINGERPRINT_ORACLE
    );
    assert_eq!(
        provenance::authors_fingerprint(),
        AUTHORS_FINGERPRINT_ORACLE
    );
}

/// The embedded anchor equals the generator's printed cross-check
/// value: the paste is the value the Python mirror computed.
#[test]
fn depth_anchor_matches_generator_oracle() {
    let anchor_hex = {
        let mut hex = String::with_capacity(64);
        for byte in provenance::DEPTH_ANCHOR {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    };
    assert_eq!(anchor_hex, DEPTH_ANCHOR_HEX_ORACLE);
}

/// The runtime recompute over the materialized bytes equals the
/// embedded anchor on a pristine build - the anchor layer passes.
#[test]
fn depth_anchor_matches_runtime_blake3() {
    let view = provenance::provenance_view();
    assert!(view.anchor_ok, "pristine build recomputes the anchor");
    assert_eq!(view.anchor_hex, DEPTH_ANCHOR_HEX_ORACLE);
}

/// The anchor payload framing is exact: domain tag, then
/// length-prefixed layers. Pinned against the real layer lengths
/// (41 manifest + 43 authors, night-ux-orion-3's year-free claim).
#[test]
fn anchor_payload_framing_shape_is_exact() {
    // The framing is private to the provenance module; the view's
    // anchor_ok already proves the recompute over the framed bytes,
    // so this pin checks the observable contract: the domain tag is
    // ASCII, the layer lengths are the generator's, and the total
    // payload length matches the framing arithmetic.
    assert_eq!(
        std::str::from_utf8(provenance::ANCHOR_DOMAIN).expect("ascii domain"),
        "zejtron/depth-matrix/v1"
    );
    assert_eq!(provenance::ANCHOR_DOMAIN.len(), 23);
    let expected_len = provenance::ANCHOR_DOMAIN.len()
        + 8
        + provenance::MANIFEST_BYTE_LEN
        + 8
        + provenance::AUTHORS_BYTE_LEN;
    assert_eq!(expected_len, 123);
}

/// Post-compile patching simulation at the verification level: the
/// three verification thirds are independent facts on the view, and
/// the status line flips to tampered when any third breaks. A pristine
/// build reports all three.
#[test]
fn pristine_view_verifies_all_three_thirds() {
    let view = provenance::provenance_view();
    assert!(view.fingerprints_ok, "the fingerprint fold agrees");
    assert!(view.binding_ok, "the layers bind coherently");
    assert!(view.anchor_ok, "the anchor recomputes");
    assert!(
        view.fingerprints_ok && view.binding_ok && view.anchor_ok,
        "the depth line reports verified"
    );
}

/// The Depth-matrix line's shape: fp= token (16 lowercase hex), the
/// verified status, the full b3: anchor, the layers token that
/// describes the masked + anchored scheme, and the runtime-depth
/// hint that rides AFTER the layers (night-hit-2: the line itself
/// proves only the artifact-byte depths; d4/d5 verify at runtime via
/// `sig`).
#[test]
fn depth_line_shape_is_stable() {
    let view = provenance::provenance_view();
    let depth = &view.depth_line;
    assert!(
        depth.starts_with("Depth-matrix: fp="),
        "depth line shape: {depth}"
    );
    assert!(
        depth.contains(" status=verified "),
        "pristine build reports verified"
    );
    assert!(
        depth.contains(
            "layers=d0:masked-words,d1:masked-words,d2:dual-fingerprint,d3:blake3-anchor"
        ),
        "layers token describes the masked + anchored scheme"
    );
    assert!(
        depth.ends_with(" (runtime depths; d4/d5 ride zejtron sig)"),
        "the runtime-depth hint rides after the layers: {depth}"
    );
    let anchor_token = depth
        .split(" anchor=b3:")
        .nth(1)
        .and_then(|tail| tail.split(" layers=").next())
        .expect("anchor token present");
    assert_eq!(anchor_token, DEPTH_ANCHOR_HEX_ORACLE);
    let fp = depth
        .split(" status=")
        .next()
        .and_then(|head| head.strip_prefix("Depth-matrix: fp="))
        .expect("fp= token present");
    assert_eq!(fp.len(), 16);
    assert!(
        fp.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

/// The identity binding's extraction law: the core is everything
/// after the marker; a manifest that lost the marker is a tampering
/// signal, and a rebranded manifest no longer binds the authors
/// layer. Since night-ux-orion-3 the claim carries no year tail, so
/// the extraction strips nothing.
#[test]
fn identity_core_extraction_law() {
    // The pristine view: the core IS the display (night-remake-2
    // unified display and coherence; orion-3 removed the year tail
    // from the claim bytes), and the core binds the authors prefix.
    let view = provenance::provenance_view();
    assert_eq!(view.identity, "rezky_nightky (oxyzenQ)");
    assert!(AUTHORS_ORACLE.starts_with("rezky_nightky (oxyzenQ)"));
    assert_eq!(view.contact, "oxyzenQ@proton.me");
    // The rebrand arm lives in the provenance module's private
    // extraction; the observable contract is the D1 row's direction,
    // pinned through collect() below and the view's binding flag.
    assert!(view.binding_ok);
}

/// night-ux-orion-3, the owner's year-format law pinned at every
/// rendered surface: years ride at the front (the Copyright line's
/// range), never glued behind the holder. The -V body, the sig text
/// report, and the sig JSON line must carry no ") 2026" tail
/// anywhere.
#[test]
fn year_tail_never_renders_behind_the_holder() {
    let body = crate::info::version_body();
    assert!(
        !body.contains(") 2026"),
        "-V must not render a year behind the holder"
    );
    let matrix = collect();
    let report = matrix_report(&matrix);
    assert!(
        !report.contains(") 2026"),
        "the sig report must not render a year behind the holder"
    );
    let json = matrix_json(&matrix);
    assert!(
        !json.contains(") 2026"),
        "the sig JSON line must not render a year behind the holder"
    );
}

/// The collected matrix on a linux host: the rows ride in D0..D5
/// order, the image hash is present, and the verdict is the build's
/// own truth. The test binary verifies itself - the D4 row is the
/// real self-check: the test binary's own build stamped the digest
/// over the same object bytes it embedded, so a patched camera fails
/// every suite lane that builds the crate.
///
/// The D5 honesty law (night-netrunner-Z1, the zelynic
/// night-solid-defense-2 precedent; the class split is night-hit-2):
/// the commit-signature row reports the BUILD's own verified verdict,
/// so a tree on a HEAD signed by the pinned maintainer key reads
/// AUTHENTIC 6/6 and a tree on an unsigned HEAD (a plain dev commit,
/// a CI lane) reads UNSIGNED 5/6 - a missing provenance link, not a
/// modification, exit 1 unchanged. Both are the pristine truth for
/// their build, and the matrix must never claim otherwise.
#[test]
#[cfg(target_os = "linux")]
fn collect_verifies_the_running_test_binary_authentic() {
    let matrix = collect();
    let ids: Vec<&str> = matrix.rows.iter().map(|row| row.id).collect();
    assert_eq!(ids, vec!["D0", "D1", "D2", "D3", "D4", "D5"]);
    // The depths before D5 never refuse on a pristine build; D5
    // rides the build's own commit-signature truth.
    let stamp = crate::info::vcs_commit_sig();
    let sig_verified = stamp
        .strip_prefix("verified:")
        .is_some_and(|fpr| fpr == crate::info::commit_sig::PINNED_MAINTAINER_KEY_FPR);
    if sig_verified {
        assert!(matrix.refused.is_none(), "no depth may refuse: {matrix:?}");
        assert!(matrix.is_authentic());
        for row in &matrix.rows {
            assert_eq!(row.status, DepthStatus::Pass, "row {} refused", row.id);
        }
        assert_eq!(matrix.verified, 6);
        assert_eq!(
            matrix.verdict_text(),
            "SIGNATURE: AUTHENTIC (6/6 depths verified)"
        );
    } else {
        // The honesty arm (night-hit-2): the lone-unsigned-D5 shape
        // reads the UNSIGNED class - the integrity depths above all
        // verify, so the verdict names the missing provenance link,
        // never tampering, and the exit law stays 1.
        assert_eq!(matrix.refused.as_ref().map(|(id, _)| *id), Some("D5"));
        assert!(!matrix.is_authentic());
        assert_eq!(matrix.verdict, SigVerdict::Unsigned);
        assert_eq!(matrix.verified, 5, "D0-D4 verify regardless: {matrix:?}");
        assert_eq!(
            matrix.verdict_text(),
            "SIGNATURE: UNSIGNED (5/6 depths verified)"
        );
        // The report carries the class's own note, named.
        let report = matrix_report(&matrix);
        assert!(
            report.contains("a missing provenance link, not a"),
            "the unsigned note rides the report: {report}"
        );
    }
    assert_eq!(matrix.identity, "rezky_nightky (oxyzenQ)");
    assert_eq!(matrix.contact, "oxyzenQ@proton.me");
    assert_eq!(matrix.authors, AUTHORS_ORACLE);
    assert_eq!(matrix.fingerprint, MANIFEST_FINGERPRINT_ORACLE);
    assert_eq!(matrix.anchor, DEPTH_ANCHOR_HEX_ORACLE);
    let hash = matrix
        .binary_self_hash
        .as_ref()
        .expect("the image lane is available on linux");
    assert_eq!(hash.len(), 64);
    assert_eq!(matrix.commit, super::super::build_hash());
    assert_eq!(matrix.build_time, super::super::build_time());
}

// ── night-frontier-Z5, the D4 camera-object pins ─────────────────────

/// The pristine build's real self-check: the stamp the test binary's
/// own build.rs produced recomputes from the very PROBE_ELF bytes the
/// binary carries. A build whose object was patched after staging
/// fails HERE, in every lane that compiles the crate.
#[test]
fn the_embedded_camera_object_recomputes_the_build_stamp() {
    // env!, not option_env!.expect(): the lint-clippy law - and the
    // honest shape, since a test binary of this tree cannot exist
    // without the stamp (the build.rs lanes always produce it).
    let stamped = env!("ZEJTRON_CAMERA_OBJECT_B3");
    let (status, detail) = camera_object_row(Some(stamped), crate::ebpf::camera_object::PROBE_ELF);
    assert_eq!(status, DepthStatus::Pass, "{detail}");
    assert!(
        detail.contains("recomputes from the embedded probe object"),
        "{detail}"
    );
    assert!(detail.starts_with("b3:"), "{detail}");
}

/// The tamper arm, through the real verify path: one flipped byte in
/// the embedded object must refuse, naming BOTH digests - the
/// recomputed one and the stamped one.
#[test]
fn a_patched_camera_object_refuses_naming_both_digests() {
    let stamped = "e642ace8b8e9a3f549434d21c45413688fc6e3ec3afb7292f078cd0850f996ec";
    let mut patched = crate::ebpf::camera_object::PROBE_ELF.to_vec();
    let middle = patched.len() / 2;
    patched[middle] ^= 0x01;
    let (status, detail) = camera_object_row(Some(stamped), &patched);
    assert_eq!(status, DepthStatus::Refused, "{detail}");
    assert!(detail.contains("hashes to b3:"), "{detail}");
    assert!(detail.contains(stamped), "{detail}");
    assert!(detail.contains("patched after the build"), "{detail}");
}

/// The absence arm: a build without the stamp (an older build.rs) is
/// unavailable with the reason named - never a guess, never a pass.
#[test]
fn a_build_without_the_stamp_names_the_unavailability() {
    let (status, detail) = camera_object_row(None, crate::ebpf::camera_object::PROBE_ELF);
    assert_eq!(status, DepthStatus::Unavailable, "{detail}");
    assert!(
        detail.contains("did not stamp the camera object digest"),
        "{detail}"
    );
}
