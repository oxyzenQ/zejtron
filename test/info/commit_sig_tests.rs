// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! Pins for the D5 commit-signature policy (night-netrunner-Z1, the
//! zelynic night-solid-defense-2 lineage). The module is
//! #[path]-wired from src/info/commit_sig.rs, so `super::` reaches
//! the policy exactly like the sibling test files do. Every verdict
//! class is pinnable WITHOUT a keyring: the policy is pure over the
//! build-time stamp, and the synthetic stamps below cover every
//! state the stamp grammar emits - the fail-closed law means the
//! arm list is the whole contract (anything unknown refuses).

use super::*;
use crate::info::signature::DepthStatus;

const PINNED: &str = PINNED_MAINTAINER_KEY_FPR;

/// The pin itself is load-bearing: a 40-hex fingerprint, and the
/// long id's tail matches the key asset the docs name (the same
/// value build/gpg.rs verifies against, one source of truth).
#[test]
fn the_pinned_fingerprint_is_the_documented_shape() {
    assert_eq!(PINNED.len(), 40, "a full OpenPGP fingerprint is 40 hex");
    assert!(
        PINNED.bytes().all(|b| b.is_ascii_hexdigit()),
        "hex only: {PINNED}"
    );
    assert!(
        PINNED.ends_with("47A50AEF4B65AAC2"),
        "the long id docs/VERIFY_RELEASE.md publishes: {PINNED}"
    );
}

#[test]
fn verified_by_the_pinned_key_passes_naming_the_key() {
    let (status, detail) = commit_signature_verdict(&format!("verified:{PINNED}"), "089badd");
    assert_eq!(status, DepthStatus::Pass, "{detail}");
    assert!(
        detail.contains("089badd") && detail.contains("47A50AEF4B65AAC2"),
        "names the commit and the key: {detail}"
    );
}

/// The signing-subkey world: gpg's VALIDSIG reports the SUBKEY when
/// a subkey signed; build/gpg.rs already resolves to the primary
/// before stamping, so a stamped fpr that is not the pinned primary
/// is a foreign signer - even a well-formed one.
#[test]
fn verified_by_a_foreign_fingerprint_refuses_by_name() {
    let foreign = "A".repeat(39) + "2";
    let (status, detail) = commit_signature_verdict(&format!("verified:{foreign}"), "089badd");
    assert_eq!(
        status,
        DepthStatus::Refused,
        "a foreign signer must refuse: {detail}"
    );
    assert!(
        detail.contains("NOT the pinned maintainer key"),
        "names the tamper shape: {detail}"
    );
}

#[test]
fn wrong_key_refuses_naming_both_keys() {
    let (status, detail) = commit_signature_verdict(
        "wrong-key:0123456789abcdef0123456789abcdef01234567",
        "ab12cd3",
    );
    assert_eq!(status, DepthStatus::Refused);
    assert!(
        detail.contains("89abcdef01234567"),
        "the foreign key: {detail}"
    );
    assert!(detail.contains("47A50AEF4B65AAC2"), "the pin: {detail}");
}

#[test]
fn no_key_with_evidence_names_the_foreign_signer() {
    let (status, detail) =
        commit_signature_verdict("no-key:0123456789abcdef0123456789abcdef01234567", "ab12cd3");
    assert_eq!(status, DepthStatus::Refused);
    assert!(detail.contains("signed by 0123456789abcdef0123456789abcdef01234567"));
    // The bare state (ERRSIG carried no full fpr) still refuses.
    let (status, _) = commit_signature_verdict("no-key", "ab12cd3");
    assert_eq!(status, DepthStatus::Refused);
}

#[test]
fn unsigned_refuses_as_the_incomplete_chain() {
    let (status, detail) = commit_signature_verdict("unsigned", "ab12cd3");
    assert_eq!(status, DepthStatus::Refused);
    assert!(
        detail.contains("NO GPG signature") && detail.contains("ab12cd3"),
        "the row states the gap: {detail}"
    );
}

/// The state word the matrix's verdict class reads (night-hit-2):
/// the pre-colon token, the whole stamp when no separator rides.
/// The verdict match and the class computation consume the same
/// words - this pin is the no-drift contract.
#[test]
fn commit_signature_state_names_the_stamp_state() {
    assert_eq!(commit_signature_state("unsigned"), "unsigned");
    assert_eq!(commit_signature_state("unsigned:6e0e3dd"), "unsigned");
    assert_eq!(
        commit_signature_state("verified:F5324E0967F104D58CE025F347A50AEF4B65AAC2"),
        "verified"
    );
    assert_eq!(commit_signature_state("wrong-key:ab12cd3"), "wrong-key");
    assert_eq!(commit_signature_state("bad-signature"), "bad-signature");
    assert_eq!(commit_signature_state("no-vcs"), "no-vcs");
    // An unknown grammar rides through as its own word - the
    // fail-closed verdict match, not the state fn, decides what it
    // means.
    assert_eq!(
        commit_signature_state("quantum-sealed:xyz"),
        "quantum-sealed"
    );
    assert_eq!(commit_signature_state("plain"), "plain");
}

#[test]
fn degraded_states_refuse_their_honest_sentences() {
    for stamp in ["bad-signature", "no-vcs", "unavailable", "unstamped", ""] {
        let (status, detail) = commit_signature_verdict(stamp, "ab12cd3");
        assert_eq!(status, DepthStatus::Refused, "{stamp} must refuse");
        assert!(!detail.is_empty(), "{stamp} must say why");
    }
}

/// The fail-closed law's own pin: a stamp grammar this binary does
/// not know (a future build.rs state) refuses, never a silent pass.
#[test]
fn an_unknown_stamp_state_refuses_fail_closed() {
    let (status, detail) = commit_signature_verdict("quantum-sealed", "ab12cd3");
    assert_eq!(status, DepthStatus::Refused);
    assert!(
        detail.contains("fail-closed"),
        "the unknown state names its law: {detail}"
    );
}

/// The live build's own row (the honest-truth twin, the zelynic
/// precedent): the D5 row reports the BUILD's own verified verdict,
/// so a tree on a signed HEAD reads Pass and a tree on an unsigned
/// HEAD reads Refused - both are the pristine truth for their
/// build, and the matrix must never claim otherwise.
#[test]
fn the_live_stamp_maps_to_its_honest_verdict() {
    let stamp = crate::info::vcs_commit_sig();
    let (status, detail) = commit_signature_verdict(stamp, "089badd");
    let verified = stamp
        .strip_prefix("verified:")
        .is_some_and(|fpr| fpr == PINNED_MAINTAINER_KEY_FPR);
    assert_eq!(
        status,
        if verified {
            DepthStatus::Pass
        } else {
            DepthStatus::Refused
        },
        "the stamp {stamp:?} must map honestly: {detail}"
    );
}
