// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The D5 commit-signature policy (night-netrunner-Z1, ported from
//! the zelynic night-solid-defense-2 precedent): the runtime half of
//! the GPG commit binding, pure over the build-time stamp so every
//! verdict class is unit-testable without a keyring.
//!
//! The gap this row closes (the supply-chain hole the owner's
//! adversarial review named): D0-D2 prove the ownership claim, D3
//! fingerprints the whole image, D4 seals the embedded camera
//! object - but the `commit` line the matrix carries was a CLAIM,
//! not a bound fact. A binary swapped on the release channel
//! replays its own claims and the matrix had no row that could
//! disagree. D5 closes exactly that: build.rs verified the commit
//! the binary was built from against the PINNED maintainer public
//! key (the repo's own tracked copy, imported into an isolated
//! throwaway keyring - never the building user's), and this row
//! turns that verdict into the matrix's sixth depth. The
//! out-of-band twin: a consumer who verified the maintainer key
//! (keyservers, GitHub, docs/VERIFY_RELEASE.md) verifies the SIGNED
//! TAG the release was cut from, the tag names the commit, and D5
//! proves the binary really was built from a commit signed by that
//! same key - the chain from key to tag to commit to binary closes
//! with no channel left to MITM silently.
//!
//! The pinned fingerprint is the SAME file build/gpg.rs reads -
//! `include_str!` on both sides, one source of truth, zero drift
//! between the verifier and the reporter.
//!
//! Fail-closed is the row's law, deliberately stricter than the D4
//! missing-stamp precedent: D4's absent stamp maps the row to
//! `unavailable` (an old build's age signal - the sig report names
//! it, the exit stays 0), but D5's absent, unknown, or foreign
//! verdict is a refusal, because a supply-chain row that can pass
//! by saying nothing reopens the exact hole it exists to close. A
//! build from an unsigned HEAD (a plain dev tree, a CI lane) is
//! the honest refusal here - the row refuses, named as the
//! incomplete chain.
//!
//! The verdict CLASS splits the unsigned shape out of tampering
//! (night-hit-2, the zelynic night-dragon-fly-4 shape): the
//! commit-signature row still refuses on an unsigned commit, but the
//! matrix's verdict reads UNSIGNED - a missing provenance link, not
//! a modification - because every integrity depth above it verifies.
//! [`commit_signature_state`] is the one parse the verdict match and
//! the matrix's class computation share, so the two cannot drift.

use super::signature::DepthStatus;

/// The maintainer's pinned primary key fingerprint (ed25519,
/// `F5324E0967F104D58CE025F347A50AEF4B65AAC2`, long id
/// `47A50AEF4B65AAC2` - the identity that signs the release
/// commits and tags per docs/VERIFY_RELEASE.md). Single-sourced
/// from `assets/gpg/pinned-maintainer-fpr.txt` (no trailing
/// newline: the include is the value).
pub(crate) const PINNED_MAINTAINER_KEY_FPR: &str =
    include_str!("../../assets/gpg/pinned-maintainer-fpr.txt");

/// The stamp's state word: the part before the `:` separator
/// (`state:evidence`), or the whole stamp when no separator rides.
/// The matrix's verdict class (night-hit-2) reads this word to split
/// the unsigned shape out of the tamper class; the verdict match
/// below consumes the same words, one grammar, no drift.
#[must_use]
pub(crate) fn commit_signature_state(stamp: &str) -> &str {
    stamp.split_once(':').map_or(stamp, |(state, _)| state)
}

/// The D5 verdict: `(status, detail)` for the sig matrix's
/// commit-signature row. Every state of the build-time stamp maps
/// to an honest sentence; only a verified match against the pinned
/// fingerprint passes - unsigned, foreign-key, broken, missing and
/// unknown all REFUSE, naming their shape (the estate's
/// fails-by-name law).
#[must_use]
pub(crate) fn commit_signature_verdict(stamp: &str, commit_sha: &str) -> (DepthStatus, String) {
    let (state, evidence) = match stamp.split_once(':') {
        Some((state, evidence)) => (state, Some(evidence)),
        None => (stamp, None),
    };
    match state {
        "verified" => {
            let fpr = evidence.unwrap_or_default();
            if fpr == PINNED_MAINTAINER_KEY_FPR {
                (
                    DepthStatus::Pass,
                    format!(
                        "commit {commit_sha} carries a GPG signature by the pinned \
                         maintainer key {} (verified against the repo's pinned public \
                         key at build time)",
                        short_fpr(fpr)
                    ),
                )
            } else {
                // A VALIDSIG that is not the pin: the signature is
                // real but the signer is not the maintainer - the
                // MITM shape, named by fingerprint.
                (
                    DepthStatus::Refused,
                    format!(
                        "commit {commit_sha} is signed by {} - NOT the pinned \
                         maintainer key {}",
                        short_fpr(fpr),
                        short_fpr(PINNED_MAINTAINER_KEY_FPR)
                    ),
                )
            }
        }
        "wrong-key" => (
            DepthStatus::Refused,
            format!(
                "commit {commit_sha} carries a valid GPG signature by {} - NOT the \
                 pinned maintainer key {}",
                short_fpr(evidence.unwrap_or("an unknown key")),
                short_fpr(PINNED_MAINTAINER_KEY_FPR)
            ),
        ),
        "no-key" => (
            DepthStatus::Refused,
            format!(
                "commit {commit_sha} carries a signature the pinned maintainer key \
                 does not cover{} - not the maintainer's signature",
                evidence
                    .map(|fpr| format!(" (signed by {fpr})"))
                    .unwrap_or_default()
            ),
        ),
        "bad-signature" => (
            DepthStatus::Refused,
            format!(
                "commit {commit_sha} carries a GPG signature that FAILED the \
                 cryptographic check"
            ),
        ),
        "unsigned" => (
            DepthStatus::Refused,
            format!(
                "commit {commit_sha} carries NO GPG signature - the provenance \
                 chain stops at an unbound commit; bind releases to signed \
                 commits/tags"
            ),
        ),
        "no-vcs" => (
            DepthStatus::Refused,
            "built from a source snapshot without VCS evidence - the commit \
             signature cannot be verified here"
                .to_string(),
        ),
        "unavailable" => (
            DepthStatus::Refused,
            "signature evidence exists but the build machine could not verify \
             (git/gpg unavailable at build time)"
                .to_string(),
        ),
        // "unstamped" and anything a future stamp grammar emits but
        // this binary does not know: fail closed, never a silent
        // pass.
        other => (
            DepthStatus::Refused,
            format!("no commit-signature verdict ({other}) - fail-closed"),
        ),
    }
}

/// The display shape for fingerprints: 16-hex long id when the input
/// carries at least that much, else the input as-is (an honest
/// shorter token beats a truncated lie).
fn short_fpr(fpr: &str) -> String {
    if fpr.len() >= 16 {
        fpr[fpr.len() - 16..].to_string()
    } else {
        fpr.to_string()
    }
}

#[cfg(test)]
#[path = "../../test/info/commit_sig_tests.rs"]
mod tests;
