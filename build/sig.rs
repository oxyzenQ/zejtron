// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// The depth-matrix signature's payload format (night-signature-1) -
// the ONE shared definition, included by build.rs (which computes and
// stamps the anchor) and by src/info/signature.rs (which recomputes
// and verifies it at runtime). A module shared across that boundary
// must stay std-only (the build.rs law) and must never reference any
// other crate module - the payload format is the contract between the
// build lane and every binary that ever ships, so it lives alone.
//
// The format law: every ingredient is pure printable ASCII, `|`-joined
// (none of the ingredients ever carries a `|`), and every ingredient
// is visible in the binary's own `-V` report - identity on the
// Depth-sig line, commit on the Build: line, build-time on the
// Build-time: line. That is what makes the anchor externally
// recomputable (docs/VERIFY_RELEASE.md): anyone holding the binary
// and a b3sum can rebuild the payload bytes from the report alone and
// compare the anchor, without executing the artifact.

/// The signature identity, verbatim (night-signature-1). The owner's
/// claim burned into every build - the same text the Depth-sig line
/// renders and the D0 depth verifies. One const, shared by the build
/// lane and the runtime, so the two can never drift.
pub(crate) const SIG_IDENTITY: &str = "rezky_nightky (oxyzenQ) 2026";

/// The payload format tag. `ns1` = night-signature-1. A future change
/// to the payload layout bumps the tag, so an old verifier can never
/// silently "verify" a new payload shape (it would compute a
/// different anchor and refuse - the honest direction).
pub(crate) const SIG_PAYLOAD_TAG: &str = "ns1";

/// The marker tag burned into the binary image (depth D1). Grep-able
/// on the artifact (`grep -a ZJNS1 <binary>`) without executing it -
/// the forensic lane's own read-only discipline, pointed at the
/// binary itself.
pub(crate) const SIG_MARKER_TAG: &str = "ZJNS1";

/// The anchored payload bytes: `ns1|<identity>|<commit>|<build-time>`.
/// The caller feeds exactly the values build.rs stamped (the commit
/// chain's canonical 7-char shape, the `M/D/YYYY HH:MM (UTC)`
/// build-time string) - the same strings the -V report renders.
pub(crate) fn sig_payload(commit: &str, build_time: &str) -> String {
    format!("{SIG_PAYLOAD_TAG}|{SIG_IDENTITY}|{commit}|{build_time}")
}

/// The marker line burned into the image: the payload's facts plus
/// the anchor over them, one newline-terminated line so a `strings`
/// or `grep -a` probe reads it whole. The WRITER's seat is the build
/// lane (build.rs stages OUT_DIR/nz_sig.bin); the runtime crate only
/// reads - the allow is the honest count of that split, the same
/// shape lane.rs records for its own crate-level split.
#[allow(dead_code)]
pub(crate) fn sig_marker(commit: &str, build_time: &str, anchor: &str) -> String {
    format!("{SIG_MARKER_TAG}|{SIG_IDENTITY}|{commit}|{build_time}|{anchor}\n")
}

/// The parsed fields of one marker line. Lifetimes borrow the image
/// bytes - the runtime never copies what it only compares.
pub(crate) struct SigMarkerFields<'a> {
    pub identity: &'a str,
    pub commit: &'a str,
    pub build_time: &'a str,
    pub anchor: &'a str,
}

/// Parse the first INTACT marker line out of raw image bytes. The
/// scan walks every occurrence of the tag and accepts the first one
/// that parses strictly - the tag string itself also lives in rodata
/// as the comparison const, and linker layout may place it before or
/// after the staged marker (the musl gate caught exactly that
/// ordering), so a first-occurrence parse would read rodata garbage
/// and refuse an honest binary. Strict: the tag must lead the line,
/// the split must yield exactly five fields, the anchor must be 64
/// lowercase hex digits, and no field may be empty. Anything else is
/// None - the caller refuses by name rather than verifying against a
/// shape it does not understand.
pub(crate) fn parse_sig_marker(bytes: &[u8]) -> Option<SigMarkerFields<'_>> {
    let tag = SIG_MARKER_TAG.as_bytes();
    let mut from = 0;
    while let Some(rel) = find_subslice(&bytes[from..], tag) {
        let start = from + rel;
        if let Some(fields) = parse_sig_marker_at(bytes, start) {
            return Some(fields);
        }
        from = start + tag.len();
    }
    None
}

/// The strict single-candidate parse at one byte offset: the tag
/// leads the line, the line is newline-terminated, five `|`-split
/// fields, a non-empty identity/commit/build-time, and a 64-hex
/// anchor.
fn parse_sig_marker_at(bytes: &[u8], start: usize) -> Option<SigMarkerFields<'_>> {
    let rest = &bytes[start..];
    let end = rest.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&rest[..end]).ok()?;
    let fields: Vec<&str> = line.split('|').collect();
    if fields.len() != 5 || fields[0] != SIG_MARKER_TAG {
        return None;
    }
    let (identity, commit, build_time, anchor) = (fields[1], fields[2], fields[3], fields[4]);
    if identity.is_empty() || commit.is_empty() || build_time.is_empty() {
        return None;
    }
    if !is_anchor_hex(anchor) {
        return None;
    }
    Some(SigMarkerFields {
        identity,
        commit,
        build_time,
        anchor,
    })
}

/// The anchor's one shape: exactly 64 lowercase hex digits (the
/// blake3 hex the build lane renders). Uppercase or short forms are
/// rejected - the verifier refuses rather than guessing.
fn is_anchor_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Naive subslice search (std only - the module carries no
/// dependencies). The needle is 5 bytes, so the scan cost is a
/// few dozen milliseconds over the largest image this crate ships.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// The format suite. In the build-script crate these never execute
// (cargo does not run build-script tests); in the runtime crate they
// ride the standing `cargo test` run (the module is #[path]-included
// by src/info/signature.rs), so every drift between the two sides
// fails the unit gate, not a release day.

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "127c6ed";
    const BUILD_TIME: &str = "11/13/2026 09:41 (UTC)";

    #[test]
    fn payload_format_is_pinned_byte_for_byte() {
        // The external verification recipe in docs/VERIFY_RELEASE.md
        // rebuilds exactly these bytes - the format cannot drift
        // without that recipe rotting.
        assert_eq!(
            sig_payload(COMMIT, BUILD_TIME),
            "ns1|rezky_nightky (oxyzenQ) 2026|127c6ed|11/13/2026 09:41 (UTC)"
        );
    }

    #[test]
    fn identity_is_the_owner_claim_verbatim() {
        assert_eq!(SIG_IDENTITY, "rezky_nightky (oxyzenQ) 2026");
    }

    #[test]
    fn marker_roundtrips_through_the_strict_parser() {
        let anchor = "a".repeat(64);
        let marker = sig_marker(COMMIT, BUILD_TIME, &anchor);
        let fields = parse_sig_marker(marker.as_bytes()).expect("a well-formed marker parses");
        assert_eq!(fields.identity, SIG_IDENTITY);
        assert_eq!(fields.commit, COMMIT);
        assert_eq!(fields.build_time, BUILD_TIME);
        assert_eq!(fields.anchor, anchor);
    }

    #[test]
    fn marker_parser_finds_the_line_inside_image_noise() {
        // The runtime searches the whole executable image - padding,
        // code, and unrelated rodata around the marker must not
        // confuse the scan.
        let anchor = "0123456789abcdef".repeat(4);
        let marker = sig_marker(COMMIT, BUILD_TIME, &anchor);
        let mut image = vec![0u8; 4096];
        image.extend_from_slice(marker.as_bytes());
        image.extend_from_slice(&[0xff; 1024]);
        let fields =
            parse_sig_marker(&image).expect("the marker is found inside surrounding bytes");
        assert_eq!(fields.commit, COMMIT);
    }

    #[test]
    fn marker_parser_survives_a_stray_tag_before_the_real_marker() {
        // The musl gate's layout (night-signature-1): the tag const
        // string lands in rodata BEFORE the staged marker - the scan
        // must skip candidates that do not parse strictly and find
        // the intact line, never refuse an honest binary.
        let anchor = "a".repeat(64);
        let marker = sig_marker(COMMIT, BUILD_TIME, &anchor);
        let mut image = b"ZJNS1\x01\x02garbage|without|five|fields|no".to_vec();
        image.extend_from_slice(b"\nmore noise\n");
        image.extend_from_slice(marker.as_bytes());
        let fields =
            parse_sig_marker(&image).expect("the intact marker is found past the stray tag");
        assert_eq!(fields.commit, COMMIT);
        assert_eq!(fields.anchor, anchor);
    }

    #[test]
    fn marker_parser_rejects_every_malformed_shape() {
        // No tag at all.
        assert!(parse_sig_marker(b"nothing to see here\n").is_none());
        // Tag present, wrong field count.
        assert!(parse_sig_marker(b"ZJNS1|only|three\n").is_none());
        // Wrong tag spelling.
        assert!(parse_sig_marker(b"ZJNSX|a|b|c|d\n").is_none());
        // Short or uppercase anchor (the verifier refuses, never guesses).
        assert!(parse_sig_marker(b"ZJNS1|i|c|t|abcd\n").is_none());
        let upper = sig_marker(COMMIT, BUILD_TIME, &"A".repeat(64));
        assert!(parse_sig_marker(upper.as_bytes()).is_none());
        // Empty ingredient.
        let empty_commit = sig_marker("", BUILD_TIME, &"a".repeat(64));
        assert!(parse_sig_marker(empty_commit.as_bytes()).is_none());
        // Tag present but no terminating newline.
        let open = sig_marker(COMMIT, BUILD_TIME, &"a".repeat(64));
        assert!(parse_sig_marker(open.trim_end().as_bytes()).is_none());
    }
}
