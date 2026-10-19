// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The registry-prebuilt lane (night-improve-5, the zylaxion
// night-improve-23 shape): a crates.io tarball carries no ebpf/ tree
// (cargo's package walk cannot carry the detached nested workspace),
// so the feature's object rides the tarball as the maintainer-built
// ebpf-prebuilt/zejtron-ebpf.o with its provenance manifest. This
// module stages that object into OUT_DIR for the loader's
// include_bytes! embedding.
//
// The hard rule the prompt-level contract names: the manifest's
// object sha256 MUST match the staged bytes before anything is
// staged - a stale or tampered lane panics naming both hashes, never
// silently embeds an object the manifest does not describe. The
// structural ELF validation (the same law the source-built lane
// applies to its freshly built object) runs first, so a truncated or
// damaged object fails on its shape before its identity is even
// questioned. The manifest is generator-controlled
// (scripts/dev/regenerate-ebpf-prebuilt.sh writes it), so the parser
// anchors on that exact shape - no TOML crate, std only.

use std::path::Path;

/// The staged object's OUT_DIR name - the exact path the host crate
/// embeds via include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o")).
/// Kept in lockstep with build/ebpf.rs's EBPF_STAGED_OBJECT constant.
pub(super) const STAGED_OBJECT_NAME: &str = "zejtron-ebpf.o";

/// The manifest pin a registry extract verifies its staged bytes
/// against: the [[object]] row of ebpf-prebuilt/manifest.toml.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PrebuiltPin {
    pub(super) name: String,
    pub(super) sha256: String,
    pub(super) size: u64,
}

/// Stage the prebuilt object for the loader's embedding. Panics with
/// the named drift on any inconsistency - a registry install must
/// never half-work or silently embed unverified bytes.
pub(super) fn stage_prebuilt_object(manifest_dir: &Path, out_dir: &Path) {
    let prebuilt_dir = manifest_dir.join("ebpf-prebuilt");
    let object_path = prebuilt_dir.join(STAGED_OBJECT_NAME);
    let manifest_path = prebuilt_dir.join("manifest.toml");

    let pin_text = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        panic!(
            "the ebpf feature was requested and this extract carries no ebpf/ tree (a \
             registry tarball), so the prebuilt lane is the only object source - but {} \
             is unreadable ({e}). The crate is incomplete: the ebpf-prebuilt/ lane must \
             ride the tarball (see the Cargo.toml include list); report this as a \
             packaging bug",
            manifest_path.display()
        )
    });
    let pin = parse_prebuilt_manifest(&pin_text).unwrap_or_else(|| {
        panic!(
            "{} does not carry a parsable [[object]] row (name/sha256/size) - the \
             manifest is generator-controlled by \
             scripts/dev/regenerate-ebpf-prebuilt.sh; a hand-edited or truncated \
             manifest is a broken lane, and the build refuses it by name",
            manifest_path.display()
        )
    });

    let data = std::fs::read(&object_path).unwrap_or_else(|e| {
        panic!(
            "the prebuilt object {} is unreadable ({e}) - the registry tarball is \
             incomplete without it; report this as a packaging bug",
            object_path.display()
        )
    });

    // Shape first, then identity: the same structural ELF law the
    // source-built lane applies to a fresh build, then the manifest
    // verification the prebuilt lane exists to enforce.
    crate::ebpf::validate_ebpf_object(&data).unwrap_or_else(|problem| {
        panic!(
            "the prebuilt eBPF object {} failed structural validation ({problem}) - the \
             staged lane is damaged; regenerate it with \
             ./scripts/dev/regenerate-ebpf-prebuilt.sh and re-package",
            object_path.display()
        )
    });
    verify_prebuilt_bytes(&data, &pin).unwrap_or_else(|drift| {
        panic!(
            "the prebuilt eBPF lane is stale: {drift}. The bytes on disk are not the \
             bytes the manifest pins - regenerate the lane with \
             ./scripts/dev/regenerate-ebpf-prebuilt.sh before building; embedding \
             unverified bytes is never an option"
        )
    });

    let dst = out_dir.join(STAGED_OBJECT_NAME);
    std::fs::write(&dst, &data)
        .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    println!(
        "cargo:warning=zejtron: eBPF object staged from ebpf-prebuilt/ (registry-prebuilt \
         lane, manifest-verified)"
    );
}

/// The prebuilt lane's contract, factored out pure: the staged bytes
/// must match the manifest pin's size and sha256. The Err text names
/// the exact drift (both hashes on a sha mismatch) - it rides the
/// panic verbatim.
pub(super) fn verify_prebuilt_bytes(data: &[u8], pin: &PrebuiltPin) -> Result<(), String> {
    if data.len() as u64 != pin.size {
        return Err(format!(
            "object size drift: the manifest pins {} bytes but the staged object is {} \
             bytes",
            pin.size,
            data.len()
        ));
    }
    let actual = crate::sha256::sha256_hex(data);
    if actual != pin.sha256 {
        return Err(format!(
            "object sha256 drift: the manifest pins {} but the staged object hashes to {}",
            pin.sha256, actual
        ));
    }
    Ok(())
}

/// Anchored parse of the generator-controlled manifest shape: the
/// first `name = "..."`, `sha256 = "..."`, and `size = N` lines in
/// document order form the [[object]] row. The anchor is
/// line-start-exact, so the header's ebpf_tree_sha256 key (a longer
/// name sharing the sha256 suffix) can never satisfy the object
/// anchor, and comments cannot satisfy any of the three. Each line is
/// offered to every still-empty slot, so key order cannot skew the
/// parse.
pub(super) fn parse_prebuilt_manifest(text: &str) -> Option<PrebuiltPin> {
    let mut name: Option<String> = None;
    let mut sha256: Option<String> = None;
    let mut size: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim_start();
        if name.is_none() {
            name = quoted_value(line, "name = \"").map(str::to_owned);
        }
        if sha256.is_none() {
            sha256 = quoted_value(line, "sha256 = \"").map(str::to_owned);
        }
        if size.is_none() {
            size = line
                .strip_prefix("size = ")
                .and_then(|rest| rest.trim().parse::<u64>().ok());
        }
        if name.is_some() && sha256.is_some() && size.is_some() {
            break;
        }
    }
    // All three keys must answer, and a sha pin is 64 lowercase hex
    // characters - a manifest that fails either shape is not a lane.
    let sha256 = sha256?;
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(PrebuiltPin {
        name: name?,
        sha256,
        size: size?,
    })
}

/// The quoted-string read behind the line anchors: `key` is the full
/// literal prefix (e.g. `name = "`), the value runs to the closing
/// quote. None when the line does not carry the anchor or a closing
/// quote - the caller treats None as "this line is not my key".
pub(super) fn quoted_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte the shape regenerate-ebpf-prebuilt.sh writes
    /// (comments trimmed, keys and order preserved).
    const CANONICAL: &str = r#"# generated header comment
schema = 1
generated = "2026-10-19T05:33:03Z"
toolchain = "nightly-2026-09-18"
bpf_linker = "0.11.1"
ebpf_tree_sha256 = "4af33fd76ce329dd69f3ca0901604ae4b89ea9cbae0890717d459251a4964119"
built_by = "oxyzenQ <130107241+oxyzenQ@users.noreply.github.com>"

[[object]]
name = "zejtron-ebpf"
sha256 = "1b714569f96e8f2cb01f14df7a2351231cd3269a84b8893c5cac22f957d302ed"
size = 11112

[contract]
attach_targets = ["sched_process_exec"]
version = "80.0.0-alpha.1"
"#;

    #[test]
    fn canonical_manifest_parses_to_the_object_row() {
        let pin = parse_prebuilt_manifest(CANONICAL).expect("canonical shape parses");
        assert_eq!(pin.name, "zejtron-ebpf");
        assert_eq!(
            pin.sha256,
            "1b714569f96e8f2cb01f14df7a2351231cd3269a84b8893c5cac22f957d302ed"
        );
        assert_eq!(pin.size, 11112);
    }

    #[test]
    fn the_tree_sha_header_key_never_satisfies_the_object_anchor() {
        // The header carries ebpf_tree_sha256 = "..." BEFORE the
        // [[object]] row; the anchor is "sha256 = \"" at line start,
        // so the tree pin must not be mistaken for the object pin.
        let pin = parse_prebuilt_manifest(CANONICAL).expect("parses");
        assert_ne!(
            pin.sha256,
            "4af33fd76ce329dd69f3ca0901604ae4b89ea9cbae0890717d459251a4964119"
        );
    }

    #[test]
    fn a_missing_object_key_refuses_to_parse() {
        // No sha256 row anywhere: not a lane, None - the caller panics
        // naming the manifest instead of hallucinating a pin.
        let broken = CANONICAL.replace("sha256 = \"1b714569", "xsha256 = \"1b714569");
        assert_eq!(parse_prebuilt_manifest(&broken), None);
    }

    #[test]
    fn a_non_hex_sha_pin_refuses_to_parse() {
        let broken = CANONICAL.replace(
            "sha256 = \"1b714569f96e8f2cb01f14df7a2351231cd3269a84b8893c5cac22f957d302ed\"",
            "sha256 = \"not-a-hash\"",
        );
        assert_eq!(parse_prebuilt_manifest(&broken), None);
    }

    #[test]
    fn size_drift_is_named_with_both_sides() {
        let pin = PrebuiltPin {
            name: "zejtron-ebpf".to_owned(),
            sha256: "1b714569f96e8f2cb01f14df7a2351231cd3269a84b8893c5cac22f957d302ed".to_owned(),
            size: 11112,
        };
        let err = verify_prebuilt_bytes(&[0u8; 100], &pin).unwrap_err();
        assert!(err.contains("11112") && err.contains("100"), "{err}");
    }

    #[test]
    fn sha_drift_is_named_with_both_hashes() {
        let pin = PrebuiltPin {
            name: "zejtron-ebpf".to_owned(),
            sha256: "1b714569f96e8f2cb01f14df7a2351231cd3269a84b8893c5cac22f957d302ed".to_owned(),
            size: 3,
        };
        let err = verify_prebuilt_bytes(b"abc", &pin).unwrap_err();
        assert!(err.contains("sha256 drift"), "{err}");
        // The drift names the pinned hash AND the actual one.
        assert!(err.contains("1b714569"), "{err}");
        assert!(err.contains(&crate::sha256::sha256_hex(b"abc")), "{err}");
    }

    #[test]
    fn the_matching_lane_verifies_clean() {
        let data = b"abc";
        let pin = PrebuiltPin {
            name: "zejtron-ebpf".to_owned(),
            sha256: crate::sha256::sha256_hex(data),
            size: 3,
        };
        assert_eq!(verify_prebuilt_bytes(data, &pin), Ok(()));
    }
}
