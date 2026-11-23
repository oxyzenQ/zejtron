// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
// night-netrunner-Z1: the D5 commit-signature stamp lane, ported
// from the zelynic night-solid-defense-2 precedent (the estate's
// mature reference). The supply-chain gap this closes: D0-D2 prove
// the ownership claim, D3 fingerprints the whole image, D4 seals
// the embedded camera object - but NOTHING bound the claimed commit
// (the `commit` line the sig report carries) to a signature. A
// binary swapped on the release channel replays its own claims and
// the ladder had no row that could disagree. This lane verifies, at
// build time, that the commit the binary is built from carries a
// GPG signature made by the pinned maintainer key, and stamps the
// verdict for the runtime `sig` matrix's D5 row to report.

use std::path::PathBuf;

/// The maintainer's pinned primary key fingerprint - the single
/// source of truth BOTH sides read (this file via build.rs, the
/// runtime policy in src/info/commit_sig.rs through the same
/// include), so the pin can never drift between the lane that
/// verifies and the lane that reports. No trailing newline in the
/// file: the include is the value, byte for byte.
const PINNED_FPR: &str = include_str!("../assets/gpg/pinned-maintainer-fpr.txt");

/// The armored public key the verifier imports - the repo's own
/// tracked copy, never a keyserver fetch at build time (a network
/// fetch would make every build depend on a third party AND on the
/// channel the pin exists to protect; the file is ordinary tracked
/// source, so tampering with it is a visible diff).
const PINNED_KEY: &str = "assets/gpg/maintainer-47A50AEF4B65AAC2.asc";

/// Stamp the `ZEJTRON_VCS_COMMIT_SIG` env the runtime D5 row reads.
///
/// The stamp grammar is `<state>[:<evidence-hex>]` - one line, env
/// safe, exactly the states the runtime policy knows:
///
///   verified:<fpr>     HEAD's commit signature verified against the
///                      pinned public key (the fpr is the PRIMARY
///                      key's, the one the runtime compares to the
///                      pin; a signing-subkey signature carries the
///                      primary in VALIDSIG's last field).
///   wrong-key:<fpr>    cryptographically valid, but made by a key
///                      that is NOT the pinned maintainer key - the
///                      MITM shape.
///   no-key[:<fpr>]     a signature exists but the pinned key does
///                      not cover it (gpg: NO_PUBKEY) - the signer
///                      is unknown to the pin. The tamper shape the
///                      swap-a-binary attack actually produces.
///   bad-signature      a signature exists and FAILED the crypto
///                      check (BADSIG / revoked / expired / the
///                      unsupported-algorithm ERRSIG class).
///   unsigned           HEAD's commit object carries no gpgsig
///                      header - detected WITHOUT gpg (the commit
///                      object itself answers), so the common
///                      unsigned case never spawns a keyring.
///   no-vcs             no git checkout answered (registry tarball
///                      builds) - nothing to verify, stated as
///                      such, never guessed.
///   unavailable        git or gpg could not run on this machine -
///                      the verifier's own degraded state.
///
/// Fail-closed is the LAW here (the zelynic verdict's wording): a
/// build that cannot state a verdict stamps the honest degraded
/// state, and the runtime row REFUSES on everything except a
/// verified match - never a silent pass.
pub(super) fn stamp_commit_signature() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed={PINNED_KEY}");
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join("assets/gpg/pinned-maintainer-fpr.txt")
            .display()
    );
    let state = classify_head_signature(&manifest_dir);
    println!("cargo:rustc-env=ZEJTRON_VCS_COMMIT_SIG={state}");
}

/// The full classification, one pass, pure over the shell facts (the
/// probe-verified status shapes live in the classifier's comments).
fn classify_head_signature(manifest_dir: &std::path::Path) -> String {
    // The commit object itself answers the unsigned question - no
    // keyring, no gpg, one git probe (the empirical shape: a signed
    // commit carries a `gpgsig ` header line, continuations indented).
    let commit_object = match git_stdout(manifest_dir, &["cat-file", "commit", "HEAD"]) {
        Some(text) => text,
        None => return "no-vcs".to_string(),
    };
    if !commit_object
        .lines()
        .any(|line| line.starts_with("gpgsig "))
    {
        return "unsigned".to_string();
    }

    // A signature exists: verify it against a keyring that contains
    // ONLY the pinned public key - an isolated throwaway GNUPGHOME,
    // never the building user's keyring (which could contain, and
    // thus vouch for, anyone's key).
    let key_path = manifest_dir.join(PINNED_KEY);
    let key_bytes = match std::fs::read(&key_path) {
        Ok(bytes) => bytes,
        Err(_) => return "no-key".to_string(),
    };
    let home = match make_temp_keyring(&key_bytes) {
        Some(home) => home,
        None => return "unavailable".to_string(),
    };
    let verdict = verify_in_keyring(manifest_dir, &home);
    let _ = std::fs::remove_dir_all(&home);
    verdict
}

/// Run one git command in the manifest dir, `None` when git is
/// absent or the command fails (a missing answer is a missing
/// answer, never a guess).
fn git_stdout(dir: &std::path::Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Create a 0700 temporary GNUPGHOME holding exactly the pinned
/// public key. `None` when gpg is absent or refuses the import -
/// the verifier's own honest "cannot verify" state.
fn make_temp_keyring(key_bytes: &[u8]) -> Option<PathBuf> {
    let home = std::env::temp_dir().join(format!("zejtron-sig-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).ok()?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    let key_file = home.join("pinned.asc");
    std::fs::write(&key_file, key_bytes).ok()?;
    let import = std::process::Command::new("gpg")
        .args(["--homedir", home.to_str()?, "--batch", "--quiet"])
        .arg("--import")
        .arg(&key_file)
        .output()
        .ok()?;
    if !import.status.success() {
        let _ = std::fs::remove_dir_all(&home);
        return None;
    }
    Some(home)
}

/// `git verify-commit --raw HEAD` inside the isolated keyring, then
/// classify from gpg's status lines (the shapes recorded live in
/// the zelynic night-solid-defense-2 probe, all three cases, plus
/// the zejtron live re-probe of this tree's own signed HEAD):
///
///   verified, exit 0:
///     [GNUPG:] GOODSIG <keyid> <name>
///     [GNUPG:] VALIDSIG <signer-fpr> <date> <ts> ... <primary-fpr>
///   foreign signer, exit 1:
///     [GNUPG:] ERRSIG <keyid> 22 10 00 <ts> 9 <full-fpr>
///     [GNUPG:] NO_PUBKEY <keyid>
///   (unsigned never reaches here - cat-file answered first)
fn verify_in_keyring(dir: &std::path::Path, home: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .env("GNUPGHOME", home)
        .args(["verify-commit", "--raw", "HEAD"])
        .output();
    let out = match out {
        Ok(out) => out,
        Err(_) => return "unavailable".to_string(),
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut validsig_signer = None;
    let mut validsig_primary = None;
    let mut errsig_fpr = None;
    let mut saw_no_pubkey = false;
    let mut saw_bad = false;
    for line in stderr.lines() {
        let rest = match line.strip_prefix("[GNUPG:] ") {
            Some(rest) => rest,
            None => continue,
        };
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        match tokens.first().copied() {
            Some("VALIDSIG") if tokens.len() > 1 => {
                validsig_signer = Some(tokens[1].to_string());
                // The PRIMARY key's fpr rides the LAST field when a
                // subkey signed (GnuPG's status contract); a primary
                // signature repeats the same fpr there. gpg 2.4.7
                // emits an extra field between class and primary (the
                // rig caught the parser reading a bare "00" as the
                // primary), so the primary is located by SHAPE - the
                // last 40-hex token - not by a version-fragile index.
                validsig_primary = tokens
                    .iter()
                    .rev()
                    .find(|t| t.len() == 40 && t.bytes().all(|b| b.is_ascii_hexdigit()))
                    .map(|s| s.to_string());
            }
            Some("NO_PUBKEY") => saw_no_pubkey = true,
            Some("ERRSIG") if tokens.len() >= 8 => {
                errsig_fpr = Some(tokens[7].to_string());
            }
            Some("BADSIG") | Some("EXPKEYSIG") | Some("REVKEYSIG") => saw_bad = true,
            _ => {}
        }
    }
    if let (Some(signer), primary) = (validsig_signer, validsig_primary) {
        let primary = primary.unwrap_or_else(|| signer.clone());
        if signer == PINNED_FPR || primary == PINNED_FPR {
            return format!("verified:{primary}");
        }
        return format!("wrong-key:{signer}");
    }
    if saw_no_pubkey {
        return match errsig_fpr {
            Some(fpr) => format!("no-key:{fpr}"),
            None => "no-key".to_string(),
        };
    }
    if saw_bad || errsig_fpr.is_some() {
        return "bad-signature".to_string();
    }
    // A signed commit whose verification produced no verdict line at
    // all (exit noise, a gpg that answered nothing) is a broken
    // verification, and broken fails closed - never a silent pass.
    "bad-signature".to_string()
}
