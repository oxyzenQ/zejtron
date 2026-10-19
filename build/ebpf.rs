// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The eBPF object staging machinery (night-improve-1), split out of
// build.rs per the 600-LOC no-mercy cap (the zelynic/zylaxion build/
// module precedent: the lane lives beside its build.rs). Called from
// build.rs's main(); everything here is build-script-only.
//
// ── The staging lanes ─────────────────────────────────────────────────
//
//   dormant           - the `ebpf` feature is off: nothing stages, the
//                       loader module is not compiled either.
//   source-built      - a git checkout: the ebpf/ crate is
//                       cross-compiled by a nested cargo invocation
//                       under the dated nightly pin, and the artifact
//                       is staged after structural validation.
//   registry-prebuilt - a registry tarball (cargo's package walk
//                       cannot carry the detached ebpf/ workspace):
//                       the maintainer-built ebpf-prebuilt/zejtron-ebpf.o
//                       is staged after manifest verification
//                       (build/prebuilt.rs; provenance in
//                       ebpf-prebuilt/manifest.toml, written by
//                       scripts/dev/regenerate-ebpf-prebuilt.sh, the
//                       one writer of the lane). This is the lane a
//                       plain `cargo install zejtron` rides: the full
//                       eBPF binary with no toolchain on the target
//                       machine - the preflight and the nested build
//                       never run there.
//
// The lane that ran is stamped at compile time (the
// ZEJTRON_EBPF_LANE rustc-env, the zylaxion stamp shape), so a
// binary carries its own provenance answer.
//
// The lane keeps the zylaxion hardening that earned its place: the
// prerequisite preflight (fail before compile time with the
// one-command fix) and the RUSTFLAGS poison strip plus the v3 force
// (env rustflags shadow config; host-CPU flags are poison for
// bpfel). The self-heal retry is deliberately absent in this pass: a
// validation failure panics with the exact violation and the
// one-line remedy (delete ebpf/target and rebuild) - honest and lean
// beats retry machinery the pass does not need.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The staged object's OUT_DIR name - the exact path the host crate
/// embeds via include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o")).
/// One source of truth: build/prebuilt.rs owns the constant (the
/// registry lane stages under the same name the source-built lane
/// does), and both lanes read it from there.
const EBPF_STAGED_OBJECT: &str = crate::prebuilt::STAGED_OBJECT_NAME;

/// The pinned bpf-linker release the nested build links with - the
/// second half of the validated pair (the dated nightly pin is the
/// first half, read live from ebpf/rust-toolchain.toml). The
/// preflight names this version in its fix message so a drifted host
/// install is diagnosable in one read.
const BPF_LINKER_VERSION: &str = "0.11.1";

/// Dispatch the eBPF object staging lane for the loader's embedding.
/// A no-op without the `ebpf` feature - no BPF build attempted, no
/// preflight panic, no prebuilt staging. With the feature on, the
/// selection rule is the ebpf/ tree's presence: a git checkout
/// source-builds the object, a registry tarball stages the
/// manifest-verified prebuilt one (build/prebuilt.rs).
pub(super) fn build_ebpf_object() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let ebpf_dir = manifest_dir.join("ebpf");

    // Rerun triggers: the ebpf crate's sources and its build wiring,
    // plus the prebuilt lane's directory (a refreshed ebpf-prebuilt/
    // must retarget every dependent build). ebpf/target is
    // deliberately NOT watched - the nested cargo owns its own
    // freshness, and watching build output would loop.
    for rel in [
        "src",
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config.toml",
        "rust-toolchain.toml",
        "bpfel-unknown-none.json",
    ] {
        println!("cargo:rerun-if-changed={}", ebpf_dir.join(rel).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("ebpf-prebuilt").display()
    );

    // Only the ebpf feature needs the object.
    if std::env::var_os("CARGO_FEATURE_EBPF").is_none() {
        println!("cargo:rustc-env=ZEJTRON_EBPF_LANE=dormant (not compiled)");
        return;
    }

    // The registry-prebuilt lane (night-improve-5): a crates.io
    // extract carries no ebpf/ tree, so the maintainer-built object
    // rides the tarball (ebpf-prebuilt/, the Cargo.toml include list)
    // and stages after manifest verification - no nightly, no
    // bpf-linker, no nested build on the target machine.
    if !ebpf_dir.join("Cargo.toml").is_file() {
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
        crate::prebuilt::stage_prebuilt_object(&manifest_dir, &out_dir);
        println!("cargo:rustc-env=ZEJTRON_EBPF_LANE=registry-prebuilt");
        return;
    }

    // Preflight BEFORE the nested build: name the missing prerequisite
    // and its one-command fix, and catch a missing bpf-linker even when
    // ebpf/target is fully cached (a warm build skips the link step).
    let toolchain = ebpf_toolchain_pin(&ebpf_dir).unwrap_or_else(|| {
        panic!(
            "could not read the channel pin from {} - the file is part of the tree; \
             restore it or re-clone",
            ebpf_dir.join("rust-toolchain.toml").display()
        );
    });
    preflight_ebpf_prerequisites(&toolchain);

    run_nested_ebpf_build(&ebpf_dir, &toolchain);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let release_dir = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release");
    let data =
        read_validated_ebpf_object(&release_dir.join("zejtron-ebpf")).unwrap_or_else(|problem| {
            panic!(
                "the eBPF object zejtron-ebpf failed validation ({problem}) - delete \
                 ebpf/target and rebuild; if it fails again the bpf-linker {BPF_LINKER_VERSION} \
                 install is suspect (./scripts/dev/bootstrap-ebpf.sh reinstalls the pair)"
            )
        });
    let dst = out_dir.join(EBPF_STAGED_OBJECT);
    std::fs::write(&dst, &data)
        .unwrap_or_else(|e| panic!("failed to stage {} into OUT_DIR: {e}", dst.display()));
    println!("cargo:rustc-env=ZEJTRON_EBPF_LANE=source-built");
}

/// Read the dated nightly pin from ebpf/rust-toolchain.toml (the
/// `channel = "..."` line). Parsing it live - instead of hardcoding a
/// second copy here - means bumping the pin in its own file re-targets
/// the preflight and the nested build with no drift possible.
fn ebpf_toolchain_pin(ebpf_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(ebpf_dir.join("rust-toolchain.toml")).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("channel") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let channel = rest.trim().trim_matches('"');
        if !channel.is_empty() {
            return Some(channel.to_owned());
        }
    }
    None
}

/// Verify the two source-build prerequisites BEFORE the nested build
/// spends compile time: the dated nightly pin (listed in rustup) and
/// the pinned bpf-linker release on PATH. Each failure names its fix
/// in one line. No silent skip.
fn preflight_ebpf_prerequisites(toolchain: &str) {
    let listed = Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    if !listed
        .lines()
        .any(|l| l.starts_with(&format!("{toolchain}-")))
    {
        panic!(
            "the eBPF source-build needs the dated nightly pin {toolchain} (rust-src \
             included) and it is not installed. One command: rustup toolchain install \
             {toolchain} --profile minimal --component rust-src (or \
             ./scripts/dev/bootstrap-ebpf.sh, which installs it plus bpf-linker)"
        );
    }
    let linker = match Command::new("bpf-linker").arg("--version").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => panic!(
            "the eBPF source-build needs bpf-linker {BPF_LINKER_VERSION} on PATH and rustc \
             cannot invoke it. One command: ./scripts/dev/bootstrap-ebpf.sh (or fetch \
             https://github.com/aya-rs/bpf-linker/releases/download/v{BPF_LINKER_VERSION}/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
             and put bpf-linker on PATH)"
        ),
    };
    if !linker.contains(BPF_LINKER_VERSION) {
        panic!(
            "bpf-linker on PATH reports '{linker}', expected {BPF_LINKER_VERSION} - the \
             toolchain/linker pair is validated together; install the pinned release \
             (./scripts/dev/bootstrap-ebpf.sh)"
        );
    }
}

/// The nested eBPF cross-build invocation. The toolchain is forced
/// through `rustup run <pin> cargo` (the CARGO env var handed to
/// build scripts points at the resolved stable cargo, which would
/// silently drop the nightly-only -Z flags); cwd inside ebpf/ keeps
/// the crate's own .cargo/config.toml in effect; target and build-std
/// are ALSO passed explicitly so the invocation is correct even
/// without the config. The target argument names the repo-local
/// bpfel-unknown-none.json spec (the builtin tier-3 spec carries
/// atomic-cas: false, which would break the atomic counter) - the
/// artifact still lands at target/bpfel-unknown-none/. Environment:
/// the parent's RUSTC/RUSTC_WRAPPER are poison for the sub-build (the
/// stable compiler would compile build-std core); the inherited
/// rustflags pass through the host-poison strip and then get the v3
/// codegen level forced. --locked keeps the committed Cargo.lock
/// authoritative; stdio is inherited so the nested compiler output
/// streams through to the build log.
fn run_nested_ebpf_build(ebpf_dir: &Path, toolchain: &str) {
    let mut nested = Command::new("rustup");
    nested
        .args(["run", toolchain, "cargo"])
        .current_dir(ebpf_dir)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "bpfel-unknown-none.json",
            "--package",
            "zejtron-ebpf",
        ])
        .args(["-Z", "build-std=core"])
        .args(["-Z", "json-target-spec"])
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER");
    strip_host_poison_rustflags(&mut nested);
    force_bpf_v3_rustflags(&mut nested);
    let status = nested.status().unwrap_or_else(|e| {
        panic!(
            "failed to launch `rustup run {toolchain} cargo` - rustup is a hard \
             prerequisite of the pure-Rust eBPF build: {e}"
        )
    });
    if !status.success() {
        panic!(
            "the pure-Rust eBPF build failed with prerequisites present ({toolchain} and \
             bpf-linker {BPF_LINKER_VERSION} were both verified) - the nested compiler \
             output above is the diagnosis"
        );
    }
}

/// Read one built eBPF object and structurally validate it. The Err
/// text is user-facing (it rides the panic), so it names the exact
/// violation instead of a bare "corrupt".
fn read_validated_ebpf_object(path: &Path) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("not readable: {e}"))?;
    validate_ebpf_object(&data)?;
    Ok(data)
}

/// Structural validation of the built eBPF object - enough ELF law to
/// catch every on-disk damage mode that would make aya's parser reject
/// the bytes, with zero build-dependencies: identity (magic,
/// ELFCLASS64, little-endian, version 1), ET_REL + EM_BPF (the only
/// shape bpf-linker emits), a section header table that exists, uses
/// 64-byte entries, and lies fully inside the file (bpf-linker places
/// it LAST, which makes this the truncation killer), and the three
/// sections aya's loader demands from this object: one program
/// section (tracepoint OR kprobe - the Phase 1 tap is a tracepoint;
/// the kprobe arm keeps the validator honest for later passes), the
/// maps section (legacy map definitions), and the license section
/// (the verifier refuses GPL-addressable programs without it).
pub(crate) fn validate_ebpf_object(data: &[u8]) -> Result<(), String> {
    if data.len() < 64 {
        return Err(format!(
            "too short to hold an ELF64 header: {} bytes",
            data.len()
        ));
    }
    if !data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Err("ELF magic missing (not an ELF file)".to_string());
    }
    if data[4] != 2 {
        return Err(format!("not ELFCLASS64: class {}", data[4]));
    }
    if data[5] != 1 {
        return Err(format!("not little-endian: data encoding {}", data[5]));
    }
    if data[6] != 1 {
        return Err(format!("unknown ELF version {}", data[6]));
    }
    let u16_at = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
    let u32_at =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let u64_at = |off: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[off..off + 8]);
        u64::from_le_bytes(b)
    };
    let e_type = u16_at(16);
    if e_type != 1 {
        return Err(format!("not ET_REL (relocatable): type {e_type}"));
    }
    let e_machine = u16_at(18);
    if e_machine != 247 {
        // 247 = EM_BPF - the only machine bpf-linker emits.
        return Err(format!("not EM_BPF: machine {e_machine}"));
    }
    let shoff = u64_at(0x28) as usize;
    let shentsize = u16_at(0x3A) as usize;
    let shnum = u16_at(0x3C) as usize;
    let shstrndx = u16_at(0x3E) as usize;
    if shentsize != 64 {
        return Err(format!("section entry size is {shentsize}, expected 64"));
    }
    let table_end = shoff
        .checked_add(
            shentsize
                .checked_mul(shnum)
                .ok_or("section table size overflow")?,
        )
        .ok_or("section table end overflow")?;
    if table_end > data.len() {
        return Err(format!(
            "section header table ({shoff}..{table_end}) lies past the file end ({} \
             bytes) - the object is truncated",
            data.len()
        ));
    }

    // The section-name string table: every sh_name is an offset into
    // it. Without it the demanded-sections check below is blind.
    if shstrndx >= shnum {
        return Err(format!(
            "section name string table index {shstrndx} is out of range ({shnum} sections)"
        ));
    }
    let str_base = shoff + shstrndx * 64;
    let str_offset = u64_at(str_base + 0x18) as usize;
    let str_size = u64_at(str_base + 0x20) as usize;
    let str_end = str_offset
        .checked_add(str_size)
        .ok_or("section name string table end overflow")?;
    if str_end > data.len() {
        return Err(format!(
            "section name string table ({str_offset}..{str_end}) lies past the file end \
             ({} bytes) - the object is truncated",
            data.len()
        ));
    }
    let strtab = &data[str_offset..str_end];
    let name_at = |offset: usize| -> Option<&str> {
        let bytes = strtab.get(offset..)?;
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).ok()
    };

    let mut has_program_section = false;
    let mut has_maps_section = false;
    let mut has_license_section = false;
    for i in 0..shnum {
        let base = shoff + i * 64;
        let sh_name = u32_at(base) as usize;
        let sh_offset = u64_at(base + 0x18) as usize;
        let sh_size = u64_at(base + 0x20) as usize;
        let sh_type = u32_at(base + 4);
        // NOBITS (8) occupies no file space; everything else must fit.
        if sh_type != 8 {
            let end = sh_offset
                .checked_add(sh_size)
                .ok_or("section end overflow")?;
            if end > data.len() {
                return Err(format!(
                    "section {i} ({sh_offset}..{end}) lies past the file end ({} \
                     bytes) - the object is truncated",
                    data.len()
                ));
            }
        }
        if let Some(name) = name_at(sh_name) {
            if name.starts_with("tracepoint") || name.starts_with("kprobe") {
                has_program_section = true;
            }
            if name == "maps" {
                has_maps_section = true;
            }
            if name == "license" {
                has_license_section = true;
            }
        }
    }
    if !has_program_section {
        return Err(
            "no tracepoint/kprobe program section found - aya's loader demands one".to_string(),
        );
    }
    if !has_maps_section {
        return Err("no maps section found - aya's loader demands one".to_string());
    }
    if !has_license_section {
        return Err("no license section found - the verifier demands one".to_string());
    }
    Ok(())
}

/// Strip the host-poison tokens from the inherited rustflags before
/// the nested bpfel build sees them: host-CPU and host-linker flags
/// are poison for a cross-build ("-Ctarget-cpu=native" lowers for the
/// BUILD host's ISA; "-Clinker=..." retargets the linker). Everything
/// else survives verbatim, so CI's `RUSTFLAGS="-D warnings"` contract
/// keeps covering the ebpf crate.
fn strip_host_poison_rustflags(cmd: &mut Command) {
    if let Some(value) = std::env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        match strip_host_poison(&value.to_string_lossy(), '\u{1f}') {
            Some(filtered) => {
                cmd.env("CARGO_ENCODED_RUSTFLAGS", filtered);
            }
            None => {
                cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
            }
        }
    }
    if let Some(value) = std::env::var_os("RUSTFLAGS") {
        match strip_host_poison(&value.to_string_lossy(), ' ') {
            Some(filtered) => {
                cmd.env("RUSTFLAGS", filtered);
            }
            None => {
                cmd.env_remove("RUSTFLAGS");
            }
        }
    }
}

/// The pure token filter behind the poison strip: `Some(joined)` when
/// any token was dropped, `None` when nothing changed (so the caller
/// can env_remove instead of re-setting an identical value).
fn strip_host_poison(value: &str, sep: char) -> Option<String> {
    let tokens: Vec<&str> = value
        .split(sep)
        .filter(|t| {
            let t = t.trim();
            !(t.contains("target-cpu")
                || t.contains("linker=")
                || t.contains("link-self-contained"))
        })
        .collect();
    let dropped = tokens.len() != value.split(sep).count();
    if dropped {
        Some(tokens.join(&sep.to_string()))
    } else {
        None
    }
}

/// Force the v3 BPF codegen level onto the nested build, whatever
/// survived the poison strip: the LLVM BPF backend selects the
/// BPF_ATOMIC RMW instructions (the stats counter needs them) only at
/// cpu v3. A set env variable SHADOWS config rustflags entirely, so
/// the flag is appended to whichever rustflags variable survived; with
/// neither variable set the ebpf/.cargo/config.toml supplies the same
/// flag.
fn force_bpf_v3_rustflags(cmd: &mut Command) {
    const FLAG: &str = "-Ctarget-cpu=v3";
    // An empty-but-SET variable is the same as unset for flag purposes
    // - appending to it would inject an empty token that rustc reads
    // as a phantom filename.
    let encoded = std::env::var_os("CARGO_ENCODED_RUSTFLAGS").filter(|v| !v.is_empty());
    if let Some(value) = encoded {
        let joined = format!("{}\u{1f}{FLAG}", value.to_string_lossy());
        cmd.env("CARGO_ENCODED_RUSTFLAGS", joined);
    } else {
        let plain = std::env::var_os("RUSTFLAGS").filter(|v| !v.is_empty());
        if let Some(value) = plain {
            let joined = format!("{} {FLAG}", value.to_string_lossy());
            cmd.env("RUSTFLAGS", joined);
        }
        // Neither variable set (or both empty): the ebpf/.cargo/config.toml
        // supplies the same flag to the nested build.
    }
}

// The build script's own test suite is NOT executed by `cargo test`
// (cargo never runs build-script tests) - it is a standing contract
// verified standalone alongside build.rs's suite:
//   rustc --edition 2021 --test build.rs -o /tmp/zejtron-build-test && /tmp/zejtron-build-test
// The suite lives in build/ebpf_tests.rs (the 600-LOC no-mercy split,
// night-improve-1): a pure move, same `super::` reach, same runner.

#[cfg(test)]
#[path = "ebpf_tests.rs"]
mod tests;
