// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The eBPF staging module's test suite (night-improve-1), split out
//! of build/ebpf.rs per the 600-LOC no-mercy cap - a pure move: the
//! same `super::` reach into build/ebpf.rs's private surface, wired by
//! `#[cfg(test)] #[path = "ebpf_tests.rs"] mod tests;` there. Never
//! executed by `cargo test` (cargo does not run build-script tests);
//! the standing contract is the standalone runner:
//!   rustc --edition 2021 --test build.rs -o /tmp/zejtron-build-test && /tmp/zejtron-build-test

use super::*;

/// Build a minimal ET_REL EM_BPF little-endian ELF64 in memory:
/// an ELF header, three named sections (the names given), and a
/// section header table with a section-name string table. Every
/// field the validator reads is placed at its ABI offset.
fn minimal_bpf_elf(section_names: &[&str]) -> Vec<u8> {
    // The section-name string table always starts with the
    // required NUL byte; each name is NUL-terminated.
    let mut strtab: Vec<u8> = vec![0u8];
    let mut name_offsets: Vec<u32> = Vec::new();
    for name in section_names {
        name_offsets.push(u32::try_from(strtab.len()).unwrap());
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
    }
    // Layout: ELF header (64) + strtab + one byte of section
    // payload per section, then the section header table
    // (shstrndx included as the last entry).
    let mut buf = vec![0u8; 64];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // little-endian
    buf[6] = 1; // version 1
    buf[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    buf[18..20].copy_from_slice(&247u16.to_le_bytes()); // EM_BPF
    let strtab_offset = 64usize;
    buf.extend_from_slice(&strtab);
    let payload_offset = buf.len();
    for _ in section_names {
        buf.push(0); // one byte of section payload each
    }
    let shoff = buf.len();
    let shnum = section_names.len() + 1; // sections + shstrtab
    let str_size = strtab.len();
    // The section header table: shnum entries of 64 bytes each, zeroed
    // first so the per-entry copies below stay in range (the table
    // lies past the payload, at the file's end).
    buf.resize(shoff + shnum * 64, 0);
    // The sections themselves (one payload byte each).
    for (i, offset) in name_offsets.iter().enumerate() {
        let base = shoff + i * 64;
        let mut entry = vec![0u8; 64];
        entry[0..4].copy_from_slice(&offset.to_le_bytes());
        entry[4..8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
        let sh_offset = payload_offset + i;
        entry[0x18..0x20].copy_from_slice(&(sh_offset as u64).to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&1u64.to_le_bytes()); // one byte
        buf[base..base + 64].copy_from_slice(&entry);
    }
    // The section-name string table entry, last.
    let str_base = shoff + section_names.len() * 64;
    let mut str_entry = vec![0u8; 64];
    str_entry[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
    str_entry[0x18..0x20].copy_from_slice(&(strtab_offset as u64).to_le_bytes());
    str_entry[0x20..0x28].copy_from_slice(&(str_size as u64).to_le_bytes());
    buf[str_base..str_base + 64].copy_from_slice(&str_entry);
    // Header fields: section table position and count.
    buf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    buf[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // shentsize
    buf[0x3C..0x3E].copy_from_slice(&(u16::try_from(shnum).unwrap()).to_le_bytes());
    buf[0x3E..0x40].copy_from_slice(
        &(u16::try_from(shnum - 1).unwrap()).to_le_bytes(), // shstrndx
    );
    buf
}

#[test]
fn ebpf_object_validator_accepts_the_tap_shape() {
    // The Phase 1 tap shape: one tracepoint program section, the
    // maps section, the license section.
    let elf = minimal_bpf_elf(&["tracepoint/sched_process_exec", "maps", "license"]);
    assert_eq!(validate_ebpf_object(&elf), Ok(()));
}

#[test]
fn ebpf_object_validator_accepts_the_kprobe_arm() {
    // Later passes may ship kprobe programs; the validator's
    // program-section arm accepts them.
    let elf = minimal_bpf_elf(&["kprobe/input_event", "maps", "license"]);
    assert_eq!(validate_ebpf_object(&elf), Ok(()));
}

#[test]
fn ebpf_object_validator_names_each_missing_section() {
    // No program section.
    let elf = minimal_bpf_elf(&["maps", "license"]);
    assert!(
        validate_ebpf_object(&elf)
            .unwrap_err()
            .starts_with("no tracepoint/kprobe program section")
    );
    // No maps section.
    let elf = minimal_bpf_elf(&["tracepoint/sched_process_exec", "license"]);
    assert!(
        validate_ebpf_object(&elf)
            .unwrap_err()
            .starts_with("no maps section")
    );
    // No license section.
    let elf = minimal_bpf_elf(&["tracepoint/sched_process_exec", "maps"]);
    assert!(
        validate_ebpf_object(&elf)
            .unwrap_err()
            .starts_with("no license section")
    );
}

#[test]
fn ebpf_object_validator_rejects_damage() {
    // Too short.
    assert!(
        validate_ebpf_object(&[0x7f, b'E', b'L', b'F'])
            .unwrap_err()
            .starts_with("too short")
    );
    // Not ELF at all.
    let mut elf = minimal_bpf_elf(&["tracepoint/x", "maps", "license"]);
    elf[0] = 0x00;
    assert!(
        validate_ebpf_object(&elf)
            .unwrap_err()
            .starts_with("ELF magic missing")
    );
    // Wrong machine (not EM_BPF).
    let mut elf = minimal_bpf_elf(&["tracepoint/x", "maps", "license"]);
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    assert!(
        validate_ebpf_object(&elf)
            .unwrap_err()
            .starts_with("not EM_BPF")
    );
    // Truncated: the section header table past the file end.
    let elf = minimal_bpf_elf(&["tracepoint/x", "maps", "license"]);
    let cut = elf.len() - 40;
    assert!(
        validate_ebpf_object(&elf[..cut])
            .unwrap_err()
            .contains("truncated")
    );
}

#[test]
fn rustflags_poison_strip_drops_host_tokens_only() {
    // Space-separated RUSTFLAGS form.
    assert_eq!(
        strip_host_poison("-D warnings -Ctarget-cpu=native", ' ').as_deref(),
        Some("-D warnings")
    );
    // Encoded form (unit separator).
    assert_eq!(
        strip_host_poison("-D\u{1f}warnings\u{1f}-Clinker=clang", '\u{1f}').as_deref(),
        Some("-D\u{1f}warnings")
    );
    // Clean flags pass through untouched (None = nothing dropped).
    assert_eq!(strip_host_poison("-D warnings", ' '), None);
    // Empty string is nothing to strip.
    assert_eq!(strip_host_poison("", ' '), None);
}
