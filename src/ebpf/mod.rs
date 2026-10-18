// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The userspace eBPF surface (night-improve-1, the zelynic/zylaxion
//! lineage discipline): the chain - load, verifier, tracepoint,
//! counter, readback, detach - as infrastructure only. No command
//! consumes the counter yet; only `doctor` reads it.
//!
//! Three concerns in this entry module, shared by both build lanes:
//!
//! - the pin path constants (single source of truth for everything
//!   the tap leaves at /sys/fs/bpf/zejtron - the loader writes them,
//!   the doctor stats them, `bpftool` prints them verbatim);
//! - the kernel facts probe (std-only: /proc/sys/kernel/osrelease,
//!   /sys/kernel/btf/vmlinux, /sys/kernel/security/lockdown,
//!   /proc/self/status CapEff - no subprocess, no PATH dependency,
//!   no libc; the precise instrument for a kernel-facing lane);
//! - the AlignedElf embedding wrapper (feature builds only).
//!
//! The verb surface both lanes expose - [`attach`] and [`detach`] -
//! carries the same signature whether the binary was built with the
//! `ebpf` feature or not: the dormant lane returns the honest refusal
//! instead of pretending.
//!
//! The loader and the counter readback (the `loader` and
//! `readback` modules) compile only under the `ebpf` feature; the
//! kernel facts and pin paths compile always because the doctor's
//! \[eBPF\] section is always present and always honest about what
//! this binary can do.

use std::path::Path;

/// Root pin directory on bpffs. Everything zejtron leaves in the
/// kernel lives under this one directory - `detach` removes it whole.
pub const PIN_DIR: &str = "/sys/fs/bpf/zejtron";

/// Program pin (the tap program itself, for introspection and reload).
pub const PIN_PROG: &str = "/sys/fs/bpf/zejtron/tap";

/// Link pin (the attachment - this is what keeps the tap alive after
/// the attach process exits; unlinking it detaches the tap).
pub const PIN_LINK: &str = "/sys/fs/bpf/zejtron/tap_link";

/// Map pin - the stats counter (`stats[0]` counts sched_process_exec
/// events since attach; the doctor reads it through this pin).
pub const PIN_MAP_STATS: &str = "/sys/fs/bpf/zejtron/stats";

/// Every pin the attach lane plants, in removal order (link first -
/// unlinking the link detaches the tap; program and map last).
pub const ALL_PINS: [&str; 3] = [PIN_LINK, PIN_PROG, PIN_MAP_STATS];

/// True when every pin of a complete attach exists. A partial pin set
/// (a crashed attach, a manual rm) reads as NOT attached - `attach`
/// cleans and replants, the doctor names the partial set.
pub fn all_pins_present() -> bool {
    ALL_PINS.iter().all(|p| Path::new(p).exists())
}

/// True when at least one pin exists - the "zejtron left something in
/// the kernel" signal the doctor's Pins row and `attach`'s self-heal
/// path read.
pub fn any_pin_present() -> bool {
    ALL_PINS.iter().any(|p| Path::new(p).exists())
}

// ── The kernel facts probe (std-only, both build lanes) ──────────────

/// The kernel's lockdown verdict, from /sys/kernel/security/lockdown.
/// The active mode is the bracketed entry ("\[none\] integrity
/// confidentiality"); an absent interface means the lockdown LSM is
/// not compiled in and cannot block anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockdownMode {
    /// No lockdown (the bracketed entry is `[none]`, or the interface
    /// is absent - the LSM is not in the kernel).
    None,
    /// `[integrity]` - kernel-integrity lockdown; blocks eBPF program
    /// loads.
    Integrity,
    /// `[confidentiality]` - the strict mode; blocks eBPF program
    /// loads.
    Confidentiality,
    /// The interface exists but this process may not read it (the
    /// file is root-only on hardened hosts). The attach attempt
    /// itself names the verdict if lockdown blocks it - the doctor
    /// never guesses.
    Unknown,
}

impl LockdownMode {
    /// The row label for the doctor's \[eBPF\] section.
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Integrity => "integrity",
            Self::Confidentiality => "confidentiality",
            Self::Unknown => "unknown (unreadable)",
        }
    }

    /// True when this mode blocks eBPF program loads.
    pub fn blocks_bpf(self) -> bool {
        matches!(self, Self::Integrity | Self::Confidentiality)
    }
}

/// The kernel floor for the eBPF lane: 5.15 (the verified floor the
/// zelynic/zylaxion lineages pin; the BPF_ATOMIC v3 bytecode and the
/// tracepoint surfaces are all inside it).
pub const KERNEL_FLOOR: (u32, u32) = (5, 15);

/// Every kernel fact the \[eBPF\] lane decisions ride on, probed once
/// and shared by the doctor's section and the attach preflight - one
/// probe, one verdict, no drift between the two surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFacts {
    /// The kernel release ("5.15.0-arch1-1" shape), from
    /// /proc/sys/kernel/osrelease. `None` when unreadable - rare, but
    /// the verdict names it honestly.
    pub release: Option<String>,
    /// /sys/kernel/btf/vmlinux exists (needed by the verifier for
    /// BTF-powered loads; Phase 1's tracepoint object carries legacy
    /// map definitions, but BTF presence is still reported - later
    /// phases lean on it).
    pub btf_present: bool,
    /// The lockdown verdict.
    pub lockdown: LockdownMode,
    /// CAP_BPF (bit 39) in the effective capability set.
    pub cap_bpf: bool,
    /// CAP_PERFMON (bit 38) in the effective capability set.
    pub cap_perfmon: bool,
}

impl KernelFacts {
    /// The release for display: the probed string or "unknown".
    pub fn release_label(&self) -> &str {
        self.release.as_deref().unwrap_or("unknown")
    }

    /// True when the release meets the 5.15 floor. An unparsable or
    /// unreadable release is NOT a pass - the lane refuses what it
    /// cannot verify.
    pub fn kernel_meets_floor(&self) -> bool {
        let Some((major, minor)) = self.release.as_deref().and_then(parse_kernel_version) else {
            return false;
        };
        (major, minor) >= KERNEL_FLOOR
    }

    /// True when the effective capability set carries both CAP_BPF
    /// and CAP_PERFMON - what a tracepoint load needs on 5.8+. The
    /// CapEff line is the truth regardless of euid: a container root
    /// without the bits reads honestly as incapable.
    pub fn caps_sufficient(&self) -> bool {
        self.cap_bpf && self.cap_perfmon
    }

    /// The honest caps row label: which of the two capabilities is
    /// missing, named.
    pub fn caps_label(&self) -> String {
        match (self.cap_bpf, self.cap_perfmon) {
            (true, true) => "CAP_BPF + CAP_PERFMON present".to_owned(),
            (true, false) => "missing (CAP_PERFMON)".to_owned(),
            (false, true) => "missing (CAP_BPF)".to_owned(),
            (false, false) => "missing (CAP_BPF + CAP_PERFMON)".to_owned(),
        }
    }
}

/// Parse "major.minor" out of a kernel release string ("5.15.0-xyz",
/// "6.1.11", "5.10.134-013.15.kangaroo.al8.x86_64"). Returns None for
/// anything that does not open with two numeric components.
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The doctor's \[eBPF\] section lane verdict, computed from the kernel
/// facts and the pin state. The dormant verdict is a property of the
/// BINARY (the feature is compile-time), so a featureless build never
/// claims any live lane no matter what the host allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneVerdict {
    /// The binary carries the loader, the host allows attach, nothing
    /// is attached: `doctor --attach` plants the tap.
    Live,
    /// The binary carries the loader and every pin of a complete
    /// attach exists: the tap is counting. The event count and the
    /// attach moment are read separately (the count needs the map
    /// readback, which only feature builds have).
    LiveAttached,
    /// The lane cannot run here, and the string names exactly why
    /// (kernel below the floor, lockdown active, capabilities
    /// missing).
    Snapshot(String),
    /// This binary was built without the ebpf feature: the honest
    /// refusal, never a fake lane.
    Dormant,
}

/// Classify the lane from the probed facts. The order is the doctor
/// contract's order: the kernel floor and lockdown first (a host that
/// blocks eBPF blocks it whether or not something is attached), the
/// pin state second (an attached tap reports live even from an
/// unprivileged doctor - reading the pinned counter needs no
/// capabilities, only the bpffs walk), the capabilities last (they
/// gate ATTACH, not the read side).
pub fn lane_verdict(facts: &KernelFacts) -> LaneVerdict {
    if !cfg!(feature = "ebpf") {
        return LaneVerdict::Dormant;
    }
    if !facts.kernel_meets_floor() {
        return LaneVerdict::Snapshot(format!(
            "kernel {} is below the {} floor",
            facts.release_label(),
            floor_label()
        ));
    }
    if facts.lockdown.blocks_bpf() {
        return LaneVerdict::Snapshot(format!("lockdown {} blocks eBPF", facts.lockdown.label()));
    }
    if all_pins_present() {
        return LaneVerdict::LiveAttached;
    }
    if any_pin_present() {
        // A partial pin set (an interrupted attach): the lane itself
        // is healthy, `doctor --attach` heals the set. Not "attached"
        // - the counter cannot be trusted from a half state.
        return LaneVerdict::Live;
    }
    if !facts.caps_sufficient() {
        return LaneVerdict::Snapshot(format!(
            "no CAP_BPF/CAP_PERFMON ({}) - attach needs root",
            facts.caps_label()
        ));
    }
    LaneVerdict::Live
}

/// The floor as a display label ("5.15").
pub fn floor_label() -> String {
    format!("{}.{}", KERNEL_FLOOR.0, KERNEL_FLOOR.1)
}

/// Probe every kernel fact the lane decisions ride on. std-only: no
/// subprocess, no PATH dependency, no libc - the same
/// read-the-source discipline the rest of zejtron applies to /proc.
pub fn probe_kernel() -> KernelFacts {
    KernelFacts {
        release: read_kernel_release(),
        btf_present: Path::new("/sys/kernel/btf/vmlinux").exists(),
        lockdown: probe_lockdown(),
        cap_bpf: cap_bit_present(CAP_BPF),
        cap_perfmon: cap_bit_present(CAP_PERFMON),
    }
}

/// CAP_BPF, capability bit 39 (Linux 5.8+).
const CAP_BPF: u32 = 39;

/// CAP_PERFMON, capability bit 38 (Linux 5.8+).
const CAP_PERFMON: u32 = 38;

/// Read the kernel release from /proc/sys/kernel/osrelease (the same
/// string `uname -r` prints, without the subprocess).
fn read_kernel_release() -> Option<String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let release = release.trim();
    if release.is_empty() {
        None
    } else {
        Some(release.to_owned())
    }
}

/// Read the lockdown verdict. The file's active mode is the bracketed
/// entry; an absent file means the LSM is not in the kernel (none).
fn probe_lockdown() -> LockdownMode {
    let Ok(content) = std::fs::read_to_string("/sys/kernel/security/lockdown") else {
        // Absent: the lockdown LSM is not compiled in - nothing can
        // be locked down. (A permission denial on a present file is
        // the unreadable case, handled by the same arm honestly
        // below: the doctor never guesses a mode it cannot read, but
        // an absent interface is a fact, not a guess.)
        if std::path::Path::new("/sys/kernel/security/lockdown").exists() {
            return LockdownMode::Unknown;
        }
        return LockdownMode::None;
    };
    let content = content.trim();
    if content.contains("[integrity]") {
        LockdownMode::Integrity
    } else if content.contains("[confidentiality]") {
        LockdownMode::Confidentiality
    } else if content.contains("[none]") {
        LockdownMode::None
    } else {
        LockdownMode::Unknown
    }
}

/// True when `bit` is set in the process's effective capability set
/// (the CapEff line of /proc/self/status, the kernel's own truth
/// about what this process may do - not a guess from euid).
fn cap_bit_present(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("CapEff:") else {
            continue;
        };
        let hex = rest.trim();
        // CapEff is a 64-bit mask in hexadecimal, no 0x prefix. Bits
        // past the parsed width (an empty or short line) read as
        // absent - the honest direction.
        let Ok(mask) = u64::from_str_radix(hex, 16) else {
            return false;
        };
        return mask & (1u64 << bit) != 0;
    }
    false
}

// ── The AlignedElf embedding (feature builds only) ───────────────────

#[cfg(feature = "ebpf")]
pub mod embedded;

/// The loader (attach/detach) and the counter readback - feature
/// builds only.
#[cfg(feature = "ebpf")]
pub mod loader;
#[cfg(feature = "ebpf")]
pub mod readback;

/// The verb surface both lanes expose: the same signatures, so the
/// doctor's dispatch cannot tell them apart.
#[cfg(feature = "ebpf")]
pub use loader::{attach, detach};

/// The dormant lane: the same signatures, the honest refusal.
#[cfg(not(feature = "ebpf"))]
pub use dormant::{attach, detach};

/// The dormant lane (a binary built without the `ebpf` feature): the
/// verbs exist, the answer is the refusal - never a fake success,
/// never a silent no-op.
#[cfg(not(feature = "ebpf"))]
pub mod dormant {
    /// The refusal text both dormant verbs return.
    pub const DORMANT_REFUSAL: &str = "this binary was built without the ebpf feature - rebuild with \
         --features ebpf to attach the tap";

    /// Dormant attach: refuse (nothing this binary could plant).
    pub fn attach() -> Result<String, String> {
        Err(DORMANT_REFUSAL.to_owned())
    }

    /// Dormant detach: refuse (the pins belong to a feature-built
    /// binary; this one cannot know their state honestly, and a fake
    /// "nothing to detach" success would be worse than the refusal).
    pub fn detach() -> Result<String, String> {
        Err(DORMANT_REFUSAL.to_owned())
    }
}

#[cfg(test)]
#[path = "../../test/ebpf/lane_tests.rs"]
mod tests;
