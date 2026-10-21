// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Path security guard for zejtron's own state I/O.
//!
//! ## Scope
//!
//! zejtron is a Linux introspection tool — by design it reads arbitrary
//! user-specified paths (`zejtron why /etc/shadow`, `zejtron touch ~/.ssh/id_rsa`).
//! Those read-only investigation commands are NOT gated here.
//!
//! This module only protects zejtron's own STATE I/O. Its one
//! consumer — the retired environment-snapshot lane (a state
//! directory under `$XDG_DATA_HOME/zejtron/`, or
//! `~/.local/share/zejtron/`) — was removed in the v80 surface
//! reduction (night-improve-0): the
//! read-only claim is literal and zejtron no longer writes state.
//! The guard stays as the tested foundation for any future lane that
//! would reintroduce state I/O; nothing in the current tree writes.
//!
//! ## Threat model
//!
//! Without this guard, a malicious or careless environment could redirect
//! zejtron's state writes via `XDG_DATA_HOME=/etc` or `XDG_DATA_HOME=~/.ssh`,
//! causing state files to be written into protected directories. Writing
//! them into system or credential directories violates
//! the principle of least privilege and could mask other attacks.
//!
//! ## Policy
//!
//! The zejtron state directory must resolve to either:
//!   - `$XDG_DATA_HOME/zejtron/` (when XDG_DATA_HOME is set, non-empty, AND
//!     not a system/credential path), OR
//!   - `~/.local/share/zejtron/` (default)
//!
//! Any other location — including system paths (`/etc`, `/usr`, `/var`, etc.)
//! and user credential paths (`~/.ssh`, `~/.gnupg`) — is rejected with a
//! clear error message.
//!
//! ## Status
//!
//! Deliberately retained without a production caller (night-improve-0,
//! restated by the night-total-lts-3 audit): the retired
//! environment-snapshot lane was this module's one consumer, and the
//! read-only claim is literal - nothing in the current tree writes
//! state. The scoped dead-code allowance below covers exactly this
//! documented retention; the tests keep the guard honest while it
//! waits.

#![allow(dead_code)]

use std::path::{Component, Path, PathBuf};

/// Lexically normalize a path: collapse `.` and `..` components without
/// requiring the file to exist on disk. Does NOT follow symlinks.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    let _ = out.pop();
                }
                Some(Component::RootDir) | None => {}
                _ => {
                    let _ = out.pop();
                }
            },
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Canonicalize a path for comparison. Tries `std::fs::canonicalize` first
/// (resolves symlinks, requires existence); falls back to lexical
/// normalization for paths that don't exist yet.
fn canonical_for_compare(path: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    lexical_normalize(path).unwrap_or_else(|| path.to_path_buf())
}

/// Return true if the canonical path falls inside a known-dangerous prefix
/// that zejtron's state must NEVER touch — even if an XDG env var points
/// there.
fn is_dangerous(canonical: &Path) -> bool {
    let s = canonical.to_string_lossy();
    let home = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).to_string_lossy().into_owned())
        .unwrap_or_default();

    // System paths — never valid for zejtron state, even if XDG env vars
    // point here. zejtron is a user-space tool; its state must live under
    // the user's home or proper XDG dirs, NOT in /etc, /usr, /var, etc.
    let deny_prefixes: &[&str] = &[
        "/etc/", "/usr/", "/var/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/root/",
        "/proc/", "/sys/", "/dev/",
    ];

    for prefix in deny_prefixes {
        if s.starts_with(prefix) {
            return true;
        }
    }

    // User credential stores — never valid for zejtron state
    let user_deny_subdirs: &[&str] = &[".ssh/", ".gnupg/", ".kwallet/", ".local/share/keyrings/"];
    if !home.is_empty() {
        for sub in user_deny_subdirs {
            let full = format!("{home}/{sub}");
            if s.starts_with(&full) {
                return true;
            }
        }
    }

    false
}

/// Resolve the zejtron state directory (`$XDG_DATA_HOME/zejtron` or
/// `~/.local/share/zejtron`), rejecting dangerous XDG overrides.
///
/// Returns the canonicalized, validated directory path, or an error message
/// explaining why the resolved location is unsafe.
pub fn resolve_state_dir() -> Result<PathBuf, String> {
    let candidate: PathBuf =
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            PathBuf::from(&xdg).join("zejtron")
        } else {
            let home = std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "HOME is required when XDG_DATA_HOME is not set".to_string())?;
            PathBuf::from(home).join(".local/share/zejtron")
        };

    let canonical = canonical_for_compare(&candidate);
    if is_dangerous(&canonical) {
        return Err(format!(
            "zejtron state directory resolves to a protected path (blocked by pathguard): {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
#[path = "../../test/system/pathguard_tests.rs"]
mod tests;
