// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::process::Command;

const GITHUB_API_URL: &str = "https://api.github.com/repos/oxyzenQ/zejtron/releases/latest";
const RELEASES_URL: &str = "https://github.com/oxyzenQ/zejtron/releases/latest";

#[derive(Debug, PartialEq, Eq)]
enum UpdateStatus {
    UpToDate,
    UpdateAvailable,
    CurrentIsNewer,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SemVer {
    fn parse(version: &str) -> Option<Self> {
        let version = version.trim();
        let version = version.strip_prefix('v').unwrap_or(version);
        let version = version
            .split_once('-')
            .map_or(version, |(stable, _)| stable);
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

fn normalize_version(version: &str) -> String {
    let version = version.trim();
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn compare_versions(current: &str, latest: &str) -> UpdateStatus {
    match (SemVer::parse(current), SemVer::parse(latest)) {
        (Some(current), Some(latest)) if current == latest => UpdateStatus::UpToDate,
        (Some(current), Some(latest)) if current > latest => UpdateStatus::CurrentIsNewer,
        _ => UpdateStatus::UpdateAvailable,
    }
}

fn extract_tag_name(json: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let rest = json.get(json.find(key)? + key.len()..)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// True when the tag carries no control characters (C0 controls or
/// DEL). Everything else - printable ASCII and UTF-8 multibyte -
/// passes; the bytes that could weaponize a terminal never do.
fn tag_is_safe(tag: &str) -> bool {
    tag.bytes().all(|b| !(b < 0x20 || b == 0x7f))
}

fn curl_failure(code: i32) -> &'static str {
    match code {
        6 => "DNS resolution failed",
        7 => "connection refused",
        28 => "network request timed out",
        35 => "SSL/TLS handshake failed",
        _ => "network request failed",
    }
}

fn http_failure(code: u16) -> &'static str {
    match code {
        403 => "GitHub API request was rate-limited or forbidden",
        404 => "no latest GitHub release found for oxyzenQ/zejtron",
        _ => "GitHub API returned an unexpected error",
    }
}

pub fn check_update(current_version: &str) -> Result<(), String> {
    // The network surface must never ride root privileges (the
    // sibling contract): refuse euid 0 before any network I/O with
    // the one behavioral rule that matters - a clear error message,
    // not a foot-gun.
    if crate::process::effective_uid() == Some(0) {
        return Err(
            "update check refuses root - re-run without sudo (the network surface must never ride root privileges)"
                .to_owned(),
        );
    }

    let output = Command::new("curl")
        .args([
            "--silent",
            "--max-time",
            "15",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "User-Agent: zejtron",
            "--write-out",
            "\n%{http_code}",
            GITHUB_API_URL,
        ])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "curl is not available on PATH".to_string()
            } else {
                format!("failed to run curl: {e}")
            }
        })?;

    if !output.status.success() {
        return Err(curl_failure(output.status.code().unwrap_or(-1)).to_string());
    }

    let raw =
        String::from_utf8(output.stdout).map_err(|_| "response was not valid UTF-8".to_string())?;
    let (body, status) = raw
        .rsplit_once('\n')
        .ok_or_else(|| "GitHub API response was malformed".to_string())?;
    let status = status.trim().parse::<u16>().unwrap_or(0);
    if status != 200 {
        return Err(http_failure(status).to_string());
    }

    let latest_tag = extract_tag_name(body)
        .ok_or_else(|| "could not parse latest release tag from GitHub response".to_string())?;
    // Fail-closed tag safety: the tag is untrusted input that reaches
    // the terminal verbatim, so a response whose tag field carries
    // control characters (escape sequences, OSC 52 clipboard
    // rewrites, output forging) is rejected outright - never
    // sanitized into something else, never printed. Printable ASCII
    // and UTF-8 pass; C0 controls and DEL fail.
    if !tag_is_safe(&latest_tag) {
        return Err(
            "GitHub API response contained an invalid release tag (control characters)".to_owned(),
        );
    }
    // The status word is a verdict token, so it rides the owner's
    // tier colors: an affirmative "up to date" verdict is green, an
    // "update available" attention verdict is warning yellow, and
    // the informational "current is newer" curiosity state stays
    // plain - it asks for no action. In Mono mode (piped, NO_COLOR)
    // all three render as their plain text.
    let status = match compare_versions(current_version, &latest_tag) {
        UpdateStatus::UpToDate => crate::output::ok("up to date"),
        UpdateStatus::UpdateAvailable => crate::output::warn("update available"),
        UpdateStatus::CurrentIsNewer => "current is newer than latest release".to_owned(),
    };

    println!("zejtron update check");
    println!("Current: {}", normalize_version(current_version));
    println!("Latest:  {}", normalize_version(&latest_tag));
    println!("Status:  {status}");
    println!("Source:  {RELEASES_URL}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tag_name() {
        assert_eq!(
            extract_tag_name(r#"{"tag_name":"v2.4.3"}"#),
            Some("v2.4.3".to_string())
        );
    }

    #[test]
    fn tag_safety_rejects_control_characters_and_accepts_printable() {
        // Every control byte class a terminal-attack payload would
        // ride: ESC (0x1b), newline, carriage return, tab, NUL, DEL.
        assert!(!tag_is_safe("\x1b]52;c;"));
        assert!(!tag_is_safe("v1\n.0"));
        assert!(!tag_is_safe("v1\r.0"));
        assert!(!tag_is_safe("v1\t.0"));
        assert!(!tag_is_safe("v1\0.0"));
        assert!(!tag_is_safe("v1\x7f.0"));
        // Honest tags pass, including non-ASCII multibyte (only
        // control bytes fail - the 0x80+ range rides UTF-8 legally).
        assert!(tag_is_safe("v80.0.0"));
        assert!(tag_is_safe("v11.0.0-beta.1"));
        assert!(tag_is_safe("v11.0.0-caf\u{e9}"));
    }

    #[test]
    fn compares_versions() {
        assert_eq!(compare_versions("2.4.3", "v2.4.3"), UpdateStatus::UpToDate);
        assert_eq!(
            compare_versions("2.4.2", "v2.4.3"),
            UpdateStatus::UpdateAvailable
        );
        assert_eq!(
            compare_versions("2.5.0", "v2.4.3"),
            UpdateStatus::CurrentIsNewer
        );
    }
}
