// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::process::Command;

const ALLOWED_PREFIXES: &[&str] = &[
    "git rev-parse --show-toplevel",
    "git rev-parse --abbrev-ref HEAD",
    "git rev-parse HEAD",
    "git rev-parse --abbrev-ref",
    "git rev-list --left-right --count",
    "git status --porcelain=v1 --branch",
    "git remote -v",
    "git log -1 --oneline",
    "git log -1 --format",
    "git stash list",
    "git describe --tags --always",
    "git symbolic-ref --short",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitReport {
    pub root: Option<String>,
    pub branch: Option<String>,
    pub is_detached: bool,
    pub head_hash: Option<String>,
    pub upstream: Option<String>,
    pub ahead: Option<usize>,
    pub behind: Option<usize>,
    pub status: StatusSummary,
    pub latest: Option<CommitInfo>,
    pub stash_count: usize,
    pub last_tag: Option<String>,
    pub remotes: Vec<RemoteEntry>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusSummary {
    Clean,
    Dirty { modified: usize, untracked: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub url: String,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let report = collect_report();
    println!("{}", render_report(&report));
    Ok(())
}

fn git_cmd(args: &[&str]) -> Option<String> {
    let full = format!("git {}", args.join(" "));
    if !ALLOWED_PREFIXES.iter().any(|p| full.starts_with(p)) {
        return None;
    }

    let output = Command::new("git").args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn collect_report() -> GitReport {
    if !git_available() {
        return GitReport {
            root: None,
            branch: None,
            is_detached: false,
            head_hash: None,
            upstream: None,
            ahead: None,
            behind: None,
            status: StatusSummary::Clean,
            latest: None,
            stash_count: 0,
            last_tag: None,
            remotes: vec![],
            error: Some("git binary not found".to_owned()),
        };
    }

    let root = git_cmd(&["rev-parse", "--show-toplevel"]);

    if root.is_none() {
        return GitReport {
            root: None,
            branch: None,
            is_detached: false,
            head_hash: None,
            upstream: None,
            ahead: None,
            behind: None,
            status: StatusSummary::Clean,
            latest: None,
            stash_count: 0,
            last_tag: None,
            remotes: vec![],
            error: Some("not inside a git repository".to_owned()),
        };
    }

    let branch_raw = git_cmd(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let is_detached = branch_raw.as_deref() == Some("HEAD");
    let branch = if is_detached {
        None
    } else {
        branch_raw.clone()
    };

    let head_hash = git_cmd(&["rev-parse", "HEAD"]);

    // Upstream tracking branch
    let upstream = git_cmd(&[
        "rev-parse",
        "--abbrev-ref",
        "--symbolic-full-name",
        "@{upstream}",
    ]);

    // Ahead/behind count vs upstream
    let (ahead, behind) = if upstream.is_some() {
        parse_ahead_behind(git_cmd(&[
            "rev-list",
            "--left-right",
            "--count",
            "@{upstream}...HEAD",
        ]))
    } else {
        (None, None)
    };

    let status_output = git_cmd(&["status", "--porcelain=v1", "--branch"]);

    // Full commit info: hash|author|email|date|subject
    let latest = parse_commit_info(git_cmd(&["log", "-1", "--format=%h|%an|%ae|%ad|%s"]));

    let stash_count = git_cmd(&["stash", "list"])
        .map(|s| s.lines().count())
        .unwrap_or(0);

    let last_tag = git_cmd(&["describe", "--tags", "--always"]);

    let remote_output = git_cmd(&["remote", "-v"]);

    let status = parse_status(status_output.as_deref());
    let remotes = parse_remotes(remote_output.as_deref());

    GitReport {
        root,
        branch,
        is_detached,
        head_hash,
        upstream,
        ahead,
        behind,
        status,
        latest,
        stash_count,
        last_tag,
        remotes,
        error: None,
    }
}

/// Parse "ahead\tbehind" output from `git rev-list --left-right --count @{upstream}...HEAD`.
fn parse_ahead_behind(output: Option<String>) -> (Option<usize>, Option<usize>) {
    let Some(s) = output else {
        return (None, None);
    };
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 2 {
        return (None, None);
    }
    let behind = parts[0].parse::<usize>().ok();
    let ahead = parts[1].parse::<usize>().ok();
    (ahead, behind)
}

/// Parse "hash|author|email|date|subject" into CommitInfo.
fn parse_commit_info(output: Option<String>) -> Option<CommitInfo> {
    let s = output?;
    let parts: Vec<&str> = s.splitn(5, '|').collect();
    if parts.len() != 5 {
        return None;
    }
    Some(CommitInfo {
        hash: parts[0].to_owned(),
        author: parts[1].to_owned(),
        email: parts[2].to_owned(),
        date: parts[3].to_owned(),
        subject: parts[4].to_owned(),
    })
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn parse_status(output: Option<&str>) -> StatusSummary {
    let Some(text) = output else {
        return StatusSummary::Clean;
    };

    let mut modified = 0usize;
    let mut untracked = 0usize;

    for line in text.lines() {
        if line.starts_with("## ") {
            continue;
        }
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            continue;
        }
        if bytes[0] == b'?' {
            untracked += 1;
        } else if bytes[0] != b' ' || bytes.get(1).is_some_and(|&b| b != b' ') {
            modified += 1;
        }
    }

    if modified == 0 && untracked == 0 {
        StatusSummary::Clean
    } else {
        StatusSummary::Dirty {
            modified,
            untracked,
        }
    }
}

/// Redact userinfo (credentials) from remote URLs.
///
/// Only HTTP/HTTPS-style URLs with userinfo are modified:
///   `https://TOKEN@host/path`  -> `https://<redacted>@host/path`
///   `https://USER:TOKEN@host`   -> `https://<redacted>@host`
///   `http://USER:TOKEN@host`    -> `http://<redacted>@host`
///   `git+https://TOKEN@host`    -> `git+https://<redacted>@host`
///
/// Safe URLs are returned unchanged:
///   `git@host:path`, `ssh://git@host/path`,
///   `https://host/path` (no userinfo), `file:///path`
pub fn sanitize_remote_url(url: &str) -> String {
    // We only redact credentials from http/https-style URLs.
    // SSH URLs (scp-style or ssh://), file://, and other schemes are safe.
    if !url.starts_with("http://")
        && !url.starts_with("https://")
        && !url.starts_with("git+http://")
        && !url.starts_with("git+https://")
    {
        return url.to_owned();
    }

    // URLs without @ have no userinfo to redact.
    let at_pos = match url.rfind('@') {
        Some(pos) => pos,
        None => return url.to_owned(),
    };

    // scheme_end points past "://" — e.g. "https://".len() == 8.
    let scheme_end = url.find("://").map(|p| p + 3).unwrap();

    // The @ must come after the scheme:// for this to be a credential-bearing URL.
    if at_pos <= scheme_end {
        return url.to_owned();
    }

    // Reconstruct: scheme://<redacted>@rest
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..scheme_end]);
    out.push_str("<redacted>");
    out.push_str(&url[at_pos..]);
    out
}

pub fn parse_remotes(output: Option<&str>) -> Vec<RemoteEntry> {
    let Some(text) = output else {
        return vec![];
    };

    let mut entries: Vec<RemoteEntry> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0];
        let url = parts[1];

        if seen.contains(&name.to_owned()) {
            continue;
        }
        seen.push(name.to_owned());

        entries.push(RemoteEntry {
            name: name.to_owned(),
            url: sanitize_remote_url(url),
        });
    }

    entries
}

#[cfg(test)]
pub fn parse_latest_commit(output: Option<&str>) -> Option<String> {
    output.map(|s| s.to_owned())
}

pub fn render_report(report: &GitReport) -> String {
    if let Some(ref error) = report.error {
        return format!("git\n└── {error}");
    }

    let has_remotes = !report.remotes.is_empty();
    let mut items: Vec<String> = Vec::new();

    if let Some(ref root) = report.root {
        items.push(format!("root: {root}"));
    }

    if report.is_detached {
        items.push("branch: (detached HEAD)".to_owned());
    } else if let Some(ref branch_name) = report.branch {
        let mut line = format!("branch: {branch_name}");
        if let Some(ref up) = report.upstream {
            line.push_str(&format!(" <- {up}"));
            let mut ab = Vec::new();
            if let Some(a) = report.ahead
                && a > 0
            {
                ab.push(format!("↑{a}"));
            }
            if let Some(b) = report.behind
                && b > 0
            {
                ab.push(format!("↓{b}"));
            }
            if !ab.is_empty() {
                line.push_str(&format!(" ({})", ab.join(" ")));
            }
        } else {
            line.push_str(" <- (no upstream)");
        }
        items.push(line);
    }

    if let Some(ref hash) = report.head_hash {
        items.push(format!("head: {hash}"));
    }

    let status_label = match &report.status {
        StatusSummary::Clean => "clean".to_owned(),
        StatusSummary::Dirty {
            modified,
            untracked,
        } => format!("dirty ({modified} modified, {untracked} untracked)"),
    };
    items.push(format!("status: {status_label}"));

    if let Some(ref commit) = report.latest {
        items.push(format!(
            "latest: {} {} <{}> {}",
            commit.hash, commit.author, commit.email, commit.subject
        ));
        items.push(format!("        {}", commit.date));
    }

    if report.stash_count > 0 {
        items.push(format!("stash: {} entries", report.stash_count));
    }

    if let Some(ref tag) = report.last_tag {
        items.push(format!("describe: {tag}"));
    }

    let mut lines = vec!["git".to_owned()];

    for (i, item) in items.iter().enumerate() {
        let is_last = !has_remotes && i + 1 == items.len();
        let branch = if is_last { "└" } else { "├" };
        lines.push(format!("{branch}── {item}"));
    }

    if has_remotes {
        lines.push("└── remotes".to_owned());
        for (i, remote) in report.remotes.iter().enumerate() {
            let is_last = i + 1 == report.remotes.len();
            let leaf = if is_last { "└──" } else { "├──" };
            lines.push(format!("    {leaf} {} {}", remote.name, remote.url));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
#[path = "../../test/commands/git_tests.rs"]
mod tests;
