// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: MIT

use std::error::Error;
use std::process::Command;

const ALLOWED_PREFIXES: &[&str] = &[
    "git rev-parse --show-toplevel",
    "git rev-parse --abbrev-ref HEAD",
    "git status --porcelain=v1 --branch",
    "git remote -v",
    "git log -1 --oneline",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitReport {
    pub root: Option<String>,
    pub branch: Option<String>,
    pub status: StatusSummary,
    pub latest: Option<String>,
    pub remotes: Vec<RemoteEntry>,
    pub error: Option<String>,
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
            status: StatusSummary::Clean,
            latest: None,
            remotes: vec![],
            error: Some("git binary not found".to_owned()),
        };
    }

    let root = git_cmd(&["rev-parse", "--show-toplevel"]);

    if root.is_none() {
        return GitReport {
            root: None,
            branch: None,
            status: StatusSummary::Clean,
            latest: None,
            remotes: vec![],
            error: Some("not inside a git repository".to_owned()),
        };
    }

    let branch = git_cmd(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let status_output = git_cmd(&["status", "--porcelain=v1", "--branch"]);
    let latest = git_cmd(&["log", "-1", "--oneline"]);
    let remote_output = git_cmd(&["remote", "-v"]);

    let status = parse_status(status_output.as_deref());
    let remotes = parse_remotes(remote_output.as_deref());

    GitReport {
        root,
        branch,
        status,
        latest,
        remotes,
        error: None,
    }
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
            url: url.to_owned(),
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

    if let Some(ref branch_name) = report.branch {
        items.push(format!("branch: {branch_name}"));
    }

    let status_label = match &report.status {
        StatusSummary::Clean => "clean".to_owned(),
        StatusSummary::Dirty {
            modified,
            untracked,
        } => format!("dirty ({modified} modified, {untracked} untracked)"),
    };
    items.push(format!("status: {status_label}"));

    if let Some(ref latest) = report.latest {
        items.push(format!("latest: {latest}"));
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
mod tests {
    use super::*;

    #[test]
    fn parse_status_clean() {
        let output = Some("## main...origin/main\n");
        assert_eq!(parse_status(output), StatusSummary::Clean);
    }

    #[test]
    fn parse_status_clean_empty() {
        assert_eq!(parse_status(None), StatusSummary::Clean);
    }

    #[test]
    fn parse_status_modified() {
        let output = Some("## main\n M src/main.rs\n?? newfile.txt\n");
        assert_eq!(
            parse_status(output),
            StatusSummary::Dirty {
                modified: 1,
                untracked: 1
            }
        );
    }

    #[test]
    fn parse_status_only_untracked() {
        let output = Some("## main\n?? foo.txt\n?? bar/\n");
        assert_eq!(
            parse_status(output),
            StatusSummary::Dirty {
                modified: 0,
                untracked: 2
            }
        );
    }

    #[test]
    fn parse_status_only_modified() {
        let output = Some("## main\n M file.rs\n M Cargo.toml\nMM src/lib.rs\n");
        assert_eq!(
            parse_status(output),
            StatusSummary::Dirty {
                modified: 3,
                untracked: 0
            }
        );
    }

    #[test]
    fn parse_remotes_origin() {
        let output = Some(
            "origin\tgit@github.com:user/repo.git (fetch)\n\
             origin\tgit@github.com:user/repo.git (push)\n",
        );
        let remotes = parse_remotes(output);
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].name, "origin");
        assert_eq!(remotes[0].url, "git@github.com:user/repo.git");
    }

    #[test]
    fn parse_remotes_multiple() {
        let output = Some(
            "origin\tgit@github.com:user/repo.git (fetch)\n\
             origin\tgit@github.com:user/repo.git (push)\n\
             upstream\thttps://github.com/upstream/repo.git (fetch)\n\
             upstream\thttps://github.com/upstream/repo.git (push)\n",
        );
        let remotes = parse_remotes(output);
        assert_eq!(remotes.len(), 2);
        assert_eq!(remotes[0].name, "origin");
        assert_eq!(remotes[1].name, "upstream");
        assert_eq!(remotes[1].url, "https://github.com/upstream/repo.git");
    }

    #[test]
    fn parse_remotes_empty() {
        assert!(parse_remotes(None).is_empty());
        assert!(parse_remotes(Some("")).is_empty());
    }

    #[test]
    fn latest_commit_passthrough() {
        assert_eq!(
            parse_latest_commit(Some("abc1234 fix something")),
            Some("abc1234 fix something".to_owned())
        );
        assert_eq!(parse_latest_commit(None), None);
    }

    #[test]
    fn render_error_not_a_repo() {
        let report = GitReport {
            root: None,
            branch: None,
            status: StatusSummary::Clean,
            latest: None,
            remotes: vec![],
            error: Some("not inside a git repository".to_owned()),
        };
        let output = render_report(&report);
        assert_eq!(output, "git\n└── not inside a git repository");
    }

    #[test]
    fn render_error_git_missing() {
        let report = GitReport {
            root: None,
            branch: None,
            status: StatusSummary::Clean,
            latest: None,
            remotes: vec![],
            error: Some("git binary not found".to_owned()),
        };
        let output = render_report(&report);
        assert_eq!(output, "git\n└── git binary not found");
    }

    #[test]
    fn render_clean_repo_no_remotes() {
        let report = GitReport {
            root: Some("/home/u/repo".to_owned()),
            branch: Some("main".to_owned()),
            status: StatusSummary::Clean,
            latest: Some("abc1234 initial commit".to_owned()),
            remotes: vec![],
            error: None,
        };
        let output = render_report(&report);
        let expected = [
            "git",
            "├── root: /home/u/repo",
            "├── branch: main",
            "├── status: clean",
            "└── latest: abc1234 initial commit",
        ];
        assert_eq!(output, expected.join("\n"));
    }

    #[test]
    fn render_full_repo_with_remotes() {
        let report = GitReport {
            root: Some("/home/u/repo".to_owned()),
            branch: Some("main".to_owned()),
            status: StatusSummary::Clean,
            latest: Some("abc1234 fix bug".to_owned()),
            remotes: vec![RemoteEntry {
                name: "origin".to_owned(),
                url: "git@github.com:user/repo.git".to_owned(),
            }],
            error: None,
        };
        let output = render_report(&report);
        let expected = [
            "git",
            "├── root: /home/u/repo",
            "├── branch: main",
            "├── status: clean",
            "├── latest: abc1234 fix bug",
            "└── remotes",
            "    └── origin git@github.com:user/repo.git",
        ];
        assert_eq!(output, expected.join("\n"));
    }

    #[test]
    fn render_dirty_repo() {
        let report = GitReport {
            root: Some("/home/u/repo".to_owned()),
            branch: Some("dev".to_owned()),
            status: StatusSummary::Dirty {
                modified: 2,
                untracked: 1,
            },
            latest: Some("def5678 wip".to_owned()),
            remotes: vec![
                RemoteEntry {
                    name: "origin".to_owned(),
                    url: "git@github.com:user/repo.git".to_owned(),
                },
                RemoteEntry {
                    name: "upstream".to_owned(),
                    url: "https://github.com/up/repo.git".to_owned(),
                },
            ],
            error: None,
        };
        let output = render_report(&report);
        assert!(output.contains("status: dirty (2 modified, 1 untracked)"));
        assert!(output.contains("└── remotes"));
    }

    #[test]
    fn no_malformed_tree_prefixes() {
        let report = GitReport {
            root: Some("/r".to_owned()),
            branch: Some("main".to_owned()),
            status: StatusSummary::Clean,
            latest: Some("abc1234 msg".to_owned()),
            remotes: vec![RemoteEntry {
                name: "origin".to_owned(),
                url: "git@github.com:u/r.git".to_owned(),
            }],
            error: None,
        };
        let output = render_report(&report);
        for line in output.lines() {
            assert!(!line.contains("├── └──"), "malformed: {line}");
            assert!(!line.contains("├── │"), "malformed: {line}");
            assert!(!line.contains("└── ├──"), "malformed: {line}");
            assert!(!line.contains("└── │"), "malformed: {line}");
        }
    }

    #[test]
    fn stable_output_shape() {
        let report = GitReport {
            root: Some("/path/to/repo".to_owned()),
            branch: Some("main".to_owned()),
            status: StatusSummary::Clean,
            latest: Some("abc1234 message".to_owned()),
            remotes: vec![RemoteEntry {
                name: "origin".to_owned(),
                url: "git@github.com:oxyzenQ/zejtron.git".to_owned(),
            }],
            error: None,
        };
        let output = render_report(&report);
        assert!(output.starts_with("git\n"));
        assert!(output.contains("root: /path/to/repo"));
        assert!(output.contains("branch: main"));
        assert!(output.contains("status: clean"));
        assert!(output.contains("latest: abc1234 message"));
        assert!(output.contains("origin git@github.com:oxyzenQ/zejtron.git"));
    }
}
