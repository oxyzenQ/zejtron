// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! git unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/git.rs, so `super::` reaches the module exactly like the
//! inline tests did.

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
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
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
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
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
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        root: Some("/home/u/repo".to_owned()),
        branch: Some("main".to_owned()),
        status: StatusSummary::Clean,
        latest: None,
        remotes: vec![],
        error: None,
    };
    let output = render_report(&report);
    // With latest: None and no upstream, the report shows root/branch/status
    assert!(output.contains("root: /home/u/repo"));
    assert!(output.contains("branch: main <- (no upstream)"));
    assert!(output.contains("status: clean"));
    // No latest line when latest is None
    assert!(!output.contains("latest:"));
}

#[test]
fn render_full_repo_with_remotes() {
    let report = GitReport {
        root: Some("/home/u/repo".to_owned()),
        branch: Some("main".to_owned()),
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        status: StatusSummary::Clean,
        latest: None,
        stash_count: 0,
        last_tag: None,
        remotes: vec![RemoteEntry {
            name: "origin".to_owned(),
            url: "git@github.com:user/repo.git".to_owned(),
        }],
        error: None,
    };
    let output = render_report(&report);
    // With latest: None, the report has no latest line
    assert!(output.contains("git"));
    assert!(output.contains("root: /home/u/repo"));
    assert!(output.contains("branch: main <- (no upstream)"));
    assert!(output.contains("status: clean"));
    assert!(output.contains("remotes"));
    assert!(output.contains("origin git@github.com:user/repo.git"));
}

#[test]
fn render_dirty_repo() {
    let report = GitReport {
        root: Some("/home/u/repo".to_owned()),
        branch: Some("dev".to_owned()),
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        status: StatusSummary::Dirty {
            modified: 2,
            untracked: 1,
        },
        latest: None,
        stash_count: 0,
        last_tag: None,
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
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        root: Some("/r".to_owned()),
        branch: Some("main".to_owned()),
        status: StatusSummary::Clean,
        latest: None,
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
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        root: Some("/path/to/repo".to_owned()),
        branch: Some("main".to_owned()),
        status: StatusSummary::Clean,
        latest: None,
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
    assert!(output.contains("origin git@github.com:oxyzenQ/zejtron.git"));
}

// ── URL sanitization tests ──

#[test]
fn sanitize_token_only_https() {
    assert_eq!(
        sanitize_remote_url("https://TOKEN@github.com/owner/repo.git"),
        "https://<redacted>@github.com/owner/repo.git"
    );
}

#[test]
fn sanitize_user_token_https() {
    assert_eq!(
        sanitize_remote_url("https://USER:TOKEN@github.com/owner/repo.git"),
        "https://<redacted>@github.com/owner/repo.git"
    );
}

#[test]
fn sanitize_user_token_http() {
    assert_eq!(
        sanitize_remote_url("http://USER:TOKEN@example.com/repo.git"),
        "http://<redacted>@example.com/repo.git"
    );
}

#[test]
fn sanitize_git_https_prefix() {
    assert_eq!(
        sanitize_remote_url("git+https://TOKEN@host/path"),
        "git+https://<redacted>@host/path"
    );
}

#[test]
fn sanitize_git_http_prefix() {
    assert_eq!(
        sanitize_remote_url("git+http://TOKEN@host/path"),
        "git+http://<redacted>@host/path"
    );
}

#[test]
fn safe_ssh_scp_style_unchanged() {
    assert_eq!(
        sanitize_remote_url("git@github.com:oxyzenQ/zejtron.git"),
        "git@github.com:oxyzenQ/zejtron.git"
    );
}

#[test]
fn safe_ssh_url_unchanged() {
    assert_eq!(
        sanitize_remote_url("ssh://git@github.com/oxyzenQ/zejtron.git"),
        "ssh://git@github.com/oxyzenQ/zejtron.git"
    );
}

#[test]
fn safe_https_no_credentials_unchanged() {
    assert_eq!(
        sanitize_remote_url("https://github.com/oxyzenQ/zejtron.git"),
        "https://github.com/oxyzenQ/zejtron.git"
    );
}

#[test]
fn safe_file_url_unchanged() {
    assert_eq!(
        sanitize_remote_url("file:///home/u/repo"),
        "file:///home/u/repo"
    );
}

#[test]
fn parse_remotes_redacts_token_https() {
    let output = Some(
        "origin\thttps://ghp_abc123@github.com/user/repo.git (fetch)\n\
         origin\thttps://ghp_abc123@github.com/user/repo.git (push)\n",
    );
    let remotes = parse_remotes(output);
    assert_eq!(remotes.len(), 1);
    assert_eq!(
        remotes[0].url,
        "https://<redacted>@github.com/user/repo.git"
    );
}

#[test]
fn parse_remotes_redacts_user_token_https() {
    let output = Some(
        "origin\thttps://alice:ghp_secret@github.com/alice/repo.git (fetch)\n\
         origin\thttps://alice:ghp_secret@github.com/alice/repo.git (push)\n",
    );
    let remotes = parse_remotes(output);
    assert_eq!(remotes.len(), 1);
    assert_eq!(
        remotes[0].url,
        "https://<redacted>@github.com/alice/repo.git"
    );
}

#[test]
fn parse_remotes_preserves_safe_ssh_url() {
    let output = Some(
        "origin\tgit@github.com:oxyzenQ/zejtron.git (fetch)\n\
         origin\tgit@github.com:oxyzenQ/zejtron.git (push)\n",
    );
    let remotes = parse_remotes(output);
    assert_eq!(remotes.len(), 1);
    assert_eq!(remotes[0].url, "git@github.com:oxyzenQ/zejtron.git");
}

#[test]
fn parse_remotes_preserves_safe_https_url() {
    let output = Some(
        "upstream\thttps://github.com/upstream/repo.git (fetch)\n\
         upstream\thttps://github.com/upstream/repo.git (push)\n",
    );
    let remotes = parse_remotes(output);
    assert_eq!(remotes.len(), 1);
    assert_eq!(remotes[0].url, "https://github.com/upstream/repo.git");
}

#[test]
fn renderer_output_has_no_raw_token() {
    let report = GitReport {
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        root: Some("/home/u/repo".to_owned()),
        branch: Some("main".to_owned()),
        status: StatusSummary::Clean,
        latest: None,
        remotes: vec![RemoteEntry {
            name: "origin".to_owned(),
            url: "https://ghp_supersecret@github.com/user/repo.git".to_owned(),
        }],
        error: None,
    };
    // Simulate what parse_remotes does: sanitize before storing
    let sanitized_url = sanitize_remote_url(&report.remotes[0].url);
    let report = GitReport {
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        remotes: vec![RemoteEntry {
            url: sanitized_url,
            ..report.remotes.into_iter().next().unwrap()
        }],
        ..report
    };
    let output = render_report(&report);
    assert!(!output.contains("ghp_supersecret"));
    assert!(output.contains("<redacted>"));
}

#[test]
fn renderer_hides_token_via_parse_remotes() {
    // End-to-end: parse_remotes already sanitizes
    let output = Some(
        "origin\thttps://ghp_ABCDEF123456@github.com/user/repo.git (fetch)\n\
         origin\thttps://ghp_ABCDEF123456@github.com/user/repo.git (push)\n",
    );
    let remotes = parse_remotes(output);
    let report = GitReport {
        is_detached: false,
        head_hash: None,
        upstream: None,
        ahead: None,
        behind: None,
        stash_count: 0,
        last_tag: None,
        root: Some("/r".to_owned()),
        branch: Some("main".to_owned()),
        status: StatusSummary::Clean,
        latest: None,
        remotes,
        error: None,
    };
    let rendered = render_report(&report);
    assert!(!rendered.contains("ghp_ABCDEF123456"));
    assert!(rendered.contains("<redacted>@github.com/user/repo.git"));
}
