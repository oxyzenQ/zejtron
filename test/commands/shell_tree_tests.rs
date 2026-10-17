// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! shell output-shape pins: the config-label provenance rows
//! and the full-tree exact-shape pin. Split from
//! shell_tests.rs when the relocation pushed it past the 600-line
//! no-mercy cap (night-improve-18, the diff_tests/guard_tests
//! discipline); #[path]-wired from src/commands/shell.rs as a
//! sibling module, so `super::` reaches the shell module the
//! same way.

use super::*;

#[test]
fn config_label_parent_source() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: None,
        env_vars: vec![],
        configs: vec![ConfigEntry {
            display_path: "~/.bashrc".to_owned(),
            status: ConfigStatus::Readable,
        }],
        config_source: Some(ConfigSource::Parent("bash".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    assert!(output.contains("└── configs (bash, via parent process)"));
    assert!(!output.contains("via $SHELL"));
}

#[test]
fn config_label_login_source() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: None,
        env_vars: vec![],
        configs: vec![ConfigEntry {
            display_path: "~/.zshrc".to_owned(),
            status: ConfigStatus::Readable,
        }],
        config_source: Some(ConfigSource::Login("zsh".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    assert!(output.contains("└── configs (zsh, via $SHELL)"));
    assert!(!output.contains("via parent process"));
}

#[test]
fn config_label_no_source() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: None,
        env_vars: vec![],
        configs: vec![ConfigEntry {
            display_path: "HOME is not set; cannot resolve config paths".to_owned(),
            status: ConfigStatus::Missing,
        }],
        config_source: None,

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    assert!(output.contains("└── configs"));
    assert!(!output.contains("via parent process"));
    assert!(!output.contains("via $SHELL"));
}

#[test]
fn full_tree_output_exact_shape() {
    let report = ShellReport {
        parent: Some(ParentProcess {
            name: "bash".to_owned(),
            pid: 1700,
        }),
        login_shell: Some("/bin/zsh".to_owned()),
        terminal: Some("xterm-256color".to_owned()),
        env_vars: vec![
            ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
            ("SHELL".to_owned(), "/bin/zsh".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
        ],
        configs: vec![ConfigEntry {
            display_path: "~/.zshrc".to_owned(),
            status: ConfigStatus::Readable,
        }],
        config_source: Some(ConfigSource::Parent("bash".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    let expected = [
        "shell",
        "",
        "├── invocation",
        "│   ├── parent: bash pid=1700",
        "│   └── login: /bin/zsh",
        "├── terminal",
        "│   └── TERM=xterm-256color",
        "├── environment",
        "│   ├── HISTFILE=/home/u/.zsh_history",
        "│   ├── SHELL=/bin/zsh",
        "│   └── TERM=xterm-256color",
        "└── configs (bash, via parent process)",
        "    └── ~/.zshrc readable",
    ];
    assert_eq!(output, expected.join("\n"));
}
