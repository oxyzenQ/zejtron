// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! shell unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/shell.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

fn parse_cmdline_bytes(bytes: &[u8]) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = Vec::new();
    for &byte in bytes {
        if byte == 0 {
            if !current.is_empty() {
                args.push(String::from_utf8_lossy(&current).to_string());
                current.clear();
            }
        } else {
            current.push(byte);
        }
    }
    if !current.is_empty() {
        args.push(String::from_utf8_lossy(&current).to_string());
    }
    args
}

#[test]
fn classifies_known_shells() {
    assert_eq!(classify_shell("zsh"), Some("zsh"));
    assert_eq!(classify_shell("bash"), Some("bash"));
    assert_eq!(classify_shell("fish"), Some("fish"));
    assert_eq!(classify_shell("dash"), Some("dash"));
    assert_eq!(classify_shell("sh"), Some("sh"));
    assert_eq!(classify_shell("nu"), Some("nu"));
}

#[test]
fn classifies_login_shell_prefix() {
    assert_eq!(classify_shell("-zsh"), Some("zsh"));
    assert_eq!(classify_shell("-bash"), Some("bash"));
    assert_eq!(classify_shell("-fish"), Some("fish"));
    assert_eq!(classify_shell("-sh"), Some("sh"));
}

#[test]
fn classifies_unknown_as_none() {
    assert_eq!(classify_shell("python3"), None);
    assert_eq!(classify_shell("vim"), None);
    assert_eq!(classify_shell(""), None);
}

#[test]
fn classifies_case_insensitive() {
    assert_eq!(classify_shell("ZSH"), Some("zsh"));
    assert_eq!(classify_shell("BASH"), Some("bash"));
    assert_eq!(classify_shell("Fish"), Some("fish"));
}

#[test]
fn extracts_shell_name_from_path() {
    assert_eq!(shell_name_from_path("/bin/zsh"), Some("zsh"));
    assert_eq!(shell_name_from_path("/usr/bin/bash"), Some("bash"));
    assert_eq!(shell_name_from_path("/bin/fish"), Some("fish"));
    assert_eq!(shell_name_from_path("/usr/local/bin/dash"), Some("dash"));
}

#[test]
fn extracts_shell_name_from_trailing_slash() {
    assert_eq!(shell_name_from_path("/bin/"), None);
    assert_eq!(shell_name_from_path("/"), None);
}

#[test]
fn extracts_shell_name_from_bare_filename() {
    assert_eq!(shell_name_from_path("sh"), Some("sh"));
    assert_eq!(shell_name_from_path("bash"), Some("bash"));
}

#[test]
fn parses_cmdline_with_nul_separators() {
    let bytes: &[u8] = b"bash\0--login\0-i\0";
    let args = parse_cmdline_bytes(bytes);
    assert_eq!(args, vec!["bash", "--login", "-i"]);
}

#[test]
fn parses_cmdline_empty() {
    let args = parse_cmdline_bytes(b"");
    assert!(args.is_empty());
}

#[test]
fn parses_cmdline_single_arg() {
    let args = parse_cmdline_bytes(b"zsh");
    assert_eq!(args, vec!["zsh"]);
}

#[test]
fn parses_cmdline_trailing_nul() {
    let args = parse_cmdline_bytes(b"bash\0");
    assert_eq!(args, vec!["bash"]);
}

#[test]
fn parses_cmdline_multiple_nuls_between() {
    let args = parse_cmdline_bytes(b"sh\0\0--help\0");
    assert_eq!(args, vec!["sh", "--help"]);
}

#[test]
fn renders_parent_metadata_with_fixtures() {
    let report = ShellReport {
        parent: Some(ParentProcess {
            name: "bash".to_owned(),
            pid: 1700,
        }),
        login_shell: Some("/bin/zsh".to_owned()),
        terminal: Some("xterm-256color".to_owned()),
        env_vars: vec![
            ("SHELL".to_owned(), "/bin/zsh".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
        ],
        configs: vec![
            ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            },
            ConfigEntry {
                display_path: "~/.zshenv".to_owned(),
                status: ConfigStatus::Missing,
            },
        ],
        config_source: Some(ConfigSource::Parent("bash".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);

    assert!(output.starts_with("shell"));
    assert!(output.contains("parent: bash pid=1700"));
    assert!(output.contains("login: /bin/zsh"));
    assert!(output.contains("TERM=xterm-256color"));
    assert!(output.contains("SHELL=/bin/zsh"));
    assert!(output.contains("~/.zshrc readable"));
    assert!(output.contains("~/.zshenv missing"));
}

#[test]
fn renders_without_parent() {
    let report = ShellReport {
        parent: None,
        login_shell: Some("/bin/bash".to_owned()),
        terminal: Some("dumb".to_owned()),
        env_vars: vec![("SHELL".to_owned(), "/bin/bash".to_owned())],
        configs: vec![],
        config_source: Some(ConfigSource::Login("bash".to_owned())),
        ancestor_chain: vec![],
    };

    let output = render_report(&report);

    assert!(output.contains("login: /bin/bash"));
    assert!(!output.contains("parent:"));
}

#[test]
fn renders_without_login_shell() {
    let report = ShellReport {
        parent: Some(ParentProcess {
            name: "sh".to_owned(),
            pid: 42,
        }),
        login_shell: None,
        terminal: None,
        env_vars: vec![],
        configs: vec![],
        config_source: Some(ConfigSource::Parent("sh".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    assert!(output.contains("parent: sh pid=42"));
    assert!(!output.contains("login:"));
}

#[test]
fn renders_missing_home_configs() {
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
    assert!(output.contains("HOME is not set"));
}

#[test]
fn config_paths_zsh_with_zdotdir() {
    let entries = config_paths_zsh("/home/user", Some("/opt/zdot"));
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].display_path, "/opt/zdot/.zshenv");
    assert_eq!(entries[1].display_path, "/opt/zdot/.zprofile");
    assert_eq!(entries[2].display_path, "/opt/zdot/.zshrc");
}

#[test]
fn config_paths_zsh_without_zdotdir() {
    let entries = config_paths_zsh("/home/user", None);
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].display_path, "~/.zshenv");
    assert_eq!(entries[4].display_path, "~/.zlogout");
}

#[test]
fn generates_config_paths_bash() {
    let entries = super::config_paths_bash("/home/user");
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].display_path, "~/.bash_profile");
    assert_eq!(entries[1].display_path, "~/.bash_login");
    assert_eq!(entries[2].display_path, "~/.profile");
    assert_eq!(entries[3].display_path, "~/.bashrc");
    assert_eq!(entries[4].display_path, "~/.bash_logout");
}

#[test]
fn config_paths_fish_with_xdg() {
    let entries = config_paths_fish("/home/user", Some("/opt/config"));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].display_path, "/opt/config/fish/config.fish");
}

#[test]
fn config_paths_fish_without_xdg() {
    let entries = config_paths_fish("/home/user", None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].display_path, "~/.config/fish/config.fish");
}

#[test]
fn generates_config_paths_sh() {
    let entries = super::config_paths_sh("/home/user");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].display_path, "~/.profile");
}

#[test]
fn config_paths_unknown_shell() {
    let entries = config_paths("python", "/home/user", None, None);
    assert!(entries.is_empty());
}

#[test]
fn filter_env_returns_only_safe_keys() {
    unsafe {
        env::set_var("ZEJTRON_TEST_SHELL_VAR", "should_not_appear");
        env::remove_var("ZEJTRON_TEST_SHELL_VAR");
    }

    let vars = filter_shell_env();

    for (key, _) in &vars {
        assert!(SAFE_ENV_KEYS.contains(&key.as_str()));
    }
}

#[test]
fn filter_env_returns_sorted_keys() {
    let vars = filter_shell_env();
    for window in vars.windows(2) {
        assert!(window[0].0 <= window[1].0);
    }
}

#[test]
fn filter_env_returns_expected_keys_when_set() {
    unsafe {
        env::set_var("SHELL", "/bin/bash");
        env::set_var("TERM", "xterm");
    }

    let vars = filter_shell_env();

    let has_shell = vars.iter().any(|(k, _)| k == "SHELL");
    let has_term = vars.iter().any(|(k, _)| k == "TERM");
    assert!(has_shell);
    assert!(has_term);
}

#[test]
fn stable_output_shape() {
    let report = ShellReport {
        parent: Some(ParentProcess {
            name: "bash".to_owned(),
            pid: 100,
        }),
        login_shell: Some("/bin/zsh".to_owned()),
        terminal: Some("xterm-256color".to_owned()),
        env_vars: vec![("SHELL".to_owned(), "/bin/zsh".to_owned())],
        configs: vec![ConfigEntry {
            display_path: "~/.zshrc".to_owned(),
            status: ConfigStatus::Readable,
        }],
        config_source: Some(ConfigSource::Parent("bash".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);

    assert!(output.starts_with("shell\n"));
    assert!(output.contains("├── invocation"));
    assert!(output.contains("│   ├── parent:"));
    assert!(output.contains("│   └── login:"));
    assert!(output.contains("├── terminal"));
    assert!(output.contains("├── environment"));
    assert!(output.contains("└── configs"));
}

#[test]
fn no_malformed_tree_prefixes() {
    let report = ShellReport {
        parent: Some(ParentProcess {
            name: "bash".to_owned(),
            pid: 100,
        }),
        login_shell: Some("/bin/zsh".to_owned()),
        terminal: Some("xterm-256color".to_owned()),
        env_vars: vec![
            ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
            ("SHELL".to_owned(), "/bin/zsh".to_owned()),
            ("STARSHIP_SHELL".to_owned(), "zsh".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
        ],
        configs: vec![
            ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            },
            ConfigEntry {
                display_path: "~/.zshenv".to_owned(),
                status: ConfigStatus::Missing,
            },
        ],
        config_source: Some(ConfigSource::Parent("bash".to_owned())),

        ancestor_chain: vec![],
    };

    let output = render_report(&report);

    for line in output.lines() {
        assert!(!line.contains("├── └──"), "malformed prefix found: {line}");
        assert!(!line.contains("├── │"), "malformed prefix found: {line}");
        assert!(!line.contains("└── ├──"), "malformed prefix found: {line}");
        assert!(!line.contains("└── │"), "malformed prefix found: {line}");
    }
}

#[test]
fn no_malformed_tree_prefixes_no_configs() {
    let report = ShellReport {
        parent: None,
        login_shell: Some("/bin/bash".to_owned()),
        terminal: Some("dumb".to_owned()),
        env_vars: vec![
            ("SHELL".to_owned(), "/bin/bash".to_owned()),
            ("TERM".to_owned(), "dumb".to_owned()),
        ],
        configs: vec![],
        config_source: None,
        ancestor_chain: vec![],
    };

    let output = render_report(&report);

    for line in output.lines() {
        assert!(!line.contains("├── └──"), "malformed prefix found: {line}");
        assert!(!line.contains("├── │"), "malformed prefix found: {line}");
    }
}

#[test]
fn terminal_section_formatting_with_configs() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: Some("xterm-direct".to_owned()),
        env_vars: vec![],
        configs: vec![ConfigEntry {
            display_path: "~/.profile".to_owned(),
            status: ConfigStatus::Missing,
        }],
        config_source: None,

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    let lines: Vec<&str> = output.lines().collect();

    let term_header = *lines.iter().find(|l| l.contains("terminal")).unwrap();
    let term_child = *lines
        .iter()
        .find(|l| l.contains("TERM=xterm-direct"))
        .unwrap();

    assert_eq!(term_header, "├── terminal");
    assert_eq!(term_child, "│   └── TERM=xterm-direct");
}

#[test]
fn terminal_section_formatting_without_configs() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: Some("xterm-direct".to_owned()),
        env_vars: vec![],
        configs: vec![],
        config_source: None,
        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    let lines: Vec<&str> = output.lines().collect();

    let term_header = *lines.iter().find(|l| l.contains("terminal")).unwrap();
    let term_child = *lines
        .iter()
        .find(|l| l.contains("TERM=xterm-direct"))
        .unwrap();

    assert_eq!(term_header, "└── terminal");
    assert_eq!(term_child, "    └── TERM=xterm-direct");
}

#[test]
fn environment_section_formatting_with_configs() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: None,
        env_vars: vec![
            ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
            ("SHELL".to_owned(), "/bin/zsh".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
        ],
        configs: vec![ConfigEntry {
            display_path: "~/.zshrc".to_owned(),
            status: ConfigStatus::Readable,
        }],
        config_source: None,

        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    let lines: Vec<&str> = output.lines().collect();

    let env_header = *lines.iter().find(|l| l.contains("environment")).unwrap();
    assert_eq!(env_header, "├── environment");

    assert!(lines.contains(&"│   ├── HISTFILE=/home/u/.zsh_history"));
    assert!(lines.contains(&"│   ├── SHELL=/bin/zsh"));
    assert!(lines.contains(&"│   └── TERM=xterm-256color"));
}

#[test]
fn environment_section_formatting_without_configs() {
    let report = ShellReport {
        parent: None,
        login_shell: None,
        terminal: None,
        env_vars: vec![("SHELL".to_owned(), "/bin/bash".to_owned())],
        configs: vec![],
        config_source: None,
        ancestor_chain: vec![],
    };

    let output = render_report(&report);
    let lines: Vec<&str> = output.lines().collect();

    let env_header = *lines.iter().find(|l| l.contains("environment")).unwrap();
    assert_eq!(env_header, "└── environment");

    assert!(lines.contains(&"    └── SHELL=/bin/bash"));
}
