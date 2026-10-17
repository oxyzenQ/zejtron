// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! pathguard unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/system/pathguard.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use std::sync::Mutex;

/// Serialize env-mutating tests so they don't interfere with each other or
/// with other tests that read HOME / XDG_DATA_HOME. cargo test runs tests
/// in parallel by default; without this lock, mutating env vars from one
/// test would corrupt another test's view of the environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper: set HOME and optionally XDG_DATA_HOME for the test, restore on drop.
fn with_test_env<F: FnOnce()>(home: &str, xdg_data: Option<&str>, f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    let old_home = std::env::var_os("HOME");
    let old_xdg = std::env::var_os("XDG_DATA_HOME");

    // SAFETY: env mutation is serialized by ENV_LOCK; restored before return.
    unsafe {
        std::env::set_var("HOME", home);
        match xdg_data {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }

    f();

    // SAFETY: same locked context, restoring prior values.
    unsafe {
        match old_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match old_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
}

#[test]
fn test_lexical_normalize_collapses_dots() {
    let p = Path::new("/home/user/.local/share/zejtron/../other");
    let n = lexical_normalize(p).unwrap();
    assert_eq!(n, PathBuf::from("/home/user/.local/share/other"));
}

#[test]
fn test_default_state_dir_under_home() {
    with_test_env("/home/testuser", None, || {
        let dir = resolve_state_dir().unwrap();
        assert_eq!(dir, PathBuf::from("/home/testuser/.local/share/zejtron"));
    });
}

#[test]
fn test_xdg_data_home_respected_when_safe() {
    with_test_env("/home/testuser", Some("/custom/xdg"), || {
        let dir = resolve_state_dir().unwrap();
        assert_eq!(dir, PathBuf::from("/custom/xdg/zejtron"));
    });
}

#[test]
fn test_xdg_to_etc_is_blocked() {
    with_test_env("/home/testuser", Some("/etc"), || {
        let r = resolve_state_dir();
        assert!(r.is_err(), "XDG_DATA_HOME=/etc must be blocked");
        assert!(r.unwrap_err().contains("pathguard"));
    });
}

#[test]
fn test_xdg_to_user_ssh_is_blocked() {
    with_test_env("/home/testuser", Some("/home/testuser/.ssh"), || {
        let r = resolve_state_dir();
        assert!(r.is_err(), "XDG_DATA_HOME=~/.ssh must be blocked");
    });
}

#[test]
fn test_xdg_to_var_is_blocked() {
    with_test_env("/home/testuser", Some("/var/lib"), || {
        assert!(resolve_state_dir().is_err());
    });
}

#[test]
fn test_xdg_to_proc_sys_dev_blocked() {
    with_test_env("/home/testuser", None, || {
        for p in [
            "/proc", "/sys", "/dev", "/boot", "/root", "/usr", "/bin", "/sbin", "/lib",
        ] {
            // SAFETY: single-threaded test, value restored by with_test_env.
            unsafe {
                std::env::set_var("XDG_DATA_HOME", p);
            }
            assert!(
                resolve_state_dir().is_err(),
                "XDG_DATA_HOME={p} must be blocked"
            );
        }
    });
}

#[test]
fn test_dangerous_paths_detected() {
    with_test_env("/home/testuser", None, || {
        assert!(is_dangerous(Path::new("/etc/passwd")));
        assert!(is_dangerous(Path::new("/etc/zejtron/env/x.env")));
        assert!(is_dangerous(Path::new("/usr/bin/bash")));
        assert!(is_dangerous(Path::new("/var/log/x")));
        assert!(is_dangerous(Path::new("/boot/vmlinuz")));
        assert!(is_dangerous(Path::new("/root/.bashrc")));
        assert!(is_dangerous(Path::new("/proc/self/status")));
        assert!(is_dangerous(Path::new("/sys/kernel")));
        assert!(is_dangerous(Path::new("/dev/null")));
        assert!(is_dangerous(Path::new("/home/testuser/.ssh/id_rsa")));
        assert!(is_dangerous(Path::new("/home/testuser/.gnupg/secring.gpg")));
        // Not dangerous — valid state location
        assert!(!is_dangerous(Path::new(
            "/home/testuser/.local/share/zejtron/env/x.env"
        )));
        assert!(!is_dangerous(Path::new("/custom/xdg/zejtron")));
    });
}

#[test]
fn test_missing_home_without_xdg_errors() {
    let _guard = ENV_LOCK.lock().unwrap();
    let old_home = std::env::var_os("HOME");
    let old_xdg = std::env::var_os("XDG_DATA_HOME");
    // SAFETY: serialized by ENV_LOCK, restored below.
    unsafe {
        std::env::remove_var("HOME");
        std::env::remove_var("XDG_DATA_HOME");
    }

    let r = resolve_state_dir();
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("HOME is required"));

    // SAFETY: serialized by ENV_LOCK, restoring prior values.
    unsafe {
        match old_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match old_xdg {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
}
