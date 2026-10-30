// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The std-only temp-dir guard (night-dragon-maintenance-T1, the
//! tempfile retirement): the reference project's own shape - a
//! throwaway directory under `std::env::temp_dir()` with RAII
//! cleanup, zero dependencies, the same two-method surface the test
//! tree consumed from the crate (`new() -> io::Result<Self>` and
//! `path() -> &Path`), so the call sites stay byte-identical.
//!
//! The dependency that used to own this job (tempfile) was the
//! single dev-dependency, and its transitive subtree (fastrand,
//! getrandom, rustix, linux-raw-sys, errno, r-efi - seven lockfile
//! entries) existed for nothing else. The crate never rode any
//! shipped binary, but every contributor checkout and every CI run
//! compiled it; the supply-chain law (independence over
//! convenience) retires it in favor of the thirty std lines below.
//!
//! Uniqueness: the name is pid + nanos + a per-copy counter, and
//! the directory is created with `create_dir` (the exclusive,
//! fails-on-existing primitive), retrying on `AlreadyExists` - the
//! same construction the retired crate used internally, without
//! the getrandom dependency that powered it. A test binary's
//! modules each embed their own copy of this file (the #[path]
//! discipline), so the counter is per-copy: the retry loop, not
//! the counter, is the correctness guarantee.
//!
//! Cleanup: Drop removes the tree (`remove_dir_all`), best-effort
//! like the crate before it - a failed cleanup never masks a test
//! failure, and a crashed run leaves its directory for the OS temp
//! cleaner, the exact contract the tests ran under before.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A throwaway directory: created exclusive on construction,
/// removed with everything under it on drop.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a unique empty directory under the system temp dir.
    /// The `io::Result` shape (and the `.unwrap()` it invites at
    /// call sites) is deliberate parity with the crate this
    /// replaced - the 22 existing call sites stay unchanged.
    pub(crate) fn new() -> io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let mut attempt = COUNTER.fetch_add(1, Ordering::Relaxed);
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("zejtron-test-{pid}-{nanos}-{attempt}"));
            // create_dir (not create_dir_all): the exclusive
            // primitive. A collision is a retry, never a silent
            // share - two tests must never see one directory.
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    attempt = COUNTER.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// The directory's path. Everything the call sites reach for.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort, the retired crate's own contract: a cleanup
        // failure (a fixture left busy) must not mask the test's
        // real verdict.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
