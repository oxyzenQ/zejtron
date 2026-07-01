// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

pub fn version_text(hash: &str) -> String {
    let hash = if hash.trim().is_empty() {
        "unknown"
    } else {
        hash.trim()
    };
    let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    format!(
        "Version: v{}\n\
         Build: {target} ({hash})\n\
         Copyright: (c) 2026 rezky_nightky (oxyzenQ)\n\
         License: GPL-3.0-only\n\
         Source: https://github.com/oxyzenQ/zejtron",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_version_with_hash() {
        assert_eq!(
            version_text("abc123"),
            format!(
                "Version: v{}\nBuild: {}-{} (abc123)\nCopyright: (c) 2026 rezky_nightky (oxyzenQ)\nLicense: GPL-3.0-only\nSource: https://github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        );
    }

    #[test]
    fn has_five_lines() {
        assert_eq!(version_text("abc123").lines().count(), 5);
    }

    #[test]
    fn falls_back_to_unknown_for_empty_hash() {
        assert_eq!(
            version_text("  "),
            format!(
                "Version: v{}\nBuild: {}-{} (unknown)\nCopyright: (c) 2026 rezky_nightky (oxyzenQ)\nLicense: GPL-3.0-only\nSource: https://github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        );
    }
}
