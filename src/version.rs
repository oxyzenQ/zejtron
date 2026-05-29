// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: MIT

pub fn version_text(hash: &str) -> String {
    let hash = if hash.trim().is_empty() {
        "unknown"
    } else {
        hash.trim()
    };

    format!(
        "zejtron v{} ({hash})\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/zejtron",
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
                "zejtron v{} (abc123)\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn falls_back_to_unknown_for_empty_hash() {
        assert_eq!(
            version_text("  "),
            format!(
                "zejtron v{} (unknown)\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION")
            )
        );
    }
}
