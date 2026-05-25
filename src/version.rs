pub fn version_text(hash: &str) -> String {
    let hash = if hash.trim().is_empty() {
        "unknown"
    } else {
        hash.trim()
    };

    format!(
        "nestkit v{} ({hash})\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/nestkit",
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
                "nestkit v{} (abc123)\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/nestkit",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn falls_back_to_unknown_for_empty_hash() {
        assert_eq!(
            version_text("  "),
            format!(
                "nestkit v{} (unknown)\n© 2026 rezky_nightky\nMIT · github.com/oxyzenQ/nestkit",
                env!("CARGO_PKG_VERSION")
            )
        );
    }
}
