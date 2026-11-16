// SPDX-License-Identifier: MIT
//! Claim-name equivalence shared with authentication protocol implementations.
//! This is per-character Unicode lowercase, without locale-sensitive casing,
//! normalization or full case folding. Keep this module allocation-free.

/// Canonical characters, using the mapping supplied by the Rust toolchain.
/// Callers own validation, storage and allocation failure handling.
pub fn canonical_chars(name: &str) -> impl Iterator<Item = char> + '_ {
    name.chars().flat_map(char::to_lowercase)
}

/// Compare claim names without allocating or changing their display spelling.
pub fn names_equal(left: &str, right: &str) -> bool {
    canonical_chars(left).eq(canonical_chars(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_names_share_the_existing_kacs_mapping() {
        for (left, right) in [
            ("Department", "department"),
            ("Équipe", "équipe"),
            ("İ", "i\u{307}"),
            ("K", "k"),
            ("ΟΣ", "οσ"),
        ] {
            assert!(names_equal(left, right), "{left} != {right}");
        }
    }

    #[test]
    fn names_are_not_normalized_or_fully_case_folded() {
        for (left, right) in [("é", "e\u{301}"), ("ß", "ss"), ("ΟΣ", "ος"), ("I", "ı")] {
            assert!(!names_equal(left, right), "{left} == {right}");
        }
    }
}
