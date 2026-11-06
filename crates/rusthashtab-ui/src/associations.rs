//! The checksum-file extensions this product can produce and interpret.
//!
//! # Why the list is derived rather than written down
//!
//! The shell's "Open with" registration is only allowed to name file types this
//! product can actually read back and write itself. A hand-maintained list drifts
//! the moment an algorithm gains an extension, and a stale list is invisible: the
//! registry simply advertises a type that opens a window with an error row.
//!
//! So the set is derived from the algorithm table at runtime, plus the two
//! non-algorithm formats the exporter offers:
//!
//! * `sfv` -- CRC32 in SFV form;
//! * `hash` -- the corz form.
//!
//! The registry's extension spellings are lowercase by contract, and a test
//! enforces it. Keeping `&'static str` here rather than allocating a lowercase
//! copy means the shell can write the values without a second allocation, and it
//! makes an uppercase extension a test failure at the source instead of a
//! registry key nobody can reconcile with the parse table.

use rusthashtab_hash::ALGORITHMS;
use std::collections::BTreeSet;

/// The program identifier used for every checksum-file type this product writes.
///
/// One ProgId for all extensions rather than one per format: the standalone
/// window decides what a file is from its extension, so the shell does not need a
/// separate registration per algorithm. The name is not version-specific, so a
/// future build can take over the existing registration.
pub const PROG_ID: &str = "rustHashTab.ChecksumFile";

/// Every checksum-file extension this product can produce or interpret.
///
/// Lowercase, de-duplicated, sorted, and independent of which algorithms the
/// user has enabled: the association describes what the build can read, not what
/// the current settings happen to hash with.
#[must_use]
pub fn extensions() -> Vec<&'static str> {
    let mut set: BTreeSet<&'static str> = BTreeSet::new();

    for algorithm in ALGORITHMS {
        for extension in algorithm.extensions {
            set.insert(extension);
        }
    }
    // The two formats that are not owned by one algorithm. `sfv` is CRC32 in SFV
    // form and `hash` is the corz form; both are written by the exporter and read
    // by the manifest detector.
    set.insert("sfv");
    set.insert("hash");

    set.into_iter().collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::export::{ExportChoice, extension};
    use rusthashtab_hash::registry;

    /// Every registry spelling is lowercase, which is what lets [`extensions`]
    /// keep `&'static str` instead of allocating a normalised copy. An uppercase
    /// extension in the table would otherwise produce a registry value that never
    /// matches the extension Windows reports.
    #[test]
    fn every_registry_extension_is_lowercase() {
        for algorithm in ALGORITHMS {
            for extension in algorithm.extensions {
                assert_eq!(
                    *extension,
                    extension.to_ascii_lowercase(),
                    "{} has a non-lowercase extension `{extension}`",
                    algorithm.name
                );
            }
        }
    }

    #[test]
    fn the_set_is_sorted_unique_and_lowercase() {
        let extensions = extensions();
        assert!(!extensions.is_empty());

        let mut sorted = extensions.clone();
        sorted.sort_unstable();
        assert_eq!(extensions, sorted, "the list must be deterministic");

        for window in extensions.windows(2) {
            assert_ne!(window[0], window[1], "duplicate extension");
        }
        for extension in &extensions {
            assert_eq!(*extension, extension.to_ascii_lowercase());
        }
    }

    /// The three formats a user is most likely to meet must all be there. This is
    /// a floor, not the whole set: the derived list is allowed to grow.
    #[test]
    fn the_documented_formats_are_present() {
        let extensions = extensions();
        for wanted in ["sha256", "md5", "sfv", "hash"] {
            assert!(
                extensions.contains(&wanted),
                "`{wanted}` is missing from the association set"
            );
        }
        assert!(!extensions.contains(&"txt"));
    }

    /// Every extension we advertise has to be one the parser can name. `sfv` and
    /// `hash` are special-cased by the manifest detector; every other extension
    /// must resolve through the algorithm table.
    #[test]
    fn every_advertised_extension_is_interpretable() {
        for extension in extensions() {
            let known =
                matches!(extension, "sfv" | "hash") || registry::by_extension(extension).is_some();
            assert!(known, "`{extension}` has no parser");
        }
    }

    /// The exporter's suggested extension for every choice must be in the set,
    /// because that is the file name a user gets from the Save dialog.
    #[test]
    fn every_export_choice_suggests_an_advertised_extension() {
        let extensions = extensions();
        let mut choices: Vec<ExportChoice> = ALGORITHMS
            .iter()
            .enumerate()
            .filter(|(_, algorithm)| !algorithm.extensions.is_empty())
            .map(|(index, _)| ExportChoice::Algorithm(index))
            .collect();
        choices.push(ExportChoice::Sfv);
        choices.push(ExportChoice::DotHash);

        for choice in choices {
            let suggested = extension(choice);
            assert!(
                extensions.contains(&suggested),
                "{choice:?} suggests `{suggested}`, which is not advertised"
            );
        }
    }
}
