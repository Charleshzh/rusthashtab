//! Turning scan results into the rows and counters the page displays.
//!
//! # Why formatting happens here and not on the paint path
//!
//! The list view is owner-drawn, so its paint path runs on the shell's thread with
//! a device context held. Formatting a digest into a `String` there would allocate
//! on every repaint, and a repaint can be triggered by anything the user does to
//! the dialog. Every row is therefore fully formatted once, when the result
//! arrives, and the paint path only copies characters out of a buffer that already
//! exists.
//!
//! # Why the hex comes from the sumfile crate
//!
//! Uppercase-or-lowercase display is the same decision in the page and in an
//! exported checksum file, and the two must not be able to disagree. The encoder
//! lives in `rusthashtab-sumfile` because that is where the export path already
//! needed it, and this module calls it rather than writing a second one.

use crate::{Counters, ListRow};
use rusthashtab_scan::{FileResult, MatchState};

/// Build the rows for one finished file.
///
/// One row per enabled algorithm, in table order, so the list can be compared
/// column by column between files.
///
/// A file that could not be read produces one row: the error belongs to the file,
/// not to each algorithm, and repeating it 31 times would bury the other files.
pub fn rows_for(
    job_index: usize,
    result: &FileResult,
    enabled: &[bool],
    upper: bool,
) -> Vec<ListRow> {
    if let Some(code) = result.error {
        return vec![ListRow {
            job_index,
            algorithm: usize::MAX,
            digest_hex: String::new(),
            match_state: MatchState::NotChecked,
            error: Some(code),
        }];
    }

    rusthashtab_hash::ALGORITHMS
        .iter()
        .enumerate()
        .filter(|(index, _)| enabled.get(*index).copied().unwrap_or(false))
        .filter_map(|(index, _algorithm)| {
            let digest = result.digests.get(index)?;
            if digest.is_empty() {
                // An enabled algorithm with no digest means the scanner dropped
                // it. Showing an empty cell would look like a zero-length digest,
                // so the row is skipped and the count of rows is what says so.
                return None;
            }
            Some(ListRow {
                job_index,
                algorithm: index,
                digest_hex: rusthashtab_sumfile::export::to_hex(digest, upper),
                match_state: MatchState::NotChecked,
                error: None,
            })
        })
        .collect()
}

/// Recount the status line's four categories from the rows of one file.
///
/// The categories are mutually exclusive and the order they are decided in is the
/// order the status line prints them, which is why this returns a whole
/// [`Counters`] rather than adjusting one in place.
pub fn count_file(state: MatchState, failed: bool, counters: &mut Counters) {
    if failed {
        counters.error = counters.error.saturating_add(1);
        return;
    }
    match state {
        MatchState::Matched { .. } => counters.matched = counters.matched.saturating_add(1),
        MatchState::Mismatched => counters.mismatched = counters.mismatched.saturating_add(1),
        MatchState::NotChecked => {
            counters.nothing_to_check = counters.nothing_to_check.saturating_add(1)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_hash::ALGORITHMS;
    use std::path::PathBuf;

    fn index_of(name: &str) -> usize {
        ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
            .expect("the algorithm is in the table")
    }

    fn enabled_all() -> Vec<bool> {
        vec![true; ALGORITHMS.len()]
    }

    fn result_with(digests: Vec<Vec<u8>>, error: Option<u32>) -> FileResult {
        FileResult {
            path: PathBuf::from(r"C:\file.bin"),
            digests,
            size: 1,
            error,
        }
    }

    /// One row per enabled algorithm, and the digests are the ones the scan
    /// produced.
    #[test]
    fn every_enabled_algorithm_gets_a_row() {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        let sha256 = index_of("SHA-256");
        digests[sha256] = vec![0xAB; 32];

        let rows = rows_for(0, &result_with(digests, None), &enabled_all(), true);

        assert_eq!(rows.len(), 1, "only one algorithm had a digest");
        assert_eq!(rows[0].algorithm, sha256);
        assert_eq!(rows[0].digest_hex, "AB".repeat(32));
        assert_eq!(rows[0].error, None);
    }

    /// A disabled algorithm must not produce a row, however complete its digest.
    #[test]
    fn a_disabled_algorithm_gets_no_row() {
        let mut enabled = enabled_all();
        let sha256 = index_of("SHA-256");
        enabled[sha256] = false;

        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        digests[sha256] = vec![0xAB; 32];

        assert!(rows_for(0, &result_with(digests, None), &enabled, true).is_empty());
    }

    /// An enabled algorithm with no digest means the scanner dropped it. An empty
    /// cell would read as a zero-length digest, so no row is the honest answer.
    #[test]
    fn an_enabled_algorithm_with_no_digest_gets_no_row() {
        let digests = vec![Vec::new(); ALGORITHMS.len()];
        assert!(rows_for(0, &result_with(digests, None), &enabled_all(), true).is_empty());
    }

    /// The digest is taken from the scan byte for byte, and the case setting only
    /// changes how it is spelled.
    #[test]
    fn the_hex_honours_the_case_setting() {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        digests[index_of("MD5")] = vec![0xde, 0xad, 0xbe, 0xef];

        let upper = rows_for(0, &result_with(digests.clone(), None), &enabled_all(), true);
        assert_eq!(upper[0].digest_hex, "DEADBEEF");

        let lower = rows_for(0, &result_with(digests, None), &enabled_all(), false);
        assert_eq!(lower[0].digest_hex, "deadbeef");
    }

    /// An unreadable file gets one row, not one per algorithm: the error is the
    /// file's, and thirty-one copies of it would bury every other file in the list.
    #[test]
    fn an_unreadable_file_gets_exactly_one_row() {
        let rows = rows_for(0, &result_with(Vec::new(), Some(5)), &enabled_all(), true);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].error, Some(5));
        assert!(rows[0].digest_hex.is_empty());
        assert_eq!(
            rows[0].algorithm,
            usize::MAX,
            "an error row belongs to no algorithm"
        );
    }

    /// A short `enabled` vector must not index out of bounds.
    #[test]
    fn a_short_enabled_list_is_treated_as_disabled() {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        digests[0] = vec![1, 2, 3, 4];
        assert!(rows_for(0, &result_with(digests, None), &[], true).is_empty());
    }

    /// The four categories are mutually exclusive, and the order they are decided
    /// in is the order the status line prints them.
    #[test]
    fn each_file_lands_in_exactly_one_category() {
        let mut counters = Counters::default();

        count_file(MatchState::NotChecked, true, &mut counters);
        assert_eq!(
            counters.error, 1,
            "a failed read is an error, not unchecked"
        );

        count_file(
            MatchState::Matched {
                algorithm: 0,
                secure: true,
            },
            false,
            &mut counters,
        );
        assert_eq!(counters.matched, 1);
        assert_eq!(counters.nothing_to_check, 0);

        count_file(MatchState::Mismatched, false, &mut counters);
        assert_eq!(counters.mismatched, 1);

        count_file(MatchState::NotChecked, false, &mut counters);
        assert_eq!(counters.nothing_to_check, 1);

        let total =
            counters.matched + counters.mismatched + counters.nothing_to_check + counters.error;
        assert_eq!(total, 4, "every file was counted once");
    }

    /// A mismatch reported for a file that could not be read must not appear: the
    /// user would be told their file is corrupt when it was merely unreadable.
    #[test]
    fn a_failed_read_outranks_a_mismatch() {
        let mut counters = Counters::default();
        count_file(MatchState::Mismatched, true, &mut counters);
        assert_eq!(counters.error, 1);
        assert_eq!(counters.mismatched, 0);
    }

    /// Counting is saturating: a directory of four billion files must not wrap the
    /// status line into claiming zero.
    #[test]
    fn counting_saturates_rather_than_wrapping() {
        let mut counters = Counters {
            matched: u32::MAX,
            ..Counters::default()
        };
        count_file(
            MatchState::Matched {
                algorithm: 0,
                secure: true,
            },
            false,
            &mut counters,
        );
        assert_eq!(counters.matched, u32::MAX);
    }
}
