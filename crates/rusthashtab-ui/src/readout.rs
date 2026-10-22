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
//!
//! # Two ways to build the same rows
//!
//! [`rows_for`] builds one file's rows as its result arrives, which is the
//! incremental path the scan's callback uses. [`rebuild_rows`] rebuilds the whole
//! list from the results stored on [`crate::session::Shared`], which is what a
//! change to the verification source needs: when the expected digests change, every
//! finished file has to be re-judged, and a verdict from before the change is no
//! longer the right answer. Both paths produce rows the same way, so the two cannot
//! drift in formatting or colouring.

use crate::{Counters, JobSpec, ListRow};
use rusthashtab_scan::{FileResult, MatchState};

/// Build the rows for one finished file.
///
/// One row per enabled algorithm, in table order, so the list can be compared
/// column by column between files.
///
/// `display_path` is copied onto every row rather than looked up at paint or copy
/// time: a row is self-describing, and a lookup would be a second chance to
/// disagree with the list.
///
/// `file_verdict` is the file-level answer [`rusthashtab_scan::match_state`]
/// produced, and it decides the counters. The **row's** colour is decided here,
/// per algorithm: when a digest matches, only the algorithm whose digest actually
/// equals an expected one is marked, because "SHA-256 matched" and "MD5 matched"
/// are different statements and colouring every row of the file would say both.
/// A mismatched file colours every row red -- the expected digests exist and none
/// of them is this file, which is a statement about the file as a whole.
///
/// A file that could not be read produces one row: the error belongs to the file,
/// not to each algorithm, and repeating it 31 times would bury the other files.
/// That row is always [`MatchState::NotChecked`]: an unreadable file is not a
/// corrupt one, and colouring it as a mismatch would say the opposite.
pub fn rows_for(
    job_index: usize,
    display_path: &str,
    result: &FileResult,
    enabled: &[bool],
    upper: bool,
    file_verdict: MatchState,
    expected: &[Vec<u8>],
) -> Vec<ListRow> {
    if let Some(code) = result.error {
        return vec![ListRow {
            id: crate::row_id(job_index, usize::MAX),
            job_index,
            algorithm: usize::MAX,
            digest_hex: String::new(),
            match_state: MatchState::NotChecked,
            error: Some(code),
            display_path: display_path.to_string(),
        }];
    }

    rusthashtab_hash::ALGORITHMS
        .iter()
        .enumerate()
        .filter(|(index, _)| enabled.get(*index).copied().unwrap_or(false))
        .filter_map(|(index, algorithm)| {
            let digest = result.digests.get(index)?;
            if digest.is_empty() {
                // An enabled algorithm with no digest means the scanner dropped
                // it. Showing an empty cell would look like a zero-length digest,
                // so the row is skipped and the count of rows is what says so.
                return None;
            }
            Some(ListRow {
                id: crate::row_id(job_index, index),
                job_index,
                algorithm: index,
                digest_hex: rusthashtab_sumfile::export::to_hex(digest, upper),
                match_state: row_verdict(index, algorithm.secure, digest, expected, file_verdict),
                error: None,
                display_path: display_path.to_string(),
            })
        })
        .collect()
}

/// The verdict to colour one row with.
///
/// A file-level mismatch colours every row red; a match marks only the algorithm
/// whose digest equals an expected one. Everything else is "not checked" rather
/// than "mismatch": an algorithm that was not named by the verification source has
/// simply not been checked.
fn row_verdict(
    algorithm_index: usize,
    secure: bool,
    digest: &[u8],
    expected: &[Vec<u8>],
    file_verdict: MatchState,
) -> MatchState {
    if file_verdict == MatchState::Mismatched {
        return MatchState::Mismatched;
    }
    if expected
        .iter()
        .any(|candidate| candidate.as_slice() == digest)
    {
        return MatchState::Matched {
            algorithm: algorithm_index,
            secure,
        };
    }
    MatchState::NotChecked
}

/// Rebuild every row, and recount the status line, from the stored results.
///
/// Walks the job list in job order and skips a job with no result yet: it has not
/// been hashed, so it has no rows and must not be counted. That is also why the
/// counters are accumulated from zero here rather than adjusted in place -- the
/// result set is the source of truth, and adding a diff to counters that were
/// built by a previous pass is how a count ends up disagreeing with the list.
///
/// The expected digests are per job ([`JobSpec`] carries the path, the vector
/// carries what it should hash to), and a job index past the end of `expected`
/// simply has nothing to compare against. `rusthashtab_scan::match_state` decides
/// the verdict, including its rule that an expected digest whose length belongs to
/// no enabled algorithm is ignored rather than compared against the wrong
/// algorithm.
pub fn rebuild_rows(
    jobs: &[JobSpec],
    results: &[Option<FileResult>],
    expected: &[Vec<Vec<u8>>],
    enabled: &[bool],
    upper: bool,
) -> (Vec<ListRow>, Counters) {
    let mut rows = Vec::new();
    let mut counters = Counters::default();

    for (job_index, (job, result)) in jobs.iter().zip(results).enumerate() {
        let Some(result) = result else {
            continue;
        };
        let expected = expected
            .get(job_index)
            .map_or(&[][..], |expected| expected.as_slice());
        let verdict = rusthashtab_scan::match_state(result, expected, enabled);

        rows.extend(rows_for(
            job_index,
            &job.display_path,
            result,
            enabled,
            upper,
            verdict,
            expected,
        ));
        count_file(verdict, result.error.is_some(), &mut counters);
    }

    (rows, counters)
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

    fn digests_of(pairs: &[(usize, Vec<u8>)]) -> Vec<Vec<u8>> {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        for (index, digest) in pairs {
            digests[*index] = digest.clone();
        }
        digests
    }

    fn job(display_path: &str) -> JobSpec {
        JobSpec {
            path: PathBuf::from(format!(r"C:\dir\{display_path}")),
            display_path: display_path.to_string(),
        }
    }

    /// One row per enabled algorithm, and the digests are the ones the scan
    /// produced.
    #[test]
    fn every_enabled_algorithm_gets_a_row() {
        let sha256 = index_of("SHA-256");
        let digests = digests_of(&[(sha256, vec![0xAB; 32])]);

        let rows = rows_for(
            0,
            "file.bin",
            &result_with(digests, None),
            &enabled_all(),
            true,
            MatchState::NotChecked,
            &[],
        );

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

        let digests = digests_of(&[(sha256, vec![0xAB; 32])]);

        assert!(
            rows_for(
                0,
                "file.bin",
                &result_with(digests, None),
                &enabled,
                true,
                MatchState::NotChecked,
                &[],
            )
            .is_empty()
        );
    }

    /// An enabled algorithm with no digest means the scanner dropped it. An empty
    /// cell would read as a zero-length digest, so no row is the honest answer.
    #[test]
    fn an_enabled_algorithm_with_no_digest_gets_no_row() {
        let digests = vec![Vec::new(); ALGORITHMS.len()];
        assert!(
            rows_for(
                0,
                "file.bin",
                &result_with(digests, None),
                &enabled_all(),
                true,
                MatchState::NotChecked,
                &[],
            )
            .is_empty()
        );
    }

    /// The digest is taken from the scan byte for byte, and the case setting only
    /// changes how it is spelled.
    #[test]
    fn the_hex_honours_the_case_setting() {
        let digests = digests_of(&[(index_of("MD5"), vec![0xde, 0xad, 0xbe, 0xef])]);

        let upper = rows_for(
            0,
            "file.bin",
            &result_with(digests.clone(), None),
            &enabled_all(),
            true,
            MatchState::NotChecked,
            &[],
        );
        assert_eq!(upper[0].digest_hex, "DEADBEEF");

        let lower = rows_for(
            0,
            "file.bin",
            &result_with(digests, None),
            &enabled_all(),
            false,
            MatchState::NotChecked,
            &[],
        );
        assert_eq!(lower[0].digest_hex, "deadbeef");
    }

    /// An unreadable file gets one row, not one per algorithm: the error is the
    /// file's, and thirty-one copies of it would bury every other file in the list.
    #[test]
    fn an_unreadable_file_gets_exactly_one_row() {
        let rows = rows_for(
            0,
            "file.bin",
            &result_with(Vec::new(), Some(5)),
            &enabled_all(),
            true,
            // Deliberately contradicted: an unreadable file is never a mismatch,
            // whatever verdict a caller passes in.
            MatchState::Mismatched,
            &[],
        );

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].error, Some(5));
        assert_eq!(
            rows[0].match_state,
            MatchState::NotChecked,
            "a read failure is not a mismatch"
        );
        assert!(rows[0].digest_hex.is_empty());
        assert_eq!(
            rows[0].algorithm,
            usize::MAX,
            "an error row belongs to no algorithm"
        );
    }

    /// A match marks only the algorithm whose digest actually equals an expected
    /// one. The rest of that file's rows are "not checked": they were hashed but
    /// not compared against anything, and saying "SHA-256 matched" by colouring
    /// every row would make the MD5 row claim a verification it never had.
    #[test]
    fn a_match_marks_only_the_matching_algorithm_row() {
        let sha256 = index_of("SHA-256");
        let md5 = index_of("MD5");
        let sha_digest = vec![0x11; 32];
        let digests = digests_of(&[(sha256, sha_digest.clone()), (md5, vec![0x22; 16])]);
        let verdict = MatchState::Matched {
            algorithm: sha256,
            secure: true,
        };

        let rows = rows_for(
            3,
            r"nested\file.bin",
            &result_with(digests, None),
            &enabled_all(),
            true,
            verdict,
            std::slice::from_ref(&sha_digest),
        );

        assert_eq!(rows.len(), 2);
        let sha_row = rows
            .iter()
            .find(|row| row.algorithm == sha256)
            .expect("the SHA-256 row exists");
        assert_eq!(
            sha_row.match_state,
            MatchState::Matched {
                algorithm: sha256,
                secure: true
            }
        );
        let md5_row = rows
            .iter()
            .find(|row| row.algorithm == md5)
            .expect("the MD5 row exists");
        assert_eq!(
            md5_row.match_state,
            MatchState::NotChecked,
            "a row whose digest was not compared must not claim a verdict"
        );

        for row in &rows {
            assert_eq!(row.display_path, r"nested\file.bin");
        }
    }

    /// A weak algorithm that matches is marked as weak, so the display can colour
    /// it differently from a secure match.
    #[test]
    fn a_weak_match_marks_its_own_row_and_is_not_secure() {
        let md5 = index_of("MD5");
        let sha256 = index_of("SHA-256");
        let md5_digest = vec![0x33; 16];
        let digests = digests_of(&[(md5, md5_digest.clone()), (sha256, vec![0x44; 32])]);
        let verdict = MatchState::Matched {
            algorithm: md5,
            secure: false,
        };

        let rows = rows_for(
            0,
            "file.bin",
            &result_with(digests, None),
            &enabled_all(),
            true,
            verdict,
            std::slice::from_ref(&md5_digest),
        );

        let md5_row = rows
            .iter()
            .find(|row| row.algorithm == md5)
            .expect("the MD5 row exists");
        assert_eq!(
            md5_row.match_state,
            MatchState::Matched {
                algorithm: md5,
                secure: false
            }
        );
        let sha_row = rows
            .iter()
            .find(|row| row.algorithm == sha256)
            .expect("the SHA-256 row exists");
        assert_eq!(sha_row.match_state, MatchState::NotChecked);
    }

    /// When the file verdict is a mismatch, every row of that file is red: the
    /// expected digests exist and none of the file's digests is one of them, which
    /// is a statement about the file, not about one algorithm.
    #[test]
    fn a_mismatch_marks_every_row() {
        let sha256 = index_of("SHA-256");
        let md5 = index_of("MD5");
        let digests = digests_of(&[(sha256, vec![0x11; 32]), (md5, vec![0x22; 16])]);

        let rows = rows_for(
            0,
            "file.bin",
            &result_with(digests, None),
            &enabled_all(),
            true,
            MatchState::Mismatched,
            &[vec![0x99; 32]],
        );

        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|row| row.match_state == MatchState::Mismatched)
        );
    }

    /// An error row belongs to a file too: it must carry the path, or the row
    /// would say nothing about which file could not be read.
    #[test]
    fn an_error_row_carries_the_display_path() {
        let rows = rows_for(
            1,
            r"nested\gone.bin",
            &result_with(Vec::new(), Some(5)),
            &enabled_all(),
            true,
            MatchState::NotChecked,
            &[],
        );
        assert_eq!(rows[0].display_path, r"nested\gone.bin");
    }

    /// A short `enabled` vector must not index out of bounds.
    #[test]
    fn a_short_enabled_list_is_treated_as_disabled() {
        let digests = digests_of(&[(0, vec![1, 2, 3, 4])]);
        assert!(
            rows_for(
                0,
                "file.bin",
                &result_with(digests, None),
                &[],
                true,
                MatchState::NotChecked,
                &[],
            )
            .is_empty()
        );
    }

    /// Rebuilding walks the jobs in job order and skips the ones that have not
    /// finished. A skipped job is not counted: the status line reports hashed
    /// files, not selected ones.
    #[test]
    fn rebuild_rows_keeps_order_and_skips_unfinished_jobs() {
        let jobs = vec![job("a.bin"), job("b.bin"), job("c.bin")];
        let md5 = index_of("MD5");
        let results = vec![
            Some(result_with(digests_of(&[(md5, vec![0xAA; 16])]), None)),
            None,
            Some(result_with(digests_of(&[(md5, vec![0xCC; 16])]), None)),
        ];

        let (rows, counters) = rebuild_rows(
            &jobs,
            &results,
            &[Vec::new(), Vec::new(), Vec::new()],
            &enabled_all(),
            true,
        );

        assert_eq!(rows.len(), 2, "one digest per finished job");
        assert_eq!(
            rows.iter().map(|row| row.job_index).collect::<Vec<_>>(),
            vec![0, 2],
            "rows follow job order, and the unfinished job contributes none"
        );
        assert_eq!(rows[0].display_path, "a.bin");
        assert_eq!(rows[1].display_path, "c.bin");
        assert_eq!(counters.nothing_to_check, 2);
        assert_eq!(
            counters.matched + counters.mismatched + counters.nothing_to_check + counters.error,
            2,
            "each finished file is counted exactly once"
        );
    }

    /// Rebuilding recounts from zero, and each finished file lands in exactly one
    /// category -- including the error category for a file that could not be read.
    #[test]
    fn rebuild_rows_counts_each_finished_file_once() {
        let jobs = vec![job("matched.bin"), job("wrong.bin"), job("gone.bin")];
        let sha256 = index_of("SHA-256");
        let good = vec![0x42; 32];
        let results = vec![
            Some(result_with(digests_of(&[(sha256, good.clone())]), None)),
            Some(result_with(digests_of(&[(sha256, vec![0x00; 32])]), None)),
            Some(result_with(Vec::new(), Some(5))),
        ];
        let expected = vec![vec![good.clone()], vec![good], vec![vec![0x42; 32]]];

        let (rows, counters) = rebuild_rows(&jobs, &results, &expected, &enabled_all(), true);

        assert_eq!(rows.len(), 3, "two digests and one error row");
        assert_eq!(counters.matched, 1);
        assert_eq!(counters.mismatched, 1);
        assert_eq!(counters.error, 1);
        assert_eq!(counters.nothing_to_check, 0);
    }

    /// A job past the end of the expected-digest table has nothing to compare
    /// against; the rebuild must treat that as "not checked", not panic or invent a
    /// mismatch.
    #[test]
    fn rebuild_rows_tolerates_a_short_expected_table() {
        let jobs = vec![job("a.bin")];
        let sha256 = index_of("SHA-256");
        let results = vec![Some(result_with(
            digests_of(&[(sha256, vec![0x42; 32])]),
            None,
        ))];

        let (rows, counters) = rebuild_rows(&jobs, &results, &[], &enabled_all(), true);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].match_state, MatchState::NotChecked);
        assert_eq!(counters.nothing_to_check, 1);
    }

    /// Rebuilding an empty result set is how the page starts: no rows, no counts.
    #[test]
    fn rebuild_rows_of_nothing_is_empty() {
        let (rows, counters) = rebuild_rows(&[], &[], &[], &enabled_all(), true);
        assert!(rows.is_empty());
        assert_eq!(counters, Counters::default());
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
