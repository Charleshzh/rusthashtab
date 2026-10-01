//! Comparing a file's digests against the digests it was expected to have.
//!
//! # Why "secure" changes the answer
//!
//! A file can legitimately be listed in a sumfile under several algorithms at
//! once, and the same expected digest may be short enough to compare equal to
//! more than one of them — a CRC32 value can collide with the first four bytes
//! of an MD5. When two enabled algorithms both match, the interesting answer is
//! the strong one: reporting "matched (CRC32)" for a file whose SHA-256 also
//! matched would make a weak algorithm look like the thing being verified.
//! Hence a secure match outranks a weak one regardless of table order.

use crate::{FileResult, MatchState};
use rusthashtab_hash::ALGORITHMS;

/// Compare a finished file against its expected digests.
///
/// Returns [`MatchState::NotChecked`] when there was nothing to compare against,
/// and also when the file could not be read: a read failure is reported through
/// [`FileResult::error`], and counting it as a mismatch would tell the user their
/// file is corrupt when in fact it was merely unreadable.
pub(crate) fn match_state(
    result: &FileResult,
    expected: &[Vec<u8>],
    enabled: &[bool],
) -> MatchState {
    if result.error.is_some() || expected.is_empty() {
        return MatchState::NotChecked;
    }

    let mut weak_match: Option<usize> = None;

    for (index, algorithm) in ALGORITHMS.iter().enumerate() {
        if !enabled.get(index).copied().unwrap_or(false) {
            continue;
        }
        let digest = match result.digests.get(index) {
            Some(digest) if !digest.is_empty() => digest.as_slice(),
            _ => continue,
        };
        for candidate in expected {
            if candidate.as_slice() != digest {
                continue;
            }
            if algorithm.secure {
                return MatchState::Matched {
                    algorithm: index,
                    secure: true,
                };
            }
            weak_match = Some(index);
        }
    }

    match weak_match {
        Some(algorithm) => MatchState::Matched {
            algorithm,
            secure: false,
        },
        None => MatchState::Mismatched,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Indices of the algorithms used below, looked up by name so a table
    /// reordering cannot silently turn these tests into no-ops.
    fn index_of(name: &str) -> usize {
        ALGORITHMS
            .iter()
            .position(|a| a.name == name)
            .expect("algorithm is in the table")
    }

    fn enabled_all() -> Vec<bool> {
        vec![true; ALGORITHMS.len()]
    }

    /// A result carrying a digest for exactly one algorithm.
    fn result_with(index: usize, digest: Vec<u8>) -> FileResult {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        digests[index] = digest;
        FileResult {
            path: PathBuf::from(r"C:\file.bin"),
            digests,
            size: 1,
            error: None,
        }
    }

    #[test]
    fn no_expected_digest_is_not_checked() {
        let sha256 = index_of("SHA-256");
        let result = result_with(sha256, vec![0xAB; 32]);
        assert_eq!(
            match_state(&result, &[], &enabled_all()),
            MatchState::NotChecked
        );
    }

    #[test]
    fn a_matching_secure_digest_is_reported_as_secure() {
        let sha256 = index_of("SHA-256");
        let digest = vec![0x42; 32];
        let result = result_with(sha256, digest.clone());
        assert_eq!(
            match_state(&result, std::slice::from_ref(&digest), &enabled_all()),
            MatchState::Matched {
                algorithm: sha256,
                secure: true
            }
        );
    }

    #[test]
    fn a_matching_weak_digest_is_reported_but_not_as_secure() {
        let crc32 = index_of("CRC32");
        let digest = vec![0x01, 0x02, 0x03, 0x04];
        let result = result_with(crc32, digest.clone());
        assert_eq!(
            match_state(&result, std::slice::from_ref(&digest), &enabled_all()),
            MatchState::Matched {
                algorithm: crc32,
                secure: false
            }
        );
    }

    /// The reason `secure` is not simply "the first algorithm that matched".
    #[test]
    fn a_secure_match_outranks_a_weak_one_earlier_in_the_table() {
        let crc32 = index_of("CRC32");
        let sha256 = index_of("SHA-256");
        let mut result = result_with(crc32, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        result.digests[sha256] = vec![0x11; 32];

        let state = match_state(
            &result,
            &[vec![0xAA, 0xBB, 0xCC, 0xDD], vec![0x11; 32]],
            &enabled_all(),
        );
        assert_eq!(
            state,
            MatchState::Matched {
                algorithm: sha256,
                secure: true
            }
        );
    }

    #[test]
    fn a_different_expected_digest_is_a_mismatch() {
        let sha256 = index_of("SHA-256");
        let result = result_with(sha256, vec![0x00; 32]);
        assert_eq!(
            match_state(&result, &[vec![0xFF; 32]], &enabled_all()),
            MatchState::Mismatched
        );
    }

    #[test]
    fn a_disabled_algorithm_never_matches() {
        let sha256 = index_of("SHA-256");
        let digest = vec![0x42; 32];
        let result = result_with(sha256, digest.clone());
        let mut enabled = enabled_all();
        enabled[sha256] = false;
        assert_eq!(
            match_state(&result, std::slice::from_ref(&digest), &enabled),
            MatchState::Mismatched
        );
    }

    /// An unreadable file is not a corrupt one.
    #[test]
    fn a_read_failure_is_not_counted_as_a_mismatch() {
        let sha256 = index_of("SHA-256");
        let mut result = result_with(sha256, Vec::new());
        result.error = Some(5);
        assert_eq!(
            match_state(&result, &[vec![0x42; 32]], &enabled_all()),
            MatchState::NotChecked
        );
    }
}
