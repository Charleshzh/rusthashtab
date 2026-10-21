//! Checksum-file verification: matching sumfile entries to hashed files.
//!
//! # Why matching is not a string comparison
//!
//! A checksum file lists *names*, not paths, and those names are rarely spelled
//! the way the scanner spells the same file: tools lower-case them, write `/` on
//! Windows, list bare basenames, or name a file relative to the checksum file's
//! own directory. The rules below are the resolution order, and each one exists
//! because a real checksum file uses it.
//!
//! 1. **A key is the normalized, case-folded path.** [`normalize_path`] makes the
//!    path absolute and resolves `.` and `..` lexically; the text is then
//!    lower-cased and `/` is folded to `\`. Windows file systems are
//!    case-insensitive, so `C:\Data\A.TXT` and `c:\data\a.txt` name the same file
//!    and must not become two keys.
//! 2. **An entry with no file name belongs to the file the checksum file is named
//!    after.** A `data.bin.sha256` holding a single bare digest is the digest of
//!    `data.bin`. The extension list comes from [`rusthashtab_hash::ALGORITHMS`],
//!    so a newly registered extension works here without a second list to keep
//!    in sync. A checksum file whose name has no registered extension names no
//!    file, and its entry is unmatched.
//! 3. **A relative entry is relative to the checksum file, not to us.** The user
//!    may have opened a checksum file from anywhere; its author wrote names next
//!    to it. An entry that is absolute (`C:\…`, `\\server\share\…`) is normalized
//!    on its own, and a sibling `..` is resolved lexically rather than by asking
//!    the file system (which would follow junctions).
//! 4. **A bare basename falls back to a basename match.** After rule 3 fails, an
//!    entry that is *only* a file name may still name a file the user selected
//!    from a different directory. If exactly one job has that name it matches;
//!    if several do, the one in the checksum file's own directory wins; if that
//!    is still ambiguous the entry is left unmatched rather than arbitrarily
//!    pointing at one of the candidates. A basename inside a directory
//!    (`sub\a.txt`) never takes this shortcut: the directory was a choice, and
//!    ignoring it would verify the wrong file.
//! 5. **Entries accumulate, duplicates do not.** One file may be listed under
//!    several algorithms. Every digest is kept, but an exactly repeated digest is
//!    stored once, since it carries no new information and would make "how many
//!    expectations does this file have" wrong.
//! 6. **`unmatched` counts entries, not files.** It exists so the page can tell
//!    the user how much of the checksum file had no counterpart in the scan; one
//!    file with three entries and one file with one entry are different numbers.
//!
//! # What is deliberately not decided here
//!
//! An entry's digest is *not* tied to an algorithm. The sumfile formats do not
//! record which algorithm produced a digest -- a `.sha256` extension is a hint,
//! not a guarantee -- so the only sound rule is digest length, and it is applied
//! later by [`rusthashtab_scan::match_state`], which compares against every
//! enabled algorithm of that output length. Assigning an algorithm here would let
//! a mislabelled checksum file look verified.
//!
//! # Sidecar checksum files
//!
//! [`attach_sidecars`] is the "check the file against the checksum next to it"
//! behaviour. It is a separate entry point rather than something the page does
//! unconditionally, because whether to look is a user setting
//! (`Settings::look_for_sumfiles`) and the caller is the one that knows it.

use crate::JobSpec;
use rusthashtab_hash::ALGORITHMS;
use rusthashtab_scan::{FileJob, normalize_path};
use rusthashtab_sumfile::MAX_DIGEST_LEN;
use rusthashtab_sumfile::parse::{ParseOutcome, hex_to_bytes, parse_all};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

/// Largest checksum file this module will read, in bytes.
///
/// A checksum file has one line per hashed file, so 16 MiB is hundreds of
/// thousands of entries -- far past [`crate::MAX_HASHED_FILES`], and past what a
/// user could have selected. The cap is not a format limit: it bounds the
/// allocation for a file chosen by name (or found next to a hashed file), which
/// must not be able to stall the page by pointing at a multi-gigabyte file.
pub const MAX_SUMFILE_BYTES: u64 = 16 * 1024 * 1024;

/// The result of matching one checksum file against the scan's jobs.
///
/// `expected` is indexed like the job list: one digest list per job, in the order
/// the scanner reported them. A job that appears nowhere in the checksum file has
/// an empty list, which [`rusthashtab_scan::match_state`] reports as
/// [`rusthashtab_scan::MatchState::NotChecked`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumfileMatch {
    /// Expected digests, one vector per job, in job order.
    pub expected: Vec<Vec<Vec<u8>>>,
    /// Entries in the checksum file that named no job in the scan.
    pub unmatched: usize,
    /// Whether the parser saw a line it could not interpret.
    ///
    /// Not fatal: the entries before the bad line are still usable, and a partial
    /// verification is more useful to the user than none. The page shows this so
    /// an incomplete checksum file is visible rather than silently ignored.
    pub had_error: bool,
}

/// Why a checksum file could not be read.
#[derive(Debug, thiserror::Error)]
pub enum SumfileError {
    /// The file is larger than [`MAX_SUMFILE_BYTES`].
    #[error("checksum file is larger than {MAX_SUMFILE_BYTES} bytes")]
    TooLarge,
    /// The file could not be opened or read; the OS message is included.
    #[error("{0}")]
    Io(String),
}

/// Read and parse one checksum file.
///
/// The size check uses the metadata first so an enormous file is rejected without
/// reading it, and repeats the check on the bytes actually read because a file
/// can grow between the two calls. A file that is not valid UTF-8 is decoded
/// lossily rather than refused: checksum files are routinely written in the
/// system ANSI code page, and losing the odd filename beats losing the whole
/// verification. The replacement characters make that one entry unmatched, which
/// is visible in [`SumfileMatch::unmatched`].
///
/// # Errors
///
/// [`SumfileError::TooLarge`] when the file exceeds [`MAX_SUMFILE_BYTES`], and
/// [`SumfileError::Io`] when it cannot be opened or read.
pub fn read_sumfile(path: &Path) -> Result<ParseOutcome, SumfileError> {
    let metadata = std::fs::metadata(path).map_err(|error| SumfileError::Io(error.to_string()))?;
    if metadata.len() > MAX_SUMFILE_BYTES {
        return Err(SumfileError::TooLarge);
    }

    let bytes = std::fs::read(path).map_err(|error| SumfileError::Io(error.to_string()))?;
    // The file may have grown between `metadata` and `read`, so the limit is
    // enforced on what was actually allocated as well.
    if bytes.len() as u64 > MAX_SUMFILE_BYTES {
        return Err(SumfileError::TooLarge);
    }

    let text = String::from_utf8_lossy(&bytes);
    Ok(parse_all(&text))
}

/// Match a parsed checksum file against the jobs the page is hashing.
///
/// The rules are the six listed in the module documentation; the important
/// contract is that the returned `expected` has exactly one entry per job in
/// `jobs`, so a caller can index it with the scan's job index and never has to
/// look a file up by name again.
///
/// `sumfile` is the path the entries are resolved against (rule 3) and the path
/// whose file name rule 2 reads. It does not have to exist: a pasted checksum
/// file has no path of its own, and the dialog passes a synthetic one.
#[must_use]
pub fn match_sumfile(parsed: &ParseOutcome, sumfile: &Path, jobs: &[JobSpec]) -> SumfileMatch {
    let sumfile = normalize_path(sumfile);
    let sumfile_dir = sumfile.parent().map(Path::to_path_buf).unwrap_or_default();
    let sumfile_dir_key = key_text(&sumfile_dir);

    // Index the jobs both ways once: a checksum file routinely names thousands of
    // files, and a linear scan per entry would make verification quadratic.
    let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut parent_keys: Vec<String> = Vec::with_capacity(jobs.len());
    for (index, job) in jobs.iter().enumerate() {
        by_key.entry(path_key(&job.path)).or_default().push(index);
        if let Some(name) = job.path.file_name() {
            by_name
                .entry(name.to_string_lossy().to_lowercase())
                .or_default()
                .push(index);
        }
        parent_keys.push(job.path.parent().map(path_key).unwrap_or_default());
    }

    let mut expected: Vec<Vec<Vec<u8>>> = vec![Vec::new(); jobs.len()];
    let mut unmatched = 0;

    for entry in &parsed.entries {
        let Some(targets) = resolve_targets(
            &entry.path,
            &sumfile,
            &sumfile_dir,
            &sumfile_dir_key,
            &by_key,
            &by_name,
            &parent_keys,
        ) else {
            unmatched += 1;
            continue;
        };

        for index in targets {
            let digests = &mut expected[index];
            if !digests.iter().any(|existing| existing == &entry.digest) {
                digests.push(entry.digest.clone());
            }
        }
    }

    SumfileMatch {
        expected,
        unmatched,
        had_error: parsed.had_error,
    }
}

/// Attach the expectations from checksum files found next to each file.
///
/// For every job this looks for `<file name>.<extension>` in the job's own
/// directory, for every extension registered in [`rusthashtab_hash::ALGORITHMS`]
/// (for example `data.bin.sha256` next to `data.bin`), reads each one that
/// exists, and keeps only the expectation that names the job being processed.
/// Digests already present on the job are not added again.
///
/// Whether to call this at all is the caller's decision: it implements the
/// user's "look for checksum files" setting, and only the page knows that
/// setting. Returning `0` therefore also covers a page that never looked.
///
/// A sidecar that cannot be read, is too large, or turns out to be some other
/// kind of file is skipped silently: it was found by name, not chosen by the
/// user, so there is nothing to report and no reason to disturb a scan that is
/// otherwise fine.
///
/// Directory listings are cached per directory, because the page usually hashes
/// many files in the same folder and each job would otherwise re-enumerate it.
///
/// Returns the number of jobs that gained at least one new expected digest.
pub fn attach_sidecars(jobs: &mut [FileJob]) -> usize {
    if jobs.is_empty() {
        return 0;
    }

    // A read-only view of the jobs for the matcher. It is built up front so the
    // matching below does not need the mutable borrow the additions require.
    let specs: Vec<JobSpec> = jobs
        .iter()
        .map(|job| JobSpec {
            path: job.path.clone(),
            display_path: job.display_path.clone(),
        })
        .collect();

    let extensions = registered_extensions();
    let mut directories: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut additions: Vec<Vec<Vec<u8>>> = vec![Vec::new(); jobs.len()];
    let mut attached = 0;

    for (index, job) in jobs.iter().enumerate() {
        let (Some(parent), Some(file_name)) = (job.path.parent(), job.path.file_name()) else {
            continue;
        };
        let parent = parent.to_path_buf();
        let file_name = file_name.to_string_lossy().to_lowercase();

        let names = directories
            .entry(parent.clone())
            .or_insert_with(|| directory_names(&parent));

        let mut candidates: Vec<PathBuf> = Vec::new();
        for extension in &extensions {
            let candidate = format!("{file_name}.{}", extension.to_lowercase());
            if names.contains(&candidate) {
                candidates.push(parent.join(candidate));
            }
        }
        if candidates.is_empty() {
            continue;
        }

        let mut added_here = false;
        for candidate in candidates {
            let Ok(parsed) = read_sumfile(&candidate) else {
                continue;
            };
            let matched = match_sumfile(&parsed, &candidate, &specs);
            let Some(digests) = matched.expected.get(index) else {
                continue;
            };
            for digest in digests {
                if jobs[index].expected.contains(digest) || additions[index].contains(digest) {
                    continue;
                }
                additions[index].push(digest.clone());
                added_here = true;
            }
        }
        if added_here {
            attached += 1;
        }
    }

    for (index, digests) in additions.into_iter().enumerate() {
        if let Some(job) = jobs.get_mut(index) {
            job.expected.extend(digests);
        }
    }

    attached
}

/// Decode a digest pasted by the user.
///
/// The text is trimmed (a copy from a terminal usually brings a newline), then
/// decoded as hex. The length must be even and between four characters and
/// [`MAX_DIGEST_LEN`] hex-encoded digest lengths: shorter than four cannot be any
/// supported digest, and longer than the longest algorithm's hex form cannot be
/// either. Case does not matter; [`hex_to_bytes`] accepts both.
///
/// Returns `None` for anything else, including a checksum file's `HASH  FILE`
/// line: this entry point takes a digest, and silently extracting the leading
/// hash of a line the user pasted from a checksum file would hide the mistake.
#[must_use]
pub fn parse_pasted(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.len() < 4 || trimmed.len() > MAX_DIGEST_LEN * 2 || !trimmed.len().is_multiple_of(2) {
        return None;
    }
    hex_to_bytes(trimmed)
}

/// Resolve one entry to job indices, or `None` when it names none.
fn resolve_targets(
    entry: &str,
    sumfile: &Path,
    sumfile_dir: &Path,
    sumfile_dir_key: &str,
    by_key: &HashMap<String, Vec<usize>>,
    by_name: &HashMap<String, Vec<usize>>,
    parent_keys: &[String],
) -> Option<Vec<usize>> {
    let entry = entry.trim();

    // Rule 2: a file name-less entry belongs to the file the checksum file is
    // named after.
    if entry.is_empty() {
        let name = sumfile.file_name()?.to_string_lossy();
        let stem = strip_registered_extension(&name)?;
        let key = path_key(&sumfile_dir.join(stem));
        return by_key.get(&key).cloned();
    }

    // Rule 3: absolute entries stand alone; relative ones live next to the
    // checksum file.
    let raw = Path::new(entry);
    let absolute = if raw.has_root() {
        normalize_path(raw)
    } else {
        normalize_path(&sumfile_dir.join(raw))
    };

    if let Some(indices) = by_key.get(&path_key(&absolute)) {
        return Some(indices.clone());
    }

    // Rule 4: only a bare basename gets the directory-less fallback.
    if !is_bare_file_name(raw) {
        return None;
    }
    let name = raw.file_name()?.to_string_lossy().to_lowercase();
    let candidates = by_name.get(&name)?;
    if candidates.len() == 1 {
        return Some(candidates.clone());
    }

    // Several jobs have this name: the one in the checksum file's directory is
    // the only defensible choice. Anything else would verify a different file
    // and tell the user it was checked.
    let same_directory: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|index| {
            parent_keys
                .get(*index)
                .is_some_and(|key| key == sumfile_dir_key)
        })
        .collect();
    (same_directory.len() == 1).then_some(same_directory)
}

/// The matching key for a path: normalized, slash-folded, lower-cased.
fn path_key(path: &Path) -> String {
    key_text(&normalize_path(path))
}

/// The matching key for a path that has already been normalized.
fn key_text(normalized: &Path) -> String {
    normalized
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

/// Whether the entry is a bare file name, with no directory part at all.
fn is_bare_file_name(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

/// Strip a registered checksum-file extension from a file name.
///
/// Returns the name without the dot and extension, or `None` when the name ends
/// in no registered extension. Matching is ASCII case-insensitive, like the file
/// system that holds it.
fn strip_registered_extension(name: &str) -> Option<&str> {
    for algorithm in ALGORITHMS {
        for extension in algorithm.extensions {
            let Some(dot) = name.len().checked_sub(extension.len()) else {
                continue;
            };
            if dot == 0 {
                continue;
            }
            let (head, tail) = name.split_at(dot);
            if head.ends_with('.') && tail.eq_ignore_ascii_case(extension) {
                return Some(&head[..head.len() - 1]);
            }
        }
    }
    None
}

/// Every registered checksum-file extension, deduplicated, in table order.
fn registered_extensions() -> Vec<&'static str> {
    let mut seen = HashSet::new();
    let mut extensions = Vec::new();
    for algorithm in ALGORITHMS {
        for extension in algorithm.extensions {
            if seen.insert(*extension) {
                extensions.push(*extension);
            }
        }
    }
    extensions
}

/// The lower-cased names in a directory, for sidecar lookups.
///
/// An unreadable directory yields an empty set: the sidecar lookup is best
/// effort, and a permission problem here is not a scan failure.
fn directory_names(directory: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    if let Ok(reader) = std::fs::read_dir(directory) {
        for entry in reader.flatten() {
            names.insert(entry.file_name().to_string_lossy().to_lowercase());
        }
    }
    names
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    /// The SHA-256 of the empty input, used as a plausible digest throughout.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// The MD5 of the empty input.
    const MD5_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";

    /// A uniquely named temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusthashtab-ui-verify-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Create a file (and its parent directories) with `contents`.
        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn job(path: &Path) -> JobSpec {
        JobSpec {
            path: normalize_path(path),
            display_path: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }

    fn file_job(path: &Path) -> FileJob {
        FileJob {
            path: normalize_path(path),
            display_path: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            expected: Vec::new(),
            size: 0,
        }
    }

    fn digest(hex: &str) -> Vec<u8> {
        hex_to_bytes(hex).expect("test fixture is valid hex")
    }

    #[test]
    fn read_sumfile_parses_a_gnu_style_checksum_file() {
        let dir = TempDir::new("read");
        let path = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  a.txt\n"));
        let parsed = read_sumfile(&path).unwrap();
        assert!(!parsed.had_error);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].path, "a.txt");
        assert_eq!(parsed.entries[0].digest, digest(SHA256_EMPTY));
    }

    /// The metadata check must reject the file before it is read: the whole
    /// point of the cap is not to allocate the file.
    #[test]
    fn read_sumfile_rejects_a_file_over_the_limit() {
        let dir = TempDir::new("large");
        let path = dir.path().join("huge.sha256");
        let file = fs::File::create(&path).unwrap();
        // Sparse: the file is over the limit without writing 16 MiB to disk.
        file.set_len(MAX_SUMFILE_BYTES + 1).unwrap();
        drop(file);

        assert!(matches!(read_sumfile(&path), Err(SumfileError::TooLarge)));
    }

    #[test]
    fn read_sumfile_reports_an_io_error_for_a_missing_file() {
        let dir = TempDir::new("missing");
        match read_sumfile(&dir.path().join("not-there.sha256")) {
            Err(SumfileError::Io(message)) => assert!(!message.is_empty()),
            other => panic!("expected an IO error, got {other:?}"),
        }
    }

    /// ANSI checksum files are common; refusing them wholesale would lose a
    /// verification the user can otherwise mostly complete.
    #[test]
    fn read_sumfile_decodes_a_non_utf8_file_lossily() {
        let dir = TempDir::new("ansi");
        let path = dir.path().join("sums.txt");
        let mut bytes = format!("{SHA256_EMPTY}  ").into_bytes();
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        bytes.extend_from_slice(b".txt\n");
        fs::write(&path, bytes).unwrap();

        let parsed = read_sumfile(&path).unwrap();
        assert_eq!(parsed.entries.len(), 1, "the entry itself is still usable");
    }

    #[test]
    fn a_relative_entry_resolves_against_the_checksum_file_directory() {
        let dir = TempDir::new("relative");
        let target = dir.path().join("a.bin");
        let sumfile = dir.write("sub/sums.sha256", &format!("{SHA256_EMPTY}  ..\\a.bin\n"));

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
        assert_eq!(matched.unmatched, 0);
    }

    #[test]
    fn separators_and_case_do_not_prevent_a_match() {
        let dir = TempDir::new("case");
        let target = dir.path().join("sub").join("a.txt");
        let sumfile = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  SUB/A.TXT\n"));
        let job = job(&target);

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job]);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
        assert_eq!(matched.unmatched, 0);
    }

    #[test]
    fn a_bare_digest_belongs_to_the_file_the_checksum_file_is_named_after() {
        let dir = TempDir::new("bare");
        let target = dir.path().join("data.bin");
        let sumfile = dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
        assert_eq!(matched.unmatched, 0);
    }

    /// A checksum file with no registered extension cannot say which file a bare
    /// digest belongs to, so it must name nothing rather than guess.
    #[test]
    fn a_bare_digest_in_an_unregistered_checksum_file_matches_nothing() {
        let dir = TempDir::new("bare-unregistered");
        let target = dir.path().join("data.bin");
        let sumfile = dir.write("checksums.dat", &format!("{SHA256_EMPTY}\n"));

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert!(matched.expected.iter().all(Vec::is_empty));
        assert_eq!(matched.unmatched, 1);
    }

    #[test]
    fn entries_for_files_outside_the_job_list_are_counted_as_unmatched() {
        let dir = TempDir::new("unmatched");
        let present = dir.path().join("present.txt");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  present.txt\n{MD5_EMPTY}  absent.txt\n"),
        );

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&present)]);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
        assert_eq!(matched.unmatched, 1);
    }

    #[test]
    fn several_entries_for_one_file_accumulate() {
        let dir = TempDir::new("accumulate");
        let target = dir.path().join("a.txt");
        let sumfile = dir.write(
            "sums.txt",
            &format!("{SHA256_EMPTY}  a.txt\n{MD5_EMPTY}  a.txt\n{SHA256_EMPTY} *a.txt\n"),
        );

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert_eq!(
            matched.expected,
            vec![vec![digest(SHA256_EMPTY), digest(MD5_EMPTY)]],
            "a repeated digest is stored once, a different one is kept"
        );
    }

    #[test]
    fn a_unique_basename_matches_a_file_in_another_directory() {
        let dir = TempDir::new("basename-unique");
        let target = dir.path().join("somewhere").join("a.txt");
        let sumfile = dir.write("elsewhere/sums.sha256", &format!("{SHA256_EMPTY}  a.txt\n"));

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
        assert_eq!(matched.unmatched, 0);
    }

    /// Two files with the same name and no way to tell them apart: verifying
    /// either would be a guess, so neither is verified and the entry is counted.
    #[test]
    fn an_ambiguous_basename_matches_nothing() {
        let dir = TempDir::new("basename-ambiguous");
        let first = dir.path().join("one").join("a.txt");
        let second = dir.path().join("two").join("a.txt");
        let sumfile = dir.write("elsewhere/sums.sha256", &format!("{SHA256_EMPTY}  a.txt\n"));

        let matched = match_sumfile(
            &read_sumfile(&sumfile).unwrap(),
            &sumfile,
            &[job(&first), job(&second)],
        );
        assert!(matched.expected.iter().all(Vec::is_empty));
        assert_eq!(matched.unmatched, 1);
    }

    /// A directory component is a real constraint, not decoration: ignoring it to
    /// score a basename match would verify a different file.
    #[test]
    fn a_nested_entry_does_not_fall_back_to_a_basename_match() {
        let dir = TempDir::new("nested");
        let target = dir.path().join("elsewhere").join("a.txt");
        let sumfile = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  sub\\a.txt\n"));

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert!(matched.expected.iter().all(Vec::is_empty));
        assert_eq!(matched.unmatched, 1);
    }

    #[test]
    fn a_malformed_line_is_reported_but_earlier_entries_survive() {
        let dir = TempDir::new("malformed");
        let target = dir.path().join("a.txt");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  a.txt\nthis is not a checksum line\n"),
        );

        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[job(&target)]);
        assert!(matched.had_error);
        assert_eq!(matched.expected, vec![vec![digest(SHA256_EMPTY)]]);
    }

    #[test]
    fn an_empty_job_list_leaves_every_entry_unmatched() {
        let dir = TempDir::new("no-jobs");
        let sumfile = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  a.txt\n"));
        let matched = match_sumfile(&read_sumfile(&sumfile).unwrap(), &sumfile, &[]);
        assert!(matched.expected.is_empty());
        assert_eq!(matched.unmatched, 1);
    }

    #[test]
    fn pasted_digests_are_hex_decoded_and_trimmed() {
        assert_eq!(parse_pasted(SHA256_EMPTY).unwrap(), digest(SHA256_EMPTY));
        assert_eq!(
            parse_pasted(&format!("  {SHA256_EMPTY}\r\n")).unwrap(),
            digest(SHA256_EMPTY)
        );
        assert_eq!(
            parse_pasted(&SHA256_EMPTY.to_uppercase()).unwrap(),
            digest(SHA256_EMPTY)
        );
        // Four characters is the shortest accepted digest (a bare CRC32).
        assert_eq!(
            parse_pasted("deadbeef").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        // The longest supported digest is PH256-528 at 66 bytes.
        let longest = "ab".repeat(MAX_DIGEST_LEN);
        assert_eq!(parse_pasted(&longest).unwrap().len(), MAX_DIGEST_LEN);
    }

    #[test]
    fn pasted_digests_reject_bad_input() {
        assert_eq!(parse_pasted(""), None);
        assert_eq!(parse_pasted("   "), None);
        assert_eq!(parse_pasted("ab"), None, "too short to be a digest");
        assert_eq!(parse_pasted("abc"), None, "odd length");
        assert_eq!(parse_pasted("zzzz"), None, "not hex");
        assert_eq!(
            parse_pasted(&"ab".repeat(MAX_DIGEST_LEN + 1)),
            None,
            "longer than the longest supported digest"
        );
        // A whole checksum line is not a pasted digest: the filename would be
        // silently dropped.
        assert_eq!(parse_pasted(&format!("{SHA256_EMPTY}  a.txt")), None);
    }

    #[test]
    fn attach_sidecars_adds_the_digest_next_to_the_file() {
        let dir = TempDir::new("sidecar-hit");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));

        let mut jobs = vec![file_job(&target)];
        assert_eq!(attach_sidecars(&mut jobs), 1);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    #[test]
    fn attach_sidecars_accumulates_every_registered_format() {
        let dir = TempDir::new("sidecar-many");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}  data.bin\n"));
        dir.write("data.bin.md5", &format!("{MD5_EMPTY}  data.bin\n"));

        let mut jobs = vec![file_job(&target)];
        assert_eq!(attach_sidecars(&mut jobs), 1);
        // Candidates are tried in algorithm-table order, so MD5's extension is
        // found before SHA-256's. The order does not matter to verification --
        // `match_state` compares every digest -- but pinning it keeps the
        // function's output reproducible.
        assert_eq!(
            jobs[0].expected,
            vec![digest(MD5_EMPTY), digest(SHA256_EMPTY)]
        );
    }

    #[test]
    fn attach_sidecars_leaves_files_without_a_sidecar_alone() {
        let dir = TempDir::new("sidecar-miss");
        let target = dir.write("data.bin", "content");

        let mut jobs = vec![file_job(&target)];
        assert_eq!(attach_sidecars(&mut jobs), 0);
        assert!(jobs[0].expected.is_empty());
    }

    #[test]
    fn attach_sidecars_ignores_an_unreadable_sidecar() {
        let dir = TempDir::new("sidecar-bad");
        let target = dir.write("data.bin", "content");
        // Named like a sidecar, but not a checksum file at all.
        dir.write("data.bin.sha256", "this is not a checksum line\n");

        let mut jobs = vec![file_job(&target)];
        assert_eq!(attach_sidecars(&mut jobs), 0);
        assert!(jobs[0].expected.is_empty());
    }

    #[test]
    fn attach_sidecars_does_not_duplicate_an_existing_expectation() {
        let dir = TempDir::new("sidecar-duplicate");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));

        let mut jobs = vec![file_job(&target)];
        jobs[0].expected.push(digest(SHA256_EMPTY));
        assert_eq!(attach_sidecars(&mut jobs), 0, "nothing new was attached");
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    #[test]
    fn attach_sidecars_with_no_jobs_does_nothing() {
        let mut jobs: Vec<FileJob> = Vec::new();
        assert_eq!(attach_sidecars(&mut jobs), 0);
    }

    /// The sidecar for one file must not leak onto another file in the same
    /// directory: only the job's own entry is kept.
    #[test]
    fn attach_sidecars_only_takes_the_job_it_was_found_for() {
        let dir = TempDir::new("sidecar-scope");
        let first = dir.write("first.bin", "one");
        let second = dir.write("second.bin", "two");
        dir.write("first.bin.sha256", &format!("{SHA256_EMPTY}  first.bin\n"));

        let mut jobs = vec![file_job(&first), file_job(&second)];
        assert_eq!(attach_sidecars(&mut jobs), 1);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
        assert!(jobs[1].expected.is_empty());
    }
}
