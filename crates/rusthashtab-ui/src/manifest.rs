//! Checksum files interpreted as manifests of the files to hash.
//!
//! # What a manifest adds over verification
//!
//! Verification ([`crate::verify`]) attaches expected digests to the files the
//! user selected. A manifest is the opposite direction: the user selects one
//! checksum file, and the files it lists become the scan. That is the workflow
//! behind "check this folder against its `SHA256SUMS`": the user has the checksum
//! file, and selecting it should hash what it names rather than hash the
//! checksum file itself.
//!
//! # Detection
//!
//! [`is_manifest_candidate`] answers whether a path has the *shape* this module
//! can interpret: one regular file whose extension is one the algorithm table
//! claims, plus the two format-level extensions `sfv` (CRC32 lists) and `hash`
//! (the corz format). [`plan`] then reads it through
//! [`crate::verify::read_sumfile`], so the 16 MiB cap and the lossy decoding of
//! ANSI checksum files are shared with verification instead of reimplemented.
//!
//! A file with no entry that names a file is not a manifest. A
//! `payload.bin.sha256` holding a single bare digest is a checksum *of* one file,
//! not a list of files, and treating it as an empty manifest would replace the
//! file the user selected with nothing. The caller falls back to ordinary
//! hashing, which is exactly the right behaviour for that file.
//!
//! # Resolution and display
//!
//! Entry paths resolve lexically against the checksum file's directory, with the
//! same rules as [`crate::verify`]: no `canonicalize`, so a junction named inside
//! a manifest cannot silently redirect the scan to another volume, and `..` is
//! resolved by [`rusthashtab_scan::normalize_path`] before any path is opened.
//!
//! A job's display path is its path relative to the checksum file's directory
//! when the target is inside it, and the absolute path otherwise. Keeping the
//! manifest's own spelling would show `..\..\elsewhere` for a target that is not
//! below the manifest, which is not a name the user can act on; an absolute path
//! at least says where the file is. The checksum file itself, when it joins the
//! scan, is shown by its file name rather than as an empty relative path.
//!
//! # Inferred algorithm, and why nothing is persisted
//!
//! A `SHA256SUMS` file holds SHA-256 digests, and hashing it with all 31
//! algorithms produces 30 columns of noise. [`algorithm_for_file_name`] derives
//! the one algorithm the extension names: `sfv` names CRC32, a registered
//! extension names its algorithm, and `hash` or an unknown extension names none.
//! `plan`'s caller decides whether that inference *replaces* the user's enabled
//! set or is *unioned* with it; this module never writes the choice to the
//! settings store. A manifest scan is a temporary view of one selection, not a
//! preference, and the settings layer is the only owner of preferences.
//!
//! # Side effects
//!
//! [`plan`] reads the checksum file and stats the files it names. It creates,
//! modifies, and deletes nothing. It does not open the listed files: a missing
//! file becomes a job with size 0 so the scanner reports the OS error in its
//! usual row, instead of the manifest scan silently having fewer files than the
//! manifest lists.

use crate::verify::read_sumfile;
use rusthashtab_hash::ALGORITHMS;
use rusthashtab_hash::registry::by_extension;
use rusthashtab_scan::{FileJob, normalize_path, path_key};
use std::collections::HashMap;
use std::path::Path;

/// The extension of an SFV checksum file, which holds CRC32 values.
///
/// CRC32 predates the extension lists in [`ALGORITHMS`] and has none of its own,
/// so the format's extension is spelled here; [`algorithm_for_file_name`] maps it
/// back to CRC32.
const SFV_EXTENSION: &str = "sfv";

/// The extension of a corz `.hash` checksum file.
///
/// A `.hash` file may carry digests from several algorithms -- the format has a
/// per-line algorithm banner -- so the extension names no single algorithm.
const CORZ_EXTENSION: &str = "hash";

/// The algorithm table name of the algorithm an SFV file's values belong to.
const SFV_ALGORITHM: &str = "CRC32";

/// A checksum file interpreted as a list of files to hash.
///
/// Built by [`plan`]; carrying `jobs` and `enabled` together is deliberate. The
/// page must hand the scanner an algorithm set that matches the digests the
/// manifest actually contains, and the two are decided from the same file: one
/// value cannot be applied without the other, so they are not separate calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPlan {
    /// Files to hash, in manifest order.
    ///
    /// When the caller asked for the checksum file itself to be hashed, it is the
    /// first job and carries no expected digest.
    pub jobs: Vec<FileJob>,
    /// Algorithms to hash with, indexed like [`rusthashtab_hash::ALGORITHMS`].
    ///
    /// With no inferred algorithm this is the caller's list unchanged. With one,
    /// it is long enough to address every table index, and holds either only the
    /// inferred algorithm (`algorithm_only` was set) or the inferred algorithm
    /// plus everything the caller had enabled.
    pub enabled: Vec<bool>,
    /// The algorithm the checksum file's extension names, if any.
    ///
    /// An index into [`rusthashtab_hash::ALGORITHMS`], and [`None`] for `hash`
    /// files, unknown extensions, and a checksum file whose name has no
    /// extension at all.
    pub inferred: Option<usize>,
    /// Entries that named a file and became a job.
    ///
    /// A file listed under two algorithms is two entries and one job, and both
    /// entries count. An entry that names only the checksum file itself counts
    /// only when the caller asked for the checksum file to be hashed: otherwise
    /// it named nothing the scan will hash.
    pub named_entries: usize,
    /// Parsed entries that named no file.
    ///
    /// A bare digest line is a legal entry in the single-hash file formats, but
    /// names no path, so it cannot become a job. A file whose entries are *all*
    /// like that has no named entry and [`plan`] returns [`None`] instead; this
    /// counter exists so a future mixed format can report the unused lines rather
    /// than silently dropping them.
    pub unmatched: usize,
    /// Whether the parser saw a line it could not interpret.
    ///
    /// Not fatal, exactly as in verification: the entries before the bad line are
    /// still usable, and a partial manifest is more useful than none. The page
    /// shows this so a damaged checksum file is visible rather than silently
    /// producing a shorter scan.
    pub had_error: bool,
}

/// Whether `path` is a checksum file this module can interpret as a manifest.
///
/// True for a single regular file whose extension is ASCII-case-insensitively one
/// of the registered algorithm extensions, `sfv`, or `hash`. A directory that
/// happens to be named `old.sha256`, and a path that no longer exists, are not
/// candidates: they cannot be read as a manifest, so the caller should fall back
/// to hashing them normally.
#[must_use]
pub fn is_manifest_candidate(path: &Path) -> bool {
    let Some(extension) = path.extension() else {
        return false;
    };
    if !is_manifest_extension(&extension.to_string_lossy()) {
        return false;
    }

    // "Single regular file" is a file-system fact, not a spelling one. A
    // directory called `old.sha256` is a directory, and the ordinary path has to
    // keep working for it.
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// The algorithm that checksum files with this extension hold.
///
/// An index into [`rusthashtab_hash::ALGORITHMS`], or [`None`] when the extension
/// names no single algorithm. `sfv` maps to CRC32; `hash` and unknown extensions
/// map to [`None`]. The name is accepted with or without a directory part, so a
/// full path works as well as a bare file name.
#[must_use]
pub fn algorithm_for_file_name(name: &str) -> Option<usize> {
    let extension = Path::new(name).extension()?.to_str()?;

    if extension.eq_ignore_ascii_case(SFV_EXTENSION) {
        return ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == SFV_ALGORITHM);
    }
    if extension.eq_ignore_ascii_case(CORZ_EXTENSION) {
        return None;
    }

    let algorithm = by_extension(extension)?;
    ALGORITHMS
        .iter()
        .position(|candidate| candidate.name == algorithm.name)
}

/// Read one checksum file and plan the scan it describes.
///
/// Returns [`None`] when the path is not a candidate (see
/// [`is_manifest_candidate`]), cannot be read, exceeds
/// [`crate::verify::MAX_SUMFILE_BYTES`], or names no file the scan would hash.
/// Every [`None`] means "not a manifest, hash the selection normally", so a
/// failed interpretation never loses the user's selection.
///
/// `enabled` is the page's current algorithm set, indexed like
/// [`rusthashtab_hash::ALGORITHMS`]. `hash_sumfile_too` asks for the checksum file
/// itself to be hashed as well, and when set it is the first job with no expected
/// digest (the file cannot contain its own digest and be updated atomically).
/// `algorithm_only` decides whether an inferred algorithm replaces `enabled` or is
/// added to it; when no algorithm can be inferred, `enabled` is returned
/// unchanged either way.
#[must_use]
pub fn plan(
    path: &Path,
    enabled: &[bool],
    hash_sumfile_too: bool,
    algorithm_only: bool,
) -> Option<ManifestPlan> {
    if !is_manifest_candidate(path) {
        return None;
    }

    let parsed = read_sumfile(path).ok()?;

    let sumfile = normalize_path(path);
    let sumfile_dir = sumfile.parent().map(Path::to_path_buf).unwrap_or_default();
    let sumfile_key = path_key(&sumfile);
    let sumfile_name = sumfile.file_name()?.to_string_lossy().into_owned();
    let inferred = algorithm_for_file_name(&sumfile_name);

    let mut jobs: Vec<FileJob> = Vec::new();
    let mut job_index: HashMap<String, usize> = HashMap::new();
    let mut named_entries = 0usize;
    let mut unmatched = 0usize;

    for entry in &parsed.entries {
        let name = entry.path.trim();
        if name.is_empty() {
            // A bare digest is a legal entry in the single-hash formats, but it
            // names no file. It is not a parse error, so it is reported as
            // unmatched rather than folded into `had_error`.
            unmatched += 1;
            continue;
        }

        // Absolute entries stand on their own; relative ones live next to the
        // checksum file. The test is `is_absolute` rather than "does not start
        // with a separator", so a rooted path without a drive (`\foo`) keeps the
        // checksum file's drive when it is joined below, which is what a Windows
        // user writing it next to the manifest means.
        let raw = Path::new(name);
        let resolved = if raw.is_absolute() {
            normalize_path(raw)
        } else {
            normalize_path(&sumfile_dir.join(raw))
        };
        let key = path_key(&resolved);

        // The checksum file is the source of the list, not one of the files it
        // lists. It joins the scan only when the caller asked for it, and then as
        // the first job below, so a self-reference must not create a second job.
        if key == sumfile_key {
            if hash_sumfile_too {
                // It becomes the first job below; the entry's digest is not
                // attached because the checksum file cannot contain its own
                // digest and stay consistent with itself.
                named_entries += 1;
            }
            continue;
        }

        match job_index.get(&key).copied() {
            Some(index) => {
                // One file may be listed under several algorithms. Every digest
                // is kept, but an exact repeat is dropped: it carries no new
                // information and would make "how many expectations does this
                // file have" wrong.
                let expected = &mut jobs[index].expected;
                if !expected.iter().any(|known| known == &entry.digest) {
                    expected.push(entry.digest.clone());
                }
                named_entries += 1;
            }
            None => {
                job_index.insert(key, jobs.len());
                jobs.push(FileJob {
                    display_path: display_path(&resolved, &sumfile_dir),
                    size: file_size(&resolved),
                    path: resolved,
                    expected: vec![entry.digest.clone()],
                });
                named_entries += 1;
            }
        }
    }

    // A file whose only named entry is a reference to itself is not a manifest of
    // anything. The ordinary fallback -- hash the selected checksum file -- is
    // more useful than a scan with no files, and this also covers the
    // bare-digest-only file that the candidate gate cannot distinguish.
    if named_entries == 0 {
        return None;
    }

    if hash_sumfile_too {
        // First, because it is the source: the user asked to see the checksum file
        // hashed next to what it describes, and leading with it keeps that
        // relationship visible in job order.
        jobs.insert(
            0,
            FileJob {
                path: sumfile.clone(),
                display_path: sumfile_name,
                expected: Vec::new(),
                size: file_size(&sumfile),
            },
        );
    }

    Some(ManifestPlan {
        jobs,
        enabled: enabled_for(enabled, inferred, algorithm_only),
        inferred,
        named_entries,
        unmatched,
        had_error: parsed.had_error,
    })
}

/// Whether an extension names a checksum format this module understands.
fn is_manifest_extension(extension: &str) -> bool {
    extension.eq_ignore_ascii_case(SFV_EXTENSION)
        || extension.eq_ignore_ascii_case(CORZ_EXTENSION)
        || ALGORITHMS.iter().any(|algorithm| {
            algorithm
                .extensions
                .iter()
                .any(|known| known.eq_ignore_ascii_case(extension))
        })
}

/// The algorithm set the scan should use.
///
/// No inferred algorithm means there is nothing to narrow to, so the caller's set
/// is returned exactly. With one, the result is at least as long as the algorithm
/// table (a short input must not make a table index unaddressable) and holds
/// either only that algorithm or its union with the caller's set.
fn enabled_for(enabled: &[bool], inferred: Option<usize>, algorithm_only: bool) -> Vec<bool> {
    let Some(inferred) = inferred else {
        return enabled.to_vec();
    };

    let length = ALGORITHMS.len().max(enabled.len());
    let mut chosen = if algorithm_only {
        vec![false; length]
    } else {
        let mut union = enabled.to_vec();
        union.resize(length, false);
        union
    };
    if let Some(slot) = chosen.get_mut(inferred) {
        *slot = true;
    }
    chosen
}

/// How a resolved target is shown in the File column.
///
/// Relative to the checksum file's directory when the target is inside it, and
/// the normalized absolute path otherwise. Backslashes are the display spelling on
/// this platform, so any forward slash the manifest used is folded. The caller
/// shows the checksum file itself by its file name, not through this function: the
/// relative form of the checksum file is the empty path.
fn display_path(resolved: &Path, sumfile_dir: &Path) -> String {
    let shown = resolved
        .strip_prefix(sumfile_dir)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(resolved);
    shown.to_string_lossy().replace('/', "\\")
}

/// Size of a resolved target, or 0 when it cannot be read.
///
/// A missing target must still become a job: the scanner's error row is how the
/// user learns the manifest names a file that is not there. Dropping it here would
/// silently shrink the manifest and make the scan look clean.
fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// The SHA-256 of the empty input, used as a plausible digest throughout.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// The MD5 of the empty input.
    const MD5_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";
    /// The CRC32 of the empty input, in the SFV spelling.
    const CRC32_EMPTY: &str = "00000000";

    /// A uniquely named temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusthashtab-ui-manifest-{tag}-{}-{}",
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

    /// Index of an algorithm in the table, by display name.
    fn index_of(name: &str) -> usize {
        ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
            .unwrap_or_else(|| panic!("{name} is not in the algorithm table"))
    }

    fn all_enabled() -> Vec<bool> {
        vec![true; ALGORITHMS.len()]
    }

    fn digest(hex: &str) -> Vec<u8> {
        rusthashtab_sumfile::parse::hex_to_bytes(hex).expect("test fixture is valid hex")
    }

    fn plan_of(path: &Path) -> ManifestPlan {
        plan(path, &all_enabled(), false, false).expect("the fixture is a valid manifest")
    }

    #[test]
    fn the_extension_gate_accepts_registered_extensions_case_insensitively() {
        let dir = TempDir::new("candidates");
        for name in [
            "a.sha256",
            "b.SHA256",
            "c.sfv",
            "d.HASH",
            "e.md5sum",
            "f.xxh3-128",
        ] {
            let path = dir.write(name, "");
            assert!(is_manifest_candidate(&path), "{name} must be a candidate");
        }

        for name in ["a.bin", "b.xyz", "no-extension"] {
            let path = dir.write(name, "");
            assert!(
                !is_manifest_candidate(&path),
                "{name} names no checksum format"
            );
        }
    }

    #[test]
    fn a_directory_or_a_missing_path_is_not_a_manifest() {
        let dir = TempDir::new("not-files");
        let directory = dir.path().join("folder.sha256");
        fs::create_dir(&directory).unwrap();
        assert!(!is_manifest_candidate(&directory));
        assert_eq!(
            plan(&directory, &all_enabled(), false, false),
            None,
            "a directory cannot be read as a manifest"
        );

        let missing = dir.path().join("gone.sha256");
        assert!(!is_manifest_candidate(&missing));
        assert_eq!(plan(&missing, &all_enabled(), false, false), None);
    }

    #[test]
    fn the_extension_names_the_algorithm_it_can_check() {
        assert_eq!(
            algorithm_for_file_name("SUMS.SHA256"),
            Some(index_of("SHA-256"))
        );
        assert_eq!(
            algorithm_for_file_name("sums.sha256"),
            Some(index_of("SHA-256"))
        );
        assert_eq!(algorithm_for_file_name("sums.md5"), Some(index_of("MD5")));
        assert_eq!(
            algorithm_for_file_name("sums.xxh3-128"),
            Some(index_of("XXH3-128"))
        );
        assert_eq!(algorithm_for_file_name("sums.sfv"), Some(index_of("CRC32")));
        assert_eq!(algorithm_for_file_name("SUMS.SFV"), Some(index_of("CRC32")));

        assert_eq!(algorithm_for_file_name("logs.hash"), None);
        assert_eq!(algorithm_for_file_name("LOGS.HASH"), None);
        assert_eq!(algorithm_for_file_name("notes.bin"), None);
        assert_eq!(algorithm_for_file_name("noextension"), None);
    }

    #[test]
    fn a_file_holding_only_a_bare_digest_is_not_a_manifest() {
        let dir = TempDir::new("bare");
        let sumfile = dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));
        assert_eq!(plan(&sumfile, &all_enabled(), false, false), None);
    }

    #[test]
    fn a_checksum_file_over_the_cap_is_not_a_manifest() {
        // `read_sumfile` rejects this without allocating it; the manifest path
        // must translate that failure into "not a manifest", never into a panic
        // or a partial plan.
        let dir = TempDir::new("too-large");
        let path = dir.path().join("huge.sha256");
        let file = fs::File::create(&path).unwrap();
        file.set_len(crate::verify::MAX_SUMFILE_BYTES + 1).unwrap();
        drop(file);

        assert!(is_manifest_candidate(&path));
        assert_eq!(plan(&path, &all_enabled(), false, false), None);
    }

    #[test]
    fn entries_resolve_relative_to_the_checksum_files_directory() {
        let dir = TempDir::new("resolve");
        let target = dir.write("a.txt", "abc");
        let nested = dir.write("sub/local.txt", "hello");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  sub\\..\\a.txt\n{MD5_EMPTY}  SUB/local.txt\n"),
        );

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 2);

        assert_eq!(plan.jobs[0].path, normalize_path(&target));
        assert_eq!(plan.jobs[0].display_path, "a.txt");
        assert_eq!(plan.jobs[0].size, 3);
        assert_eq!(plan.jobs[0].expected, vec![digest(SHA256_EMPTY)]);

        // The manifest spells the path `SUB/local.txt`; the resolved path keeps
        // that spelling because resolution is lexical, but the identity is the
        // on-disk file. Windows is case-insensitive, so a case-sensitive path
        // comparison here would be testing the wrong thing.
        assert_eq!(path_key(&plan.jobs[1].path), path_key(&nested));
        assert_eq!(plan.jobs[1].display_path, r"SUB\local.txt");
        assert_eq!(plan.jobs[1].size, 5);
        assert_eq!(plan.jobs[1].expected, vec![digest(MD5_EMPTY)]);
    }

    #[test]
    fn dot_and_dotdot_are_resolved_before_a_target_is_opened() {
        let dir = TempDir::new("dotdot");
        let target = dir.write("a.txt", "x");
        let sumfile = dir.write(
            "sub/sums.sha256",
            &format!("{SHA256_EMPTY}  .\\..\\a.txt\n"),
        );

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].path, normalize_path(&target));
        assert_eq!(plan.jobs[0].size, 1);
        assert_eq!(
            plan.jobs[0].display_path,
            normalize_path(&target).to_string_lossy().replace('/', "\\"),
            "the target is outside the manifest's directory, so it is shown absolutely"
        );
    }

    #[test]
    fn an_absolute_entry_is_used_as_written() {
        let outside = TempDir::new("outside");
        let target = outside.write("payload.bin", "xyz");
        let dir = TempDir::new("absolute");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  {}\n", target.display()),
        );

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].path, normalize_path(&target));
        assert_eq!(plan.jobs[0].size, 3);
        assert_eq!(
            plan.jobs[0].display_path,
            normalize_path(&target).to_string_lossy().replace('/', "\\"),
            "a target outside the manifest's directory is shown absolutely"
        );
    }

    #[test]
    fn one_file_listed_twice_is_one_job_with_every_distinct_digest() {
        let dir = TempDir::new("dedupe");
        let target = dir.write("a.txt", "payload");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  a.txt\n{MD5_EMPTY}  .\\A.TXT\n{SHA256_EMPTY}  a.txt\n"),
        );

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].path, normalize_path(&target));
        assert_eq!(plan.jobs[0].display_path, "a.txt", "first spelling wins");
        assert_eq!(
            plan.jobs[0].expected,
            vec![digest(SHA256_EMPTY), digest(MD5_EMPTY)],
            "both algorithms are kept, the repeated digest is not duplicated"
        );
        assert_eq!(plan.named_entries, 3);
        assert_eq!(plan.unmatched, 0);
    }

    #[test]
    fn hash_sumfile_too_false_leaves_the_checksum_file_out() {
        let dir = TempDir::new("sumfile-false");
        let other = dir.write("other.txt", "x");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  other.txt\n{MD5_EMPTY}  sums.sha256\n"),
        );

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].path, normalize_path(&other));
        assert_eq!(
            plan.named_entries, 1,
            "a self-reference that is not hashed did not become a job"
        );
    }

    #[test]
    fn hash_sumfile_too_true_puts_the_checksum_file_first_without_a_digest() {
        let dir = TempDir::new("sumfile-true");
        let other = dir.write("other.txt", "x");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  other.txt\n{MD5_EMPTY}  sums.sha256\n"),
        );

        let plan = plan(&sumfile, &all_enabled(), true, false).unwrap();
        assert_eq!(plan.jobs.len(), 2, "the manifest lists itself and one file");
        assert_eq!(plan.jobs[0].path, normalize_path(&sumfile));
        assert_eq!(plan.jobs[0].display_path, "sums.sha256");
        assert!(
            plan.jobs[0].expected.is_empty(),
            "a checksum file has no expected digest of its own"
        );
        assert_eq!(plan.jobs[0].size, fs::metadata(&sumfile).unwrap().len());
        assert_eq!(plan.jobs[1].path, normalize_path(&other));
        assert_eq!(plan.named_entries, 2);
    }

    #[test]
    fn hash_sumfile_too_true_never_duplicates_the_checksum_file() {
        let dir = TempDir::new("sumfile-dedup");
        let other = dir.write("other.txt", "x");
        let sumfile = dir.write(
            "sums.sha256",
            &format!(
                "{SHA256_EMPTY}  other.txt\n{MD5_EMPTY}  sums.sha256\n{MD5_EMPTY}  .\\sums.sha256\n"
            ),
        );

        let plan = plan(&sumfile, &all_enabled(), true, false).unwrap();
        let paths: Vec<PathBuf> = plan.jobs.iter().map(|job| job.path.clone()).collect();
        assert_eq!(
            paths,
            vec![normalize_path(&sumfile), normalize_path(&other)]
        );
    }

    #[test]
    fn a_manifest_that_lists_only_itself_falls_back_to_ordinary_hashing() {
        let dir = TempDir::new("self-only");
        let sumfile = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  sums.sha256\n"));

        assert_eq!(
            plan(&sumfile, &all_enabled(), false, false),
            None,
            "nothing would be hashed, so the selection must not be replaced"
        );

        let hashed = plan(&sumfile, &all_enabled(), true, false).unwrap();
        assert_eq!(hashed.jobs.len(), 1);
        assert_eq!(hashed.jobs[0].path, normalize_path(&sumfile));
    }

    #[test]
    fn a_missing_listed_file_becomes_a_job_the_scanner_can_report() {
        let dir = TempDir::new("missing-listed");
        let sumfile = dir.write("sums.sha256", &format!("{SHA256_EMPTY}  not-there.bin\n"));

        let plan = plan_of(&sumfile);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(
            plan.jobs[0].path,
            normalize_path(&dir.path().join("not-there.bin"))
        );
        assert_eq!(
            plan.jobs[0].size, 0,
            "a missing file still becomes a job, so the scanner reports it"
        );
        assert_eq!(plan.jobs[0].display_path, "not-there.bin");
    }

    #[test]
    fn an_algorithm_extension_narrows_the_enabled_set_to_that_algorithm() {
        let dir = TempDir::new("narrow");
        let target = dir.write("a.txt", "");
        let sumfile = dir.write("a.sha256", &format!("{SHA256_EMPTY}  a.txt\n"));

        let mut enabled = vec![false; ALGORITHMS.len()];
        enabled[index_of("MD5")] = true;
        enabled[index_of("SHA-1")] = true;

        let narrowed = plan(&sumfile, &enabled, false, true).unwrap();
        assert_eq!(narrowed.inferred, Some(index_of("SHA-256")));
        assert_eq!(
            narrowed.enabled.len(),
            ALGORITHMS.len(),
            "every table index stays addressable"
        );
        for (index, on) in narrowed.enabled.iter().enumerate() {
            assert_eq!(
                *on,
                index == index_of("SHA-256"),
                "only the inferred algorithm may be enabled"
            );
        }

        let unioned = plan(&sumfile, &enabled, false, false).unwrap();
        assert!(unioned.enabled[index_of("MD5")]);
        assert!(unioned.enabled[index_of("SHA-1")]);
        assert!(unioned.enabled[index_of("SHA-256")]);
        assert_eq!(unioned.enabled.iter().filter(|on| **on).count(), 3);
        assert_eq!(
            unioned.jobs[0].path,
            normalize_path(&target),
            "the jobs are the same either way"
        );
    }

    #[test]
    fn an_sfv_manifest_enables_crc32() {
        let dir = TempDir::new("sfv");
        let sumfile = dir.write("sums.sfv", &format!("a.txt {CRC32_EMPTY}\n"));

        let disabled = vec![false; ALGORITHMS.len()];
        let plan = plan(&sumfile, &disabled, false, true).unwrap();
        assert_eq!(plan.inferred, Some(index_of("CRC32")));
        assert!(plan.enabled[index_of("CRC32")]);
        assert_eq!(plan.enabled.iter().filter(|on| **on).count(), 1);
        assert_eq!(plan.jobs[0].expected, vec![vec![0, 0, 0, 0]]);
    }

    #[test]
    fn a_manifest_with_no_inferable_algorithm_keeps_the_enabled_set() {
        let dir = TempDir::new("no-inference");
        dir.write("a.txt", "");
        let sumfile = dir.write("sums.hash", &format!("{SHA256_EMPTY}  a.txt\n"));

        let enabled = vec![true, false, true];
        let plan = plan(&sumfile, &enabled, false, true).unwrap();
        assert_eq!(
            plan.inferred, None,
            "a `.hash` file can mix algorithms and so names none"
        );
        assert_eq!(
            plan.enabled, enabled,
            "with nothing to narrow to, the caller's set is returned unchanged"
        );
    }

    #[test]
    fn a_malformed_line_is_reported_without_losing_the_entries_before_it() {
        let dir = TempDir::new("had-error");
        dir.write("a.txt", "");
        let sumfile = dir.write(
            "sums.sha256",
            &format!("{SHA256_EMPTY}  a.txt\nthis line is not a checksum entry\n"),
        );

        let plan = plan_of(&sumfile);
        assert!(plan.had_error, "the bad line must be visible to the page");
        assert_eq!(plan.jobs.len(), 1, "the entry before it is still usable");
        assert_eq!(plan.unmatched, 0);
    }

    #[test]
    fn a_file_that_is_not_utf8_still_plans_the_entries_it_can() {
        // Checksum files written in an ANSI code page are decoded lossily, like
        // verification does; the replacement characters make that one entry a
        // different name, not a reason to reject the manifest.
        let dir = TempDir::new("ansi");
        dir.write("a.txt", "");
        let path = dir.path().join("sums.sha256");
        let mut bytes = format!("{SHA256_EMPTY}  a.txt\n{MD5_EMPTY}  ").into_bytes();
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        bytes.extend_from_slice(b".txt\n");
        fs::write(&path, bytes).unwrap();

        let plan = plan_of(&path);
        assert_eq!(plan.jobs.len(), 2);
        assert!(!plan.had_error);
    }
}
