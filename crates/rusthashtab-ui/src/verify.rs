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
//!
//! It is deliberately **stricter** than [`match_sumfile`]: a sidecar was found by
//! name rather than chosen by the user, so every entry in it must name the file
//! the sidecar belongs to. An entry naming another file is reported as unmatched
//! instead of being attached to that other file, and only extensions of the
//! algorithms actually being hashed are tried.

use crate::JobSpec;
use rusthashtab_hash::ALGORITHMS;
use rusthashtab_scan::{FileJob, normalize_path, path_key};
use rusthashtab_sumfile::MAX_DIGEST_LEN;
use rusthashtab_sumfile::parse::{ParseOutcome, base64_to_bytes, hex_to_bytes, parse_all};
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

/// Extension of an SFV checksum file.
///
/// Spelled out rather than taken from [`rusthashtab_hash::ALGORITHMS`]: CRC32, the
/// algorithm SFV carries, deliberately has no registered extension of its own
/// (the export selector uses `sfv` explicitly), so the sidecar lookup and the
/// bare-digest rule need this one extra name.
pub(crate) const SFV_EXTENSION: &str = "sfv";

/// Extension of a corz `.hash` checksum file.
///
/// The format can mix algorithms, which is why it is accepted as a checksum-file
/// extension but never used to infer one.
pub(crate) const CORZ_EXTENSION: &str = "hash";

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

/// What looking for sidecar checksum files found.
///
/// The counts exist so the page can say what happened. A sidecar that was found
/// but could not be used is otherwise indistinguishable from one that was never
/// there, and the user would be left believing a file had been checked when it
/// had not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SidecarAttach {
    /// Jobs that gained at least one new expected digest.
    pub attached: usize,
    /// Entries in read sidecars that named no file in the scan -- or, strictly,
    /// named a different file than the one the sidecar belongs to.
    pub unmatched: usize,
    /// Whether any read sidecar contained a line that could not be parsed.
    pub had_error: bool,
    /// Sidecars that existed but could not be read (I/O error, or over the size
    /// cap).
    pub unreadable: usize,
}

/// Attach the expectations from checksum files found next to each file.
///
/// For every job this looks for `<file name>.<extension>` in the job's own
/// directory and reads each one that exists. The extension set is **the enabled
/// algorithms' registered extensions**, plus `sfv` when CRC32 is enabled: a
/// sidecar for an algorithm that is not being hashed cannot verify anything, and
/// reading it anyway could compare its digest against a different algorithm of
/// the same length and report a mismatch that is not real.
///
/// # Strictness
///
/// A sidecar was found by name, not chosen by the user, so it is only allowed to
/// describe the file it sits next to. An entry with a path is resolved relative
/// to the sidecar's own directory (absolute paths stand alone) and is used only
/// when it names *that* job. Entries naming another file are counted in
/// [`SidecarAttach::unmatched`] instead of being attached somewhere else; the
/// basename fallback in [`match_sumfile`] is deliberately not used here.
///
/// A digest with no file name belongs to the file the sidecar is named after,
/// which is exactly the job being processed.
///
/// Digests already present on the job are not added again. Directory listings are
/// cached per directory, because the page usually hashes many files in the same
/// folder and each job would otherwise re-enumerate it.
///
/// Whether to call this at all is the caller's decision: it implements the
/// user's "look for checksum files" setting, and only the page knows that
/// setting. An empty result therefore also covers a page that never looked.
#[must_use]
pub fn attach_sidecars(jobs: &mut [FileJob], enabled: &[bool]) -> SidecarAttach {
    let mut totals = SidecarAttach::default();
    if jobs.is_empty() {
        return totals;
    }

    let extensions = enabled_sidecar_extensions(enabled);
    if extensions.is_empty() {
        return totals;
    }

    let mut directories: HashMap<PathBuf, HashSet<String>> = HashMap::new();
    let mut additions: Vec<Vec<Vec<u8>>> = vec![Vec::new(); jobs.len()];

    for (index, job) in jobs.iter().enumerate() {
        let (Some(parent), Some(file_name)) = (job.path.parent(), job.path.file_name()) else {
            continue;
        };
        let parent = parent.to_path_buf();
        let file_name = file_name.to_string_lossy().to_lowercase();
        let job_key = path_key(&job.path);

        let names = directories
            .entry(parent.clone())
            .or_insert_with(|| directory_names(&parent));

        for extension in &extensions {
            let candidate = format!("{file_name}.{}", extension.to_lowercase());
            if !names.contains(&candidate) {
                continue;
            }
            let candidate = parent.join(candidate);

            let parsed = match read_sumfile(&candidate) {
                Ok(parsed) => parsed,
                Err(_) => {
                    totals.unreadable = totals.unreadable.saturating_add(1);
                    continue;
                }
            };
            if parsed.had_error {
                totals.had_error = true;
            }

            for entry in &parsed.entries {
                if entry.path.trim().is_empty() {
                    push_digest(&mut additions[index], &job.expected, &entry.digest);
                    continue;
                }

                let raw = Path::new(&entry.path);
                let resolved = if raw.has_root() {
                    normalize_path(raw)
                } else {
                    normalize_path(&parent.join(raw))
                };
                if path_key(&resolved) == job_key {
                    push_digest(&mut additions[index], &job.expected, &entry.digest);
                } else {
                    totals.unmatched = totals.unmatched.saturating_add(1);
                }
            }
        }
    }

    for (index, digests) in additions.into_iter().enumerate() {
        if digests.is_empty() {
            continue;
        }
        if let Some(job) = jobs.get_mut(index) {
            job.expected.extend(digests);
            totals.attached = totals.attached.saturating_add(1);
        }
    }

    totals
}

/// Add one digest to a job's pending sidecar expectations unless it is already
/// there.
fn push_digest(pending: &mut Vec<Vec<u8>>, existing: &[Vec<u8>], digest: &[u8]) {
    if existing.iter().any(|known| known == digest) || pending.iter().any(|known| known == digest) {
        return;
    }
    pending.push(digest.to_vec());
}

/// The checksum-file extensions a sidecar lookup may try, in algorithm-table
/// order.
///
/// Only enabled algorithms contribute: a sidecar for an algorithm that is not
/// being hashed cannot verify anything, and reading it anyway would let a
/// same-length digest from another algorithm look like a mismatch. `sfv` is
/// special-cased because CRC32 has no registered extension of its own.
fn enabled_sidecar_extensions(enabled: &[bool]) -> Vec<&'static str> {
    let mut seen = HashSet::new();
    let mut extensions = Vec::new();
    for (index, algorithm) in ALGORITHMS.iter().enumerate() {
        if !enabled.get(index).copied().unwrap_or(false) {
            continue;
        }
        if algorithm.name == "CRC32" && seen.insert(SFV_EXTENSION) {
            extensions.push(SFV_EXTENSION);
        }
        for extension in algorithm.extensions {
            if seen.insert(*extension) {
                extensions.push(*extension);
            }
        }
    }
    extensions
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

/// How a pasted digest was spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PastedStyle {
    /// A bare hex digest.
    Hex,
    /// A bare base64 digest.
    Base64,
    /// A whole checksum line (GNU or SFV).
    Line,
}

/// A digest parsed from the paste box, with the file name it named (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastedDigest {
    /// Decoded digest bytes.
    pub digest: Vec<u8>,
    /// The file name the line named, if it carried one.
    pub file_name: Option<String>,
    /// How the input was spelled.
    pub style: PastedStyle,
}

/// Why pasted text could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PastedError {
    /// Nothing was pasted.
    Empty,
    /// The text was not a digest or a single checksum line.
    NotADigest,
    /// The text held more than one checksum line.
    MultipleEntries,
    /// The digest names a file that is not in the selection.
    FileNotSelected,
    /// The digest names more than one selected file.
    AmbiguousFile,
    /// The digest length is not produced by any enabled algorithm.
    LengthNotEnabled,
    /// Current-file scope was requested without a selected row.
    NoCurrentFile,
}

/// Which files a pasted digest applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteScope {
    /// Every file in the scan.
    All,
    /// One job, identified by its index in the job list.
    Current(usize),
}

/// Parse the paste box.
///
/// Accepts a bare hex digest, a bare base64 digest, or exactly one checksum line
/// in the GNU or SFV spelling. A line that names a file keeps that name; the
/// caller uses it to pick the target, which is what makes "paste one line from a
/// checksum file" work without the user first selecting a row.
///
/// Deliberately does **not** search arbitrary prose for a digest: a paste that
/// happens to contain a 64-character hex string is not a request to check it.
pub fn parse_pasted_line(text: &str) -> Result<PastedDigest, PastedError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(PastedError::Empty);
    }

    // Bare hex first: the dominant spelling, and it is also what `parse_all`
    // recognises as a single-hash file.
    if trimmed.len().is_multiple_of(2)
        && (4..=MAX_DIGEST_LEN * 2).contains(&trimmed.len())
        && let Some(digest) = hex_to_bytes(trimmed)
    {
        return Ok(PastedDigest {
            digest,
            file_name: None,
            style: PastedStyle::Hex,
        });
    }

    // A bare base64 digest is not a checksum *line*; the line parser would reject
    // it because it requires a file name. Only a single base64-looking token is
    // considered: the decoder itself tolerates whitespace for file input, which
    // would make "this is not a digest" decode into bytes and then be reported as
    // the wrong length rather than as not a digest at all.
    if !trimmed.chars().any(char::is_whitespace)
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
        && let Some(digest) = base64_to_bytes(trimmed)
        && (4..=MAX_DIGEST_LEN).contains(&digest.len())
    {
        return Ok(PastedDigest {
            digest,
            file_name: None,
            style: PastedStyle::Base64,
        });
    }

    let parsed = parse_all(trimmed);
    if parsed.had_error {
        return Err(PastedError::NotADigest);
    }
    match parsed.entries.as_slice() {
        [] => Err(PastedError::NotADigest),
        [entry] => Ok(PastedDigest {
            digest: entry.digest.clone(),
            file_name: (!entry.path.is_empty()).then(|| entry.path.clone()),
            style: PastedStyle::Line,
        }),
        _ => Err(PastedError::MultipleEntries),
    }
}

/// Pick the jobs a pasted digest applies to.
///
/// A line that names a file targets that file; a bare digest uses the requested
/// scope. `strict` makes a named file resolve by full path instead of by unique
/// basename, which is the difference between "this name is probably that file"
/// and "this is that file".
pub fn resolve_pasted_targets(
    pasted: &PastedDigest,
    jobs: &[JobSpec],
    scope: PasteScope,
    strict: bool,
) -> Result<Vec<usize>, PastedError> {
    if jobs.is_empty() {
        return Err(PastedError::FileNotSelected);
    }

    if let Some(name) = &pasted.file_name {
        let target = resolve_named_target(name, jobs, strict)?;
        if let PasteScope::Current(current) = scope
            && current != target
        {
            return Err(PastedError::FileNotSelected);
        }
        return Ok(vec![target]);
    }

    match scope {
        PasteScope::All => Ok((0..jobs.len()).collect()),
        PasteScope::Current(current) => {
            if current < jobs.len() {
                Ok(vec![current])
            } else {
                Err(PastedError::NoCurrentFile)
            }
        }
    }
}

/// Resolve one file name from a pasted line to exactly one job.
fn resolve_named_target(name: &str, jobs: &[JobSpec], strict: bool) -> Result<usize, PastedError> {
    if strict {
        let wanted = path_key(Path::new(name));
        let matches: Vec<usize> = jobs
            .iter()
            .enumerate()
            .filter(|(_, job)| path_key(&job.path) == wanted)
            .map(|(index, _)| index)
            .collect();
        return match matches.as_slice() {
            [only] => Ok(*only),
            [] => Err(PastedError::FileNotSelected),
            _ => Err(PastedError::AmbiguousFile),
        };
    }

    let wanted = Path::new(name)
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| name.to_lowercase());
    let matches: Vec<usize> = jobs
        .iter()
        .enumerate()
        .filter(|(_, job)| {
            job.path
                .file_name()
                .is_some_and(|file| file.to_string_lossy().to_lowercase() == wanted)
                || job.display_path.to_lowercase() == name.to_lowercase()
        })
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(PastedError::FileNotSelected),
        _ => Err(PastedError::AmbiguousFile),
    }
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
/// system that holds it. `sfv` and `hash` are included even though CRC32 and the
/// corz format have no algorithm-owned extension: a bare digest in
/// `payload.bin.hash` still names `payload.bin`.
fn strip_registered_extension(name: &str) -> Option<&str> {
    for extension in [SFV_EXTENSION, CORZ_EXTENSION] {
        if let Some(stem) = strip_one_extension(name, extension) {
            return Some(stem);
        }
    }
    for algorithm in ALGORITHMS {
        for extension in algorithm.extensions {
            if let Some(stem) = strip_one_extension(name, extension) {
                return Some(stem);
            }
        }
    }
    None
}

/// Strip one known extension, if `name` ends in it.
fn strip_one_extension<'a>(name: &'a str, extension: &str) -> Option<&'a str> {
    let dot = name.len().checked_sub(extension.len())?;
    if dot == 0 {
        return None;
    }
    let (head, tail) = name.split_at(dot);
    if head.ends_with('.') && tail.eq_ignore_ascii_case(extension) {
        Some(&head[..head.len() - 1])
    } else {
        None
    }
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

    /// A pasted GNU line keeps its file name; that is what lets the page target
    /// one file without the user selecting a row first.
    #[test]
    fn a_gnu_line_keeps_its_file_name() {
        let pasted = parse_pasted_line(&format!("{SHA256_EMPTY}  nested/a.txt")).expect("valid");
        assert_eq!(pasted.digest, digest(SHA256_EMPTY));
        assert_eq!(pasted.file_name.as_deref(), Some("nested/a.txt"));
        assert_eq!(pasted.style, PastedStyle::Line);
    }

    /// A bare base64 digest is accepted; the line parser would reject it because
    /// it has no file name.
    #[test]
    fn a_bare_base64_digest_is_accepted() {
        let pasted = parse_pasted_line("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
            .expect("valid base64");
        assert_eq!(pasted.digest, digest(SHA256_EMPTY));
        assert_eq!(pasted.file_name, None);
        assert_eq!(pasted.style, PastedStyle::Base64);
    }

    #[test]
    fn several_lines_are_rejected() {
        let text = format!("{SHA256_EMPTY}  a.txt\n{SHA256_EMPTY}  b.txt");
        assert_eq!(parse_pasted_line(&text), Err(PastedError::MultipleEntries));
    }

    /// A bare digest applies to the whole selection by default; current-file
    /// scope names one job.
    #[test]
    fn paste_scope_selects_all_or_one_job() {
        let dir = TempDir::new("paste-scope");
        let first = dir.path().join("a.txt");
        let second = dir.path().join("b.txt");
        let jobs = vec![job(&first), job(&second)];
        let pasted = parse_pasted_line(SHA256_EMPTY).expect("valid hex");

        assert_eq!(
            resolve_pasted_targets(&pasted, &jobs, PasteScope::All, false),
            Ok(vec![0, 1])
        );
        assert_eq!(
            resolve_pasted_targets(&pasted, &jobs, PasteScope::Current(1), false),
            Ok(vec![1])
        );
    }

    /// A named line targets the named file, and strict mode requires the full
    /// path rather than a unique basename.
    #[test]
    fn a_named_line_targets_that_file_and_strict_requires_the_path() {
        let dir = TempDir::new("paste-named");
        let first = dir.path().join("a.txt");
        let second = dir.path().join("b.txt");
        let jobs = vec![job(&first), job(&second)];
        let pasted = parse_pasted_line(&format!("{SHA256_EMPTY}  a.txt")).expect("valid line");

        assert_eq!(
            resolve_pasted_targets(&pasted, &jobs, PasteScope::All, false),
            Ok(vec![0])
        );
        assert_eq!(
            resolve_pasted_targets(&pasted, &jobs, PasteScope::All, true),
            Err(PastedError::FileNotSelected),
            "strict mode compares the full path, not the basename"
        );

        let exact = format!("{SHA256_EMPTY}  {}", first.display());
        let exact = parse_pasted_line(&exact).expect("valid line");
        assert_eq!(
            resolve_pasted_targets(&exact, &jobs, PasteScope::All, true),
            Ok(vec![0])
        );
    }

    /// Every algorithm enabled, as a fresh sidecar lookup in a test would have.
    fn enabled_all() -> Vec<bool> {
        vec![true; ALGORITHMS.len()]
    }

    /// Exactly one algorithm enabled, looked up by name.
    fn enabled_only(name: &str) -> Vec<bool> {
        let mut enabled = vec![false; ALGORITHMS.len()];
        let index = ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
            .expect("the algorithm is in the table");
        enabled[index] = true;
        enabled
    }

    #[test]
    fn attach_sidecars_adds_the_digest_next_to_the_file() {
        let dir = TempDir::new("sidecar-hit");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 1);
        assert_eq!(result.unmatched, 0);
        assert!(!result.had_error);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    #[test]
    fn attach_sidecars_accumulates_every_enabled_format() {
        let dir = TempDir::new("sidecar-many");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}  data.bin\n"));
        dir.write("data.bin.md5", &format!("{MD5_EMPTY}  data.bin\n"));

        let mut jobs = vec![file_job(&target)];
        assert_eq!(attach_sidecars(&mut jobs, &enabled_all()).attached, 1);
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
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result, SidecarAttach::default());
        assert!(jobs[0].expected.is_empty());
    }

    /// A malformed line is not fatal: the entries before it are still attached,
    /// and the page can say that some lines were ignored.
    #[test]
    fn a_malformed_sidecar_is_reported_but_earlier_entries_survive() {
        let dir = TempDir::new("sidecar-bad");
        let target = dir.write("data.bin", "content");
        dir.write(
            "data.bin.sha256",
            &format!("{SHA256_EMPTY}  data.bin\nthis is not a checksum line\n"),
        );

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 1);
        assert!(result.had_error);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    #[test]
    fn attach_sidecars_does_not_duplicate_an_existing_expectation() {
        let dir = TempDir::new("sidecar-duplicate");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}\n"));

        let mut jobs = vec![file_job(&target)];
        jobs[0].expected.push(digest(SHA256_EMPTY));
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 0, "nothing new was attached");
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    #[test]
    fn attach_sidecars_with_no_jobs_does_nothing() {
        let mut jobs: Vec<FileJob> = Vec::new();
        assert_eq!(
            attach_sidecars(&mut jobs, &enabled_all()),
            SidecarAttach::default()
        );
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
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 1);
        assert_eq!(result.unmatched, 0);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
        assert!(jobs[1].expected.is_empty());
    }

    /// A sidecar was found by name, not chosen by the user: an entry that names
    /// another file must not be attached anywhere, and must be counted so the
    /// page can say the sidecar did not verify this file.
    #[test]
    fn a_sidecar_entry_naming_another_file_is_unmatched() {
        let dir = TempDir::new("sidecar-wrong-name");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}  other.bin\n"));

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 0);
        assert_eq!(result.unmatched, 1);
        assert!(jobs[0].expected.is_empty());
    }

    /// A nested name is a real constraint: it does not fall back to a basename
    /// match, unlike an explicitly chosen checksum file.
    #[test]
    fn a_sidecar_with_a_nested_name_does_not_fall_back_to_the_job() {
        let dir = TempDir::new("sidecar-nested");
        let target = dir.write("data.bin", "content");
        dir.write(
            "data.bin.sha256",
            &format!("{SHA256_EMPTY}  sub\\data.bin\n"),
        );

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 0);
        assert_eq!(result.unmatched, 1);
    }

    /// An absolute entry that really names the job is accepted.
    #[test]
    fn an_absolute_entry_naming_the_job_is_accepted() {
        let dir = TempDir::new("sidecar-absolute");
        let target = dir.write("data.bin", "content");
        dir.write(
            "data.bin.sha256",
            &format!("{SHA256_EMPTY}  {}\n", target.display()),
        );

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 1);
        assert_eq!(jobs[0].expected, vec![digest(SHA256_EMPTY)]);
    }

    /// A sidecar for an algorithm that is not being hashed cannot verify
    /// anything, and reading it could compare its digest against a different
    /// algorithm of the same length. It is therefore not even looked at.
    #[test]
    fn a_sidecar_for_a_disabled_algorithm_is_not_read() {
        let dir = TempDir::new("sidecar-disabled");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}  data.bin\n"));

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_only("MD5"));
        assert_eq!(result, SidecarAttach::default());
        assert!(jobs[0].expected.is_empty());
    }

    /// SFV has no algorithm-owned extension (CRC32 deliberately has none), so
    /// the sidecar lookup special-cases it when CRC32 is enabled.
    #[test]
    fn an_sfv_sidecar_is_read_when_crc32_is_enabled() {
        let dir = TempDir::new("sidecar-sfv");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sfv", "data.bin 00000000\n");

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_only("CRC32"));
        assert_eq!(result.attached, 1);
        assert_eq!(jobs[0].expected, vec![digest("00000000")]);
    }

    /// A directory that happens to be named like a sidecar is found by name but
    /// cannot be read; the page reports that rather than pretending it was not
    /// there.
    #[test]
    fn an_unreadable_sidecar_is_counted() {
        let dir = TempDir::new("sidecar-dir");
        let target = dir.write("data.bin", "content");
        fs::create_dir(dir.path().join("data.bin.sha256"))
            .expect("the directory must be creatable");

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &enabled_all());
        assert_eq!(result.attached, 0);
        assert_eq!(result.unreadable, 1);
    }

    #[test]
    fn a_sidecar_lookup_with_no_enabled_algorithms_does_nothing() {
        let dir = TempDir::new("sidecar-none-enabled");
        let target = dir.write("data.bin", "content");
        dir.write("data.bin.sha256", &format!("{SHA256_EMPTY}  data.bin\n"));

        let mut jobs = vec![file_job(&target)];
        let result = attach_sidecars(&mut jobs, &vec![false; ALGORITHMS.len()]);
        assert_eq!(result, SidecarAttach::default());
        assert!(jobs[0].expected.is_empty());
    }

    /// `sfv` and `hash` are checksum-file extensions even though no algorithm
    /// owns them, so a bare digest in such a file still names the file the name
    /// describes.
    #[test]
    fn strip_registered_extension_recognizes_sfv_and_hash() {
        assert_eq!(strip_registered_extension("data.bin.sfv"), Some("data.bin"));
        assert_eq!(
            strip_registered_extension("data.bin.HASH"),
            Some("data.bin")
        );
        assert_eq!(
            strip_registered_extension("data.bin.sha256"),
            Some("data.bin")
        );
        assert_eq!(strip_registered_extension("data.bin"), None);
    }
}
