//! Checksum-file export: choosing a format and algorithm, and writing the file.
//!
//! # Why the plan is a separate step
//!
//! Exporting is three decisions the user can see before anything is written: the
//! format (which is inferred from the file name), which algorithm's digest goes
//! into the file, and how the lines are spaced and terminated (which comes from
//! the settings). [`plan`] makes all three without touching the file system, so
//! the caller can build a plan, let the user look at it, and only then call
//! [`write`]. It also means the selection rules are testable without a dialog.
//!
//! # How the format is chosen
//!
//! The extension of the file the user is saving to decides, matching what other
//! tools do with the same name:
//!
//! * a registered algorithm extension (`md5`, `sha256sum`, `sha1`, `xxh64`, …)
//!   writes that algorithm's digests in `sha256sum`-style form;
//! * `.sfv` writes CRC32 digests in SFV form, the one format whose lines put the
//!   file name first;
//! * `.hash` writes the corz form, whose extra `#algo#path#timestamp` lines only
//!   make sense with a secure algorithm, so the first enabled secure one is used
//!   (and the first enabled algorithm at all if none is secure);
//! * anything else -- an unknown extension or none -- writes the first enabled
//!   algorithm in `sha256sum`-style form, which is the least surprising default.
//!
//! A digest for an algorithm that was not hashed does not exist, so asking for
//! an algorithm that is not enabled is an error rather than an empty file. The
//! result also never contains a digests list that is empty: a scan with nothing
//! to export says so through [`ExportError::NothingToExport`].
//!
//! # Paths in the output
//!
//! Entries carry [`crate::JobSpec::display_path`], the name the user saw in the
//! File column. The file is written next to whatever the user chooses, so the
//! display path is what makes the checksum file usable by a person; the slash
//! direction is then applied by the formatter according to the settings.

use crate::JobSpec;
use rusthashtab_hash::{ALGORITHMS, registry};
use rusthashtab_scan::FileResult;
use rusthashtab_settings::Settings;
use rusthashtab_sumfile::{ExportFormat, ExportOptions, FileSum, export};
use std::path::{Path, PathBuf};

/// Everything needed to write one checksum file.
///
/// The plan is data, not an action: building it reads no file and writes no file,
/// so a caller can build one to show the user what will happen and can rebuild it
/// cheaply when a setting changes.
#[derive(Debug, Clone)]
pub struct ExportPlan {
    /// Where the file will be written, exactly as the user chose it.
    pub path: PathBuf,
    /// Which flavour of checksum file to write.
    pub format: ExportFormat,
    /// Index into [`rusthashtab_hash::ALGORITHMS`] of the digest to export.
    pub algorithm: usize,
    /// Formatting knobs, mapped from the user's settings.
    pub options: ExportOptions,
    /// The lines to write, in display-path order (the formatter sorts them).
    pub entries: Vec<FileSum>,
}

/// Why a checksum file could not be planned or written.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// None of the hashed files has a usable digest for the chosen algorithm.
    #[error("there are no successful hashes to export")]
    NothingToExport,
    /// Every algorithm is disabled, so there is nothing that could be exported.
    #[error("no hashing algorithm is enabled")]
    NoAlgorithmEnabled,
    /// The file name asked for an algorithm the user has turned off.
    ///
    /// That algorithm was not hashed, so its digests are absent; writing the file
    /// anyway would produce an empty or misleading checksum file.
    #[error("the algorithm for the chosen file name is not enabled")]
    AlgorithmNotEnabled,
    /// SFV is defined over CRC32, and CRC32 is disabled.
    #[error("SFV export needs CRC32, which is disabled")]
    Crc32NotEnabled,
    /// The file could not be written; the OS message is included.
    #[error("{0}")]
    Io(String),
}

/// Plan an export to `target`.
///
/// `results` is indexed like `jobs` and may be shorter than it (a scan still in
/// progress); a job with no result yet, a failed file, and a file with no digest
/// for the chosen algorithm are all simply not exported.
///
/// `enabled` is indexed like [`rusthashtab_hash::ALGORITHMS`] and must be the
/// same flags the scan used: an algorithm that was off has no digest, even if the
/// settings were changed afterwards.
///
/// # Errors
///
/// [`ExportError::NoAlgorithmEnabled`] when `enabled` contains no `true`,
/// [`ExportError::Crc32NotEnabled`] for an SFV target when CRC32 is off,
/// [`ExportError::AlgorithmNotEnabled`] when the file name names a disabled
/// algorithm, and [`ExportError::NothingToExport`] when no job produced a digest
/// for the selected algorithm.
pub fn plan(
    target: &Path,
    results: &[Option<FileResult>],
    jobs: &[JobSpec],
    settings: &Settings,
    enabled: &[bool],
) -> Result<ExportPlan, ExportError> {
    let first_enabled = enabled
        .iter()
        .position(|on| *on)
        .ok_or(ExportError::NoAlgorithmEnabled)?;

    let extension = target
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let (format, algorithm) = match extension.as_str() {
        "sfv" => (ExportFormat::Sfv, crc32_algorithm(enabled)?),
        "hash" => {
            // The corz form annotates each line with the algorithm that produced
            // it, and is meant for strong digests; falling back to the first
            // enabled algorithm keeps the export possible on a machine where
            // every secure algorithm is switched off.
            let secure = enabled.iter().enumerate().find_map(|(index, on)| {
                (*on && ALGORITHMS.get(index).is_some_and(|a| a.secure)).then_some(index)
            });
            (ExportFormat::DotHash, secure.unwrap_or(first_enabled))
        }
        other => match registry::by_extension(other) {
            Some(found) => {
                let algorithm = ALGORITHMS
                    .iter()
                    .position(|algorithm| algorithm.name == found.name)
                    .ok_or(ExportError::NoAlgorithmEnabled)?;
                if !enabled.get(algorithm).copied().unwrap_or(false) {
                    return Err(ExportError::AlgorithmNotEnabled);
                }
                (ExportFormat::Sumfile, algorithm)
            }
            // Unknown extension or no extension at all: the first enabled
            // algorithm is the one the page shows first, so it is the digest the
            // user most likely has in mind.
            None => (ExportFormat::Sumfile, first_enabled),
        },
    };

    let options = ExportOptions {
        upper: settings.sumfile_uppercase,
        forward_slashes: settings.sumfile_forward_slashes,
        unix_endings: settings.sumfile_unix_endings,
        double_space: settings.sumfile_double_space,
        banner: settings.sumfile_banner,
        banner_date: settings.sumfile_banner_date,
        corz_compatible: settings.sumfile_dot_hash_compatible,
        algorithm_label: algorithm_label(algorithm),
    };

    let mut entries = Vec::new();
    for (job, result) in jobs.iter().zip(results) {
        let Some(result) = result else {
            continue;
        };
        if result.error.is_some() {
            continue;
        }
        let Some(digest) = result.digests.get(algorithm) else {
            continue;
        };
        if digest.is_empty() {
            continue;
        }
        entries.push(FileSum {
            path: job.display_path.clone(),
            digest: digest.clone(),
        });
    }

    if entries.is_empty() {
        return Err(ExportError::NothingToExport);
    }

    Ok(ExportPlan {
        path: target.to_path_buf(),
        format,
        algorithm,
        options,
        entries,
    })
}

/// Write a planned checksum file.
///
/// The content is UTF-8 without a byte-order mark, which is what every tool that
/// reads these files expects; a BOM would become part of the first line's digest
/// or comment marker. Line endings and path separators come from the plan's
/// [`ExportOptions`], so the caller does not have to remember them here.
///
/// Returns the number of entries written.
///
/// # Errors
///
/// [`ExportError::Io`] when the file cannot be created or written.
pub fn write(plan: &ExportPlan) -> Result<usize, ExportError> {
    let text = export(&plan.entries, plan.format, &plan.options);
    std::fs::write(&plan.path, text.as_bytes())
        .map_err(|error| ExportError::Io(error.to_string()))?;
    Ok(plan.entries.len())
}

/// The CRC32 algorithm's table index, or the "SFV needs CRC32" error.
fn crc32_algorithm(enabled: &[bool]) -> Result<usize, ExportError> {
    let index = ALGORITHMS
        .iter()
        .position(|algorithm| algorithm.name == "CRC32")
        .ok_or(ExportError::Crc32NotEnabled)?;
    if enabled.get(index).copied().unwrap_or(false) {
        Ok(index)
    } else {
        Err(ExportError::Crc32NotEnabled)
    }
}

/// The algorithm name as it appears in a corz `.hash` line.
///
/// Lower-cased and stripped of `-` and spaces, which is how the corz form spells
/// `SHA-256` (`sha256`). Other punctuation is left alone: the label is only a
/// hint for a reader, and rewriting it further would make this table and that
/// format disagree the day an algorithm is renamed.
fn algorithm_label(index: usize) -> String {
    ALGORITHMS
        .get(index)
        .map(|algorithm| algorithm.name.to_lowercase().replace(['-', ' '], ""))
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_sumfile::parse::parse_all;
    use std::fs;

    /// The SHA-256 of the empty input.
    const SHA256_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    /// The MD5 of the empty input.
    const MD5_EMPTY: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];

    /// A uniquely named temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "rusthashtab-ui-export-{tag}-{}-{}",
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
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Settings with the banner off, so the tests can compare exact lines.
    fn settings() -> Settings {
        Settings {
            sumfile_banner: false,
            ..Settings::default()
        }
    }

    fn all_enabled() -> Vec<bool> {
        vec![true; ALGORITHMS.len()]
    }

    fn only(name: &str) -> Vec<bool> {
        let mut enabled = vec![false; ALGORITHMS.len()];
        enabled[index_of(name)] = true;
        enabled
    }

    fn index_of(name: &str) -> usize {
        ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
            .expect("algorithm is in the table")
    }

    fn spec(display_path: &str) -> JobSpec {
        JobSpec {
            path: PathBuf::from(format!(r"C:\scan\{display_path}")),
            display_path: display_path.to_string(),
        }
    }

    fn result_with(name: &str, digest: &[u8]) -> FileResult {
        let mut digests = vec![Vec::new(); ALGORITHMS.len()];
        digests[index_of(name)] = digest.to_vec();
        FileResult {
            path: PathBuf::from(r"C:\scan\a.txt"),
            digests,
            size: 1,
            error: None,
        }
    }

    #[test]
    fn a_registered_extension_selects_that_algorithm_and_the_sumfile_format() {
        let plan = plan(
            Path::new("out.sha256"),
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::Sumfile);
        assert_eq!(plan.algorithm, index_of("SHA-256"));
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].path, "a.txt");
        assert_eq!(plan.entries[0].digest, SHA256_EMPTY.to_vec());
        assert_eq!(plan.path, PathBuf::from("out.sha256"));
    }

    #[test]
    fn an_unknown_extension_uses_the_first_enabled_algorithm() {
        let plan = plan(
            Path::new("out.txt"),
            &[Some(result_with("MD5", &MD5_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &only("MD5"),
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::Sumfile);
        assert_eq!(plan.algorithm, index_of("MD5"));
    }

    #[test]
    fn a_file_with_no_extension_uses_the_first_enabled_algorithm() {
        let plan = plan(
            Path::new("out"),
            &[Some(result_with("SHA-1", &[0x11; 20]))],
            &[spec("a.txt")],
            &settings(),
            &only("SHA-1"),
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::Sumfile);
        assert_eq!(plan.algorithm, index_of("SHA-1"));
    }

    #[test]
    fn an_sfv_extension_selects_crc32_and_the_sfv_format() {
        let plan = plan(
            Path::new("out.sfv"),
            &[Some(result_with("CRC32", &[0x5B, 0x72, 0x1D, 0x06]))],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::Sfv);
        assert_eq!(plan.algorithm, index_of("CRC32"));
    }

    /// SFV is defined over CRC32; with CRC32 off there is no valid SFV file to
    /// write, and silently writing some other digest under a `.sfv` name would
    /// produce a file other tools misread.
    #[test]
    fn an_sfv_export_without_crc32_is_refused() {
        let mut enabled = all_enabled();
        enabled[index_of("CRC32")] = false;

        let error = plan(
            Path::new("out.sfv"),
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &enabled,
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::Crc32NotEnabled));
    }

    #[test]
    fn a_dot_hash_extension_prefers_the_first_secure_algorithm() {
        // CRC32 is enabled first in the table but is not secure; SHA-256 is the
        // first secure enabled algorithm.
        let mut enabled = vec![false; ALGORITHMS.len()];
        enabled[index_of("CRC32")] = true;
        enabled[index_of("SHA-256")] = true;

        let plan = plan(
            Path::new("out.hash"),
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &enabled,
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::DotHash);
        assert_eq!(plan.algorithm, index_of("SHA-256"));
        assert_eq!(plan.options.algorithm_label, "sha256");
    }

    #[test]
    fn a_dot_hash_extension_falls_back_to_the_first_enabled_algorithm() {
        let plan = plan(
            Path::new("out.hash"),
            &[Some(result_with("CRC32", &[0x00, 0x01, 0x02, 0x03]))],
            &[spec("a.txt")],
            &settings(),
            &only("CRC32"),
        )
        .unwrap();

        assert_eq!(plan.format, ExportFormat::DotHash);
        assert_eq!(plan.algorithm, index_of("CRC32"));
    }

    #[test]
    fn a_disabled_algorithm_named_by_the_extension_is_refused() {
        let mut enabled = all_enabled();
        enabled[index_of("MD5")] = false;

        let error = plan(
            Path::new("out.md5"),
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &enabled,
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::AlgorithmNotEnabled));
    }

    #[test]
    fn no_enabled_algorithm_is_an_error() {
        let error = plan(
            Path::new("out.sha256"),
            &[],
            &[],
            &settings(),
            &vec![false; ALGORITHMS.len()],
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::NoAlgorithmEnabled));
    }

    #[test]
    fn a_scan_with_no_finished_file_has_nothing_to_export() {
        let error = plan(
            Path::new("out.sha256"),
            &[None],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::NothingToExport));
    }

    /// An unreadable file is not a file with a digest: exporting it would put a
    /// name in a checksum file with no checksum to verify it against.
    #[test]
    fn a_failed_file_is_not_exported() {
        let mut failed = result_with("SHA-256", &SHA256_EMPTY);
        failed.error = Some(5);

        let error = plan(
            Path::new("out.sha256"),
            &[Some(failed)],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::NothingToExport));
    }

    #[test]
    fn a_file_without_a_digest_for_the_chosen_algorithm_is_not_exported() {
        let empty_digest = result_with("SHA-256", &[]);
        let error = plan(
            Path::new("out.sha256"),
            &[Some(empty_digest)],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap_err();

        assert!(matches!(error, ExportError::NothingToExport));
    }

    #[test]
    fn entries_keep_only_files_that_hashed_with_the_chosen_algorithm() {
        let good = result_with("SHA-256", &SHA256_EMPTY);
        // A result from a scan where SHA-256 was off: all digests empty.
        let mut other = result_with("MD5", &MD5_EMPTY);
        other.digests[index_of("SHA-256")] = Vec::new();

        let plan = plan(
            Path::new("out.sha256"),
            &[Some(good), Some(other)],
            &[spec("good.txt"), spec("other.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap();

        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].path, "good.txt");
    }

    #[test]
    fn export_options_follow_the_settings() {
        let settings = Settings {
            sumfile_uppercase: false,
            sumfile_forward_slashes: false,
            sumfile_unix_endings: false,
            sumfile_double_space: true,
            sumfile_banner: false,
            sumfile_banner_date: true,
            sumfile_dot_hash_compatible: false,
            ..Settings::default()
        };

        let plan = plan(
            Path::new("out.sha256"),
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("dir/a.txt")],
            &settings,
            &all_enabled(),
        )
        .unwrap();

        assert!(!plan.options.upper);
        assert!(!plan.options.forward_slashes);
        assert!(!plan.options.unix_endings);
        assert!(plan.options.double_space);
        assert!(!plan.options.banner);
        assert!(plan.options.banner_date);
        assert!(!plan.options.corz_compatible);
        assert_eq!(plan.options.algorithm_label, "sha256");
    }

    #[test]
    fn the_algorithm_label_is_lowercase_without_dashes_or_spaces() {
        assert_eq!(algorithm_label(index_of("SHA-256")), "sha256");
        assert_eq!(algorithm_label(index_of("SHA3-512")), "sha3512");
        assert_eq!(
            algorithm_label(index_of("GOST 2012 (256)")),
            "gost2012(256)"
        );
    }

    /// The real proof that the file is usable: parse what was written and compare
    /// it with the entries that went in.
    #[test]
    fn write_produces_a_file_that_parses_back_to_the_same_entries() {
        let dir = TempDir::new("roundtrip");
        let target = dir.path().join("out.sha256");
        let jobs = [spec("a.txt"), spec("b.txt")];
        let results = [
            Some(result_with("SHA-256", &SHA256_EMPTY)),
            Some(result_with("SHA-256", &[0x42; 32])),
        ];

        let plan = plan(&target, &results, &jobs, &settings(), &all_enabled()).unwrap();
        let count = write(&plan).unwrap();
        assert_eq!(count, plan.entries.len());
        assert_eq!(count, 2);

        let text = fs::read_to_string(&target).unwrap();
        assert!(!text.starts_with('\u{feff}'), "no BOM may be written");
        let parsed = parse_all(&text);
        assert!(!parsed.had_error);
        assert_eq!(parsed.entries, plan.entries);

        // The default settings use one space plus the GNU binary marker.
        assert!(text.contains(" *a.txt"), "{text}");
        assert!(text.contains(" *b.txt"), "{text}");
    }

    #[test]
    fn write_honours_the_configured_line_endings() {
        let dir = TempDir::new("crlf");
        let target = dir.path().join("out.sha256");
        let settings = Settings {
            sumfile_banner: false,
            sumfile_unix_endings: false,
            ..Settings::default()
        };

        let plan = plan(
            &target,
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings,
            &all_enabled(),
        )
        .unwrap();
        write(&plan).unwrap();

        let text = fs::read_to_string(&target).unwrap();
        assert!(text.contains("\r\n"), "{text:?}");
        assert!(!text.contains("\n\n"), "every line ends once: {text:?}");
    }

    /// The corz lines are the reason `.hash` exists; they must actually be in the
    /// file, with the lower-case label the plan carries.
    #[test]
    fn a_dot_hash_export_writes_the_corz_line() {
        let dir = TempDir::new("corz");
        let target = dir.path().join("out.hash");

        // Only SHA-256 is enabled: with every algorithm on, the first *secure*
        // one in table order is RipeMD160, which this result has no digest for.
        let plan = plan(
            &target,
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &only("SHA-256"),
        )
        .unwrap();
        write(&plan).unwrap();

        let text = fs::read_to_string(&target).unwrap();
        assert!(
            text.starts_with("#sha256#a.txt#1970.01.01@00.00:00\n"),
            "{text}"
        );
    }

    #[test]
    fn write_reports_an_io_error() {
        let dir = TempDir::new("io-error");
        // A directory that does not exist: the write cannot succeed.
        let target = dir.path().join("no-such-directory").join("out.sha256");
        let plan = plan(
            &target,
            &[Some(result_with("SHA-256", &SHA256_EMPTY))],
            &[spec("a.txt")],
            &settings(),
            &all_enabled(),
        )
        .unwrap();

        match write(&plan) {
            Err(ExportError::Io(message)) => assert!(!message.is_empty()),
            other => panic!("expected an IO error, got {other:?}"),
        }
    }
}
