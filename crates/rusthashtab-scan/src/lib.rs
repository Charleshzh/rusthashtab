//! File discovery and the concurrent hashing pipeline.
//!
//! # Shape of the pipeline
//!
//! The upstream design — which this crate reproduces because it is the part
//! users notice — is:
//!
//! * one task per file, all running concurrently;
//! * each task reads its file in 2 MiB blocks with **asynchronous** I/O;
//! * each block is fed to every enabled algorithm;
//! * a bounded pool of read buffers caps memory; when it is exhausted, tasks
//!   queue instead of allocating;
//! * progress is reported as bytes completed, so the bar advances even while a
//!   different file is being read.
//!
//! # Deliberate differences from the upstream implementation
//!
//! * **No global thread pool.** Spawning rayon or an equivalent inside
//!   `explorer.exe` is a defect. This crate owns its worker threads and shuts
//!   them down deterministically.
//! * **Per-file block size is a constant, not a tunable.** 2 MiB was chosen to
//!   amortise syscall overhead while staying well inside L2/L3 on modern parts.
//! * **Read buffers are recycled through a small free list**, so steady-state
//!   hashing performs no allocation per block.
//!
//! # Not yet implemented
//!
//! This module is scaffolding. The types below fix the interfaces so the UI and
//! shell layers can be written against them.

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

/// Bytes read per asynchronous I/O operation.
pub const BLOCK_SIZE: usize = 2 << 20;

/// Maximum number of outstanding read buffers.
///
/// Caps peak memory at [`MAX_INFLIGHT_BLOCKS`] × [`BLOCK_SIZE`] = 1 GiB. Reads
/// beyond this queue rather than allocate, which is what keeps a scan of a
/// directory tree from exhausting memory on a machine with many files.
pub const MAX_INFLIGHT_BLOCKS: usize = 512;

/// One file to hash, with any digests it is expected to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileJob {
    /// Absolute, normalized path.
    pub path: PathBuf,
    /// Path shown to the user, relative to the scan root when possible.
    pub display_path: String,
    /// Digests this file is expected to equal, from a sumfile.
    pub expected: Vec<Vec<u8>>,
}

/// Everything a scan produces for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// The job this result corresponds to.
    pub path: PathBuf,
    /// Digest per enabled algorithm, in table order; empty if that algorithm
    /// was disabled or the file could not be read.
    pub digests: Vec<Vec<u8>>,
    /// Size in bytes, or 0 if unknown.
    pub size: u64,
    /// `None` on success, otherwise the OS error code.
    pub error: Option<u32>,
}

/// Outcome of comparing a file's digests against the expected ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchState {
    /// No expected digest was available to compare against.
    NotChecked,
    /// At least one enabled algorithm matched.
    Matched {
        /// Index into the algorithm table of the matching algorithm.
        algorithm: usize,
        /// Whether that algorithm is considered cryptographically secure.
        secure: bool,
    },
    /// Expected digests existed but none matched.
    Mismatched,
}

/// Progress notification handed to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Bytes hashed so far across all files.
    pub done: u64,
    /// Total bytes to hash.
    pub total: u64,
    /// Files finished so far.
    pub files_done: usize,
    /// Files in the scan.
    pub files_total: usize,
}

/// Expand a user selection into a flat list of files.
///
/// Directories are walked recursively. Reparse points (symlinks, junctions) are
/// **not** followed: doing so risks cycles and can silently hash a completely
/// different volume than the user selected.
///
/// # Not yet implemented
pub fn expand_selection(_roots: &[PathBuf]) -> std::io::Result<Vec<FileJob>> {
    unimplemented!("scaffolding: directory walking lands with the scan pipeline")
}

/// Normalize a path: make it absolute, resolve `..`, and strip the `\\?\`
/// long-path prefix for display.
///
/// # Not yet implemented
pub fn normalize_path(_path: &Path) -> PathBuf {
    unimplemented!("scaffolding: path normalization lands with the scan pipeline")
}
