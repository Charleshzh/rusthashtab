//! File discovery and the concurrent hashing pipeline.
//!
//! # Shape of the pipeline
//!
//! The design the users notice, and therefore the one this crate reproduces:
//!
//! * the selection is expanded to one job per file ([`expand_selection`]);
//! * a worker takes one file at a time and hashes it from open to finalize;
//! * each file is read in 2 MiB blocks with **asynchronous** I/O, several blocks
//!   ahead, so the device stays busy while the worker hashes;
//! * every block is fed to every enabled algorithm;
//! * a bounded pool of read buffers caps memory; when it is exhausted, workers
//!   queue instead of allocating;
//! * progress is reported as bytes completed across all files, so the bar keeps
//!   moving while a different file is being read.
//!
//! ```no_run
//! use rusthashtab_scan::{FileJob, ScanConfig, ScanEvent, start};
//! use std::path::PathBuf;
//!
//! let jobs = vec![FileJob {
//!     path: PathBuf::from(r"C:\Windows\notepad.exe"),
//!     display_path: "notepad.exe".to_string(),
//!     expected: Vec::new(),
//!     size: 0,
//! }];
//! let handle = start(ScanConfig::new(jobs), Box::new(|event| {
//!     if let ScanEvent::FileFinished { result, .. } = event {
//!         println!("{}: {} bytes", result.path.display(), result.size);
//!     }
//! }));
//! handle.wait();
//! ```
//!
//! # Deliberate differences from the upstream implementation
//!
//! * **No global thread pool.** Spawning rayon or an equivalent inside
//!   `explorer.exe` is a defect. This crate owns its worker threads and shuts
//!   them down deterministically: dropping the [`ScanHandle`] cancels the scan
//!   and joins every worker.
//! * **Per-file block size is a constant, not a tunable.** 2 MiB was chosen to
//!   amortise syscall overhead while staying well inside L2/L3 on modern parts.
//! * **Read buffers are recycled through a small free list**, so steady-state
//!   hashing performs no allocation per block.
//! * **A completion port is not used.** Blocks of a file are consumed in order,
//!   so a read-ahead ring of independent overlapped operations gets the same
//!   overlap with less machinery and an easier shutdown.
//!
//! # Events, not window messages
//!
//! The scanner knows nothing about `HWND`s: it reports through the sink passed to
//! [`start`], on the worker threads. Turning those events into posted window
//! messages — and quantising progress so a 10 GB scan does not post a message per
//! byte — is the UI layer's job.

#![warn(missing_docs)]

pub mod path;

#[cfg(windows)]
mod cancel;
#[cfg(windows)]
mod compare;
#[cfg(windows)]
mod engine;
#[cfg(windows)]
mod pool;
#[cfg(windows)]
mod reader;

use std::path::PathBuf;

pub use path::{FILE_ATTRIBUTE_REPARSE_POINT, expand_selection, normalize_path};

#[cfg(windows)]
pub use engine::{ScanConfig, ScanEvent, ScanHandle, ScanOutcome, start};

/// Bytes read per asynchronous I/O operation.
pub const BLOCK_SIZE: usize = 2 << 20;

/// Maximum number of outstanding read buffers.
///
/// Caps peak memory at [`MAX_INFLIGHT_BLOCKS`] × [`BLOCK_SIZE`] = 1 GiB. Reads
/// beyond this queue rather than allocate, which is what keeps a scan of a
/// directory tree from exhausting memory on a machine with many files.
pub const MAX_INFLIGHT_BLOCKS: usize = 512;

/// Blocks read ahead of the one being hashed, per worker.
///
/// Four blocks is 8 MiB in flight per worker: enough to keep a spindle or an SSD
/// queue busy through the hashing of one block, without holding so much of the
/// pool that a scan of many large files serialises on buffer availability.
pub const READ_AHEAD_BLOCKS: usize = 4;

/// Ceiling on worker threads, whatever the machine reports.
///
/// A 64-core machine does not hash 64 files faster than it hashes 16 — the disk
/// is the bottleneck, and every worker holds read-ahead buffers — so the scan
/// does not scale its thread count without limit.
pub const MAX_WORKERS: usize = 32;

/// One file to hash, with any digests it is expected to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileJob {
    /// Absolute, normalized path.
    pub path: PathBuf,
    /// Path shown to the user, relative to the scan root when possible.
    pub display_path: String,
    /// Digests this file is expected to equal, from a sumfile.
    pub expected: Vec<Vec<u8>>,
    /// Size in bytes when the job was created.
    ///
    /// Used for the progress total; the scanner re-reads the actual size when it
    /// opens the file, so a file that changes during the scan still hashes
    /// correctly.
    pub size: u64,
}

/// Everything a scan produces for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// The job this result corresponds to.
    pub path: PathBuf,
    /// Digest per enabled algorithm, in table order; empty if that algorithm was
    /// disabled or the file could not be read.
    pub digests: Vec<Vec<u8>>,
    /// Bytes actually hashed: 0 when the file could not be read at all, and the
    /// partial count when a read failed part way through.
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
    /// Bytes hashed so far across all files, clamped to [`Progress::total`].
    pub done: u64,
    /// Total bytes to hash.
    pub total: u64,
    /// Files finished so far.
    pub files_done: usize,
    /// Files in the scan.
    pub files_total: usize,
}
