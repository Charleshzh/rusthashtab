//! Sumfile parsing and export.
//!
//! Supports the four formats rustHashTab reads and writes:
//!
//! | Format | Read | Write | Notes |
//! |---|---|---|---|
//! | `sha256sum`-style hex | yes | yes | `HASH␣␣FILE` or `HASH␣*FILE` |
//! | base64 hashes | yes | — | seen in the wild next to binary artifacts |
//! | SFV | yes | yes | `FILE␣CRC32`, delimiter is always a single space |
//! | corz `.hash` | yes | yes | `#algo#path#timestamp` banner lines |
//!
//! The parser is stateful on purpose: the first line decides the comment style
//! (`#` or `;`) and the hash style (hex, SFV, base64), and subsequent lines are
//! interpreted the same way. That mirrors how the existing format ecosystem
//! behaves and avoids mis-detecting a filename that happens to look like a hash.

#![warn(missing_docs)]

pub mod export;
pub mod parse;

pub use export::{ExportFormat, ExportOptions, export};
pub use parse::{FileSumList, ParseOutcome, ParseStyle, parse_all, parse_reader};

/// Longest digest any supported algorithm produces, in bytes.
///
/// PH256-528 at 66 bytes; hex-encoded that is 132 characters.
pub const MAX_DIGEST_LEN: usize = 66;

/// A digest plus the file it is expected to belong to.
///
/// An empty `path` means "the sumfile named no file", which is legal: a
/// single-hash file next to an artifact. In that case the digest applies to the
/// file the sumfile is named after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSum {
    /// Path exactly as it appeared in the sumfile, before any resolution.
    pub path: String,
    /// Decoded digest bytes.
    pub digest: Vec<u8>,
}
