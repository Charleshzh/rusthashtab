//! The 31 hash algorithms rustHashTab exposes.
//!
//! # Design
//!
//! Every algorithm is reachable through one uniform, streaming interface: build a
//! context with [`registry::make`], feed it [`Hasher::update`] in arbitrary chunks,
//! then [`Hasher::finalize`] it. The scanner reads 2 MiB blocks from several
//! threads, so chunk-size independence is a tested invariant, not a hope.
//!
//! This deliberately replaces the upstream C++ design, which passed
//! `ctx_size`/`ctx_align` around and placement-new'd each context into a
//! caller-supplied aligned buffer. `Box<dyn Hasher>` makes that bookkeeping
//! unnecessary.
//!
//! # Coverage
//!
//! Thirty of the thirty-one algorithms come from mature crates. One does not:
//! ParallelHash, implemented in [`parallel_hash`] because the only crate offering
//! it is unusable inside a shell extension — see that module.
//!
//! # Correctness
//!
//! `cargo xtask audit` prints which external authority validates which algorithm,
//! and `cargo xtask verify` runs those checks. A digest compared only against a
//! constant this repository also produced is a regression test, not a proof.

#![warn(missing_docs)]

pub mod blake2sp;
pub mod blake3_family;
pub mod checksums;
mod digest_adapter;
pub mod ed2k;
pub mod gost;
pub mod k12;
pub mod parallel_hash;
pub mod registry;
pub mod sha2_family;
pub mod sha3_family;

pub use parallel_hash::{ParallelHash, ParallelHashError, Strength};
pub use registry::{ALGORITHMS, Algorithm};

/// Maximum digest length across all supported algorithms, in bytes.
///
/// Driven by PH256-528 at 66 bytes.
pub const MAX_DIGEST_LEN: usize = 66;

/// A streaming hash context.
///
/// Implementors are object-safe so that a scan can hold `Box<dyn Hasher>` for each
/// enabled algorithm. `Send` is required because the scanner hashes on worker
/// threads.
pub trait Hasher: Send {
    /// Write data into the context.
    fn update(&mut self, data: &[u8]);

    /// Consume the context and produce the digest.
    ///
    /// The returned vector's length always equals [`Hasher::output_len`].
    fn finalize(self: Box<Self>) -> Vec<u8>;

    /// Digest length in bytes, known before any data is hashed.
    fn output_len(&self) -> usize;
}
