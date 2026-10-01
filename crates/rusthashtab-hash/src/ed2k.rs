//! eD2k — the eDonkey2000 file hash — in both historical flavours.
//!
//! # Why this is hand-written
//!
//! The `ed2k` crate pins `digest` 0.10 while the rest of this workspace is on
//! 0.11; two incompatible trait generations in one dependency graph is a
//! maintenance trap. The construction is a ~20-line tree over MD4, so the
//! escape hatch is cheap. The crate is still used — as a dev-dependency
//! **oracle** in `tests/ed2k_oracle.rs`, exactly the role `sp800-185` plays
//! for ParallelHash.
//!
//! # The construction
//!
//! The input is split into chunks of 9,728,000 bytes (9500 KiB). Each chunk
//! is hashed with MD4. One chunk (including the empty input): the chunk's MD4
//! *is* the result. More than one chunk: the result is MD4 over the
//! concatenated chunk digests.
//!
//! The two flavours differ only when the length is a **positive multiple** of
//! the chunk size: the old ("red") behaviour appends the MD4 of an empty
//! chunk before the final MD4, the fixed ("blue") behaviour does not. They
//! are what the table calls `eD2k (Old)` and `eD2k` respectively.
//!
//! Streaming note: the tree keeps only the current chunk's MD4 context and 16
//! bytes per finished chunk, so a 1 TB file hashes in constant memory.

use crate::Hasher;
use digest::Digest;

/// Bytes per eD2k chunk: 9500 KiB.
pub const CHUNK_SIZE: usize = 9_728_000;

/// Which boundary behaviour to apply — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// The fixed behaviour: no empty trailing chunk (`eD2k`).
    Blue,
    /// The old behaviour: a positive multiple of the chunk size gets an extra
    /// empty chunk's MD4 appended (`eD2k (Old)`).
    Red,
}

/// A streaming eD2k context.
pub struct Ed2k {
    /// MD4 context of the chunk currently being filled.
    current: md4::Md4,
    /// Bytes fed into `current` so far.
    current_len: usize,
    /// Digests of completed chunks, 16 bytes each.
    chunks: Vec<u8>,
    /// Total input length, for the red-flavour boundary rule.
    total: u64,
    /// Which boundary behaviour this instance applies.
    flavour: Flavour,
}

impl Ed2k {
    /// A fresh context with the given boundary flavour.
    pub fn new(flavour: Flavour) -> Self {
        Self {
            current: md4::Md4::new(),
            current_len: 0,
            chunks: Vec::new(),
            total: 0,
            flavour,
        }
    }
}

impl Hasher for Ed2k {
    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (CHUNK_SIZE - self.current_len).min(data.len());
            self.current.update(&data[..take]);
            self.current_len += take;
            data = &data[take..];
            if self.current_len == CHUNK_SIZE {
                self.chunks
                    .extend_from_slice(&self.current.finalize_reset());
                self.current_len = 0;
            }
        }
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let mut chunks = self.chunks;
        if self.current_len > 0 {
            // The trailing partial chunk.
            chunks.extend_from_slice(&self.current.finalize());
        } else if self.total == 0 {
            // The empty input is a single empty chunk.
            chunks.extend_from_slice(&md4::Md4::digest(b""));
        } else if self.current_len == 0 && self.flavour == Flavour::Red {
            // Positive multiple of the chunk size: the old behaviour's extra
            // empty chunk. (`current_len == 0` here means the input ended
            // exactly on a boundary — the partial-chunk arm above did not run.)
            chunks.extend_from_slice(&md4::Md4::digest(b""));
        }
        if chunks.len() == 16 {
            // A single chunk: its MD4 is the result, with no second level.
            chunks
        } else {
            md4::Md4::digest(&chunks).to_vec()
        }
    }

    fn output_len(&self) -> usize {
        16
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn hex(h: Ed2k, data: &[u8]) -> String {
        let mut h = h;
        h.update(data);
        Box::new(h)
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Empty input is a single empty chunk: plain MD4 of nothing, both
    /// flavours.
    #[test]
    fn empty_input() {
        assert_eq!(
            hex(Ed2k::new(Flavour::Blue), b""),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert_eq!(
            hex(Ed2k::new(Flavour::Red), b""),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    /// Documented vectors from the `ed2k` crate's own documentation
    /// (docs.rs/ed2k): the single-chunk case, and the exact chunk-size case
    /// where the two flavours diverge.
    #[test]
    fn documented_vectors() {
        assert_eq!(
            hex(Ed2k::new(Flavour::Blue), b"hello world"),
            "aa010fbc1d14c795d86ef98c95479d17"
        );

        let boundary = vec![0x55u8; CHUNK_SIZE];
        assert_eq!(
            hex(Ed2k::new(Flavour::Blue), &boundary),
            "4127a47867b6110f0f86f2d9845fb374"
        );
        assert_eq!(
            hex(Ed2k::new(Flavour::Red), &boundary),
            "49e80f377b7e4e706dbd3ecc89f39306"
        );
    }

    /// Feeding the input in arbitrary pieces must not change the digest —
    /// the scanner hands us 2 MiB blocks, which do not align with the
    /// 9,728,000-byte chunks.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let whole = hex(Ed2k::new(Flavour::Blue), &data);

        for piece in [1usize, 65_537, 2 << 20] {
            let mut h = Ed2k::new(Flavour::Blue);
            for c in data.chunks(piece) {
                h.update(c);
            }
            assert_eq!(whole, hex(h, b""), "piece size {piece}");
        }
    }
}
