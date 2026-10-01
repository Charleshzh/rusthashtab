//! KangarooTwelve (KT128), in 33-, 32- and 64-byte output variants.
//!
//! KangarooTwelve is a XOF — tree hashing over TurboSHAKE128 — so one
//! streaming state serves all three table rows, decided at
//! [`Hasher::finalize`] time by `out_len`, like [`crate::blake3_family::Blake3`].
//! The customization string is empty, the only configuration the product
//! exposes. The `k12` crate calls this construction `CustomKt128::default()`.
//!
//! # Why KT128 and not KT256
//!
//! KT128 *is* KangarooTwelve — the only variant the standard (RFC 9861)
//! defines; KT256 is a later, higher-security-margin sibling. Checksum files
//! published as "K12" everywhere mean the RFC construction, and the RFC's own
//! test vectors are KT128. The same reasoning already fixed `PH128-264`'s
//! strength at 128 bits for a 264-bit output.
//!
//! The external authority is the RFC 9861 §5 test-vector set, vendored under
//! `vectors/k12/` and checked by `cargo xtask verify`.

use crate::Hasher;
use digest::{ExtendableOutput, Update, XofReader};

/// KangarooTwelve with empty customization, in all three output variants.
pub struct K12 {
    inner: k12::CustomKt128,
    out_len: usize,
}

impl K12 {
    /// The 33-byte (264-bit) variant.
    pub fn new_264() -> Self {
        Self::with_len(33)
    }

    /// The 32-byte (256-bit) variant.
    pub fn new_256() -> Self {
        Self::with_len(32)
    }

    /// The 64-byte (512-bit) variant.
    pub fn new_512() -> Self {
        Self::with_len(64)
    }

    fn with_len(out_len: usize) -> Self {
        Self {
            inner: k12::CustomKt128::default(),
            out_len,
        }
    }
}

impl Hasher for K12 {
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let mut out = vec![0u8; self.out_len];
        self.inner.finalize_xof().read(&mut out);
        out
    }

    fn output_len(&self) -> usize {
        self.out_len
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn hex<H: Hasher + 'static>(mut h: H, data: &[u8]) -> String {
        h.update(data);
        Box::new(h)
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The `M = empty, C = empty` case from RFC 9861 §5. The 64-byte vector
    /// covers all three rows: the 32- and 33-byte outputs are prefixes of it,
    /// because KangarooTwelve is a XOF.
    #[test]
    fn rfc9861_empty_input() {
        assert_eq!(
            hex(K12::new_256(), b""),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
        );
        assert_eq!(
            hex(K12::new_264(), b""),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e542"
        );
        assert_eq!(
            hex(K12::new_512(), b""),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5\
             4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71"
                .replace(' ', "")
        );
    }

    /// The Sakura tree switches shape at exactly 8192 bytes of `S` (message
    /// plus one byte of `length_encode(0)` for the empty customization, so the
    /// input boundary sits at 8191). RFC 9861 §5 vectors for both sides.
    #[test]
    fn sakura_boundary_vectors() {
        let ptn = |n: usize| -> Vec<u8> { (0..n).map(|i| (i % 251) as u8).collect() };
        assert_eq!(
            hex(K12::new_256(), &ptn(8191)),
            "1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6"
        );
        assert_eq!(
            hex(K12::new_256(), &ptn(8192)),
            "48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3"
        );
    }

    /// The scanner feeds 2 MiB blocks; the digest must not depend on chunking.
    /// Cross the 8192-byte Sakura boundary many times.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..40_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let whole = hex(K12::new_256(), &data);

        let mut scanner_blocks = K12::new_256();
        for c in data.chunks(2 << 20) {
            scanner_blocks.update(c);
        }
        let mut odd_blocks = K12::new_256();
        for c in data.chunks(8193) {
            odd_blocks.update(c);
        }
        assert_eq!(whole, hex(scanner_blocks, b""));
        assert_eq!(whole, hex(odd_blocks, b""));
    }

    #[test]
    fn output_lengths_match_the_table() {
        assert_eq!(K12::new_264().output_len(), 33);
        assert_eq!(K12::new_256().output_len(), 32);
        assert_eq!(K12::new_512().output_len(), 64);
    }
}
