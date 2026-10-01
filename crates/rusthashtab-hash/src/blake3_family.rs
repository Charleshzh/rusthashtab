//! BLAKE3, in the 32-byte and 64-byte output variants.
//!
//! BLAKE3 is an XOF: one streaming state serves both table rows, decided at
//! [`Hasher::finalize`] time by `out_len`, exactly like [`crate::checksums::Xxh3`].
//! The 64-byte variant reads the extended output stream rather than truncating
//! and re-hashing — truncating a 32-byte digest is *not* the same value.
//!
//! # Threading
//!
//! The `blake3` crate's parallel APIs (`update_rayon`, the `rayon` cargo
//! feature) are **off** and must stay off: a shell extension does not get to
//! join a global thread pool. `Hasher::update` is single-threaded. The
//! dependency declaration pins this with a comment; do not "helpfully" enable
//! the feature for speed.
//!
//! The external authority is BLAKE3's official `test_vectors.json`, vendored
//! under `vectors/blake3/` and checked by `cargo xtask verify`.

use crate::Hasher;

/// BLAKE3, unkeyed, in both output-length variants.
pub struct Blake3 {
    inner: blake3::Hasher,
    out_len: usize,
}

impl Blake3 {
    /// The default 32-byte variant.
    pub fn new_256() -> Self {
        Self {
            inner: blake3::Hasher::new(),
            out_len: 32,
        }
    }

    /// The 64-byte extended-output variant.
    pub fn new_512() -> Self {
        Self {
            inner: blake3::Hasher::new(),
            out_len: 64,
        }
    }
}

impl Hasher for Blake3 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        if self.out_len == 32 {
            self.inner.finalize().as_bytes().to_vec()
        } else {
            let mut out = vec![0u8; self.out_len];
            self.inner.finalize_xof().fill(&mut out);
            out
        }
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

    /// The `input_len = 0` case from the official `test_vectors.json`
    /// (BLAKE3-team/BLAKE3, `test_vectors/`). The 64-byte value is the first
    /// half of that case's 131-byte extended output.
    #[test]
    fn official_empty_input_vector() {
        assert_eq!(
            hex(Blake3::new_256(), b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex(Blake3::new_512(), b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\
             e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
                .replace(' ', "")
        );
    }

    /// BLAKE3 chunks internally at 1024 bytes; the tree fan-out changes shape
    /// at 1024 and again at every power-of-two multiple of it.
    #[test]
    fn chunk_boundaries_do_not_panic() {
        for n in [1023usize, 1024, 1025, 2048, 2049, 3072, 3073] {
            let data = vec![0xA5u8; n];
            assert_eq!(hex(Blake3::new_256(), &data).len(), 64);
            assert_eq!(hex(Blake3::new_512(), &data).len(), 128);
        }
    }

    /// The scanner feeds 2 MiB blocks; the digest must not depend on chunking.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..600_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let whole = hex(Blake3::new_256(), &data);

        let mut scanner_blocks = Blake3::new_256();
        for c in data.chunks(2 << 20) {
            scanner_blocks.update(c);
        }
        let mut odd_blocks = Blake3::new_256();
        for c in data.chunks(1027) {
            odd_blocks.update(c);
        }
        assert_eq!(whole, hex(scanner_blocks, b""));
        assert_eq!(whole, hex(odd_blocks, b""));
    }

    #[test]
    fn output_lengths_match_the_table() {
        assert_eq!(Blake3::new_256().output_len(), 32);
        assert_eq!(Blake3::new_512().output_len(), 64);
    }
}
