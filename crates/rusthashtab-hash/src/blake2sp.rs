//! BLAKE2sp — the 8-way parallel variant of BLAKE2s.
//!
//! `blake2s_simd::blake2sp` is the only maintained crate offering `sp` (the
//! RustCrypto `blake2` crate has b/s/bp but not sp), and it already exposes a
//! streaming `State`, so the wrapper is thin. Input is striped across eight
//! BLAKE2s states in 64-byte blocks, which is why the tests walk stripe
//! boundaries as well as the scanner's 2 MiB blocks.
//!
//! The external authority is the BLAKE2 team's `blake2-kat.json` (the unkeyed
//! `blake2sp` entries), vendored under `vectors/blake2/` and checked by
//! `cargo xtask verify`.

use crate::Hasher;

/// BLAKE2sp, unkeyed, 32-byte output.
pub struct Blake2sp(blake2s_simd::blake2sp::State);

impl Blake2sp {
    /// A fresh context.
    pub fn new() -> Self {
        Self(blake2s_simd::blake2sp::State::new())
    }
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Blake2sp {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().as_bytes().to_vec()
    }

    fn output_len(&self) -> usize {
        32
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

    /// The unkeyed empty-input case from the BLAKE2 team's `blake2-kat.json`
    /// (the `hash == "blake2sp"`, `key == ""` entries).
    #[test]
    fn kat_empty_input() {
        assert_eq!(
            hex(Blake2sp::new(), b""),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
    }

    /// BLAKE2sp stripes 64-byte blocks across 8 parallel states: the stripe
    /// pattern changes at 64 and again at 512 bytes.
    #[test]
    fn stripe_boundaries_do_not_panic() {
        for n in [63usize, 64, 65, 127, 128, 129, 511, 512, 513] {
            let data = vec![0xA5u8; n];
            assert_eq!(hex(Blake2sp::new(), &data).len(), 64);
        }
    }

    /// The scanner feeds 2 MiB blocks; the digest must not depend on chunking.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..150_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let whole = hex(Blake2sp::new(), &data);

        let mut scanner_blocks = Blake2sp::new();
        for c in data.chunks(2 << 20) {
            scanner_blocks.update(c);
        }
        let mut odd_blocks = Blake2sp::new();
        for c in data.chunks(65) {
            odd_blocks.update(c);
        }
        assert_eq!(whole, hex(scanner_blocks, b""));
        assert_eq!(whole, hex(odd_blocks, b""));
    }
}
