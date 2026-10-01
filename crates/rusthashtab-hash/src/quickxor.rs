//! QuickXorHash (Microsoft's 160-bit non-cryptographic file hash).
//!
//! # Why this is hand-written
//!
//! The `quickxorhash` crate was the original wrapper target, but it stores the
//! input length in a **`usize`** and XORs its little-endian bytes into the
//! tail of the digest. Microsoft's reference is explicit that the length is a
//! fixed **8-byte** little-endian value ("The expected value is 8-bytes in
//! length in little-endian format"), so on 32-bit targets the crate produces
//! digests that match no OneDrive service — a bug our i686 test run caught.
//! The algorithm is small, so this module implements it from Microsoft's
//! published reference implementation:
//!
//! * input byte `i` is XORed into a 160-bit accumulator at bit offset
//!   `(11 · i) mod 160` (the circular-shift construction);
//! * the digest is the 20 accumulator bytes, with the input length XORed as
//!   **u64** little-endian into the last 8 bytes.
//!
//! The external authority is rclone's published test-vector set (an
//! independent Go implementation of the same algorithm), vendored under
//! `vectors/quickxorhash/` and checked by `cargo xtask verify` — on every
//! supported target, including 32-bit.

use crate::Hasher;

/// Accumulator width in bits (and the shift cycle's modulus).
const WIDTH_BITS: usize = 160;
/// Accumulator width in bytes.
const WIDTH_BYTES: usize = WIDTH_BITS / 8;
/// Per-byte rotation, from Microsoft's documentation.
const SHIFT: usize = 11;

/// QuickXorHash, 20-byte output.
pub struct QuickXor {
    /// The 160-bit accumulator, little-endian byte order (byte 0 holds bits
    /// 0–7), matching Microsoft's `ulong[3]` layout.
    block: [u8; WIDTH_BYTES],
    /// Bit offset of the next input byte: `(11 · i) mod 160` for input index
    /// `i`, maintained incrementally.
    shift: usize,
    /// Total input length. **`u64`, per Microsoft's reference** — this is
    /// where the `quickxorhash` crate goes wrong on 32-bit.
    len: u64,
}

impl QuickXor {
    /// A fresh context.
    pub fn new() -> Self {
        Self {
            block: [0; WIDTH_BYTES],
            shift: 0,
            len: 0,
        }
    }
}

impl Default for QuickXor {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for QuickXor {
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            let byte = self.shift / 8;
            let bits = self.shift % 8;
            self.block[byte] ^= b << bits;
            if bits != 0 {
                // The XOR spans into the next byte, wrapping at 160 bits.
                self.block[(byte + 1) % WIDTH_BYTES] ^= b >> (8 - bits);
            }
            self.shift = (self.shift + SHIFT) % WIDTH_BITS;
        }
        self.len = self.len.wrapping_add(data.len() as u64);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let mut out = self.block;
        // Fixed 8-byte little-endian length in the tail, per the reference.
        for (i, b) in self.len.to_le_bytes().iter().enumerate() {
            out[WIDTH_BYTES - 8 + i] ^= b;
        }
        out.to_vec()
    }

    fn output_len(&self) -> usize {
        WIDTH_BYTES
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

    /// rclone's published vectors for size 0 and 1 (base64 decoded to hex
    /// here): the empty input is 20 zero bytes; one input byte sits at bit
    /// offset 0, and the 64-bit length reaches its first byte at offset 12.
    /// The size-1 case is the one that exposes a `usize` length on 32-bit.
    #[test]
    fn rclone_size0_and_size1() {
        assert_eq!(
            hex(QuickXor::new(), b""),
            "0000000000000000000000000000000000000000"
        );
        assert_eq!(
            hex(QuickXor::new(), &[0x4a]),
            "4a00000000000000000000000100000000000000"
        );
    }

    /// The XOR spans the accumulator's end when the bit offset passes byte
    /// 19 — exercise a full 160-byte shift cycle and beyond, in arbitrary
    /// pieces including the scanner's 2 MiB blocks.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let whole = hex(QuickXor::new(), &data);

        for piece in [1usize, 160, 161, 2 << 20] {
            let mut h = QuickXor::new();
            for c in data.chunks(piece) {
                h.update(c);
            }
            assert_eq!(whole, hex(h, b""), "piece size {piece}");
        }
    }

    #[test]
    fn output_length_matches_the_table() {
        assert_eq!(QuickXor::new().output_len(), 20);
    }
}
