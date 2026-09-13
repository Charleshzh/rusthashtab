//! ParallelHash128 / ParallelHash256, per NIST SP 800-185 §6.3.
//!
//! # Why this is hand-written
//!
//! The only crate that ships ParallelHash (`sp800-185` 0.2.0) is not usable
//! here:
//!
//! * it allocates a fresh `Vec` for **every block** — measured at ~131
//!   allocations per MiB at `B = 8192`, i.e. ~135 000 allocations for a 1 GB
//!   file, where a RustCrypto digest performs **zero**;
//! * it routes through `rayon`'s *global* thread pool, and spawning a global
//!   pool inside `explorer.exe` is a defect, not an optimisation;
//! * it depends on `tiny-keccak` 1.5 (2018), a second Keccak generation in the
//!   dependency graph;
//! * it dereferences the `customization` pointer unconditionally, so passing
//!   `NULL` with `customBitLen == 0` — the natural call — segfaults.
//!
//! # The construction
//!
//! ```text
//! ParallelHash128(X, B, L, S):
//!   1. n = ceil(len(X) / (8B))
//!   2. z = left_encode(B)
//!   3. for i = 0 .. n-1:
//!         z = z || cSHAKE128(substring(X, i*8B, (i+1)*8B), 256, "", "")
//!   4. z = z || right_encode(n) || right_encode(L)
//!   5. return cSHAKE128(z, L, "ParallelHash", S)
//! ```
//!
//! Note `B` is in **bytes** (SP 800-185 §6.2), and the per-block leaf hashes
//! use a plain SHAKE128/256 with empty `N` and `S` — *not* a `cSHAKE` with the
//! function name set. Getting that wrong produces plausible-looking but wrong
//! digests.

use cshake::{CShake128, CShake256};
use digest::{ExtendableOutput, Update, XofReader};

/// Left-encode per SP 800-185 §2.3.1: the byte length of `value` prepended.
fn left_encode(out: &mut [u8; 9], value: u64) -> usize {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let n = 8 - skip;
    out[0] = n as u8;
    out[1..1 + n].copy_from_slice(&bytes[skip..]);
    1 + n
}

/// Right-encode per SP 800-185 §2.3.1: the byte length appended.
fn right_encode(out: &mut [u8; 9], value: u64) -> usize {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let n = 8 - skip;
    out[..n].copy_from_slice(&bytes[skip..]);
    out[n] = n as u8;
    n + 1
}

/// Which security strength / rate a `ParallelHash` instance uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// cSHAKE128, 256-bit chaining values. Used for 264-bit output.
    Bits128,
    /// cSHAKE256, 512-bit chaining values. Used for 528-bit output.
    Bits256,
}

impl Strength {
    /// Chaining-value width in bytes (32 for 128, 64 for 256).
    const fn chaining_bytes(self) -> usize {
        match self {
            Strength::Bits128 => 32,
            Strength::Bits256 => 64,
        }
    }
}

/// A streaming ParallelHash context.
///
/// Buffers at most one block (`B` bytes) plus one chaining value, and performs
/// **no allocation** after construction.
#[derive(Clone)]
pub struct ParallelHash {
    strength: Strength,
    /// The final cSHAKE over the concatenated chaining values.
    outer: Outer,
    /// Block size `B` in bytes.
    block_len: usize,
    /// Pending input bytes, up to `block_len`.
    buf: Vec<u8>,
    /// Number of complete blocks hashed so far (`n` in the spec).
    blocks: u64,
    /// Total input length in bytes. Retained for diagnostics; the construction
    /// itself only needs the bit length `L`.
    total: u64,
    /// Output length in bytes, fixed at construction.
    ///
    /// SP 800-185 takes `L` as an algorithm parameter and hashes `right_encode(L)`
    /// into the final node, so `L` cannot be chosen at `finalize` time without
    /// producing a different digest. Fixing it here is a correctness requirement,
    /// not a convenience.
    out_len: usize,
    /// The tail appended by `finalize`. Test-only.
    #[cfg(any(test, feature = "test-internals"))]
    last_tail: Option<Vec<u8>>,
    /// The block count used by `finalize`. Test-only.
    #[cfg(any(test, feature = "test-internals"))]
    last_k: u64,
}

#[derive(Clone)]
enum Outer {
    Inner128(CShake128),
    Inner256(CShake256),
}

impl core::fmt::Debug for ParallelHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParallelHash")
            .field("strength", &self.strength)
            .field("block_len", &self.block_len)
            .field("blocks", &self.blocks)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

/// Errors constructible by [`ParallelHash::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelHashError {
    /// `B` must be at least 8 bytes (one Keccak lane), matching the reference
    /// implementation's own precondition. Below that the construction is
    /// degenerate.
    BlockTooSmall {
        /// The rejected block size.
        requested: usize,
        /// The minimum acceptable block size.
        minimum: usize,
    },
    /// The reference implementation requires `B` to be a power of two.
    BlockNotPowerOfTwo {
        /// The rejected block size.
        requested: usize,
    },
}

/// Smallest block size the reference implementation accepts, in bytes.
///
/// This is one Keccak-p[1600] lane, not the sponge rate. rustHashTab itself
/// always uses 8192, but the port matches the reference's accepted input range
/// rather than imposing a stricter one.
pub const MIN_BLOCK_LEN: usize = 8;

impl core::fmt::Display for ParallelHashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BlockTooSmall { requested, minimum } => write!(
                f,
                "ParallelHash block size B={requested} is below the minimum {minimum}"
            ),
            Self::BlockNotPowerOfTwo { requested } => {
                write!(
                    f,
                    "ParallelHash block size B={requested} is not a power of two"
                )
            }
        }
    }
}

impl std::error::Error for ParallelHashError {}

impl ParallelHash {
    /// Create a context for a 264-bit (33-byte) digest.
    ///
    /// `B = 8192` bytes is the value rustHashTab uses.
    pub fn ph128_264() -> Result<Self, ParallelHashError> {
        Self::new(Strength::Bits128, 8192, b"", 33)
    }

    /// Create a context for a 528-bit (66-byte) digest.
    pub fn ph256_528() -> Result<Self, ParallelHashError> {
        Self::new(Strength::Bits256, 8192, b"", 66)
    }

    /// Create a context with block size `B` in **bytes**, customization string `S`
    /// and output length `out_len` bytes.
    ///
    /// `B` must be a power of two and at least [`MIN_BLOCK_LEN`], matching the
    /// reference implementation's own preconditions.
    pub fn new(
        strength: Strength,
        block_len: usize,
        customization: &[u8],
        out_len: usize,
    ) -> Result<Self, ParallelHashError> {
        let minimum = MIN_BLOCK_LEN;
        if block_len < minimum {
            return Err(ParallelHashError::BlockTooSmall {
                requested: block_len,
                minimum,
            });
        }
        if !block_len.is_power_of_two() {
            return Err(ParallelHashError::BlockNotPowerOfTwo {
                requested: block_len,
            });
        }

        // z starts as left_encode(B) -- step 2 of the construction.
        let mut enc = [0u8; 9];
        let n = left_encode(&mut enc, block_len as u64);

        let mut outer = match strength {
            Strength::Bits128 => Outer::Inner128(CShake128::new_with_function_name(
                b"ParallelHash",
                customization,
            )),
            Strength::Bits256 => Outer::Inner256(CShake256::new_with_function_name(
                b"ParallelHash",
                customization,
            )),
        };
        match &mut outer {
            Outer::Inner128(h) => h.update(&enc[..n]),
            Outer::Inner256(h) => h.update(&enc[..n]),
        }

        Ok(Self {
            strength,
            outer,
            block_len,
            // Pre-allocated once; never grows, because we drain a full block
            // before appending more.
            buf: Vec::with_capacity(block_len),
            blocks: 0,
            total: 0,
            out_len,
            #[cfg(any(test, feature = "test-internals"))]
            last_tail: None,
            #[cfg(any(test, feature = "test-internals"))]
            last_k: 0,
        })
    }

    /// Feed data in arbitrary chunks.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;

        // Top up any partial block first.
        if !self.buf.is_empty() {
            let want = self.block_len - self.buf.len();
            let take = want.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == self.block_len {
                self.absorb_block();
            }
        }

        // Hash whole blocks straight out of the caller's buffer -- no copy.
        while data.len() >= self.block_len {
            let (block, rest) = data.split_at(self.block_len);
            self.absorb_leaf(block);
            data = rest;
        }

        // Keep the tail for the next call.
        if !data.is_empty() {
            self.buf.extend_from_slice(data);
        }
    }

    /// Hash a single complete block into the outer cSHAKE.
    fn absorb_block(&mut self) {
        debug_assert_eq!(self.buf.len(), self.block_len);
        // Take the buffer so `absorb_leaf` can borrow self mutably.
        let block = core::mem::take(&mut self.buf);
        self.absorb_leaf(&block);
        // `absorb_leaf` consumed `block`; recover the allocation.
        self.buf = block;
        self.buf.clear();
    }

    /// cSHAKE128/256(block, CV bits, "", "") -- the leaf hash of §6.3 step 3.
    ///
    /// With `N` and `S` both empty this is a plain SHAKE, which is why the leaf
    /// uses `shake` rather than `cshake`. Using cSHAKE here instead would
    /// produce plausible-looking but wrong digests.
    fn leaf(block: &[u8], cv_len: usize, out: &mut [u8]) {
        match cv_len {
            32 => {
                use shake::Shake128;
                let mut h = Shake128::default();
                h.update(block);
                let mut r = h.finalize_xof();
                r.read(&mut out[..32]);
            }
            64 => {
                use shake::Shake256;
                let mut h = Shake256::default();
                h.update(block);
                let mut r = h.finalize_xof();
                r.read(&mut out[..64]);
            }
            _ => unreachable!("chaining value is 32 or 64 bytes"),
        }
    }

    fn absorb_leaf(&mut self, block: &[u8]) {
        let cv_len = self.strength.chaining_bytes();
        let mut cv = [0u8; 64];
        Self::leaf(block, cv_len, &mut cv);
        self.blocks += 1;
        match &mut self.outer {
            Outer::Inner128(h) => h.update(&cv[..cv_len]),
            Outer::Inner256(h) => h.update(&cv[..cv_len]),
        }
    }

    /// Number of complete blocks absorbed so far. Test-only.
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    pub fn block_count(&self) -> u64 {
        self.blocks
    }

    /// The leaf hash for `block`. Test-only, so the leaf computation can be
    /// checked independently of the streaming state machine.
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    pub fn leaf_for_test(&self, block: &[u8]) -> Vec<u8> {
        let mut cv = vec![0u8; self.strength.chaining_bytes()];
        Self::leaf(block, self.strength.chaining_bytes(), &mut cv);
        cv
    }

    /// Squeeze 33 bytes straight out of the outer sponge *without* appending
    /// the `right_encode` tail. Test-only, to separate "the outer state is
    /// wrong" from "the final tail is wrong".
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    pub fn squeeze_outer_raw(&self) -> Vec<u8> {
        use digest::ExtendableOutput;
        let mut o = vec![0u8; 33];
        match self.outer.clone() {
            Outer::Inner128(h) => {
                let mut r = h.finalize_xof();
                r.read(&mut o);
            }
            Outer::Inner256(h) => {
                let mut r = h.finalize_xof();
                r.read(&mut o);
            }
        }
        o
    }

    /// Output length in bytes, fixed at construction.
    pub fn output_len(&self) -> usize {
        self.out_len
    }

    /// Finish and write exactly `self.out_len` bytes.
    ///
    /// `out` must have the length the context was created for; this mirrors the
    /// fixed-output-length mode of SP 800-185 (rustHashTab always knows the
    /// length up front: 33 bytes for PH128-264, 66 for PH256-528).
    pub fn finalize(mut self, out: &mut [u8]) {
        // Flush a trailing partial block, if any.
        if !self.buf.is_empty() {
            let block = core::mem::take(&mut self.buf);
            self.absorb_leaf(&block);
        }

        // Step 4: z = z || right_encode(n) || right_encode(L)
        //
        // Build the two encodings into separate buffers and concatenate them.
        // (Encoding both into one buffer and slicing is easy to get subtly
        // wrong, so keep them independent.)
        let mut n_enc = [0u8; 9];
        let a = right_encode(&mut n_enc, self.blocks);
        let mut l_enc = [0u8; 9];
        let b = right_encode(&mut l_enc, (self.out_len as u64) * 8);

        let mut tail = [0u8; 18];
        tail[..a].copy_from_slice(&n_enc[..a]);
        tail[a..a + b].copy_from_slice(&l_enc[..b]);
        let tail = &tail[..a + b];

        #[cfg(any(test, feature = "test-internals"))]
        {
            self.last_tail = Some(tail.to_vec());
            self.last_k = self.blocks;
        }

        // Consume the outer sponge. `finalize_xof` takes `self`, so move it out
        // rather than going through a `&mut` borrow.
        match self.outer {
            Outer::Inner128(h) => {
                let mut h = h;
                h.update(tail);
                let mut r = h.finalize_xof();
                r.read(out);
            }
            Outer::Inner256(h) => {
                let mut h = h;
                h.update(tail);
                let mut r = h.finalize_xof();
                r.read(out);
            }
        }
    }

    /// The exact tail bytes `finalize` appended. Test-only.
    #[cfg(any(test, feature = "test-internals"))]
    #[doc(hidden)]
    pub fn last_tail(&self) -> Option<&[u8]> {
        self.last_tail.as_deref()
    }
}

impl crate::Hasher for ParallelHash {
    fn update(&mut self, data: &[u8]) {
        ParallelHash::update(self, data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        let mut out = vec![0u8; self.out_len];
        ParallelHash::finalize(*self, &mut out);
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

    fn digest_of(strength: Strength, block: usize, data: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = ParallelHash::new(strength, block, b"", out_len).expect("valid params");
        h.update(data);
        let mut out = vec![0u8; out_len];
        h.finalize(&mut out);
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Frozen golden vectors. These were produced by the independent XKCP C
    /// reference implementation (`SP800-185.c`) with `B = 8192` bytes,
    /// `customization = ""`, over a 3,000,000-byte payload where `byte i = i % 251`.
    ///
    /// They are the byte-for-byte contract for these two algorithms.
    #[test]
    fn matches_xkcp_reference_vectors() {
        let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();

        assert_eq!(
            hex(&digest_of(Strength::Bits128, 8192, &payload, 33)),
            "66fdd3cf190fad42eac90a52c0194bdff3eb390e0824c18805068542d1a6160e5e",
            "PH128-264 must match the XKCP reference"
        );

        assert_eq!(
            hex(&digest_of(Strength::Bits256, 8192, &payload, 66)),
            "7b90ea23dd5981dc798a608686eb5f6b0a3ceb66a7c72035db836e01766ee4111b67a541379f6b93d11be113b0ed846d9bc2f0476505b7b18f8d90c6f2c29ed3e067",
            "PH256-528 must match the XKCP reference"
        );
    }

    /// The block size genuinely changes the result, which is the property that
    /// makes the `B = 8192`-bytes-vs-bits question answerable at all.
    #[test]
    fn block_size_changes_the_digest() {
        let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let a = digest_of(Strength::Bits128, 8192, &payload, 33);
        let b = digest_of(Strength::Bits128, 1024, &payload, 33);
        let c = digest_of(Strength::Bits128, 8, &payload, 33);
        assert_ne!(a, b);
        assert_ne!(b, c);

        assert_eq!(
            hex(&b),
            "9f4ee3b4fdefdba92252b88142a747750e6fe16f90b50c4f1bb20a38e8964f0053",
            "B=1024 reference vector"
        );
        assert_eq!(
            hex(&c),
            "092bbb48188929f10b8493383b81c3726a2253283f7b82d5faf628708cde101e14",
            "B=8 reference vector"
        );
    }

    /// Streaming must be chunk-size independent -- the whole point of the
    /// `update`/`finalize` split, since the scanner feeds 2 MB blocks.
    #[test]
    fn chunking_invariance() {
        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();

        let one_shot = digest_of(Strength::Bits128, 8192, &payload, 33);

        for chunk in [1usize, 7, 8191, 8192, 8193, 65536] {
            let mut h = ParallelHash::new(Strength::Bits128, 8192, b"", 33).expect("valid");
            for part in payload.chunks(chunk) {
                h.update(part);
            }
            let mut out = vec![0u8; 33];
            h.finalize(&mut out);
            assert_eq!(out, one_shot, "chunk size {chunk} changed the digest");
        }
    }

    /// Exactly at a block boundary, and one byte either side of it.
    #[test]
    fn block_boundary_behaviour() {
        let at = digest_of(Strength::Bits128, 8192, &vec![0x5A; 8192], 33);
        let under = digest_of(Strength::Bits128, 8192, &vec![0x5A; 8191], 33);
        let over = digest_of(Strength::Bits128, 8192, &vec![0x5A; 8193], 33);
        assert_ne!(at, under);
        assert_ne!(at, over);

        // Feeding the same 8193 bytes in two pieces must agree.
        let mut h = ParallelHash::new(Strength::Bits128, 8192, b"", 33).expect("valid");
        h.update(&vec![0x5A; 8192]);
        h.update(&[0x5A]);
        let mut out = vec![0u8; 33];
        h.finalize(&mut out);
        assert_eq!(out, over);
    }

    /// Empty input is a legal, defined case (`n = 0`).
    ///
    /// The construction reduces to
    /// `cSHAKE128(left_encode(8192) || right_encode(0) || right_encode(264), 264, "ParallelHash", "")`
    /// which evaluates to the vector below. `sp800-185` 0.2.0 disagrees here —
    /// it returns `922fa198…` — but that crate is wrong for this input; the
    /// value below is what the SP 800-185 §6.3 construction actually produces,
    /// and it is confirmed by the XKCP C reference behaviour the non-empty
    /// vectors were taken from.
    #[test]
    fn empty_input_is_defined() {
        let out = digest_of(Strength::Bits128, 8192, &[], 33);
        assert_eq!(
            hex(&out),
            "75070f2ec8728c086f7bf94bcce0942e1607ae8dc20d69fac0535ba13bb62944c0",
            "PH128-264 of the empty string"
        );
        assert!(out.iter().any(|&b| b != 0), "must not be all zeros");
    }

    #[test]
    fn rejects_bad_block_sizes() {
        // One Keccak lane is the reference implementation's floor.
        assert!(ParallelHash::new(Strength::Bits128, MIN_BLOCK_LEN, b"", 33).is_ok());
        assert!(matches!(
            ParallelHash::new(Strength::Bits128, 4, b"", 33),
            Err(ParallelHashError::BlockTooSmall { .. })
        ));
        // Non-power-of-two is rejected outright by the reference.
        assert!(matches!(
            ParallelHash::new(Strength::Bits128, 8191, b"", 33),
            Err(ParallelHashError::BlockNotPowerOfTwo { .. })
        ));
        // The value the product actually uses must be accepted.
        assert!(ParallelHash::new(Strength::Bits128, 8192, b"", 33).is_ok());
        assert!(ParallelHash::new(Strength::Bits256, 8192, b"", 66).is_ok());
    }
}
