//! CRC32, CRC64 (XZ), XXH32, XXH64, XXH3-64, XXH3-128.
//!
//! # Crate choices that are easy to get wrong
//!
//! * **CRC64/XZ, not just any "CRC64".** The `crc64` crate implements the *Jones*
//!   polynomial and `crc64fast` implements *ECMA*; neither is the XZ variant used
//!   here. `crc` + `crc_catalog::CRC_64_XZ` is the correct one, and its check
//!   value for `"123456789"` is `0x995dc9bbdf1939fa`.
//! * **XXH3's 128-bit output** comes from `Xxh3::digest128()`. The 64-bit variant
//!   of the same streaming state is `Xxh3::digest()`, so one context type serves
//!   both table rows — the caller picks which accessor to call.

use crate::Hasher;
use std::sync::OnceLock;

/// CRC-32/ISO-HDLC, as used by zip/gzip and by SFV checksum files.
pub struct Crc32(crc32fast::Hasher);

impl Crc32 {
    /// A fresh context.
    pub fn new() -> Self {
        Self(crc32fast::Hasher::new())
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Crc32 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().to_be_bytes().to_vec()
    }

    fn output_len(&self) -> usize {
        4
    }
}

/// CRC-64/XZ.
///
/// The `crc` crate's `Digest` borrows its `Crc` table, so the table is built once
/// and promoted to `'static`. That is one small process-lifetime leak, created on
/// first use; the alternative is rebuilding a 16-entry table per context.
fn crc64_xz_table() -> &'static crc::Crc<u64, crc::Table<16>> {
    static TABLE: OnceLock<crc::Crc<u64, crc::Table<16>>> = OnceLock::new();
    TABLE.get_or_init(|| crc::Crc::<u64, crc::Table<16>>::new(&crc::CRC_64_XZ))
}

/// CRC-64/XZ, used by the `.xz` container format.
pub struct Crc64(crc::Digest<'static, u64, crc::Table<16>>);

impl Crc64 {
    /// A fresh context.
    pub fn new() -> Self {
        Self(crc64_xz_table().digest())
    }
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Crc64 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().to_be_bytes().to_vec()
    }

    fn output_len(&self) -> usize {
        8
    }
}

/// XXH32, a fast non-cryptographic 32-bit hash.
pub struct Xxh32(xxhash_rust::xxh32::Xxh32);

impl Xxh32 {
    /// A fresh context with seed 0.
    pub fn new() -> Self {
        Self(xxhash_rust::xxh32::Xxh32::new(0))
    }
}

impl Default for Xxh32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Xxh32 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.digest().to_be_bytes().to_vec()
    }

    fn output_len(&self) -> usize {
        4
    }
}

/// XXH64, a fast non-cryptographic 64-bit hash.
pub struct Xxh64(xxhash_rust::xxh64::Xxh64);

impl Xxh64 {
    /// A fresh context with seed 0.
    pub fn new() -> Self {
        Self(xxhash_rust::xxh64::Xxh64::new(0))
    }
}

impl Default for Xxh64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Xxh64 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.digest().to_be_bytes().to_vec()
    }

    fn output_len(&self) -> usize {
        8
    }
}

/// XXH3, in both the 64-bit and 128-bit output variants.
///
/// Which one you get is decided at [`Hasher::finalize`] time by `out_len`, because
/// the streaming state is identical for both.
pub struct Xxh3 {
    inner: xxhash_rust::xxh3::Xxh3,
    out_len: usize,
}

impl Xxh3 {
    /// The 64-bit variant.
    pub fn new_64() -> Self {
        Self {
            inner: xxhash_rust::xxh3::Xxh3::new(),
            out_len: 8,
        }
    }

    /// The 128-bit variant.
    pub fn new_128() -> Self {
        Self {
            inner: xxhash_rust::xxh3::Xxh3::new(),
            out_len: 16,
        }
    }
}

impl Hasher for Xxh3 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self: Box<Self>) -> Vec<u8> {
        if self.out_len == 8 {
            self.inner.digest().to_be_bytes().to_vec()
        } else {
            self.inner.digest128().to_be_bytes().to_vec()
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

    fn hex(v: Vec<u8>) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn run<H: Hasher + 'static>(mut h: H, data: &[u8]) -> String {
        h.update(data);
        hex(Box::new(h).finalize())
    }

    /// The standard CRC check value. `"123456789"` is the canonical input every
    /// CRC catalogue quotes.
    #[test]
    fn crc32_check_value() {
        assert_eq!(run(Crc32::new(), b"123456789"), "cbf43926");
    }

    /// CRC-64/XZ check value, matching `crc_catalog`'s own documented value.
    #[test]
    fn crc64_xz_check_value() {
        assert_eq!(run(Crc64::new(), b"123456789"), "995dc9bbdf1939fa");
    }

    /// xxHash's own published sanity values for the empty string.
    #[test]
    fn xxhash_empty_input() {
        // Seed 0, empty input.
        assert_eq!(run(Xxh32::new(), b""), "02cc5d05");
        assert_eq!(run(Xxh64::new(), b""), "ef46db3751d8e999");
        assert_eq!(run(Xxh3::new_64(), b""), "2d06800538d394c2");
    }

    /// XXH3-128 of the empty string. The 64-bit hash is the low half, which is
    /// why the two share a state.
    #[test]
    fn xxh3_128_empty_input() {
        let out = run(Xxh3::new_128(), b"");
        assert_eq!(out.len(), 32, "128-bit output is 16 bytes");
        assert_eq!(out, "99aa06d3014798d86001c324468d497f");
        assert!(out.ends_with("6001c324468d497f"));
    }

    #[test]
    fn output_lengths() {
        assert_eq!(Crc32::new().output_len(), 4);
        assert_eq!(Crc64::new().output_len(), 8);
        assert_eq!(Xxh32::new().output_len(), 4);
        assert_eq!(Xxh64::new().output_len(), 8);
        assert_eq!(Xxh3::new_64().output_len(), 8);
        assert_eq!(Xxh3::new_128().output_len(), 16);
    }
}
