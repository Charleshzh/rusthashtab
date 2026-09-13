#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Differential test: the hand-written ParallelHash against an independent
//! implementation.
//!
//! `sp800-185` is used here **only** as a test oracle. It is functionally
//! correct for non-empty input (its output was itself verified byte-for-byte
//! against XKCP's C reference), but it allocates per block and drives rayon's
//! global thread pool, so it must never become a runtime dependency of the
//! shell extension.
//!
//! Keeping the oracle in a dev-dependency means a release build of the product
//! cannot accidentally pull it in.
//!
//! # Known oracle divergence
//!
//! `sp800-185` 0.2.0 is wrong for **empty input**: it returns `922fa198…` where
//! the SP 800-185 §6.3 construction gives `75070f2e…`. Our implementation
//! follows the construction, and that value is pinned as a reference vector in
//! `src/parallel_hash.rs`. The empty case is therefore excluded here and
//! covered there instead.

use rusthashtab_hash::parallel_hash::{ParallelHash, Strength};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn ours(data: &[u8], block: usize) -> Vec<u8> {
    let mut h = ParallelHash::new(Strength::Bits128, block, b"", 33).expect("valid params");
    h.update(data);
    let mut o = vec![0u8; 33];
    h.finalize(&mut o);
    o
}

fn oracle(data: &[u8], block: usize) -> Vec<u8> {
    let mut p = sp800_185::ParallelHash::new_parallelhash128(b"", block);
    p.update(data);
    let mut o = vec![0u8; 33];
    p.finalize(&mut o);
    o
}

/// Sizes chosen to straddle the 8192-byte block boundary in every relevant way.
#[test]
fn matches_oracle_across_block_boundaries() {
    for n in [
        1usize, 100, 8191, 8192, 8193, 16383, 16384, 16385, 100_000, 1_000_000,
    ] {
        let data = payload(n);
        assert_eq!(
            hex(&ours(&data, 8192)),
            hex(&oracle(&data, 8192)),
            "PH128-264 diverged from the oracle at n = {n}"
        );
    }
}

/// The same comparison at other block sizes, to catch anything that only shows
/// up when a block boundary lands differently. Block sizes must be powers of two.
#[test]
fn matches_oracle_at_other_block_sizes() {
    for block in [8usize, 16, 256, 1024, 4096] {
        for n in [1usize, 7, 8, 9, 255, 256, 257, 1023, 1024, 1025, 50_000] {
            let data = payload(n);
            assert_eq!(
                hex(&ours(&data, block)),
                hex(&oracle(&data, block)),
                "PH128-264 diverged at B = {block}, n = {n}"
            );
        }
    }
}
