//! Differential test: our hand-written eD2k tree against the `ed2k` crate
//! (dev-dependency oracle), across the chunk boundary where the two flavours
//! diverge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// The oracle crate pins digest 0.10; use its own re-export, not our 0.11.
use ed2k::digest::Digest;
use rusthashtab_hash::Hasher;
use rusthashtab_hash::ed2k::CHUNK_SIZE;

/// Deterministic payload, so a failure is reproducible from the size alone.
fn payload(n: usize) -> Vec<u8> {
    let mut state: u64 = 0x243F_6A88_85A3_08D3;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn ours(flavour: rusthashtab_hash::ed2k::Flavour, data: &[u8]) -> Vec<u8> {
    let mut h = rusthashtab_hash::ed2k::Ed2k::new(flavour);
    // Feed in awkward pieces on purpose: the boundary logic must not depend on
    // how the input is chunked.
    for c in data.chunks(65_537) {
        h.update(c);
    }
    Box::new(h).finalize()
}

#[test]
fn blue_matches_oracle_across_chunk_boundaries() {
    let cs = CHUNK_SIZE;
    for n in [
        0,
        1,
        1024,
        cs - 1,
        cs,
        cs + 1,
        2 * cs,
        2 * cs + 1,
        3 * cs - 17,
    ] {
        let data = payload(n);
        let expected = ed2k::Ed2kBlue::digest(&data);
        assert_eq!(
            ours(rusthashtab_hash::ed2k::Flavour::Blue, &data),
            expected.as_slice(),
            "blue mismatch at {n} bytes"
        );
    }
}

#[test]
fn red_matches_oracle_across_chunk_boundaries() {
    let cs = CHUNK_SIZE;
    for n in [
        0,
        1,
        1024,
        cs - 1,
        cs,
        cs + 1,
        2 * cs,
        2 * cs + 1,
        3 * cs - 17,
    ] {
        let data = payload(n);
        let expected = ed2k::Ed2kRed::digest(&data);
        assert_eq!(
            ours(rusthashtab_hash::ed2k::Flavour::Red, &data),
            expected.as_slice(),
            "red mismatch at {n} bytes"
        );
    }
}
