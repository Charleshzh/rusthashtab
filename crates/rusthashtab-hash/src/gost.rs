//! GOST R 34.11-2012 ("Streebog"), 256-bit and 512-bit.
//!
//! Both widths are `streebog` crate types implementing the `digest` traits, so
//! they share the [`digest_hasher!`] adapter. Streebog absorbs in 64-byte
//! blocks; the tests walk that boundary and the scanner's 2 MiB blocks.
//!
//! # Byte order — read before "fixing" anything
//!
//! There are two display conventions for a Streebog digest, and they are byte
//! reverses of each other:
//!
//! * **RFC 6986 §10** prints `H(M1) = 486f64c1…` — the standards document's
//!   convention.
//! * **The tool ecosystem** — gost-engine (the reference implementation), its
//!   etalon `dgst.result`, `gost12sum`, and every checksum file a user will
//!   paste into this app — prints the reverse, `1b54d01a…`.
//!
//! This crate emits the **tool-ecosystem order**, i.e. exactly what the
//! `streebog` crate's `finalize()` returns. Users compare against checksum
//! files produced by tools, not against the RFC's typesetting. The external
//! authority is gost-engine's etalon suite, vendored under `vectors/gost/` and
//! checked by `cargo xtask verify`.

use crate::Hasher;
use crate::digest_adapter::digest_hasher;
use digest::Digest;

digest_hasher!(
    Gost256,
    streebog::Streebog256,
    32,
    "GOST R 34.11-2012 (Streebog), 256-bit output."
);
digest_hasher!(
    Gost512,
    streebog::Streebog512,
    64,
    "GOST R 34.11-2012 (Streebog), 512-bit output."
);

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

    /// The M1 (63-byte ASCII) and M2 (72-byte) cases from gost-engine's
    /// etalon `dgst.result` — the reference implementation's expected outputs,
    /// in the byte order the tool ecosystem prints. RFC 6986 §10 shows the
    /// same digests byte-reversed; see the module docs.
    #[test]
    fn gost_engine_etalon_m1_m2() {
        let m1: &[u8] = b"012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(m1.len(), 63);
        assert_eq!(
            hex(Gost512::new(), m1),
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00\
             ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Gost256::new(), m1),
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        );

        // M2 in input order (RFC 6986 prints the byte-reversed form).
        let m2 = hex::decode(
            "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa\
             20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfa\
             eafb20c8e3eef0e5e2fb"
                .replace(' ', ""),
        )
        .expect("M2 hex");
        assert_eq!(m2.len(), 72);
        assert_eq!(
            hex(Gost512::new(), &m2),
            "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376\
             035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Gost256::new(), &m2),
            "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50"
        );
    }

    /// Streebog absorbs 64-byte blocks.
    #[test]
    fn block_boundaries_do_not_panic() {
        for n in [63usize, 64, 65, 127, 128, 129] {
            let data = vec![0xA5u8; n];
            assert_eq!(hex(Gost256::new(), &data).len(), 64);
            assert_eq!(hex(Gost512::new(), &data).len(), 128);
        }
    }

    /// The scanner feeds 2 MiB blocks; the digest must not depend on chunking.
    #[test]
    fn chunking_invariance() {
        let data: Vec<u8> = (0..80_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let whole = hex(Gost512::new(), &data);

        let mut scanner_blocks = Gost512::new();
        for c in data.chunks(2 << 20) {
            scanner_blocks.update(c);
        }
        let mut odd_blocks = Gost512::new();
        for c in data.chunks(65) {
            odd_blocks.update(c);
        }
        assert_eq!(whole, hex(scanner_blocks, b""));
        assert_eq!(whole, hex(odd_blocks, b""));
    }

    #[test]
    fn output_lengths_match_the_table() {
        assert_eq!(Gost256::new().output_len(), 32);
        assert_eq!(Gost512::new().output_len(), 64);
    }
}
