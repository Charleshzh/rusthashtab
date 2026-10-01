//! SHA3-224, SHA3-256, SHA3-384, SHA3-512 (FIPS 202).
//!
//! All four are `sha3` crate types implementing the `digest` traits, so they
//! share the same [`digest_hasher!`] adapter as the SHA-2 family. What differs
//! from SHA-2 is the padding boundary: Keccak absorbs at a *rate* (144, 136,
//! 104 or 72 bytes respectively) rather than a 64-byte block, which is why the
//! boundary tests below walk each rate ±1.
//!
//! The external authority for this family is OpenSSL (`openssl dgst -sha3-*`),
//! exercised by `cargo xtask verify`; the frozen constants in the tests are
//! regression values only.

use crate::Hasher;
use crate::digest_adapter::digest_hasher;
use digest::Digest;

digest_hasher!(Sha3_224, sha3::Sha3_224, 28, "SHA3-224 (FIPS 202).");
digest_hasher!(Sha3_256, sha3::Sha3_256, 32, "SHA3-256 (FIPS 202).");
digest_hasher!(Sha3_384, sha3::Sha3_384, 48, "SHA3-384 (FIPS 202).");
digest_hasher!(Sha3_512, sha3::Sha3_512, 64, "SHA3-512 (FIPS 202).");

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

    /// Empty-input and `"abc"` digests, matching FIPS 202 as printed by every
    /// independent implementation (here: cross-checked against
    /// `openssl dgst -sha3-*` before freezing).
    #[test]
    fn fips202_vectors() {
        assert_eq!(
            hex(Sha3_224::new(), b""),
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        );
        assert_eq!(
            hex(Sha3_224::new(), b"abc"),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            hex(Sha3_256::new(), b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(Sha3_256::new(), b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(Sha3_384::new(), b""),
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3\
             713831264adb47fb6bd1e058d5f004"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Sha3_384::new(), b"abc"),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
             98d88cea927ac7f539f1edf228376d25"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Sha3_512::new(), b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Sha3_512::new(), b"abc"),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
                .replace(' ', "")
        );
    }

    /// Keccak absorbs at the rate, not at a 64-byte block: 144/136/104/72
    /// bytes for 224/256/384/512. Padding bugs live one byte either side.
    #[test]
    fn rate_boundaries_do_not_panic() {
        for n in [143usize, 144, 145, 135, 136, 137, 103, 104, 105, 71, 72, 73] {
            let data = vec![0xA5u8; n];
            assert_eq!(hex(Sha3_224::new(), &data).len(), 56);
            assert_eq!(hex(Sha3_256::new(), &data).len(), 64);
            assert_eq!(hex(Sha3_384::new(), &data).len(), 96);
            assert_eq!(hex(Sha3_512::new(), &data).len(), 128);
        }
    }

    /// The scanner feeds 2 MiB blocks; the digest must not depend on chunking.
    #[test]
    fn chunking_invariance() {
        // Keccak rates are ≤ 144 bytes, so a few KiB already crosses every
        // internal boundary repeatedly; no need for a full 2 MiB here.
        let data: Vec<u8> = (0..100_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let whole = hex(Sha3_256::new(), &data);

        let mut chunked = Sha3_256::new();
        for c in data.chunks(2 << 20) {
            chunked.update(c);
        }
        let mut chunks_of_137 = Sha3_256::new(); // deliberately odd, crosses rates
        for c in data.chunks(137) {
            chunks_of_137.update(c);
        }
        assert_eq!(whole, hex(chunked, b""));
        assert_eq!(whole, hex(chunks_of_137, b""));
    }

    #[test]
    fn output_lengths_match_the_table() {
        assert_eq!(Sha3_224::new().output_len(), 28);
        assert_eq!(Sha3_256::new().output_len(), 32);
        assert_eq!(Sha3_384::new().output_len(), 48);
        assert_eq!(Sha3_512::new().output_len(), 64);
    }
}
