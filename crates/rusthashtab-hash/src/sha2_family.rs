//! MD4, MD5, RIPEMD-160, SHA-1, SHA-2.
//!
//! All six are RustCrypto crates implementing the `digest` traits. They share one
//! adapter, because the only differences are the digest length and which algorithm
//! tag they report to OpenSSL.
//!
//! # MD4
//!
//! MD4 is **not** verifiable through OpenSSL 3.x's default provider — it moved to
//! the `legacy` provider, which is often not installed (that is the case on the
//! machine this was developed on). Its authority is therefore the RFC 1320 test
//! suite.
//!
//! # Why `md-5`, not `md5`
//!
//! The RustCrypto crate is published as `md-5`; the bare `md5` name on crates.io is
//! a different, unrelated crate.

use crate::Hasher;
use digest::Digest;

/// Wrap any `digest::Digest` as a [`Hasher`].
///
/// `out_len` is passed explicitly rather than read from the type because the size
/// is needed by the scanner before a context exists.
macro_rules! digest_hasher {
    ($wrapper:ident, $inner:ty, $out_len:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $wrapper($inner);

        impl $wrapper {
            /// A fresh context.
            pub fn new() -> Self {
                Self(<$inner as Default>::default())
            }
        }

        impl Default for $wrapper {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Hasher for $wrapper {
            fn update(&mut self, data: &[u8]) {
                Digest::update(&mut self.0, data);
            }

            fn finalize(self: Box<Self>) -> Vec<u8> {
                self.0.finalize().to_vec()
            }

            fn output_len(&self) -> usize {
                $out_len
            }
        }
    };
}

digest_hasher!(
    Md4,
    md4::Md4,
    16,
    "MD4 (RFC 1320). Cryptographically broken; provided for compatibility with old checksum files."
);
digest_hasher!(
    Md5,
    md5::Md5,
    16,
    "MD5 (RFC 1321). Cryptographically broken; still the most widely published digest."
);
digest_hasher!(
    RipeMd160,
    ripemd::Ripemd160,
    20,
    "RIPEMD-160. Used by Bitcoin and by several European standards."
);
digest_hasher!(
    Sha1,
    sha1::Sha1,
    20,
    "SHA-1 (FIPS 180-4). Collision-broken; still widely published."
);
digest_hasher!(Sha224, sha2::Sha224, 28, "SHA-224 (FIPS 180-4).");
digest_hasher!(Sha256, sha2::Sha256, 32, "SHA-256 (FIPS 180-4).");
digest_hasher!(Sha384, sha2::Sha384, 48, "SHA-384 (FIPS 180-4).");
digest_hasher!(Sha512, sha2::Sha512, 64, "SHA-512 (FIPS 180-4).");

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

    /// Published empty-input vectors. These are the values printed in the
    /// respective documents and by every independent implementation.
    #[test]
    fn empty_input_vectors() {
        assert_eq!(hex(Md4::new(), b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(Md5::new(), b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(RipeMd160::new(), b""),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex(Sha1::new(), b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(Sha224::new(), b""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            hex(Sha256::new(), b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(Sha384::new(), b""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
                .replace(' ', "")
        );
        assert_eq!(
            hex(Sha512::new(), b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                .replace(' ', "")
        );
    }

    /// RFC 1320/1321's canonical `"abc"` vectors.
    #[test]
    fn abc_vectors() {
        assert_eq!(hex(Md4::new(), b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(hex(Md5::new(), b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(Sha1::new(), b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(Sha256::new(), b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Padding boundaries: SHA-2's 64-byte block is where length-extension padding
    /// bugs show up.
    #[test]
    fn block_boundary_lengths_do_not_panic() {
        for n in [55usize, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129] {
            let data = vec![0xA5u8; n];
            assert_eq!(hex(Sha256::new(), &data).len(), 64);
            assert_eq!(hex(Sha512::new(), &data).len(), 128);
            assert_eq!(hex(Md5::new(), &data).len(), 32);
        }
    }

    #[test]
    fn output_lengths_match_the_table() {
        assert_eq!(Md4::new().output_len(), 16);
        assert_eq!(Md5::new().output_len(), 16);
        assert_eq!(RipeMd160::new().output_len(), 20);
        assert_eq!(Sha1::new().output_len(), 20);
        assert_eq!(Sha224::new().output_len(), 28);
        assert_eq!(Sha256::new().output_len(), 32);
        assert_eq!(Sha384::new().output_len(), 48);
        assert_eq!(Sha512::new().output_len(), 64);
    }
}
