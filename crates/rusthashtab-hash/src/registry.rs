//! The algorithm table: static metadata plus a way to build a context.
//!
//! This is the Rust counterpart of the C++ `LegacyHashAlgorithm` table, but with
//! one deliberate difference: there are no function pointers or
//! `ctx_size`/`ctx_align` fields. Building a context is a match, and the context
//! lives behind `Box<dyn Hasher>`.
//!
//! # Adding an algorithm
//!
//! 1. Add a row to [`ALGORITHMS`] with the exact digest length.
//! 2. Add a match arm to [`make`].
//! 3. Add the corresponding entry to `xtask`'s coverage map, naming the external
//!    authority that will check it.
//! 4. Add a reference-vector test.
//!
//! Step 3 is not optional. A digest with no independent authority attached cannot
//! be distinguished from a plausible-looking wrong one.

use crate::Hasher;
use crate::checksums::{Crc32, Crc64, Xxh3, Xxh32, Xxh64};
use crate::sha2_family::{Md4, Md5, RipeMd160, Sha1, Sha224, Sha256, Sha384, Sha512};
use crate::sha3_family::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

/// Static description of one supported algorithm.
#[derive(Debug, Clone, Copy)]
pub struct Algorithm {
    /// Display name, e.g. `"SHA-256"` or `"K12-264"`.
    pub name: &'static str,
    /// Digest length in bytes.
    pub output_len: usize,
    /// Whether the algorithm is cryptographically secure.
    ///
    /// Lets a strong match outrank a weak one when several algorithms match the
    /// same expected digest. CRC32 and MD5 are not secure; SHA-256 is.
    pub secure: bool,
    /// File extensions used for checksum-file auto-detection, without the leading
    /// dot. Empty means "no associated extension".
    pub extensions: &'static [&'static str],
}

impl Algorithm {
    /// True when this algorithm has an associated checksum-file extension.
    pub const fn has_extension(&self) -> bool {
        !self.extensions.is_empty()
    }

    /// True when a context can be built for it today.
    pub fn is_implemented(&self) -> bool {
        make(self.name).is_some()
    }
}

/// The full algorithm table, in the order the UI displays them.
pub const ALGORITHMS: &[Algorithm] = &[
    Algorithm {
        name: "CRC32",
        output_len: 4,
        secure: false,
        extensions: &[],
    },
    Algorithm {
        name: "CRC64",
        output_len: 8,
        secure: false,
        extensions: &[],
    },
    Algorithm {
        name: "XXH32",
        output_len: 4,
        secure: false,
        extensions: &["xxh32"],
    },
    Algorithm {
        name: "XXH64",
        output_len: 8,
        secure: false,
        extensions: &["xxh64"],
    },
    Algorithm {
        name: "XXH3-64",
        output_len: 8,
        secure: false,
        extensions: &["xxh3-64"],
    },
    Algorithm {
        name: "XXH3-128",
        output_len: 16,
        secure: false,
        extensions: &["xxh3-128"],
    },
    Algorithm {
        name: "MD4",
        output_len: 16,
        secure: false,
        extensions: &["md4"],
    },
    Algorithm {
        name: "MD5",
        output_len: 16,
        secure: false,
        extensions: &["md5", "md5sum", "md5sums"],
    },
    Algorithm {
        name: "RipeMD160",
        output_len: 20,
        secure: true,
        extensions: &["ripemd160"],
    },
    Algorithm {
        name: "SHA-1",
        output_len: 20,
        secure: true,
        extensions: &["sha1", "sha1sum", "sha1sums"],
    },
    Algorithm {
        name: "SHA-224",
        output_len: 28,
        secure: true,
        extensions: &["sha224", "sha224sum"],
    },
    Algorithm {
        name: "SHA-256",
        output_len: 32,
        secure: true,
        extensions: &["sha256", "sha256sum", "sha256sums"],
    },
    Algorithm {
        name: "SHA-384",
        output_len: 48,
        secure: true,
        extensions: &["sha384"],
    },
    Algorithm {
        name: "SHA-512",
        output_len: 64,
        secure: true,
        extensions: &["sha512", "sha512sum", "sha512sums"],
    },
    Algorithm {
        name: "Blake2sp",
        output_len: 32,
        secure: true,
        extensions: &["blake2sp"],
    },
    Algorithm {
        name: "SHA3-224",
        output_len: 28,
        secure: true,
        extensions: &["sha3-224"],
    },
    Algorithm {
        name: "SHA3-256",
        output_len: 32,
        secure: true,
        extensions: &["sha3-256"],
    },
    Algorithm {
        name: "SHA3-384",
        output_len: 48,
        secure: true,
        extensions: &["sha3-384"],
    },
    Algorithm {
        name: "SHA3-512",
        output_len: 64,
        secure: true,
        extensions: &["sha3", "sha3-512"],
    },
    Algorithm {
        name: "K12-264",
        output_len: 33,
        secure: true,
        extensions: &["k12-264"],
    },
    Algorithm {
        name: "K12-256",
        output_len: 32,
        secure: true,
        extensions: &[],
    },
    Algorithm {
        name: "K12-512",
        output_len: 64,
        secure: true,
        extensions: &[],
    },
    Algorithm {
        name: "PH128-264",
        output_len: 33,
        secure: true,
        extensions: &["ph128-264"],
    },
    Algorithm {
        name: "PH256-528",
        output_len: 66,
        secure: true,
        extensions: &["ph256-528"],
    },
    Algorithm {
        name: "BLAKE3",
        output_len: 32,
        secure: true,
        extensions: &["blake3"],
    },
    Algorithm {
        name: "BLAKE3-512",
        output_len: 64,
        secure: true,
        extensions: &[],
    },
    Algorithm {
        name: "GOST 2012 (256)",
        output_len: 32,
        secure: true,
        extensions: &[],
    },
    Algorithm {
        name: "GOST 2012 (512)",
        output_len: 64,
        secure: true,
        extensions: &[],
    },
    Algorithm {
        name: "eD2k",
        output_len: 16,
        secure: false,
        extensions: &[],
    },
    Algorithm {
        name: "eD2k (Old)",
        output_len: 16,
        secure: false,
        extensions: &[],
    },
    Algorithm {
        name: "QuickXorHash",
        output_len: 20,
        secure: false,
        extensions: &[],
    },
];

/// Look up an algorithm by its display name.
pub fn by_name(name: &str) -> Option<&'static Algorithm> {
    ALGORITHMS.iter().find(|a| a.name == name)
}

/// Look up an algorithm by its sumfile extension (without the leading dot).
pub fn by_extension(ext: &str) -> Option<&'static Algorithm> {
    ALGORITHMS
        .iter()
        .find(|a| a.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)))
}

/// Build a streaming context for the named algorithm, or `None` if it is not
/// implemented yet.
///
/// The `None` case is deliberate and visible: it is what makes "this algorithm is
/// not done yet" distinguishable from "this algorithm produces this digest".
pub fn make(name: &str) -> Option<Box<dyn Hasher>> {
    Some(match name {
        "CRC32" => Box::new(Crc32::new()),
        "CRC64" => Box::new(Crc64::new()),
        "XXH32" => Box::new(Xxh32::new()),
        "XXH64" => Box::new(Xxh64::new()),
        "XXH3-64" => Box::new(Xxh3::new_64()),
        "XXH3-128" => Box::new(Xxh3::new_128()),
        "MD4" => Box::new(Md4::new()),
        "MD5" => Box::new(Md5::new()),
        "RipeMD160" => Box::new(RipeMd160::new()),
        "SHA-1" => Box::new(Sha1::new()),
        "SHA-224" => Box::new(Sha224::new()),
        "SHA-256" => Box::new(Sha256::new()),
        "SHA-384" => Box::new(Sha384::new()),
        "SHA-512" => Box::new(Sha512::new()),
        "SHA3-224" => Box::new(Sha3_224::new()),
        "SHA3-256" => Box::new(Sha3_256::new()),
        "SHA3-384" => Box::new(Sha3_384::new()),
        "SHA3-512" => Box::new(Sha3_512::new()),
        "PH128-264" => Box::new(crate::parallel_hash::ParallelHash::ph128_264().ok()?),
        "PH256-528" => Box::new(crate::parallel_hash::ParallelHash::ph256_528().ok()?),
        _ => return None,
    })
}

/// Number of algorithms with a working implementation.
pub fn implemented_count() -> usize {
    ALGORITHMS.iter().filter(|a| a.is_implemented()).count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn table_length_matches_product_requirement() {
        assert_eq!(
            ALGORITHMS.len(),
            31,
            "the product exposes exactly 31 algorithms"
        );
    }

    #[test]
    fn names_are_unique() {
        for (i, a) in ALGORITHMS.iter().enumerate() {
            for b in &ALGORITHMS[i + 1..] {
                assert_ne!(a.name, b.name, "duplicate algorithm name {}", a.name);
            }
        }
    }

    /// A `make` that succeeds must agree with the table on digest length, or the
    /// scanner would size buffers wrongly.
    #[test]
    fn constructed_contexts_match_the_table() {
        for a in ALGORITHMS {
            if let Some(h) = make(a.name) {
                assert_eq!(
                    h.output_len(),
                    a.output_len,
                    "{}: context reports {} bytes, table says {}",
                    a.name,
                    h.output_len(),
                    a.output_len
                );
            }
        }
    }

    #[test]
    fn extensions_resolve_back_to_their_algorithm() {
        assert_eq!(by_extension("sha256").unwrap().name, "SHA-256");
        assert_eq!(by_extension("MD5SUM").unwrap().name, "MD5");
        assert!(by_extension("not-a-real-ext").is_none());
    }

    #[test]
    fn unknown_algorithm_is_none_not_a_panic() {
        assert!(make("NoSuchAlgorithm").is_none());
    }
}
