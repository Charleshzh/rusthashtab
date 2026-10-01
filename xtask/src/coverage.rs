//! Which external authority validates which algorithm.
//!
//! # Why this table exists
//!
//! A hash is either exactly right or worthless, and a Rust unit test that compares
//! our output to a constant we produced ourselves proves nothing. Every algorithm
//! therefore needs a **source of truth that is independent of this repository**:
//! either a standard document's published vector, or a second implementation
//! maintained by someone else.
//!
//! This module is the machine-readable form of that requirement. `cargo xtask
//! verify` reports against it, and it fails loudly when an algorithm has no
//! authority at all — because "I forgot to find a reference" and "the reference
//! passed" must not look the same.
//!
//! # Coverage reality
//!
//! OpenSSL is the most convenient authority and covers the widest slice, but it is
//! *not* a complete answer: it has no xxHash, no CRC, no BLAKE2sp, no
//! KangarooTwelve, no ParallelHash, no Streebog, no eD2k and no QuickXorHash. Each
//! of those needs its own authority, listed below.

/// Where an independent check comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "kept for algorithms OpenSSL 3 ships only in the legacy provider"
)]
pub(crate) enum Authority {
    /// `openssl dgst -<name>`, or `-shake128 -xoflen N` for XOFs.
    OpenSsl {
        /// The algorithm name to pass to `openssl dgst`.
        digest: &'static str,
    },
    /// `openssl dgst -<name>` with `-provider legacy`. OpenSSL 3.x ships MD4 in the
    /// legacy provider, which is frequently absent, so this is allowed to be
    /// unavailable and falls back to the RFC vectors.
    OpenSslLegacy {
        /// The algorithm name to pass to `openssl dgst`.
        digest: &'static str,
    },
    /// A published test vector from a normative document.
    StandardVector {
        /// The document the vector comes from, e.g. `"RFC 1320 §A.5"`.
        source: &'static str,
    },
    /// An upstream reference implementation or its published vectors.
    ReferenceImpl {
        /// Human-readable description of the tool or vector set.
        what: &'static str,
    },
    /// A vector file vendored under `vectors/`, checked by `cargo xtask verify`.
    ///
    /// Stronger than [`Authority::ReferenceImpl`]: the comparison runs on every
    /// `verify` invocation rather than existing only as frozen constants in a
    /// unit test. The file itself must come from outside this repository — see
    /// the `PROVENANCE.md` next to it.
    VectorFile {
        /// Path relative to the workspace root, e.g. `"vectors/blake3/test_vectors.json"`.
        file: &'static str,
        /// Which parser and input-generation rule interprets the file.
        kind: VectorKind,
    },
}

/// How a vendored vector file is turned into (input, expected) pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VectorKind {
    /// BLAKE3's official `test_vectors.json`: cases are `{input_len, hash, …}`;
    /// the input is `i % 251` repeated, and `hash` is a 131-byte extended
    /// output of which we compare the first `output_len` bytes.
    Blake3,
    /// The BLAKE2 team's `blake2-kat.json`: entries are `{hash, in, key, out}`
    /// with hex-encoded fields. We consume only the unkeyed entries (`key ==
    /// ""`) for our algorithm's `hash` name; the keyed half is not a mode the
    /// product exposes.
    Blake2Kat {
        /// The `hash` field value to select, e.g. `"blake2sp"`.
        hash: &'static str,
    },
    /// Our curated KangarooTwelve KAT (`vectors/k12/k12-kat.json`): cases are
    /// `{msg_len, out_len, expected}`; the message is `i % 251` repeated and
    /// the customization is empty. A row compares its `output_len` bytes
    /// against the case's prefix (KangarooTwelve is a XOF), skipping cases
    /// whose `out_len` is shorter than the row's output.
    K12Kat,
    /// gost-engine's etalon suite (`vectors/gost/etalon/`): `dgst.result`
    /// lists `md_gost12_<bits>(<name>)= <hex>` lines; each `<name>` is a
    /// message file in the same directory. The row selects lines by its own
    /// output width; message files that are not vendored (the 4 GiB M7) are
    /// skipped, not failed.
    GostEtalon,
    /// rclone's QuickXorHash test file (Go source): entries are
    /// `{size, `<base64 in>`, "<base64 out>"}`, the input possibly wrapped
    /// across lines inside the backticks.
    QuickXorRclone,
}

/// Implementation state of one algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// Implemented and passing its authority check.
    Done,
    /// Implemented, but the authority check has not been run.
    Unverified,
    /// Registered in the table but the algorithm is not implemented yet.
    Pending,
}

/// One row of the coverage map.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Coverage {
    /// Display name, matching the algorithm table.
    pub name: &'static str,
    /// Digest length in bytes.
    pub output_len: usize,
    /// The independent authority for this algorithm.
    pub authority: Authority,
    /// Current implementation state.
    pub status: Status,
}

impl Coverage {
    /// True when `cargo xtask verify` actively checks this row (as opposed to
    /// authorities discharged by the crate's own test suite).
    pub(crate) const fn checked_by_verify(&self) -> bool {
        matches!(
            self.authority,
            Authority::OpenSsl { .. }
                | Authority::OpenSslLegacy { .. }
                | Authority::VectorFile { .. }
        )
    }

    /// Short description of the authority, for reports.
    pub(crate) const fn authority_label(&self) -> &'static str {
        match self.authority {
            Authority::OpenSsl { digest } => digest,
            Authority::OpenSslLegacy { digest } => digest,
            Authority::StandardVector { source } => source,
            Authority::ReferenceImpl { what } => what,
            Authority::VectorFile { file, .. } => file,
        }
    }
}

/// The full coverage map, in algorithm-table order.
///
/// `status` is updated as algorithms land. An entry may never be removed: leaving
/// a gap visible is the point.
pub(crate) const COVERAGE: &[Coverage] = &[
    Coverage {
        name: "CRC32",
        output_len: 4,
        authority: Authority::ReferenceImpl {
            what: "CRC catalogue check value 0xCBF43926 for \"123456789\"",
        },
        status: Status::Done,
    },
    Coverage {
        name: "CRC64",
        output_len: 8,
        authority: Authority::ReferenceImpl {
            what: "crc-catalog CRC_64_XZ check value 0x995dc9bbdf1939fa",
        },
        status: Status::Done,
    },
    Coverage {
        name: "XXH32",
        output_len: 4,
        authority: Authority::ReferenceImpl {
            what: "xxHash upstream sanity vector (seed 0, empty)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "XXH64",
        output_len: 8,
        authority: Authority::ReferenceImpl {
            what: "xxHash upstream sanity vector (seed 0, empty)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "XXH3-64",
        output_len: 8,
        authority: Authority::ReferenceImpl {
            what: "xxHash upstream sanity vector (seed 0, empty)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "XXH3-128",
        output_len: 16,
        authority: Authority::ReferenceImpl {
            what: "xxHash upstream sanity vector (seed 0, empty)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "MD4",
        output_len: 16,
        authority: Authority::StandardVector {
            source: "RFC 1320 §A.5 Appendix",
        },
        // The full §A.5 suite (all seven vectors) is in sha2_family's tests.
        status: Status::Done,
    },
    Coverage {
        name: "MD5",
        output_len: 16,
        authority: Authority::OpenSsl { digest: "md5" },
        status: Status::Done,
    },
    Coverage {
        name: "RipeMD160",
        output_len: 20,
        authority: Authority::OpenSsl {
            digest: "ripemd160",
        },
        status: Status::Done,
    },
    Coverage {
        name: "SHA-1",
        output_len: 20,
        authority: Authority::OpenSsl { digest: "sha1" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA-224",
        output_len: 28,
        authority: Authority::OpenSsl { digest: "sha224" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA-256",
        output_len: 32,
        authority: Authority::OpenSsl { digest: "sha256" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA-384",
        output_len: 48,
        authority: Authority::OpenSsl { digest: "sha384" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA-512",
        output_len: 64,
        authority: Authority::OpenSsl { digest: "sha512" },
        status: Status::Done,
    },
    Coverage {
        name: "Blake2sp",
        output_len: 32,
        authority: Authority::VectorFile {
            file: "vectors/blake2/blake2-kat.json",
            kind: VectorKind::Blake2Kat { hash: "blake2sp" },
        },
        status: Status::Done,
    },
    Coverage {
        name: "SHA3-224",
        output_len: 28,
        authority: Authority::OpenSsl { digest: "sha3-224" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA3-256",
        output_len: 32,
        authority: Authority::OpenSsl { digest: "sha3-256" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA3-384",
        output_len: 48,
        authority: Authority::OpenSsl { digest: "sha3-384" },
        status: Status::Done,
    },
    Coverage {
        name: "SHA3-512",
        output_len: 64,
        authority: Authority::OpenSsl { digest: "sha3-512" },
        status: Status::Done,
    },
    Coverage {
        name: "K12-264",
        output_len: 33,
        authority: Authority::VectorFile {
            file: "vectors/k12/k12-kat.json",
            kind: VectorKind::K12Kat,
        },
        status: Status::Done,
    },
    Coverage {
        name: "K12-256",
        output_len: 32,
        authority: Authority::VectorFile {
            file: "vectors/k12/k12-kat.json",
            kind: VectorKind::K12Kat,
        },
        status: Status::Done,
    },
    Coverage {
        name: "K12-512",
        output_len: 64,
        authority: Authority::VectorFile {
            file: "vectors/k12/k12-kat.json",
            kind: VectorKind::K12Kat,
        },
        status: Status::Done,
    },
    Coverage {
        name: "PH128-264",
        output_len: 33,
        authority: Authority::ReferenceImpl {
            what: "XKCP SP800-185.c reference build (frozen values in-tree)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "PH256-528",
        output_len: 66,
        authority: Authority::ReferenceImpl {
            what: "XKCP SP800-185.c reference build (frozen values in-tree)",
        },
        status: Status::Done,
    },
    Coverage {
        name: "BLAKE3",
        output_len: 32,
        authority: Authority::VectorFile {
            file: "vectors/blake3/test_vectors.json",
            kind: VectorKind::Blake3,
        },
        status: Status::Done,
    },
    Coverage {
        name: "BLAKE3-512",
        output_len: 64,
        // Same official file: its `hash` fields are 131-byte extended outputs,
        // of which this row compares the first 64 bytes.
        authority: Authority::VectorFile {
            file: "vectors/blake3/test_vectors.json",
            kind: VectorKind::Blake3,
        },
        status: Status::Done,
    },
    Coverage {
        name: "GOST 2012 (256)",
        output_len: 32,
        authority: Authority::VectorFile {
            file: "vectors/gost/etalon/dgst.result",
            kind: VectorKind::GostEtalon,
        },
        status: Status::Done,
    },
    Coverage {
        name: "GOST 2012 (512)",
        output_len: 64,
        authority: Authority::VectorFile {
            file: "vectors/gost/etalon/dgst.result",
            kind: VectorKind::GostEtalon,
        },
        status: Status::Done,
    },
    Coverage {
        name: "eD2k",
        output_len: 16,
        // Hand-written tree over md4; checked against the `ed2k` crate
        // (docs.rs vectors + differential oracle across the 9,728,000-byte
        // chunk boundary) in crates/rusthashtab-hash/tests/ed2k_oracle.rs.
        authority: Authority::ReferenceImpl {
            what: "ed2k crate: docs.rs vectors + differential oracle",
        },
        status: Status::Done,
    },
    Coverage {
        name: "eD2k (Old)",
        output_len: 16,
        authority: Authority::ReferenceImpl {
            what: "ed2k crate: docs.rs vectors + differential oracle",
        },
        status: Status::Done,
    },
    Coverage {
        name: "QuickXorHash",
        output_len: 20,
        authority: Authority::VectorFile {
            file: "vectors/quickxorhash/quickxorhash_test.go",
            kind: VectorKind::QuickXorRclone,
        },
        status: Status::Done,
    },
];

/// Totals for a progress line.
pub(crate) fn tally() -> (usize, usize, usize) {
    let done = COVERAGE.iter().filter(|c| c.status == Status::Done).count();
    let unverified = COVERAGE
        .iter()
        .filter(|c| c.status == Status::Unverified)
        .count();
    let pending = COVERAGE
        .iter()
        .filter(|c| c.status == Status::Pending)
        .count();
    (done, unverified, pending)
}
