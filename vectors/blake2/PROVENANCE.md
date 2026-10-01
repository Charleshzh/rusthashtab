# `vectors/blake2/` — provenance

## `blake2-kat.json`

- **What it is**: the official BLAKE2 known-answer tests from the BLAKE2 team's
  own repository, covering all four variants (blake2s, blake2b, blake2sp,
  blake2bp), keyed and unkeyed.
- **Source URL**: <https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json>
  (repository: <https://github.com/BLAKE2/BLAKE2>, directory `testvectors/`)
- **Retrieved**: 2026-09-13, via `Invoke-WebRequest`, file stored byte-for-byte
  as downloaded.
- **SHA-256 of the stored file**: `5031AC14800798AE15CEE79C04D65E326A575F2C968C7E2846A79BD07A1C0E61`
- **Format**: a flat JSON array of `{"hash", "in", "key", "out"}` entries, all
  values hex-encoded. `cargo xtask verify` consumes only the entries with
  `hash == "blake2sp"` and `key == ""` — the unkeyed mode is the only one this
  product exposes. (256 cases, inputs of 0–255 bytes following the
  `i mod 256` sequence.)
- **Why it qualifies as an external authority**: it is published by the
  algorithm's authors, independently of this repository, and it is what the
  upstream reference implementations test against.

## Note on `blake2sp-kat.txt`

The same repository also ships `testvectors/blake2sp-kat.txt`, but every entry
in it uses the 32-byte key `000102…1f` — a **keyed** mode this product does not
expose. It was therefore not vendored; `blake2-kat.json`'s unkeyed entries are
the applicable authority.
