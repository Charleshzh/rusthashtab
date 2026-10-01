# `vectors/blake3/` — provenance

## `test_vectors.json`

- **What it is**: the official BLAKE3 test vectors, from the BLAKE3 team's own
  repository.
- **Source URL**: <https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/test_vectors/test_vectors.json>
  (repository: <https://github.com/BLAKE3-team/BLAKE3>, directory `test_vectors/`)
- **Retrieved**: 2026-09-13, via `Invoke-WebRequest`, file stored byte-for-byte
  as downloaded.
- **SHA-256 of the stored file**: `DCB91EA8ACCC77E6D6E632AF7CDC1A99A9F3AE78CF648DA595C7D064DB32F624`
- **Format** (from the file's own `_comment`): each case is an input length;
  the input is filled with a repeating sequence of 251 bytes (`i % 251`);
  `hash` is the unkeyed extended output (131 bytes hex-encoded). We compare the
  first 32 bytes for `BLAKE3` and the first 64 bytes for `BLAKE3-512`. The
  `keyed_hash` / `derive_key` fields are not used (we expose neither mode).
- **Why it qualifies as an external authority**: it is published and
  maintained by the algorithm's authors, independently of this repository, and
  it is what the upstream Rust and C implementations test against.
