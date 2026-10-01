# `vectors/gost/` — provenance

## `etalon/` (M1–M6, carry, dgst.result)

- **What it is**: the etalon (reference) test suite of **gost-engine**, the
  reference GOST cryptographic engine (<https://github.com/gost-engine/engine>,
  directory `etalon/`). `dgst.result` lists the expected digest of each
  message file: `md_gost12_<256|512>(<name>)= <hex>`.
- **Source URLs**: `https://raw.githubusercontent.com/gost-engine/engine/master/etalon/<file>`
  for `<file>` ∈ {M1, M2, M3, M4, M5, M6, carry, dgst.result}, stored
  byte-for-byte as downloaded.
- **Retrieved**: 2026-09-13, via `Invoke-WebRequest`.
- **SHA-256 of `dgst.result`**: `146EEA1EDB8BE907A376ABBFEA51DFF52B9EA75059DC509AAC474C6605E532FC`
- **Not vendored**: `M7` — a generated 4 GiB message. Its `dgst.result` line
  is skipped by `cargo xtask verify` (missing message file ⇒ skip, and zero
  applicable cases would be a hard error).
- **Byte order**: the values are in the order the tool ecosystem prints
  (gost-engine, gost12sum). RFC 6986 §10 shows the same digests byte-reversed;
  see `crates/rusthashtab-hash/src/gost.rs` for why we follow the tools.
- **Why it qualifies as an external authority**: gost-engine is the reference
  implementation ecosystem for GOST R 34.11-2012, maintained independently of
  this repository and of the `streebog` crate we wrap; the etalon suite is
  what that ecosystem tests against.
