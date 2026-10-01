# `vectors/k12/` — provenance

## `k12-kat.json`

A curated KangarooTwelve (KT128) known-answer file with **empty
customization** — the only configuration this product exposes. Messages follow
the RFC 9861 §5 `ptn()` convention: byte `i` is `i % 251`.

### Source 1 — RFC 9861 §5 test vectors

- **What it is**: the normative test-vector section of RFC 9861,
  "KangarooTwelve and TurboSHAKE".
- **URL**: <https://www.rfc-editor.org/rfc/rfc9861.html> (working copy fetched
  from <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-kangarootwelve-11>,
  whose §5 content is identical for these cases)
- **Cases used**: all 32-byte-output vectors (empty message; `ptn(1)`,
  `ptn(17)`, `ptn(17²)`, `ptn(17³)`, `ptn(17⁴)`, `ptn(17⁵)`, `ptn(17⁶)`,
  `ptn(8191)`, `ptn(8192)` with empty customization), and the full 64-byte
  empty-message vector.
- **Why it qualifies**: it is the standards document, independent of every
  implementation.

### Source 2 — XKCP K12 Python reference implementation

- **What it is**: `KangarooTwelve.py` (+ `TurboSHAKE.py`, `Utils.py`) from the
  K12 authors' own repository — the reference implementation, by Gilles Van
  Assche (CC0).
- **URL**: <https://github.com/XKCP/K12>, directory `Python/`, `master`
  retrieved 2026-09-13. The files were *executed*, not vendored.
- **Used for**: bytes 32–64 of the non-empty 64-byte cases (the RFC only
  publishes 32-byte outputs for non-empty messages). The generator was:
  `KT128(ptn(n), b"", 64)` for n ∈ {1, 17, 289, 4913, 8191, 8192}.
- **Cross-checks that anchor it**: its empty-message 64-byte output equals the
  RFC 9861 vector byte-for-byte, and the first 32 bytes of every generated
  64-byte output equal the corresponding RFC 32-byte vector — the XOF prefix
  property holds across both sources.
- **Why it qualifies**: it is the algorithm authors' reference implementation,
  independent of the `k12` crate this product wraps (RustCrypto, different
  authors, different code).
