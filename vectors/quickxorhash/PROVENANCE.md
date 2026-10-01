# `vectors/quickxorhash/` — provenance

## `quickxorhash_test.go`

- **What it is**: the test-vector file of rclone's QuickXorHash implementation
  — an independent Go implementation of Microsoft's documented algorithm,
  carrying 70+ cases (sizes 0–64, 111, 128, 222, 256, 333) with base64-encoded
  inputs and expected outputs.
- **Source URL**: <https://raw.githubusercontent.com/rclone/rclone/master/backend/onedrive/quickxorhash/quickxorhash_test.go>
- **Retrieved**: 2026-09-13, via `Invoke-WebRequest`, file stored byte-for-byte
  as downloaded (Go source and all).
- **SHA-256 of the stored file**: `0E5E9620FD28FB51F3C571C99C947702774B3982DBD3F5C74DA944CFDE80F858`
- **How `cargo xtask verify` reads it**: each entry has the shape
  `{size, `<base64 in>`, "<base64 out>"}`; inputs may be wrapped across lines
  inside the backticks. Entries are scanned with a regex, decoded, and hashed.
- **Why it qualifies as an external authority**: rclone is an independent
  project implementing Microsoft's published algorithm documentation
  (<https://learn.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash>);
  its vector set is published, widely mirrored, and unrelated to the
  `quickxorhash` crate this product wraps.
