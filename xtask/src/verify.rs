//! Differential verification against authorities outside this repository.
//!
//! # The rule this enforces
//!
//! A digest compared against a constant that this repository also produced is not
//! verified — it is a regression test at best, and a tautology at worst. Correctness
//! comes from agreeing with something we did not write:
//!
//! * **OpenSSL** for the algorithms it implements (SHA-1/2/3, SHAKE, MD5,
//!   RIPEMD-160, BLAKE2s/BLAKE2b). It has *no* MD4 under OpenSSL 3's default
//!   provider, and no xxHash, CRC, BLAKE2sp, KangarooTwelve, ParallelHash,
//!   Streebog, eD2k or QuickXorHash at all — see [`crate::coverage`].
//! * **Frozen vectors from an independent reference build** for the rest, kept
//!   next to the implementation with the source named in a comment.
//! * **Vendored vector files** under `vectors/` for algorithms whose authority
//!   publishes machine-readable vectors (BLAKE3, BLAKE2). Each directory's
//!   `PROVENANCE.md` records where the file came from; a missing or malformed
//!   file is a hard failure, not a skip.
//!
//! # Payload sizes
//!
//! Chosen to land on the boundaries that expose padding and block bugs: SHA-2's
//! 64- and 128-byte blocks, Keccak's 136/168-byte rate, and the scanner's 2 MiB
//! read block.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use rusthashtab_hash::registry;

use crate::coverage::{Authority, COVERAGE, Coverage, Status, VectorKind};

/// Payload sizes that stress padding and block boundaries.
const SIZES: &[usize] = &[
    0,
    1,
    7,
    55,
    56,
    57,
    63,
    64,
    65,
    111,
    112,
    113,
    127,
    128,
    129,
    135,
    136,
    137,
    167,
    168,
    169,
    // The scanner's read block, and one byte either side of it.
    2 * 1024 * 1024 - 1,
    2 * 1024 * 1024,
    2 * 1024 * 1024 + 1,
];

/// Deterministic payload, so a failure is reproducible from the size alone.
fn payload(n: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Locate a tool on `PATH`.
fn find(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path) {
        for ext in exts {
            let candidate = dir.join(format!("{tool}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Run `openssl dgst` over a file and return the lowercase hex digest.
fn openssl_digest(
    openssl: &Path,
    digest: &str,
    legacy: bool,
    file: &Path,
) -> Result<String, String> {
    let mut cmd = Command::new(openssl);
    cmd.arg("dgst");
    if legacy {
        cmd.arg("-provider").arg("legacy");
        cmd.arg("-provider").arg("default");
    }
    cmd.arg(format!("-{digest}")).arg(file);

    let out = cmd.output().map_err(|e| format!("spawn failed: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(err.lines().next().unwrap_or("openssl failed").to_string());
    }
    // Modern `openssl dgst` prints "<algo>(<file>)= <hex>"; `-r` prints "<hex> *<file>".
    // Take the last whitespace-separated token that is pure hex. `rfind` scans
    // backwards directly, which is what this wants -- filtering first and then
    // taking the last element walks the whole output twice.
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .rfind(|t| t.len() >= 8 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| format!("could not parse output: {text:?}"))
}

/// Hex-encode our digest.
fn our_digest(name: &str, data: &[u8]) -> Option<String> {
    let mut h = registry::make(name)?;
    h.update(data);
    Some(
        Box::new(h)
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// Entry point: `cargo xtask verify [--require-tools]`.
pub(crate) fn run(args: &[String]) -> ExitCode {
    let require_tools = args.iter().any(|a| a == "--require-tools");
    let openssl = find("openssl");

    if openssl.is_none() && require_tools {
        eprintln!("ERROR: --require-tools was given but openssl is not on PATH.");
        return ExitCode::FAILURE;
    }

    let tmp = std::env::temp_dir().join("rusthashtab-verify");
    if let Err(e) = std::fs::create_dir_all(&tmp) {
        eprintln!("ERROR: cannot create {}: {e}", tmp.display());
        return ExitCode::FAILURE;
    }

    // Write each payload once, and keep it in memory for the in-process side.
    let mut cases: Vec<(usize, PathBuf, Vec<u8>)> = Vec::with_capacity(SIZES.len());
    for &n in SIZES {
        let path = tmp.join(format!("payload-{n}.bin"));
        let data = payload(n);
        let written = std::fs::File::create(&path).and_then(|mut f| f.write_all(&data));
        if let Err(e) = written {
            eprintln!("ERROR: cannot write {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
        cases.push((n, path, data));
    }
    println!(
        "Checking {} algorithms over {} payload sizes (0 B … {} B)\n",
        COVERAGE
            .iter()
            .filter(|c| c.status != Status::Pending && c.checked_by_verify())
            .count(),
        SIZES.len(),
        SIZES[SIZES.len() - 1]
    );

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped: Vec<(&str, String)> = Vec::new();
    let mut mismatches: Vec<String> = Vec::new();

    for cov in COVERAGE {
        if cov.status == Status::Pending {
            continue;
        }

        // Vendored vector files are self-contained: no external tool, and the
        // inputs come from the file kind's own generation rule.
        if let Authority::VectorFile { file, kind } = cov.authority {
            match check_vector_file(cov, file, kind) {
                Ok(cases) => {
                    passed += cases;
                    println!("  {:<18} OK   ({cases} cases vs {file})", cov.name);
                }
                Err(e) => {
                    mismatches.push(format!("{}: {e}", cov.name));
                    failed += 1;
                }
            }
            continue;
        }

        let (digest, legacy) = match cov.authority {
            Authority::OpenSsl { digest } => (digest, false),
            Authority::OpenSslLegacy { digest } => (digest, true),
            // Standard vectors and frozen reference values are checked by the
            // crate's own test suite, not here.
            Authority::StandardVector { .. }
            | Authority::ReferenceImpl { .. }
            | Authority::VectorFile { .. } => continue,
        };

        let Some(openssl) = openssl.as_deref() else {
            skipped.push((cov.name, "openssl not found".to_string()));
            continue;
        };

        let mut algorithm_failed = false;
        for (n, path, data) in &cases {
            // Tool side. A persistent tool error means the algorithm is absent from
            // this OpenSSL build, which is a tool limitation, not our failure.
            let reference = match openssl_digest(openssl, digest, legacy, path) {
                Ok(h) => h,
                Err(e) => {
                    skipped.push((cov.name, e));
                    algorithm_failed = true;
                    break;
                }
            };

            // Our side. A `None` here means the table marks it verified but the
            // registry cannot build it — that is a real inconsistency.
            let Some(ours) = our_digest(cov.name, data) else {
                mismatches.push(format!(
                    "{}: marked {:?} but registry::make() returns None",
                    cov.name, cov.status
                ));
                failed += 1;
                algorithm_failed = true;
                break;
            };

            if ours.len() != cov.output_len * 2 {
                mismatches.push(format!(
                    "{} n={n}: our digest is {} bytes, table says {}",
                    cov.name,
                    ours.len() / 2,
                    cov.output_len
                ));
                failed += 1;
                algorithm_failed = true;
                break;
            }
            if ours != reference {
                mismatches.push(format!(
                    "{} n={n}:\n    ours    = {ours}\n    openssl = {reference}",
                    cov.name
                ));
                failed += 1;
                algorithm_failed = true;
                break;
            }
            passed += 1;
        }

        if !algorithm_failed {
            println!(
                "  {:<18} OK   ({} sizes vs openssl -{digest})",
                cov.name,
                cases.len()
            );
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);

    if !skipped.is_empty() {
        println!("\nSkipped (tool could not supply this algorithm):");
        for (name, why) in &skipped {
            println!("  {name:<18} {why}");
        }
    }

    if !mismatches.is_empty() {
        println!("\nMISMATCHES:");
        for m in &mismatches {
            println!("  {m}");
        }
    }

    println!(
        "\n{passed} comparisons passed, {failed} failed, {} skipped",
        skipped.len()
    );

    let (done, unverified, pending) = crate::coverage::tally();
    println!(
        "Coverage: {done} verified, {unverified} awaiting a check, {pending} not implemented \
         ({} total). `cargo xtask audit` for detail.",
        COVERAGE.len()
    );

    if failed > 0 {
        eprintln!("\nVERIFICATION FAILED");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Run a vendored vector file against our implementation.
///
/// Returns the number of cases checked. Every inconsistency is an `Err` — a
/// vector file that is missing, malformed or the wrong length proves nothing,
/// and must not be allowed to look like a pass.
fn check_vector_file(cov: &Coverage, file: &str, kind: VectorKind) -> Result<usize, String> {
    // xtask lives at <workspace>/xtask, so the workspace root is one level up.
    // Anchor there rather than at the invocation directory, so `verify` works
    // from anywhere.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(file);

    // Not every authority is JSON — the GOST etalon is a text index over raw
    // message files. Branch on the kind before parsing.
    if let VectorKind::GostEtalon = kind {
        return check_gost_etalon(cov, file, &path);
    }

    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{file}: malformed JSON: {e}"))?;
    match kind {
        VectorKind::Blake3 => check_blake3_vectors(cov, file, &json),
        VectorKind::Blake2Kat { hash } => check_blake2_kat(cov, file, &json, hash),
        VectorKind::K12Kat => check_k12_kat(cov, file, &json),
        VectorKind::GostEtalon => unreachable!("handled above"),
    }
}

/// gost-engine's etalon suite. `dgst.result` lists
/// `md_gost12_<bits>(<name>)= <hex>`; each `<name>` is a message file in the
/// same directory. The row's output width selects the lines. A missing
/// message file (the 4 GiB M7, which we do not vendor) is skipped, not
/// failed; zero applicable cases is an error.
fn check_gost_etalon(cov: &Coverage, file: &str, path: &Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{file}: no parent directory"))?;
    let prefix = format!("md_gost12_{}(", cov.output_len * 8);
    let mut checked = 0usize;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some((name, expected)) = rest.split_once(")= ") else {
            return Err(format!("{file}: malformed line {line:?}"));
        };
        let msg_path = dir.join(name);
        if !msg_path.is_file() {
            continue; // not vendored (e.g. the 4 GiB M7)
        }
        let msg = std::fs::read(&msg_path)
            .map_err(|e| format!("cannot read {}: {e}", msg_path.display()))?;
        let ours = our_digest(cov.name, &msg).ok_or_else(|| {
            format!(
                "{}: marked {:?} but registry::make() returns None",
                cov.name, cov.status
            )
        })?;
        if ours != expected.trim() {
            return Err(format!(
                "{} case {name}:\n    ours     = {ours}\n    {file} = {expected}",
                cov.name
            ));
        }
        checked += 1;
    }
    if checked == 0 {
        return Err(format!(
            "{file}: no `md_gost12_{}` cases with vendored messages",
            cov.output_len * 8
        ));
    }
    Ok(checked)
}

/// Our curated KangarooTwelve KAT. Messages are `i % 251` repeated to
/// `msg_len`; customization is empty. KangarooTwelve is a XOF, so a row
/// compares its `output_len` bytes against the case's prefix, skipping cases
/// whose `out_len` is shorter than the row's output.
fn check_k12_kat(cov: &Coverage, file: &str, json: &serde_json::Value) -> Result<usize, String> {
    let cases = json
        .get("cases")
        .and_then(|c| c.as_array())
        .ok_or_else(|| format!("{file}: `cases` is not an array"))?;
    let mut checked = 0usize;
    for case in cases {
        let msg_len = case
            .get("msg_len")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{file}: bad `msg_len`"))? as usize;
        let out_len = case
            .get("out_len")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{file}: bad `out_len`"))? as usize;
        let expected_hex = case
            .get("expected")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{file}: bad `expected`"))?;
        if expected_hex.len() != out_len * 2 {
            return Err(format!(
                "{file} case n={msg_len}: `expected` is {} bytes, `out_len` says {out_len}",
                expected_hex.len() / 2
            ));
        }
        if out_len < cov.output_len {
            continue;
        }
        let input: Vec<u8> = (0..msg_len).map(|i| (i % 251) as u8).collect();
        let ours = our_digest(cov.name, &input).ok_or_else(|| {
            format!(
                "{}: marked {:?} but registry::make() returns None",
                cov.name, cov.status
            )
        })?;
        if ours != expected_hex[..cov.output_len * 2] {
            return Err(format!(
                "{} n={msg_len}:\n    ours     = {ours}\n    {file} = {}",
                cov.name,
                &expected_hex[..cov.output_len * 2]
            ));
        }
        checked += 1;
    }
    if checked == 0 {
        return Err(format!(
            "{file}: no case covers {} output bytes for {}",
            cov.output_len, cov.name
        ));
    }
    Ok(checked)
}

/// The BLAKE2 team's `blake2-kat.json`, restricted to the unkeyed entries of
/// one variant. `in` and `out` are hex; entries are selected by `hash` and
/// `key == ""`.
fn check_blake2_kat(
    cov: &Coverage,
    file: &str,
    json: &serde_json::Value,
    hash: &str,
) -> Result<usize, String> {
    let entries = json
        .as_array()
        .ok_or_else(|| format!("{file}: top level is not an array"))?;
    let mut checked = 0usize;
    for entry in entries {
        let is_wanted = entry.get("hash").and_then(|v| v.as_str()) == Some(hash)
            && entry.get("key").and_then(|v| v.as_str()) == Some("");
        if !is_wanted {
            continue;
        }
        let in_hex = entry
            .get("in")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{file}: bad `in`"))?;
        let out_hex = entry
            .get("out")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{file}: bad `out`"))?;
        if out_hex.len() != cov.output_len * 2 {
            return Err(format!(
                "{file}: `out` is {} bytes, table says {}",
                out_hex.len() / 2,
                cov.output_len
            ));
        }
        let input = hex::decode(in_hex).map_err(|e| format!("{file}: bad `in` hex: {e}"))?;
        let ours = our_digest(cov.name, &input).ok_or_else(|| {
            format!(
                "{}: marked {:?} but registry::make() returns None",
                cov.name, cov.status
            )
        })?;
        if ours != out_hex {
            return Err(format!(
                "{} n={}:\n    ours     = {ours}\n    {file} = {out_hex}",
                cov.name,
                input.len()
            ));
        }
        checked += 1;
    }
    if checked == 0 {
        return Err(format!(
            "{file}: no unkeyed `{hash}` entries found — the file is not the \
             authority it was expected to be"
        ));
    }
    Ok(checked)
}

/// BLAKE3's official `test_vectors.json`. Inputs are `i % 251` repeated; the
/// `hash` field is a 131-byte extended output, of which we compare the first
/// `output_len` bytes (32 for BLAKE3, 64 for BLAKE3-512).
fn check_blake3_vectors(
    cov: &Coverage,
    file: &str,
    json: &serde_json::Value,
) -> Result<usize, String> {
    let cases = json
        .get("cases")
        .and_then(|c| c.as_array())
        .ok_or_else(|| format!("{file}: `cases` is not an array"))?;
    let mut checked = 0usize;
    for case in cases {
        let input_len = case
            .get("input_len")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("{file}: bad `input_len`"))? as usize;
        let expected_hex = case
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{file}: bad `hash`"))?;
        if expected_hex.len() < cov.output_len * 2 {
            return Err(format!(
                "{file} case n={input_len}: expected output is {} bytes, table needs {}",
                expected_hex.len() / 2,
                cov.output_len
            ));
        }
        let input: Vec<u8> = (0..input_len).map(|i| (i % 251) as u8).collect();
        let ours = our_digest(cov.name, &input).ok_or_else(|| {
            format!(
                "{}: marked {:?} but registry::make() returns None",
                cov.name, cov.status
            )
        })?;
        if ours != expected_hex[..cov.output_len * 2] {
            return Err(format!(
                "{} n={input_len}:\n    ours     = {ours}\n    {file} = {}",
                cov.name,
                &expected_hex[..cov.output_len * 2]
            ));
        }
        checked += 1;
    }
    Ok(checked)
}
