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

use crate::coverage::{Authority, COVERAGE, Status};

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
            .filter(|c| c.status != Status::Pending && c.is_tool_backed())
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
        let (digest, legacy) = match cov.authority {
            Authority::OpenSsl { digest } => (digest, false),
            Authority::OpenSslLegacy { digest } => (digest, true),
            // Standard vectors and frozen reference values are checked by the
            // crate's own test suite, not here.
            Authority::StandardVector { .. } | Authority::ReferenceImpl { .. } => continue,
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
