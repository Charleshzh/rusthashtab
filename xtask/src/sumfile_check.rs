//! Cross-check our sumfile parsing and export against real checksum files.
//!
//! # Why this exists
//!
//! `rusthashtab-sumfile` sits between two worlds: digest bytes this repository
//! produces, and files written by tools we do not control. A unit test that
//! parses a hand-written string proves the parser agrees with that string — not
//! with the file a user actually has. So this check makes **real** files with
//! real tools in a scratch directory, and lets each side read the other's
//! output:
//!
//! * `sha256sum` writes `HASH *FILE` lines; we parse them and compare the bytes
//!   against `registry::make("SHA-256")`.
//! * `openssl dgst -sha256 -r` writes the same line shape from an independent
//!   implementation, so the parser is checked against two producers.
//! * Our `.sha256` export is handed back to `sha256sum -c`, which parses it.
//! * Our SFV export is parsed back, and when `7z` is available its CRC32 column
//!   is the external authority for the values we wrote.
//! * The corz `.hash` export has no external producer to hand it to; it is
//!   parsed back only, and the output says so rather than implying a check that
//!   did not happen.
//!
//! Missing tools are skipped by default so a contributor without Git for Windows
//! can still run `verify`. `--require-tools` turns a missing `sha256sum` or
//! `openssl` into a failure, because CI reporting success from a check it never
//! ran is the exact vacuous-gate failure the gate exists to prevent. `7z` stays
//! optional even with `--require-tools`: it would only duplicate the authority
//! the algorithm layer already carries for CRC32.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusthashtab_hash::registry;
use rusthashtab_sumfile::{ExportFormat, ExportOptions, FileSum, export, parse_all};

/// Scratch files: name, PRNG seed, length in bytes.
///
/// The names cover the two shapes that break naive parsers. A space makes the
/// digest/path boundary ambiguous in formats that separate on whitespace, and
/// `#` collides with the comment marker SFV and corz `.hash` files use. All
/// names are ASCII so console code-page differences cannot be the explanation
/// for a failure.
const FILES: &[(&str, u64, usize)] = &[
    ("plain.txt", 1, 1024),
    ("with space.txt", 2, 333),
    ("hash#tag.txt", 3, 77),
    // An empty file is legal in every format here, and it is where a "read to
    // EOF then hash" bug shows up as a wrong constant.
    ("empty.dat", 4, 0),
];

/// Sequence number for scratch directory names, so two runs cannot collide.
static SCRATCH_SEQ: AtomicUsize = AtomicUsize::new(0);

/// A scratch directory that is removed on drop, including on an early return.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// Create a uniquely named directory under the system temp directory.
    fn create(tag: &str) -> Result<Self, String> {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(scratch_dir_name(tag, std::process::id(), seq));
        std::fs::create_dir_all(&path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        Ok(Self { path })
    }

    /// The directory itself.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Best effort. A leftover directory in the temp directory is not a test
        // failure, and panicking on a cleanup error would replace the real
        // result with a confusing one.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Scratch directory basename: tag, process id and a per-process sequence.
fn scratch_dir_name(tag: &str, pid: u32, seq: usize) -> String {
    format!("rusthashtab-xtask-{tag}-{pid}-{seq}")
}

/// Deterministic payload taken from an xorshift64 stream.
fn file_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 33) as u8
        })
        .collect()
}

/// One scratch file, plus the digests our implementation produced for it.
struct Case {
    /// The name in the scratch directory, also used as the sumfile path.
    name: &'static str,
    /// SHA-256 of the file's bytes.
    sha256: Vec<u8>,
    /// CRC32 of the file's bytes.
    crc32: Vec<u8>,
}

/// Digest `data` with one algorithm from our registry.
///
/// The algorithm names here are hard-coded, so a missing registry entry means
/// this check is broken — an `Err` is more honest than silently skipping.
fn our_digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hasher = registry::make(algorithm)
        .ok_or_else(|| format!("registry::make({algorithm:?}) returned None"))?;
    hasher.update(data);
    Ok(hasher.finalize())
}

/// Write the deterministic files and hash them back from disk.
///
/// Reading back is deliberate: it proves the bytes the external tools see are
/// the bytes we hashed, instead of trusting the in-memory buffer we wrote.
fn setup(tag: &str) -> Result<(ScratchDir, Vec<Case>), String> {
    let dir = ScratchDir::create(tag)?;
    let mut cases = Vec::with_capacity(FILES.len());
    for &(name, seed, len) in FILES {
        let path = dir.path().join(name);
        let data = file_bytes(seed, len);
        std::fs::write(&path, &data)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let read_back =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if read_back != data {
            return Err(format!(
                "{}: wrote {} bytes but read back {}",
                path.display(),
                data.len(),
                read_back.len()
            ));
        }
        cases.push(Case {
            name,
            sha256: our_digest("SHA-256", &read_back)?,
            crc32: our_digest("CRC32", &read_back)?,
        });
    }
    Ok((dir, cases))
}

/// Run a command that must succeed, and hand back its captured output.
fn run_capture(mut cmd: Command, what: &str) -> Result<Output, String> {
    let out = cmd
        .output()
        .map_err(|e| format!("could not run {what}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Err(format!("{what} exited with {}: {first}", out.status));
    }
    Ok(out)
}

/// Whether a path a tool printed refers to the file called `name`.
///
/// Tools echo their arguments, but `openssl` echoes the absolute path it was
/// given while `sha256sum` echoes the relative name. Matching on the basename
/// keeps both usable without accepting a different file.
fn matches_file(printed: &str, name: &str) -> bool {
    printed == name
        || Path::new(printed)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f == name)
}

/// Compare every digest a tool reported with ours, byte for byte.
///
/// Returns how many files matched. All differences are collected into one error
/// — wrong bytes, a missing line, and a line for a file we never wrote — because
/// reporting only the first one hides how far the disagreement goes.
fn compare_entries(
    what: &str,
    parsed: &[FileSum],
    ours: &[(&str, &[u8])],
) -> Result<usize, String> {
    let mut differences: Vec<String> = Vec::new();
    let mut passed = 0usize;

    for &(name, digest) in ours {
        match parsed.iter().find(|entry| matches_file(&entry.path, name)) {
            Some(entry) if entry.digest.as_slice() == digest => passed += 1,
            Some(entry) => differences.push(format!(
                "  {name}: ours = {}  {what} = {}",
                hex::encode(digest),
                hex::encode(&entry.digest)
            )),
            None => differences.push(format!("  {name}: {what} reported no entry")),
        }
    }
    for entry in parsed {
        if !ours
            .iter()
            .any(|&(name, _)| matches_file(&entry.path, name))
        {
            differences.push(format!("  {}: unexpected entry from {what}", entry.path));
        }
    }

    if differences.is_empty() {
        Ok(passed)
    } else {
        Err(format!("{what} differences:\n{}", differences.join("\n")))
    }
}

/// Parse tool output as a sumfile, treating an unparseable line as a failure.
///
/// A producer writing a sidecar shape our parser cannot read is exactly the bug
/// this module exists to find, so it must not degrade into "no entries found".
fn parse_tool_output(raw: &str, what: &str) -> Result<Vec<FileSum>, String> {
    let outcome = parse_all(raw);
    if outcome.had_error {
        return Err(format!(
            "{what} output is not a sumfile we can parse:\n{raw}"
        ));
    }
    Ok(outcome.entries)
}

/// `sha256sum` on the real files, parsed and compared with our SHA-256.
fn check_sha256sum_parse(tool: &Path, dir: &Path, cases: &[Case]) -> Result<usize, String> {
    let mut cmd = Command::new(tool);
    cmd.current_dir(dir);
    for case in cases {
        // Bare relative names, never absolute paths and never backslashes: this
        // binary is MSYS, and an absolute Windows path came back with its
        // backslashes doubled and a stray prefix, which is not a parser bug.
        cmd.arg(case.name);
    }
    let out = run_capture(cmd, "sha256sum")?;
    let raw = String::from_utf8_lossy(&out.stdout);
    let entries = parse_tool_output(&raw, "sha256sum")?;
    let ours: Vec<(&str, &[u8])> = cases
        .iter()
        .map(|case| (case.name, case.sha256.as_slice()))
        .collect();
    compare_entries("sha256sum", &entries, &ours)
}

/// `openssl dgst -sha256 -r` on the real files, parsed and compared with ours.
fn check_openssl_parse(tool: &Path, dir: &Path, cases: &[Case]) -> Result<usize, String> {
    let mut cmd = Command::new(tool);
    cmd.args(["dgst", "-sha256", "-r"]);
    for case in cases {
        cmd.arg(dir.join(case.name));
    }
    let out = run_capture(cmd, "openssl dgst -sha256 -r")?;
    let raw = String::from_utf8_lossy(&out.stdout);
    let entries = parse_tool_output(&raw, "openssl")?;
    let ours: Vec<(&str, &[u8])> = cases
        .iter()
        .map(|case| (case.name, case.sha256.as_slice()))
        .collect();
    compare_entries("openssl", &entries, &ours)
}

/// Export a `.sha256` for the files, then make `sha256sum -c` verify it.
///
/// This is the direction that is easy to leave untested: our parser can read
/// everyone else's file while our exporter writes one no other tool accepts.
fn check_sha256sum_verify(tool: &Path, dir: &Path, cases: &[Case]) -> Result<usize, String> {
    let entries: Vec<FileSum> = cases
        .iter()
        .map(|case| FileSum {
            path: case.name.to_string(),
            digest: case.sha256.clone(),
        })
        .collect();
    let options = ExportOptions {
        upper: false,
        banner: false,
        ..ExportOptions::default()
    };
    let text = export(&entries, ExportFormat::Sumfile, &options);

    // The settings asked for lowercase and forward slashes, so the produced
    // bytes must show that, not merely the digest values being right.
    if text.to_ascii_lowercase() != text {
        return Err(format!("our .sha256 export is not lowercase:\n{text}"));
    }
    if text.contains('\\') {
        return Err(format!(
            "our .sha256 export contains a backslash path:\n{text}"
        ));
    }

    let path = dir.join("ours.sha256");
    std::fs::write(&path, &text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;

    let mut cmd = Command::new(tool);
    cmd.current_dir(dir).args(["-c", "ours.sha256"]);
    let out = run_capture(cmd, "sha256sum -c")?;
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut unconfirmed: Vec<&str> = Vec::new();
    for case in cases {
        let want = format!("{}: OK", case.name);
        if !stdout.lines().any(|line| line.trim_end() == want.as_str()) {
            unconfirmed.push(case.name);
        }
    }
    if !unconfirmed.is_empty() {
        return Err(format!(
            "sha256sum -c did not confirm {} file(s) from our export: {unconfirmed:?}\n{stdout}",
            unconfirmed.len()
        ));
    }
    Ok(cases.len())
}

/// What the SFV checks established.
struct SfvReport {
    /// Entries that survived export → parse round-trip.
    round_trip: usize,
    /// Entries whose CRC32 matched 7-Zip's, when 7-Zip was available.
    crc32_vs_7z: Option<usize>,
}

/// Export an SFV, parse it back, and cross-check its CRC32 values with `7z`.
///
/// 7-Zip cannot write an SFV, so there is no producer/consumer pair to use the
/// way there is for `.sha256`. Its `h -scrcCRC32` hash listing is still an
/// external authority for the numbers, which is what the SFV would be wrong
/// about.
fn check_sfv(cases: &[Case], dir: &Path, seven_zip: Option<&Path>) -> Result<SfvReport, String> {
    let entries: Vec<FileSum> = cases
        .iter()
        .map(|case| FileSum {
            path: case.name.to_string(),
            digest: case.crc32.clone(),
        })
        .collect();
    let options = ExportOptions {
        banner: false,
        ..ExportOptions::default()
    };
    let text = export(&entries, ExportFormat::Sfv, &options);
    let parsed = parse_tool_output(&text, "our SFV export")?;
    let ours: Vec<(&str, &[u8])> = cases
        .iter()
        .map(|case| (case.name, case.crc32.as_slice()))
        .collect();
    let round_trip = compare_entries("our SFV parse", &parsed, &ours)?;

    let crc32_vs_7z = match seven_zip {
        Some(tool) => Some(check_sfv_against_7z(tool, dir, &parsed)?),
        None => None,
    };
    Ok(SfvReport {
        round_trip,
        crc32_vs_7z,
    })
}

/// Compare the CRC32 values read back from our SFV with 7-Zip's listing.
fn check_sfv_against_7z(tool: &Path, dir: &Path, entries: &[FileSum]) -> Result<usize, String> {
    let mut cmd = Command::new(tool);
    cmd.current_dir(dir).args(["h", "-scrcCRC32"]);
    for entry in entries {
        cmd.arg(&entry.path);
    }
    let out = run_capture(cmd, "7z h -scrcCRC32")?;
    let raw = String::from_utf8_lossy(&out.stdout);
    let rows = parse_7z_crc32(&raw);
    if rows.is_empty() {
        return Err(format!("7z printed no CRC32 rows:\n{raw}"));
    }

    let mut differences: Vec<String> = Vec::new();
    let mut passed = 0usize;
    for entry in entries {
        let ours = hex::encode_upper(&entry.digest);
        match rows
            .iter()
            .find(|(name, _)| matches_file(name, &entry.path))
        {
            Some((_, theirs)) if theirs == &ours => passed += 1,
            Some((_, theirs)) => {
                differences.push(format!("  {}: our SFV = {ours}  7z = {theirs}", entry.path))
            }
            None => differences.push(format!("  {}: 7z reported no CRC32 row", entry.path)),
        }
    }
    if differences.is_empty() {
        Ok(passed)
    } else {
        Err(format!("7z CRC32 differences:\n{}", differences.join("\n")))
    }
}

/// Extract `(name, CRC32)` rows from `7z h -scrcCRC32` output.
///
/// The detail table is fixed-width: eight uppercase CRC32 hex digits, a
/// right-aligned size, then **two spaces** and the name. Splitting the whole
/// line on whitespace would truncate a name that contains spaces, so only the
/// size column is consumed, up to that two-space separator.
///
/// Two rows are not files and must be ignored: the aggregate summary
/// (`AC02426B-00000001           350  `, whose first column is more than eight
/// digits) and the per-file summary (same CRC again, but no name). Requiring a
/// non-empty name after the size is what excludes the latter.
fn parse_7z_crc32(text: &str) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let bytes = line.as_bytes();
        if bytes.len() < 12 || !bytes[..8].iter().all(u8::is_ascii_hexdigit) || bytes[8] != b' ' {
            continue;
        }
        let crc = line[..8].to_ascii_uppercase();
        let rest = line[8..].trim_start();
        let Some((size, name)) = rest.split_once("  ") else {
            continue;
        };
        let size_ok = !size.is_empty() && size.chars().all(|c| c.is_ascii_digit() || c == ',');
        if size_ok && !name.is_empty() {
            rows.push((name.to_string(), crc));
        }
    }
    rows
}

/// Export a corz `.hash` file and parse it back.
///
/// There is no external tool to hand this format to, so this only proves the
/// exporter and parser agree. That is weaker than the checks above, and the
/// output says so instead of implying otherwise.
fn check_corz(cases: &[Case]) -> Result<usize, String> {
    let entries: Vec<FileSum> = cases
        .iter()
        .map(|case| FileSum {
            path: case.name.to_string(),
            digest: case.sha256.clone(),
        })
        .collect();
    let options = ExportOptions {
        upper: false,
        banner: false,
        corz_compatible: true,
        algorithm_label: "sha256".to_string(),
        ..ExportOptions::default()
    };
    let text = export(&entries, ExportFormat::DotHash, &options);
    let parsed = parse_tool_output(&text, "our corz .hash export")?;
    let ours: Vec<(&str, &[u8])> = cases
        .iter()
        .map(|case| (case.name, case.sha256.as_slice()))
        .collect();
    compare_entries("our corz .hash parse", &parsed, &ours)
}

/// Candidate absolute paths for `exe` under each install root.
///
/// Pure so the path construction is unit-testable without the real machine
/// having those directories. `roots` is `[ProgramFiles, ProgramFiles(x86)]` in
/// production.
fn candidate_paths(exe: &str, rel_dirs: &[&str], roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(roots.len());
    for root in roots {
        let mut path = root.clone();
        for dir in rel_dirs {
            path.push(dir);
        }
        path.push(exe);
        candidates.push(path);
    }
    candidates
}

/// The install roots named by one environment variable, if it is set.
fn vendor_roots(var: &str) -> Vec<PathBuf> {
    match std::env::var_os(var) {
        Some(value) => vec![PathBuf::from(value)],
        None => Vec::new(),
    }
}

/// Look for `exe` under `<ProgramFiles>\<rel_dirs>\` and the x86 variant.
fn find_installed(exe: &str, rel_dirs: &[&str]) -> Option<PathBuf> {
    let roots: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)"]
        .into_iter()
        .flat_map(vendor_roots)
        .collect();
    candidate_paths(exe, rel_dirs, &roots)
        .into_iter()
        .find(|path| path.is_file())
}

/// Locate `sha256sum`: `PATH` first, then Git for Windows' MSYS bin directory.
fn find_sha256sum() -> Option<PathBuf> {
    crate::verify::find("sha256sum")
        .or_else(|| find_installed("sha256sum.exe", &["Git", "usr", "bin"]))
}

/// Locate `7z`: `PATH` first, then 7-Zip's default install directory.
fn find_seven_zip() -> Option<PathBuf> {
    crate::verify::find("7z").or_else(|| find_installed("7z.exe", &["7-Zip"]))
}

/// Running tally of the cross-checks.
#[derive(Default)]
struct Report {
    /// Individual comparisons that agreed.
    passed: usize,
    /// Checks that failed; each one is reported with its differences.
    failed: usize,
    /// Checks that could not run because a tool was absent.
    skipped: Vec<String>,
    /// Human-readable descriptions of every failure.
    mismatches: Vec<String>,
}

impl Report {
    /// Record a passing check and print its result line.
    fn ok(&mut self, label: &str, passed: usize) {
        self.passed += passed;
        println!("  {label:<40} OK   ({passed} entries)");
    }

    /// Record a check that ran, printing OK or FAIL from its result.
    fn check(&mut self, label: &str, result: Result<usize, String>) {
        match result {
            Ok(passed) => self.ok(label, passed),
            Err(message) => {
                self.fail(message);
                println!("  {label:<40} FAIL");
            }
        }
    }

    /// Record a failure with the details that explain it.
    fn fail(&mut self, message: String) {
        self.failed += 1;
        self.mismatches.push(message);
    }

    /// Record a check that could not run.
    fn skip(&mut self, message: String) {
        self.skipped.push(message);
    }
}

/// A missing tool: fatal under `--require-tools`, a skip otherwise.
fn missing_tool(report: &mut Report, require_tools: bool, tool: &str) {
    if require_tools {
        report.fail(format!(
            "--require-tools: {tool} not found on PATH or in its known install location"
        ));
    } else {
        report.skip(format!(
            "{tool} not found: the checks needing it were skipped"
        ));
    }
}

/// Print where a tool was found, or that it was not.
fn print_tool(tool: &str, path: Option<&Path>) {
    match path {
        Some(path) => println!("  {tool:<10} {}", path.display()),
        None => println!("  {tool:<10} not found"),
    }
}

/// Print the skip list, the mismatch details and the statistics line.
fn print_summary(report: &Report) {
    if !report.skipped.is_empty() {
        println!("\nSkipped:");
        for message in &report.skipped {
            println!("  {message}");
        }
    }
    if !report.mismatches.is_empty() {
        println!("\nSUMFILE MISMATCHES:");
        for message in &report.mismatches {
            println!("  {message}");
        }
    }
    println!(
        "\nSumfile cross-check: {} comparisons passed, {} failed, {} skipped.",
        report.passed,
        report.failed,
        report.skipped.len()
    );
}

/// Entry point, called by [`crate::verify::run`] after the digest differentials.
///
/// Returns whether every check that could run passed. A missing required tool
/// and any "ours vs tool" difference count as failure; a missing `7z` does not.
pub(crate) fn run(require_tools: bool, openssl: Option<&Path>) -> bool {
    let mut report = Report::default();
    println!("\n=== real checksum files: our parser/exporter vs external tools ===");

    let sha256sum = find_sha256sum();
    let seven_zip = find_seven_zip();
    print_tool("sha256sum", sha256sum.as_deref());
    print_tool("openssl", openssl);
    print_tool("7z", seven_zip.as_deref());

    if sha256sum.is_none() {
        missing_tool(&mut report, require_tools, "sha256sum");
    }
    if openssl.is_none() {
        missing_tool(&mut report, require_tools, "openssl");
    }
    if seven_zip.is_none() {
        report.skip(
            "7z not found: SFV CRC32 values are only checked against our CRC32 implementation; \
             CRC32 itself already has a published-check-value authority in the algorithm layer"
                .to_string(),
        );
    }

    let (dir, cases) = match setup("sumfile") {
        Ok(setup) => setup,
        Err(message) => {
            report.fail(message);
            print_summary(&report);
            return report.failed == 0;
        }
    };

    if let Some(tool) = sha256sum.as_deref() {
        report.check(
            "sha256sum parse vs our SHA-256",
            check_sha256sum_parse(tool, dir.path(), &cases),
        );
        report.check(
            "our .sha256 export via sha256sum -c",
            check_sha256sum_verify(tool, dir.path(), &cases),
        );
    }
    if let Some(tool) = openssl {
        report.check(
            "openssl dgst parse vs our SHA-256",
            check_openssl_parse(tool, dir.path(), &cases),
        );
    }

    match check_sfv(&cases, dir.path(), seven_zip.as_deref()) {
        Ok(sfv) => {
            report.ok("SFV export → parse round-trip", sfv.round_trip);
            if let Some(passed) = sfv.crc32_vs_7z {
                report.ok("SFV CRC32 vs 7z", passed);
            }
        }
        Err(message) => report.fail(message),
    }
    report.check("corz .hash export → parse round-trip", check_corz(&cases));
    println!(
        "  note: corz .hash has no external producer here; that round-trip proves \
         exporter and parser agree, not that a third tool would accept the file."
    );

    print_summary(&report);
    report.failed == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Real 7-Zip 25.01 output for the four scratch files, verbatim apart from
    /// the paths. Both summary rows are present: they are the trap.
    const SEVEN_ZIP_SAMPLE: &str = "\
7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03

Scanning
4 files, 350 bytes (1 KiB)

CRC32             Size  Name
-------- -------------  ------------
09ED66EC           100  plain.txt
ED086180           200  with space.txt
B50C79FF            50  hash#tag.txt
00000000             0  empty.dat
-------- -------------  ------------
AC02426B-00000001           350  

Files: 4
Size: 350

CRC32  for data:              AC02426B-00000001
CRC32  for data and names:    4B124137-00000002

Everything is Ok
";

    #[test]
    fn seven_zip_rows_keep_names_and_skip_summaries() {
        let rows = parse_7z_crc32(SEVEN_ZIP_SAMPLE);
        assert_eq!(
            rows,
            vec![
                ("plain.txt".to_string(), "09ED66EC".to_string()),
                ("with space.txt".to_string(), "ED086180".to_string()),
                ("hash#tag.txt".to_string(), "B50C79FF".to_string()),
                ("empty.dat".to_string(), "00000000".to_string()),
            ]
        );
    }

    /// Lowercase hex is normalised, because the comparison against our CRC32 is
    /// on the value, not on 7-Zip's formatting.
    #[test]
    fn seven_zip_rows_normalise_crc_case() {
        let rows = parse_7z_crc32("09ed66ec           100  f.txt\n");
        assert_eq!(rows, vec![("f.txt".to_string(), "09ED66EC".to_string())]);
    }

    #[test]
    fn seven_zip_header_and_empty_tables_yield_no_rows() {
        for text in [
            "",
            "CRC32             Size  Name\n-------- -------------  ------------\n",
            "CRC32  for data:              AC02426B-00000001\n",
            // The per-file summary row: a valid CRC and size, but no name.
            "09ED66EC           100  \n",
        ] {
            assert!(
                parse_7z_crc32(text).is_empty(),
                "unexpected rows for {text:?}"
            );
        }
    }

    #[test]
    fn candidate_paths_are_built_under_each_install_root() {
        let roots = vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        assert_eq!(
            candidate_paths("sha256sum.exe", &["Git", "usr", "bin"], &roots),
            vec![
                PathBuf::from(r"C:\Program Files\Git\usr\bin\sha256sum.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Git\usr\bin\sha256sum.exe"),
            ]
        );
        assert!(candidate_paths("7z.exe", &["7-Zip"], &[]).is_empty());
    }

    #[test]
    fn scratch_directory_names_are_tagged_and_unique() {
        let a = scratch_dir_name("sumfile", 4242, 0);
        let b = scratch_dir_name("sumfile", 4242, 1);
        assert!(a.contains("sumfile"));
        assert_ne!(a, b, "two runs must not share a scratch directory");
    }

    #[test]
    fn scratch_payloads_are_deterministic() {
        assert_eq!(file_bytes(1, 64), file_bytes(1, 64));
        assert_eq!(file_bytes(1, 64).len(), 64);
        assert_ne!(file_bytes(1, 64), file_bytes(2, 64));
        assert!(file_bytes(7, 0).is_empty());
    }

    #[test]
    fn matching_accepts_a_tool_echoing_its_own_path() {
        assert!(matches_file("plain.txt", "plain.txt"));
        assert!(matches_file("sub/plain.txt", "plain.txt"));
        assert!(!matches_file("other.txt", "plain.txt"));
        // openssl echoes the absolute path it was given.
        #[cfg(windows)]
        assert!(matches_file(r"C:\Temp\x\plain.txt", "plain.txt"));
    }

    #[test]
    fn compare_entries_reports_missing_and_extra_lines() {
        let ours: [(&str, &[u8]); 2] = [("a.txt", &[0xAA]), ("b.txt", &[0xBB])];
        let parsed = vec![
            FileSum {
                path: "a.txt".to_string(),
                digest: vec![0xAA],
            },
            FileSum {
                path: "c.txt".to_string(),
                digest: vec![0xCC],
            },
        ];
        let error = compare_entries("tool", &parsed, &ours).expect_err("b is missing, c is extra");
        assert!(error.contains("b.txt: tool reported no entry"), "{error}");
        assert!(
            error.contains("c.txt: unexpected entry from tool"),
            "{error}"
        );
        assert!(!error.contains("a.txt"), "a.txt matched: {error}");
    }

    #[test]
    fn compare_entries_reports_both_sides_on_a_digest_mismatch() {
        let ours: [(&str, &[u8]); 1] = [("a.txt", &[0xAA])];
        let parsed = vec![FileSum {
            path: "a.txt".to_string(),
            digest: vec![0xAB],
        }];
        let error = compare_entries("tool", &parsed, &ours).expect_err("digests differ");
        assert!(error.contains("ours = aa"), "{error}");
        assert!(error.contains("tool = ab"), "{error}");
    }

    /// `--require-tools` is the difference between "CI ran this" and "CI could
    /// not run this but reported success". Only `sha256sum` and `openssl` are
    /// required; a test keeps the two outcomes from being swapped.
    #[test]
    fn missing_tools_fail_only_when_required() {
        let mut report = Report::default();
        missing_tool(&mut report, true, "openssl");
        assert_eq!(report.failed, 1);
        assert!(report.skipped.is_empty());

        let mut report = Report::default();
        missing_tool(&mut report, false, "openssl");
        assert_eq!(report.failed, 0);
        assert_eq!(report.skipped.len(), 1);
    }
}
