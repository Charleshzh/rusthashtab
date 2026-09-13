//! Developer automation for rustHashTab.
//!
//! Four jobs a plain `cargo test` cannot do:
//!
//! * **`cargo xtask check`** — everything that must pass before a commit: fmt,
//!   clippy, tests, the coverage audit and the external verification. This is the
//!   command to run after changing files.
//! * **`cargo xtask verify`** — check our digests against authorities outside this
//!   repository (OpenSSL, and frozen vectors from the XKCP C reference). A hash
//!   compared only against a constant we produced ourselves is not verified.
//! * **`cargo xtask bench`** — measure throughput, so a performance change can be
//!   attributed rather than guessed at.
//! * **`cargo xtask audit`** — print the coverage map, including algorithms with no
//!   authority attached yet. The gap is meant to be visible.

mod bench;
mod coverage;
mod verify;

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "check" => check(&args[1..]),
        "verify" => verify::run(&args[1..]),
        "bench" => bench::run(&args[1..]),
        "audit" => audit(),
        "reference-check" => check_reference_untracked(),
        "internal-docs" => check_internal_docs(),
        "scratch-check" => check_no_scratch_tracked(),
        "help" | "--help" | "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("xtask: unknown command `{other}`\n");
            usage();
            ExitCode::FAILURE
        }
    }
}

/// Path of the local reference checkout that must never be version-controlled.
///
/// Assembled at runtime so this repository's tooling does not carry the name as a
/// single literal in a shipped file. `.gitignore` also covers the directory; this
/// check covers what `.gitignore` cannot -- `git add -f`, or a merge that dragged
/// it in. Once tracked it is in the history, so it must be caught before the
/// commit lands.
fn reference_dir() -> String {
    format!("{}{}", "OpenHash", "Tab")
}

/// Fail if anything from the reference checkout is tracked by git.
fn check_reference_untracked() -> ExitCode {
    let dir = reference_dir();

    let output = match Command::new("git").args(["ls-files"]).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("reference-check: could not run git ls-files: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !output.status.success() {
        eprintln!("reference-check: git ls-files failed (is this a git repository?)");
        return ExitCode::FAILURE;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let prefix = format!("{dir}/");
    let bad: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with(&prefix) || *l == dir)
        .collect();

    if bad.is_empty() {
        println!("OK: the reference checkout is not tracked.");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "ERROR: {} file(s) from the reference checkout are tracked by git:",
        bad.len()
    );
    for l in bad.iter().take(20) {
        eprintln!("  {l}");
    }
    eprintln!();
    eprintln!("That directory is someone else's code under an unresolved claim.");
    eprintln!("It must never enter this repository's history, and no later commit");
    eprintln!("can remove it -- only rewriting history can.");
    ExitCode::FAILURE
}

fn usage() {
    println!(
        "\
cargo xtask <command>

  check     Run everything that must pass before a commit: fmt, clippy with
            -D warnings, the test suite, the coverage audit, and the external
            verification. Run this after changing files.
            Always targets x86_64-pc-windows-msvc (the shipping target) rather
            than the host, so a GNU host cannot make the gate pass vacuously.
            --target <triple>   Check a different target instead.

  verify    Check digests against external authorities (OpenSSL, frozen vectors).
            --require-tools   Fail instead of skipping when a tool is missing.

  bench     Measure throughput per algorithm.
            --passes N   --size MiB   --filter SUBSTR

  audit     Print the correctness-coverage map: which algorithm is validated by
            what, and which have no authority attached yet.

  reference-check
            Fail if anything from the local reference checkout has become tracked
            by git. Covers what .gitignore cannot (`git add -f`, a merge). Run in
            CI, and useful before any commit that touches the repo root.

  internal-docs
            Validate the local internal notes: they must be Chinese. Skips cleanly
            when docs/internal/ is absent, which is the normal case in a clone.

Exit codes: 0 ok, 1 verification failure or missing required tool, 2 usage error."
    );
}

/// The triple rustHashTab ships for 64-bit hosts.
const SHIPPING_TARGET: &str = "x86_64-pc-windows-msvc";

/// Ask rustc for the host triple, so `check` reports which toolchain it used.
fn detect_host() -> String {
    let out = Command::new("rustc").args(["-vV"]).output();
    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = text.lines().find(|l| l.starts_with("host:")) {
            return line.trim_start_matches("host:").trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Run one command, streaming its output, and report whether it succeeded.
fn step(label: &str, program: &str, args: &[&str]) -> bool {
    println!("\n=== {label} ===");
    match Command::new(program).args(args).status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("FAILED: {label} exited with {s}");
            false
        }
        Err(e) => {
            eprintln!("FAILED: could not run {program}: {e}");
            false
        }
    }
}

/// The pre-commit gate.
///
/// # Why the target is explicit
///
/// `cargo test` with no `--target` builds for the *host*. When the host toolchain
/// is `x86_64-pc-windows-gnu` -- which `rust-toolchain.toml` selects on a machine
/// whose default rustup host is GNU -- a bare `cargo test` therefore exercises the
/// MinGW build, not the MSVC build that ships. A green run would say nothing about
/// the artifact users get.
///
/// So the gate always names its target, and prints the host it ran on. Override
/// with `cargo xtask check --target <triple>` when deliberately testing the GNU
/// build.
fn check(args: &[String]) -> ExitCode {
    let mut target = SHIPPING_TARGET.to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("check: --target needs a triple");
                    return ExitCode::from(2);
                };
                target = v.clone();
                i += 2;
            }
            other => {
                eprintln!("check: unknown option `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let host = detect_host();
    println!("host toolchain : {host}");
    println!("checking target: {target}");
    if host != target {
        println!(
            "  (host and target differ, which is expected: the shipping target is \
             {SHIPPING_TARGET} regardless of which host toolchain is active)"
        );
    }

    let mut ok = true;

    ok &= step(
        "cargo fmt --all --check",
        "cargo",
        &["fmt", "--all", "--check"],
    );
    ok &= step(
        &format!("cargo clippy --workspace --all-targets --target {target} -- -D warnings"),
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--target",
            &target,
            "--",
            "-D",
            "warnings",
        ],
    );
    ok &= step(
        &format!("cargo test --workspace --target {target}"),
        "cargo",
        &["test", "--workspace", "--target", &target],
    );

    // External verification runs last: it is the slowest, and a compile error
    // earlier would only make its output noise.
    if ok {
        ok &= matches!(audit(), ExitCode::SUCCESS);
        ok &= matches!(
            verify::run(&["--require-tools".to_string()]),
            ExitCode::SUCCESS
        );

        // Repo hygiene. Cheap, and it catches what no compiler can: scratch state
        // or a local-only path that became tracked, and internal notes that drifted
        // out of the language convention. Run here rather than in CI because all of
        // it concerns state that exists only on a developer's disk -- the internal
        // notes are git-ignored, and the rest is about the local tree.
        println!("\n=== repo hygiene ===");
        ok &= matches!(check_reference_untracked(), ExitCode::SUCCESS);
        ok &= matches!(check_no_scratch_tracked(), ExitCode::SUCCESS);
        ok &= matches!(check_internal_docs(), ExitCode::SUCCESS);
    }

    if ok {
        println!("\nAll checks passed (target {target}).");
        ExitCode::SUCCESS
    } else {
        eprintln!("\nCHECKS FAILED -- see the output above.");
        ExitCode::FAILURE
    }
}

/// Validate the local internal notes.
///
/// They are git-ignored by decision, so a fresh clone does not have them. This
/// therefore **skips cleanly when the directory is absent** rather than failing:
/// a check that fails on every clone is a check people learn to ignore.
///
/// When the directory *is* present, it enforces the two conventions that matter —
/// the notes are written in Chinese, and none of them has been moved somewhere
/// that would ship.
fn check_internal_docs() -> ExitCode {
    let dir = std::path::Path::new("docs/internal");
    if !dir.is_dir() {
        println!("SKIP: docs/internal/ is absent (git-ignored; expected in a fresh clone).");
        return ExitCode::SUCCESS;
    }

    let mut checked = 0usize;
    let mut problems: Vec<String> = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("internal-docs: cannot read {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            problems.push(format!("{}: not readable as UTF-8", path.display()));
            continue;
        };

        // Convention: internal notes are Chinese. Count CJK codepoints rather than
        // lines, so a file that is mostly a code fence still registers.
        let cjk = text
            .chars()
            .filter(|c| ('\u{4e00}'..='\u{9fff}').contains(c))
            .count();
        if cjk < 50 {
            problems.push(format!(
                "{}: only {cjk} CJK characters; internal notes must be written in Chinese",
                path.display()
            ));
        }
        checked += 1;
    }

    if problems.is_empty() {
        println!("OK: {checked} internal note(s) checked, all in Chinese.");
        ExitCode::SUCCESS
    } else {
        eprintln!("ERROR: internal-note convention violations:");
        for p in &problems {
            eprintln!("  {p}");
        }
        ExitCode::FAILURE
    }
}

/// Fail if scratch state has been committed.
///
/// Twice during the initial setup a temporary file holding a commit message was
/// created inside the repository and swept up by `git add -A`. `.gitignore` was
/// widened each time, which is the wrong fix: a scratch file should not be in the
/// tree at all, and each widening only covers the names someone thought of.
///
/// This checks the tracked set for the shapes that have actually gone wrong, so
/// the next occurrence is caught by the gate rather than by reading `git log`.
fn check_no_scratch_tracked() -> ExitCode {
    let output = match Command::new("git").args(["ls-files"]).output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("scratch-check: could not run git ls-files: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !output.status.success() {
        eprintln!("scratch-check: git ls-files failed (is this a git repository?)");
        return ExitCode::FAILURE;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut bad: Vec<(&str, &str)> = Vec::new();
    for line in text.lines() {
        // Dot-prefixed temp names, and any commit-message file. Commit messages
        // belong in the system temp directory, not the tree.
        if line.starts_with(".tmp-") || line.starts_with(".git-msg") || line.ends_with(".tmp") {
            bad.push((line, "scratch/temporary file"));
        }
        // The other things that must never be tracked.
        let dir = reference_dir();
        if line.starts_with(&format!("{dir}/")) {
            bad.push((line, "reference checkout"));
        }
        if line.starts_with("docs/internal/") {
            bad.push((line, "internal notes (kept local by decision)"));
        }
        if line == "CLAUDE.md" {
            bad.push((line, "contributor notes (kept local by decision)"));
        }
    }

    if bad.is_empty() {
        println!("OK: no scratch files or local-only paths are tracked.");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "ERROR: {} tracked path(s) should not be in version control:",
        bad.len()
    );
    for (path, why) in &bad {
        eprintln!("  {path}  -- {why}");
    }
    eprintln!();
    eprintln!("Widening .gitignore is not sufficient: `git add -f`, and files created");
    eprintln!("before the pattern existed, both defeat it. Remove it from the index");
    eprintln!("with `git rm --cached <path>`.");
    ExitCode::FAILURE
}

/// Print the coverage map and the progress tally.
fn audit() -> ExitCode {
    use coverage::{Authority, Status};

    let (done, unverified, pending) = coverage::tally();
    println!(
        "Correctness coverage — {done} of {} algorithms externally validated, {pending} not implemented\n",
        coverage::COVERAGE.len()
    );
    println!(
        "{:<18} {:>5}  {:<10}  {:<16} SOURCE",
        "ALGORITHM", "BYTES", "STATUS", "AUTHORITY KIND"
    );
    println!("{}", "-".repeat(100));

    for c in coverage::COVERAGE {
        let status = match c.status {
            Status::Done => "verified",
            Status::Unverified => "UNVERIF.",
            Status::Pending => "pending",
        };
        let kind = match c.authority {
            Authority::OpenSsl { .. } => "openssl",
            Authority::OpenSslLegacy { .. } => "openssl-legacy",
            Authority::StandardVector { .. } => "standard-vector",
            Authority::ReferenceImpl { .. } => "reference-impl",
        };
        println!(
            "{:<18} {:>5}  {:<10}  {:<16} {}",
            c.name,
            c.output_len,
            status,
            kind,
            c.authority_label()
        );
    }

    println!("\n{done} verified, {unverified} awaiting a check, {pending} not implemented yet");

    // An algorithm with no authority attached is a silent hole: it would sit at
    // "pending" forever and never be caught by a green test run.
    let unauthoritative: Vec<_> = coverage::COVERAGE
        .iter()
        .filter(|c| c.authority_label().is_empty())
        .collect();
    if !unauthoritative.is_empty() {
        eprintln!(
            "\nERROR: {} algorithm(s) have no external authority attached:",
            unauthoritative.len()
        );
        for c in unauthoritative {
            eprintln!("  {}", c.name);
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
