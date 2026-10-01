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
    // A raw string, not a line-continuation puzzle: the usage text has blank
    // lines in it, and `\` at end of line eats them. `#` elsewhere in the text
    // means the delimiter needs only one hash.
    println!(
        r#"
cargo xtask <command>

  check     Run everything that must pass before a commit: fmt, clippy with
            -D warnings, the test suite, the coverage audit, and the external
            verification. Run this after changing files.
            Names every supported target explicitly rather than trusting the
            host, so a GNU host cannot make the gate pass vacuously, and lints
            all three triples so a 32-bit-only compile error cannot hide.
            --target <triple>   Check only that target.

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

Exit codes: 0 ok, 1 verification failure or missing required tool, 2 usage error."#
    );
}

/// The triple rustHashTab ships for 64-bit hosts.
const SHIPPING_TARGET: &str = "x86_64-pc-windows-msvc";

/// Every triple we claim to support, shipping triple first.
///
/// `check` compiles all of them. Compiling only the shipping triple is how the
/// i686 build stayed broken with a green gate: `MESSAGE_MAGIC` was a 64-bit
/// literal in a `usize` context, which is a plain `error: literal out of range`
/// on a 32-bit target and therefore invisible to any x86_64-only run. Type-level
/// target bugs are exactly what the compiler catches and a code review does not.
const SUPPORTED_TARGETS: &[&str] = &[
    SHIPPING_TARGET,
    "i686-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

/// The minimum number of Chinese lines a bilingual README must carry.
///
/// Set well above a stray CJK character (someone's name in a contributors list)
/// and well below the real count, so it catches "the translation is gone" without
/// becoming a number that has to be tuned on every edit.
const MIN_README_CJK_LINES: usize = 40;

/// Sections whose tables already pair both languages on every row, so their body
/// is exempt from the "some line must be Chinese" rule.
const TABLE_ONLY_SECTIONS: &[&str] = &["## Algorithms / 算法", "## Project layout / 项目结构"];

/// Whether built test binaries for `target` can execute on this host.
///
/// The comparison is on **architecture**, not on the full triple, and that
/// distinction is the whole point. A GNU host builds `x86_64-pc-windows-msvc`
/// test binaries that run perfectly well: both are x86_64 PE binaries, and the
/// only difference is which CRT they link (msvcrt vs ucrt/msvcrt), which does not
/// stop the loader. Comparing whole triples would silently downgrade the shipping
/// target's tests to a link-only check on this machine -- the exact vacuous-gate
/// failure this command exists to prevent.
///
/// This is deliberately conservative otherwise. Only the host architecture, and
/// 32-bit x86 on any x86 host (WOW64 runs those natively), count. aarch64 test
/// binaries are linted and linked but never run, because running them would need
/// an emulator that a plain `cargo test` does not use.
fn target_is_runnable(target: &str, host: &str) -> bool {
    let (t_arch, h_arch) = (arch_of(target), arch_of(host));

    if t_arch == h_arch {
        return true;
    }
    // 32-bit x86 binaries run natively on a 64-bit x86 Windows host via WOW64.
    t_arch == "i686" && h_arch == "x86_64"
}

/// The architecture component of a target triple, e.g. `x86_64`.
///
/// Every triple rustc accepts starts with its architecture and then a hyphen, so
/// this does not need a table. A triple with no hyphen is returned unchanged: it
/// is malformed, and returning it makes the comparison above simply fail closed
/// rather than silently treating it as runnable.
fn arch_of(triple: &str) -> &str {
    triple.split('-').next().unwrap_or(triple)
}

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
/// # Why the targets are explicit
///
/// `cargo test` with no `--target` builds for the *host*. When the host toolchain
/// is `x86_64-pc-windows-gnu` -- which `rust-toolchain.toml` selects on a machine
/// whose default rustup host is GNU -- a bare `cargo test` therefore exercises the
/// MinGW build, not the MSVC build that ships. A green run would say nothing about
/// the artifact users get.
///
/// So the gate always names its targets, and prints the host it ran on. It lints
/// **every** supported triple, and runs tests wherever the built binaries can
/// actually execute.
///
/// Restrict it with `--target <triple>` when iterating on one platform; an
/// intentionally non-supported triple (e.g. the GNU build) is still accepted, but
/// only that triple is checked.
fn check(args: &[String]) -> ExitCode {
    let mut requested: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("check: --target needs a triple");
                    return ExitCode::from(2);
                };
                requested = Some(v.clone());
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

    let targets: Vec<String> = match requested {
        Some(t) => vec![t],
        None => SUPPORTED_TARGETS.iter().map(|t| (*t).to_string()).collect(),
    };

    // `cargo fmt` is target-independent: it parses, it does not compile. Run it
    // last so a formatting failure cannot mask a compile or test failure the way
    // an early `&&` would -- all the failures should be visible in one run.
    let mut ok = true;

    for target in &targets {
        let runnable = target_is_runnable(target, &host);
        println!(
            "\n--- target {target} ({}) ---",
            if runnable {
                "lint + test"
            } else {
                "lint only; test binaries cannot run on this host"
            }
        );

        ok &= step(
            &format!("cargo clippy --workspace --all-targets --target {target} -- -D warnings"),
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--target",
                target,
                "--",
                "-D",
                "warnings",
            ],
        );

        if runnable {
            ok &= step(
                &format!("cargo test --workspace --target {target}"),
                "cargo",
                &["test", "--workspace", "--target", target],
            );
        } else {
            // Still build the test harness for this triple: `clippy --all-targets`
            // type-checks it, but `cargo test --no-run` links it, and link errors
            // are target-specific too.
            ok &= step(
                &format!("cargo test --workspace --no-run --target {target}"),
                "cargo",
                &["test", "--workspace", "--no-run", "--target", target],
            );
        }
    }

    ok &= step(
        "cargo fmt --all --check",
        "cargo",
        &["fmt", "--all", "--check"],
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
        ok &= matches!(check_readme_bilingual(), ExitCode::SUCCESS);
    }

    if ok {
        let list = targets.join(", ");
        println!("\nAll checks passed (targets: {list}).");
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

/// Enforce that `README.md` stays bilingual.
///
/// English is authoritative and the Chinese half must be kept in sync. That is
/// easy to forget in a single-language edit, and nothing else catches it: the
/// file is prose, so no compiler and no test looks at it.
///
/// This duplicates the CI check in `.github/workflows/ci.yml` on purpose. A rule
/// that is only enforced in CI fails *after* the push, on the slowest possible
/// feedback loop, so the local gate should catch it first. CI keeps its own copy
/// because a gate a contributor can skip is not an enforcement mechanism.
///
/// The rules are deliberately shape-based rather than semantic. A section counts
/// as translated when *some* line in it carries CJK text, which catches a wholly
/// untranslated section but not a half-translated one. That is the honest limit
/// of a check that cannot read: it is a reminder to sync the two halves, not a
/// proof that they agree.
fn check_readme_bilingual() -> ExitCode {
    let Ok(text) = std::fs::read_to_string("README.md") else {
        eprintln!("ERROR: README.md is missing or not valid UTF-8.");
        return ExitCode::FAILURE;
    };

    let has_cjk = |s: &str| s.chars().any(|c| matches!(c, '\u{4e00}'..='\u{9fff}'));

    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        eprintln!("ERROR: README.md is empty.");
        return ExitCode::FAILURE;
    }

    // A body of text with no Chinese in it at all means the translation is simply
    // absent, which is a more useful message than listing every section.
    let cjk_lines = lines.iter().filter(|l| has_cjk(l)).count();
    if cjk_lines < MIN_README_CJK_LINES {
        eprintln!(
            "ERROR: README.md looks untranslated: only {cjk_lines} lines carry Chinese text \
             (expected at least {MIN_README_CJK_LINES})."
        );
        return ExitCode::FAILURE;
    }

    // Section headings are ASCII on purpose: anchors depend on them, and matching
    // them needs no Unicode classes.
    let headings: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.starts_with("## "))
        .collect();
    if headings.is_empty() {
        eprintln!("ERROR: README.md has no level-2 sections.");
        return ExitCode::FAILURE;
    }

    let mut problems: Vec<&str> = Vec::new();
    for (i, heading) in headings.iter().enumerate() {
        // Table-only sections pair both languages per row, so a Chinese line is not
        // guaranteed to exist in any given slice of them.
        if TABLE_ONLY_SECTIONS.contains(heading) {
            continue;
        }
        let start = lines.iter().position(|l| l == heading).unwrap_or(0) + 1;
        let end = headings
            .get(i + 1)
            .and_then(|next| lines.iter().position(|l| l == next))
            .unwrap_or(lines.len());
        if start < end && !lines[start..end].iter().any(|l| has_cjk(l)) {
            problems.push(heading);
        }
    }

    if problems.is_empty() {
        println!(
            "OK: README.md is bilingual ({cjk_lines} Chinese lines, {} sections all paired).",
            headings.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("ERROR: these README.md sections have no Chinese counterpart:");
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
            Authority::VectorFile { .. } => "vector-file",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_of_takes_the_leading_component() {
        assert_eq!(arch_of("x86_64-pc-windows-msvc"), "x86_64");
        assert_eq!(arch_of("i686-pc-windows-msvc"), "i686");
        assert_eq!(arch_of("aarch64-pc-windows-msvc"), "aarch64");
        assert_eq!(arch_of("x86_64-pc-windows-gnu"), "x86_64");
        assert_eq!(arch_of("x86_64-unknown-linux-musl"), "x86_64");
    }

    /// A triple with no hyphen cannot be split, so it comes back whole and the
    /// comparison against a real host fails closed instead of matching by accident.
    #[test]
    fn arch_of_fails_closed_on_a_malformed_triple() {
        assert_eq!(arch_of("nonsense"), "nonsense");
        assert!(!target_is_runnable("nonsense", "x86_64-pc-windows-msvc"));
    }

    /// The regression this function exists for. This machine's rustup host is
    /// GNU, and an exact-triple comparison silently downgraded the *shipping*
    /// target's tests to a link-only check.
    #[test]
    fn msvc_tests_run_on_a_gnu_host_of_the_same_architecture() {
        assert!(target_is_runnable(
            "x86_64-pc-windows-msvc",
            "x86_64-pc-windows-gnu"
        ));
        assert!(target_is_runnable(
            "x86_64-pc-windows-gnu",
            "x86_64-pc-windows-msvc"
        ));
    }

    #[test]
    fn host_architecture_always_runs() {
        for triple in SUPPORTED_TARGETS {
            assert!(
                target_is_runnable(triple, triple),
                "{triple} must run on itself"
            );
        }
    }

    /// WOW64 really does run these; the gate should not waste a build on
    /// `--no-run` for a target whose tests it could have executed.
    #[test]
    fn i686_runs_on_an_x86_64_host_but_not_the_reverse() {
        assert!(target_is_runnable(
            "i686-pc-windows-msvc",
            "x86_64-pc-windows-msvc"
        ));
        assert!(!target_is_runnable(
            "x86_64-pc-windows-msvc",
            "i686-pc-windows-msvc"
        ));
    }

    /// aarch64 binaries need an emulator a plain `cargo test` will not use.
    #[test]
    fn aarch64_is_linted_but_not_claimed_runnable() {
        assert!(!target_is_runnable(
            "aarch64-pc-windows-msvc",
            "x86_64-pc-windows-msvc"
        ));
        assert!(!target_is_runnable(
            "aarch64-pc-windows-msvc",
            "i686-pc-windows-msvc"
        ));
    }

    /// The shipping triple must stay first: it is the one whose tests actually
    /// gate a release, and the loop reports targets in this order.
    #[test]
    fn shipping_target_is_listed_first() {
        assert_eq!(SUPPORTED_TARGETS.first(), Some(&SHIPPING_TARGET));
        assert_eq!(SUPPORTED_TARGETS.len(), 3);
    }
}
