//! Resource compilation for the property sheet page.
//!
//! # What this is for, and what it is not
//!
//! This compiles a copy of the dialog template into **this crate's own artifacts**,
//! which in practice means the test binaries. That is the only way a test can build
//! a dialog from the page's real template: a test runs from its own module and
//! cannot reach into the DLL's resources, so `tests/property_sheet_page.rs` needs a
//! template in the module `GetModuleHandleW(None)` returns.
//!
//! **This copy is not what ships.** The template that `explorer.exe` uses is the one
//! `rusthashtab-shell/build.rs` compiles into the DLL, because the `hInstance` the
//! page passes to `CreatePropertySheetPageW` is the DLL's. Two things follow, and
//! both cost time to learn:
//!
//!   * The `rustc-link-arg` below does **not** reach the `cdylib`. A link argument
//!     from a library's build script applies to that library's own artifact, and a
//!     `.res` in an `.rlib` has no symbols, so the linker drops it. The DLL shipped
//!     with no template and the page was invisible while every test passed.
//!   * Deleting this file to remove the duplication breaks the tests instead. The
//!     copy is not redundant; it is for a different consumer.
//!
//! So the duplication is real and deliberate, and the two copies are checked
//! separately: `tests/property_sheet_page.rs` for this one,
//! `tests/page_in_sheet.rs::the_dll_contains_the_pages_dialog_template` for the
//! DLL's.
//!
//! # Why this calls `rc.exe` directly
//!
//! The page is a `PROPSHEETPAGEW` whose child controls come from a dialog
//! template. There are three ways to get one:
//!
//! 1. `embed-resource` / `winresource` -- both need `vswhom` + `winreg` to find
//!    `rc.exe`, and both have been observed missing from an offline cargo cache;
//! 2. `PSP_DLGINDIRECT` with a hand-written in-memory `DLGTEMPLATE` -- nobody in
//!    the Rust shell-extension ecosystem does this, Microsoft warns that a
//!    read-only template faults on some Windows versions, and it would mean
//!    hand-rolling DLU maths;
//! 3. invoke the Windows SDK's `rc.exe` ourselves and hand the linker the object.
//!
//! Option 3 is what this does. The SDK is already a hard build requirement: the
//! project pins an MSVC toolchain and a Windows SDK, and rustc finds the SDK
//! without a developer prompt. `rc.exe` ships in the same SDK. So this adds no
//! new dependency, and when it is genuinely missing the build fails with the
//! paths it looked at rather than shipping a DLL with no dialog template.
//!
//! # Which `rc.exe`
//!
//! The **host's** architecture, explained on [`resource_compiler_archs`]: a `.res`
//! file carries no machine type, and the target's `rc.exe` is often not executable
//! on the build machine.
//!
//! Nothing here contains the upstream project's identifiers, so it is safe for the
//! release-hygiene scan.

// Cargo lints apply to a build script, and two of the workspace's defaults do not
// mean what they mean elsewhere here.
//
//   * `panic!`/`expect` are how a build script *reports failure*: a build script
//     has no return value, its non-zero exit is produced by panicking, and that is
//     deliberate -- a resource that does not compile must fail the build, not
//     produce a DLL that silently has no dialog template in it.
//   * `if let ... { if ... }` is the shape that reads best here, and a `let`-chain
//     would hide that this is about an environment variable that may be absent or
//     empty.
#![allow(clippy::panic, clippy::expect_used, clippy::collapsible_if)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Which `rc.exe` to run.
///
/// # Why this is the *host* architecture, not the target's
///
/// A `.res` file is architecture-neutral: it is a resource directory, and the
/// linker folds it into the output without caring what the output's machine type
/// is. So the compiler only has to be one this machine can execute.
///
/// Choosing by target instead was tried and fails outright: on an x64 host,
/// `rc.exe` from the SDK's `arm64` directory is an ARM64 executable, and trying to
/// run it returns `os error 216`, "this version of %1 is not compatible with the
/// version of Windows you are running". The aarch64 gate target therefore could not
/// be built here at all -- which is the whole point of compiling all three.
///
/// Ordered by preference: the host's own architecture when the SDK has it, then
/// the other x86 flavours, because an x64 or x86 `rc.exe` runs on any Windows host
/// this project builds on.
fn resource_compiler_archs(host_arch: &str) -> Vec<&'static str> {
    match host_arch {
        "x86_64" => vec!["x64", "x86"],
        "aarch64" => vec!["arm64", "x64", "x86"],
        // A 32-bit host runs the 32-bit compiler and can run nothing wider.
        _ => vec!["x86"],
    }
}

/// Try a list of candidate `Windows Kits\10` roots.
fn sdk_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(dir) = std::env::var("WindowsSdkDir") {
        if !dir.is_empty() {
            roots.push(PathBuf::from(dir));
        }
    }
    for key in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(base) = std::env::var(key) {
            roots.push(PathBuf::from(base).join("Windows Kits").join("10"));
        }
    }
    roots
}

/// Newest `rc.exe` for one of `archs`, or every path that was tried.
///
/// # Where `rc.exe` actually lives
///
/// Under `bin\10.0.<build>\<arch>\`, and there is also a `bin\<arch>\` layout
/// beside the versioned ones. Not every version has every architecture: measured
/// on this machine's 10.0.26100.0, `x64`, `x86` and `arm64` are all present, while
/// older SDKs have no `arm64` directory at all. So both layouts are searched and
/// each candidate architecture is tried in turn.
///
/// "Newest" is decided by directory name, which sorts lexically because the
/// versions are dot-separated numeric.
fn find_resource_compiler(archs: &[&str]) -> Result<PathBuf, Vec<PathBuf>> {
    let mut tried = Vec::new();

    for root in sdk_roots() {
        let bin = root.join("bin");

        // Version directories, newest first, shared across the architectures so
        // that preference order is by architecture and then by version.
        let mut versions: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&bin) {
            versions = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("10."))
                })
                .collect();
            versions.sort();
            versions.reverse();
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        for arch in archs {
            // The `bin\<arch>\rc.exe` layout, then the versioned ones.
            candidates.push(bin.join(arch).join("rc.exe"));
            candidates.extend(
                versions
                    .iter()
                    .map(|version| version.join(arch).join("rc.exe")),
            );
        }

        for candidate in candidates {
            if candidate.is_file() {
                return Ok(candidate);
            }
            tried.push(candidate);
        }
    }

    Err(tried)
}

fn main() {
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" && !target_env.is_empty() {
        // Only the MSVC toolchain is supported, and only it accepts a precompiled
        // resource object on the command line. Saying so beats a confusing link
        // error later.
        println!(
            "cargo:warning=rusthashtab-ui: the dialog template is not compiled for the \
             `{target_env}` environment; the property sheet page will be unavailable"
        );
        return;
    }

    let host = std::env::var("HOST").unwrap_or_else(|_| String::from("unknown"));
    let host_arch = host.split('-').next().unwrap_or(&host).to_string();
    let archs = resource_compiler_archs(&host_arch);

    let rc = find_resource_compiler(&archs).unwrap_or_else(|tried| {
        let list = tried
            .iter()
            .map(|path| format!("  {}", path.display()))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "rusthashtab-ui: could not find a usable Windows SDK resource compiler (rc.exe) for \
             a `{host_arch}` host.\nLooked for:\n{list}\n\n\
             The property sheet page needs a compiled dialog template. Install the Windows SDK \
             (any 10.x version ships rc.exe for x64 and x86), or set WindowsSdkDir."
        )
    });

    let out_dir = std::env::var("OUT_DIR").expect("cargo always sets OUT_DIR");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo always sets this");
    let out_res = Path::new(&out_dir).join("ui.res");
    let script = Path::new(&manifest_dir).join("src").join("ui.rc");

    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&out_res)
        .arg(&script)
        .status()
        .unwrap_or_else(|error| {
            // The most likely reason for a spawn failure rather than a non-zero
            // exit: the compiler is for an architecture this machine cannot run.
            panic!(
                "could not run {}: {error}\n\
                 That usually means the SDK only ships rc.exe for an architecture this host \
                 cannot execute.",
                rc.display()
            )
        });

    if !status.success() {
        panic!("{} failed with {status}", rc.display());
    }

    println!("cargo:rustc-link-arg={}", out_res.display());
    println!("cargo:rerun-if-changed=src/ui.rc");
    println!("cargo:rerun-if-changed=build.rs");
}
