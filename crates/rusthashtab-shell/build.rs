//! Linker settings for the shell extension DLL, and the VERSIONINFO resource.
//!
//! # Four problems, all of which are linker-level
//!
//! 1. **`LNK4104`.** MSVC recommends that a DLL's standard COM exports be
//!    `PRIVATE` in a hand-written `.def`. `rustc` generates the `.def` for a
//!    `cdylib` itself and offers no per-export visibility control, so the warning
//!    cannot be fixed by writing a `.def` without giving up the generated one for
//!    every other symbol. It is suppressed explicitly and deliberately: these four
//!    exports *must* be visible, because `regsvr32` and COM look them up by name.
//!
//! 2. **`DllMain`'s name on 32-bit targets.** The x86 loader is documented as
//!    looking up `_DllMain@12`, the stdcall-decorated spelling of the DLL entry
//!    point, while `rustc` exports the undecorated `DllMain`. If the loader does
//!    not find a name it recognises, the entry point is never called: `DllMain`
//!    never records the module handle, never calls `DisableThreadLibraryCalls`,
//!    and nothing it does happens. There is no link error and no export-table
//!    difference to notice, which is what makes this worth guarding against.
//!
//!    The guard is a second, hand-written `.def` that aliases the decorated name
//!    onto the symbol `rustc` emits; `link.exe` merges module-definition files
//!    given on the command line with the one `rustc` generated.
//!
//!    **Measured, and reported honestly:** with this alias removed, the i686 build
//!    still reached its entry point on Windows 11 -- `cargo test -p
//!    rusthashtab-shell --target i686-pc-windows-msvc` covers it, and its comment
//!    says the same thing. So either the loader resolves the undecorated name too,
//!    or it calls the address in the PE header without consulting names at all.
//!    The alias is kept because the documented requirement is the decorated name
//!    and the cost is one instruction in a file nobody reads; it is **not** claimed
//!    to be the reason the entry point runs, because that was not established.
//!
//!    `/ENTRY:_DllMain@12` looks like the obvious fix and is worse: setting an
//!    entry point explicitly makes the linker skip the default CRT entry point,
//!    which drops `__CxxFrameHandler3` and turns a working link into
//!    `LNK2001: unresolved external symbol`. Also measured, not guessed.
//!
//! 3. **`LNK1201`.** The `.dll` and its import library can collide on a
//!    case-folding file system when a second artifact of the same name exists.
//!    Only a problem once there is an `.exe` (the standalone mode in a later
//!    phase), so nothing is redirected here yet; this note exists so the next
//!    person finds the reason rather than the symptom.
//!
//! Nothing here contains the upstream project's identifiers, so it is safe for
//! the release-hygiene scan.

// Cargo lints apply to a build script, and two of the workspace's defaults do not
// mean what they mean elsewhere here.
//
//   * `panic!`/`expect` are how a build script *reports failure*: a build script
//     has no return value, its non-zero exit is produced by panicking, and that is
//     deliberate -- a module-definition file or a resource that cannot be produced
//     must fail the build, not quietly produce a DLL that is missing it.
//   * `if let ... { if ... }` is the shape that reads best here, and a `let`-chain
//     would hide that this is about an environment variable that may be absent or
//     empty.
#![allow(clippy::panic, clippy::expect_used, clippy::collapsible_if)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Which `rc.exe` to run.
///
/// The **host's** architecture, not the target's. A `.res` file is a resource
/// directory and carries no machine type, so the linker folds it into an output for
/// any architecture. Choosing by target instead was tried and fails outright: on an
/// x64 host, `rc.exe` from the SDK's `arm64` directory is an ARM64 executable, and
/// trying to run it returns `os error 216`. That made the aarch64 target
/// unbuildable here, which the gate compiles on every run.
fn resource_compiler_archs(host_arch: &str) -> Vec<&'static str> {
    match host_arch {
        "x86_64" => vec!["x64", "x86"],
        "aarch64" => vec!["arm64", "x64", "x86"],
        // A 32-bit host runs the 32-bit compiler and can run nothing wider.
        _ => vec!["x86"],
    }
}

/// Candidate `Windows Kits\10` roots.
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

/// Write the extra exports needed on a 32-bit target, and return the file.
fn write_entry_point_alias(out_dir: &Path) -> PathBuf {
    let path = out_dir.join("entry.def");

    // `EXPORTS` maps a new exported name to the symbol that exists. `PRIVATE`
    // keeps it out of the import library -- the loader reads the entry-point
    // address from the PE header, not from a name, so nothing links against it.
    let contents = "\
; The 32-bit DLL entry point, under the name the x86 loader looks for.
;
; `rustc` emits and exports `DllMain` undecorated on every target, while the
; x86 loader expects `_DllMain@12` -- the stdcall-decorated spelling, because
; the entry point is called with three 32-bit arguments. Aliasing the decorated
; name onto the symbol that does exist is the whole fix; see build.rs.
EXPORTS
    \"_DllMain@12\" = DllMain PRIVATE
";

    std::fs::write(&path, contents).expect("could not write the module-definition file");
    path
}

fn main() {
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| String::from("unknown"));

    // These four exports are looked up by name at runtime, so the warning that
    // they are not PRIVATE is noise, not advice.
    println!("cargo:rustc-link-arg-cdylib=/IGNORE:4104");

    if target_arch == "x86" {
        let out_dir = std::env::var("OUT_DIR").expect("cargo always sets OUT_DIR");
        let def = write_entry_point_alias(Path::new(&out_dir));
        println!("cargo:rustc-link-arg-cdylib=/DEF:{}", def.display());
        println!("cargo:rerun-if-changed=build.rs");
    }

    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "msvc" && !target_env.is_empty() {
        println!(
            "cargo:warning=rusthashtab-shell: the VERSIONINFO resource is not compiled for the \
             `{target_env}` environment"
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
            "rusthashtab-shell: could not find a usable Windows SDK resource compiler (rc.exe) for \
             a `{host_arch}` host.\nLooked for:\n{list}\n\n\
             The DLL needs a VERSIONINFO resource, so that a copy found in explorer.exe or \
             dllhost.exe can be identified. Install the Windows SDK, or set WindowsSdkDir."
        )
    });

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo always sets this");
    let out_dir = std::env::var("OUT_DIR").expect("cargo always sets OUT_DIR");
    let out_res = Path::new(&out_dir).join("shell.res");
    let version_script = Path::new(&manifest_dir).join("src").join("shell.rc");

    // The page's dialog template has to be compiled **here**, into the DLL, and not
    // only in the library that defines the page.
    //
    // # Why
    //
    // `rustc-link-arg` emitted by a **library's** build script applies to that
    // library's own artifact -- an `.rlib` -- and a `.res` file has no symbols, so the
    // linker drops it when the `cdylib` is linked. The DLL therefore shipped with the
    // version resource and **no dialog template at all**. Measured: `AddPages`
    // returned `S_OK`, the shell accepted the page, and no window was ever built for
    // it, so the Hashes tab never appeared anywhere -- while every test passed,
    // because they either parse `ui.rc` as text or build the dialog from `rustc`'s own
    // generated resource in the test binary.
    //
    // `crates/rusthashtab-ui/tests/page_in_sheet.rs` now asserts the template is
    // reachable through the *DLL's* module, which is the check that was missing.
    let ui_manifest_dir = Path::new(&manifest_dir)
        .parent()
        .expect("crates/ has a parent")
        .join("rusthashtab-ui");
    let dialog_script = ui_manifest_dir.join("src").join("ui.rc");

    // `ui.rc` has to be found from here, and it is in the sibling crate -- that is
    // deliberate. The template is a resource of the **DLL**, because the `hInstance`
    // the page passes to `CreatePropertySheetPageW` is the DLL's, so this is where it
    // belongs even though the identifiers it uses are declared next door. The path is
    // built from `CARGO_MANIFEST_DIR` rather than written relatively, so `include`
    // resolution does not depend on the working directory.
    let dialog_include = dialog_script
        .parent()
        .expect("src/ has a parent")
        .to_path_buf();

    // The include path stays ASCII: `rc.exe` predates Unicode paths on its command
    // line, and this is a check a person can read rather than a mysterious failure.
    for path in [&dialog_script, &dialog_include] {
        assert!(
            path.to_str().is_some_and(|text| text.is_ascii()),
            "the path {} is not ASCII, and rc.exe cannot be given it on a command line. \
             Move the checkout to an ASCII path, or compile the dialog template another way.",
            path.display()
        );
    }

    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&out_res)
        .arg(&version_script)
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "could not run {}: {error}\n\
                 That usually means the SDK only ships rc.exe for an architecture this host \
                 cannot execute.",
                rc.display()
            )
        });
    if !status.success() {
        panic!(
            "{} failed with {status} while compiling {}",
            rc.display(),
            version_script.display()
        );
    }

    // A **second** invocation for the dialog template, because `rc.exe` refuses more
    // than one input file: passing both scripts to one call fails with
    // `RC1107: invalid usage`. Measured, not assumed. Both `.res` files then go to the
    // linker, which merges their resource directories.
    let out_dialog = Path::new(&out_dir).join("dialog.res");
    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&out_dialog)
        .arg("/i")
        .arg(&dialog_include)
        .arg(&dialog_script)
        .status()
        .unwrap_or_else(|error| panic!("could not run {}: {error}", rc.display()));
    if !status.success() {
        panic!(
            "{} failed with {status} while compiling {}\n\
             This is the page's dialog template. Without it the DLL has no template for the \
             page, which is exactly the bug this invocation exists to prevent.",
            rc.display(),
            dialog_script.display()
        );
    }

    println!("cargo:rustc-link-arg={}", out_res.display());
    println!("cargo:rustc-link-arg={}", out_dialog.display());
    println!("cargo:rerun-if-changed=src/shell.rc");
    println!("cargo:rerun-if-changed={}", dialog_script.display());
    println!("cargo:rerun-if-changed=build.rs");
}
