//! Copy the application manifest next to the launcher executable.
//!
//! # Why the manifest is external rather than embedded
//!
//! The EXE needs the Common Controls v6 dependency and `PerMonitorV2` DPI
//! awareness in place before its first window is created. Embedding a manifest
//! means compiling a resource with `rc.exe` (or running `mt.exe` after linking),
//! which would make a launcher that calls three Win32 functions depend on a
//! Windows SDK tool being findable. It would also duplicate machinery that
//! `rusthashtab-shell`'s build script already carries for its VERSIONINFO
//! resource. Windows falls back to a side-by-side manifest named
//! `<executable>.manifest` when the executable carries no manifest resource, so
//! this build script copies one there instead.
//!
//! # Why `OUT_DIR` is not the destination
//!
//! The loader only looks next to the executable, and `OUT_DIR` is not that
//! directory: for a build-script invocation it is
//! `target/<triple>/<profile>/build/<package>-<hash>/out/`, while the executable
//! is linked into `target/<triple>/<profile>/`. The profile directory is therefore
//! **three** directories above `OUT_DIR` (`out` -> hash -> `build` -> profile),
//! and every step is checked below: a future change to Cargo's build-script layout
//! must fail this build script rather than silently copy the manifest somewhere
//! Windows never reads.
//!
//! # Why there is no `cargo:rustc-link-arg` here
//!
//! Nothing is linked: the manifest is a file, and it is read by the loader at
//! process start rather than by the linker. The only inputs are `build.rs` and
//! `app.manifest`, both declared with `cargo:rerun-if-changed`.

// A build script reports failure by panicking -- it has no return value, and its
// non-zero exit status is the only way to fail the build. A manifest that cannot
// be put where Windows reads it must fail the build rather than produce an EXE
// that silently runs without Common Controls v6 or per-monitor DPI awareness.
#![allow(clippy::panic, clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The manifest file in this package.
const SOURCE_NAME: &str = "app.manifest";

/// The name Windows looks for next to `rusthashtab.exe`.
const DESTINATION_NAME: &str = "rusthashtab.exe.manifest";

/// Three directories above `OUT_DIR`; see the module comment for the layout.
const PROFILE_DIRECTORY_DEPTH: usize = 3;

fn main() {
    println!("cargo:rerun-if-changed={SOURCE_NAME}");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("cargo always sets CARGO_MANIFEST_DIR for a build script");
    let out_dir = std::env::var("OUT_DIR").expect("cargo always sets OUT_DIR for a build script");

    let source = Path::new(&manifest_dir).join(SOURCE_NAME);
    let destination = profile_directory(Path::new(&out_dir)).join(DESTINATION_NAME);

    // `std::fs::copy` replaces an existing file, which is what a rebuild after an
    // edit to `app.manifest` needs.
    std::fs::copy(&source, &destination).unwrap_or_else(|error| {
        panic!(
            "rusthashtab-standalone: could not copy {} to {}: {error}. The loader reads the \
             manifest from next to the executable, so an EXE without it would silently lose the \
             Common Controls v6 dependency and PerMonitorV2 DPI awareness.",
            source.display(),
            destination.display()
        )
    });
}

/// The directory `rusthashtab.exe` is linked into, derived from `OUT_DIR`.
///
/// # Panics
///
/// Panics when the path does not have the build-script layout, or when the
/// directory it lands on is not the profile Cargo says it is building. Both mean
/// the manifest would be written somewhere the loader never looks.
fn profile_directory(out_dir: &Path) -> PathBuf {
    let profile = out_dir.ancestors().nth(PROFILE_DIRECTORY_DEPTH).unwrap_or_else(|| {
        panic!(
            "rusthashtab-standalone: OUT_DIR has no ancestor {PROFILE_DIRECTORY_DEPTH} levels up \
             (expected target/<triple>/<profile>/build/<package>-<hash>/out): {}",
            out_dir.display()
        )
    });

    // The intermediate component Cargo has always put there. Checking it gives a
    // precise failure if the three-level derivation above ever lands elsewhere.
    let build_directory = out_dir.parent().and_then(Path::parent);
    let is_build_directory = build_directory
        .and_then(Path::file_name)
        .is_some_and(|name| name == "build");
    if !is_build_directory {
        panic!(
            "rusthashtab-standalone: OUT_DIR is not under a `build` directory (expected \
             target/<triple>/<profile>/build/<package>-<hash>/out): {}",
            out_dir.display()
        );
    }

    // The semantic check: the destination must be the profile directory Cargo is
    // actually building. `PROFILE` is `debug` or `release` for the two profiles
    // this workspace uses, and any custom profile name for a custom profile.
    let expected = std::env::var("PROFILE").expect("cargo always sets PROFILE for a build script");
    let actual = profile.file_name().and_then(|name| name.to_str());
    if actual != Some(expected.as_str()) {
        panic!(
            "rusthashtab-standalone: derived profile directory {} for a `{expected}` build; the \
             manifest would not be next to the executable",
            profile.display()
        );
    }

    profile.to_path_buf()
}
