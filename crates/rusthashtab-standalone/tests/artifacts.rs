//! Artifact tests for the standalone launcher: the release EXE, its external
//! manifest, and what it does when it has nothing to do.
//!
//! # Why these inspect the release build
//!
//! `cargo test` builds the debug profile, but the pair a user receives is the
//! release one. `cargo xtask check` therefore builds both `rusthashtab-shell` and
//! `rusthashtab-standalone` in release before it runs the test suite (see the
//! release-artifact step in `xtask/src/main.rs`). A plain
//! `cargo test -p rusthashtab-standalone` has no release pair to inspect, so the
//! tests below skip with an explicit message instead of failing for a reason that
//! has nothing to do with the change being tested.
//!
//! # What is deliberately not asserted here
//!
//! The real window is exercised by `tests/window_e2e.rs`, which is `#[ignore]`d
//! because it puts a visible window on the desktop. This file stays headless: it
//! reads the shipped manifest and runs the no-argument path, which must terminate
//! silently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{FALSE, FreeLibrary, HWND, LPARAM, TRUE};
use windows::Win32::System::LibraryLoader::{
    DONT_RESOLVE_DLL_REFERENCES, GetProcAddress, LoadLibraryExW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
};
use windows::core::{BOOL, PCSTR, PCWSTR};

/// File names of the release pair this crate ships with.
const EXE_NAME: &str = "rusthashtab.exe";
const DLL_NAME: &str = "rusthashtab_shell.dll";
const MANIFEST_NAME: &str = "rusthashtab.exe.manifest";

/// The export the launcher looks up. Only its presence is checked here; the ABI is
/// a compile-time contract between the two crates.
const ENTRY_NAME: &str = "StandaloneEntryW";

/// How long the no-argument launch may take before it is considered hung.
const NO_ARGUMENT_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn the_release_launcher_has_the_external_manifest_it_needs() {
    let Some(executable) = release_executable() else {
        return;
    };

    let manifest = executable.with_file_name(MANIFEST_NAME);
    let text = std::fs::read_to_string(&manifest).unwrap_or_else(|error| {
        panic!(
            "the release launcher has no readable application manifest at {} ({error}). \
             `build.rs` copies `app.manifest` next to the executable; without it the loader \
             never sees the Common Controls v6 dependency or the DPI awareness setting.",
            manifest.display()
        )
    });

    assert_xml_comments_are_well_formed(&manifest, &text);

    // Every one of these is a behaviour the launcher depends on rather than a
    // cosmetic string: controls v6 for the visuals, PerMonitorV2 for crisp windows
    // on scaled monitors, longPathAware for paths over MAX_PATH, and asInvoker so
    // the window never asks for elevation.
    for (what, needle) in [
        (
            "the Common Controls v6 dependency",
            "Microsoft.Windows.Common-Controls",
        ),
        ("the Common Controls v6 assembly version", "6.0.0.0"),
        ("per-monitor DPI awareness", "PerMonitorV2"),
        ("long path awareness", "longPathAware"),
        ("the asInvoker execution level", "asInvoker"),
    ] {
        assert!(
            text.contains(needle),
            "{} does not request {what} (`{needle}` is missing from {}):\n{text}",
            manifest.display(),
            manifest.display()
        );
    }
}

#[test]
fn the_release_launcher_exits_silently_with_no_arguments() {
    let Some((executable, _dll)) = release_artifacts() else {
        return;
    };

    // No arguments means there is nothing to show or hash. The documented
    // behaviour is a silent exit with code 0; a MessageBox (modal, so a hang) or a
    // window waiting for input are both failures. Streams are routed to null
    // because the binary is GUI-subsystem and has no console to write to.
    let mut child = Command::new(&executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start {}: {error}", executable.display()));
    let process = child.id();
    let deadline = Instant::now() + NO_ARGUMENT_TIMEOUT;

    loop {
        let exited = child
            .try_wait()
            .expect("a spawned process can always be polled");
        if let Some(status) = exited {
            assert_eq!(
                status.code(),
                Some(0),
                "{} (pid {process}) exited with {status} when started with no arguments; \
                 the no-argument path must succeed silently",
                executable.display()
            );
            return;
        }

        // Checked before sleeping: a visible top-level window from a no-argument
        // launch is the failure this test exists for. It catches a MessageBox that
        // is waiting for a click (the launch then never exits) as well as a window
        // that was shown by mistake.
        if let Some((window, title)) = visible_window_of(process) {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{} (pid {process}) created the visible window {window:?} titled `{title}` when \
                 started with no arguments. A MessageBox or a window waiting for input is a \
                 failure; the no-argument path must exit 0 without showing anything.",
                executable.display()
            );
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{} (pid {process}) was still running {} s after a no-argument launch; a modal \
                 MessageBox or a window waiting for input is the usual cause",
                executable.display(),
                NO_ARGUMENT_TIMEOUT.as_secs()
            );
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Check the manifest's comments are legal XML.
///
/// # Why this is not a full XML validation
///
/// A malformed manifest does not fail the build and does not fail `main`: the
/// side-by-side loader refuses to create the activation context, so the process
/// is terminated before the first instruction runs, with an error dialog and
/// "side-by-side configuration is incorrect". That is exactly the class of
/// artifact bug this file exists to catch, so the one failure mode this project
/// has actually hit is checked here -- `--` inside a comment, which is illegal in
/// XML and very easy to write when prose uses a double hyphen as a dash. A real
/// parser would need an XML dependency this launcher deliberately does not carry.
fn assert_xml_comments_are_well_formed(manifest: &Path, text: &str) {
    let mut rest = text;
    while let Some(opening) = rest.find("<!--") {
        let after_opening = &rest[opening + 4..];
        let closing = after_opening.find("-->").unwrap_or_else(|| {
            panic!(
                "{}: an XML comment is never closed; the manifest cannot be parsed",
                manifest.display()
            )
        });
        let body = &after_opening[..closing];
        assert!(
            !body.contains("--"),
            "{}: the XML comment `{}` contains `--`, which is not legal XML. The loader refuses \
             to start the executable at all, before `main` runs, with a side-by-side \
             configuration error.",
            manifest.display(),
            body.trim().replace('\n', " ")
        );
        rest = &after_opening[closing + 3..];
    }
}

/// Controls for the export check in [`release_artifacts`].
///
/// If [`dll_exports`] were broken in the "always false" direction, every artifact
/// test would skip forever and the gate would look green while exercising nothing
/// -- a vacuous-gate failure that is invisible in the output. `kernel32.dll` is
/// loaded by every Windows process before this test starts, so it is a stable,
/// environment-free positive control for "the check can see an export"; the
/// missing launcher entry is its negative control.
#[test]
fn the_export_check_finds_a_known_export_and_not_an_absent_one() {
    let system_root = std::env::var_os("SystemRoot").expect("Windows always sets SystemRoot");
    let kernel32 = Path::new(&system_root)
        .join("System32")
        .join("kernel32.dll");
    assert!(
        kernel32.is_file(),
        "expected {} to exist on a Windows target",
        kernel32.display()
    );
    assert!(
        dll_exports(&kernel32, "GetModuleFileNameW"),
        "the export check did not find GetModuleFileNameW in {}; a check that always returns \
         false would make every artifact test above skip silently",
        kernel32.display()
    );
    assert!(
        !dll_exports(&kernel32, ENTRY_NAME),
        "the export check claims {} exports {ENTRY_NAME}",
        kernel32.display()
    );
}

/// The release `rusthashtab.exe`, or `None` (with a printed reason) when this test
/// run has no release build to inspect.
fn release_executable() -> Option<PathBuf> {
    let executable = release_directory().join(EXE_NAME);
    if !executable.is_file() {
        println!(
            "SKIP: no release launcher at {}; build it with \
             `cargo build -p rusthashtab-standalone --release --target <triple>` first",
            executable.display()
        );
        return None;
    }
    Some(executable)
}

/// The release EXE and its sibling DLL, or `None` (with a printed reason).
///
/// The DLL has to export [`ENTRY_NAME`] for the launcher's dispatch path to be
/// exercisable at all. While the shell crate's standalone entry is not in the
/// build, the launcher would report the missing export in a modal MessageBox and
/// wait for a click, which is not something this test should turn into a failure:
/// it is a known intermediate state of the two-crate build, not a defect in the
/// launcher. The skip is printed loudly so a gate that skips is visible.
fn release_artifacts() -> Option<(PathBuf, PathBuf)> {
    let executable = release_executable()?;
    let dll = release_directory().join(DLL_NAME);

    if !dll.is_file() {
        println!(
            "SKIP: no release shell DLL at {}; the launcher cannot dispatch without it",
            dll.display()
        );
        return None;
    }
    if !dll_exports(&dll, ENTRY_NAME) {
        println!(
            "SKIP: {} does not export {ENTRY_NAME}, so the launcher's dispatch path cannot be \
             exercised by this build. This is expected until the shell crate's standalone entry \
             lands; it is not a launcher failure.",
            dll.display()
        );
        return None;
    }

    Some((executable, dll))
}

/// The `target/<triple>/release` directory the running test binary belongs to.
///
/// Found from the test executable, whose path is
/// `target/<triple>/<profile>/deps/<test>-<hash>.exe`. A `--release` test run
/// already lives in `release/`; a normal debug run has it as a sibling of `debug/`.
fn release_directory() -> PathBuf {
    let executable = std::env::current_exe().expect("a running test knows its own path");
    let deps = executable
        .parent()
        .expect("a test executable lives in deps/");
    let profile = deps
        .parent()
        .expect("deps/ lives under a profile directory");

    if profile.file_name().and_then(|name| name.to_str()) == Some("release") {
        return profile.to_path_buf();
    }
    profile
        .parent()
        .expect("the profile directory lives under target/<triple>")
        .join("release")
}

/// Whether `dll` exports `name`.
///
/// # Why the DLL is mapped but not run
///
/// `DONT_RESOLVE_DLL_REFERENCES` maps the image and its export table without
/// calling `DllMain` or resolving imports, which is all a name lookup needs. That
/// matters here: this is a shell extension DLL, and the point of the check is to
/// avoid letting it start doing anything inside the test process. The image is
/// released immediately, before anything else touches it.
fn dll_exports(dll: &Path, name: &str) -> bool {
    let mut path: Vec<u16> = dll.as_os_str().encode_wide().collect();
    path.push(0);
    let mut entry: Vec<u8> = name.bytes().collect();
    entry.push(0);

    // SAFETY: `path` is NUL-terminated and outlives the call; `None` for the file
    // handle is allowed when the name is a path.
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR::from_raw(path.as_ptr()),
            None,
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    let Ok(module) = module else {
        return false;
    };

    // SAFETY: `module` was just loaded above; `entry` is a NUL-terminated ASCII
    // name. GetProcAddress does not take ownership of the module.
    let exported = unsafe { GetProcAddress(module, PCSTR::from_raw(entry.as_ptr())) }.is_some();

    // SAFETY: `module` came from LoadLibraryExW and is released exactly once here.
    let _ = unsafe { FreeLibrary(module) };
    exported
}

/// The first visible top-level window owned by `process`, with its title.
///
/// Used both to prove that the no-argument path shows nothing and, in the ignored
/// end-to-end test, to find the window the DLL creates.
fn visible_window_of(process: u32) -> Option<(HWND, String)> {
    /// Enumeration state handed to the callback through `lParam`.
    struct Search {
        process: u32,
        found: Option<(HWND, String)>,
    }

    /// `EnumWindows` callback; see the safety comment at the call site.
    unsafe extern "system" fn callback(window: HWND, parameter: LPARAM) -> BOOL {
        // SAFETY: `EnumWindows` passes back exactly the pointer it was given, and
        // the `Search` it points to outlives the whole enumeration.
        let search = unsafe { &mut *(parameter.0 as *mut Search) };

        let mut owner = 0u32;
        // SAFETY: `window` is a handle provided by the enumeration and `owner` is a
        // live local; the API only writes the process id through the pointer.
        unsafe { GetWindowThreadProcessId(window, Some(std::ptr::from_mut(&mut owner))) };
        if owner != search.process {
            return TRUE;
        }

        // SAFETY: `window` is a handle provided by the enumeration; the call only
        // reads the window's visibility style.
        let visible = unsafe { IsWindowVisible(window) }.as_bool();
        if !visible {
            return TRUE;
        }

        let mut title = [0u16; 256];
        // SAFETY: `title` is a live, writable slice of u16; the API writes at most
        // its length and applies no further requirements.
        let length = unsafe { GetWindowTextW(window, &mut title) } as usize;
        let title = String::from_utf16_lossy(&title[..length.min(title.len())]);

        search.found = Some((window, title));
        // Stop the enumeration: the first visible window is enough for every caller.
        FALSE
    }

    let mut search = Search {
        process,
        found: None,
    };
    // SAFETY: `callback` matches `WNDENUMPROC`, and `parameter` points at `search`,
    // which outlives the call. A return value of `Err` only means the callback
    // stopped the enumeration early, which is the documented way to stop.
    let _ = unsafe {
        EnumWindows(
            Some(callback),
            LPARAM(std::ptr::from_mut(&mut search) as isize),
        )
    };

    search.found
}
