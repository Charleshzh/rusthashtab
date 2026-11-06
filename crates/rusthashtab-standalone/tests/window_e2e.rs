//! End-to-end tests for the standalone launcher: it spawns the real release
//! `rusthashtab.exe`, finds the top-level window the DLL creates, resizes it,
//! closes it, and checks that the launcher exits cleanly.
//!
//! # Why these are `#[ignore]`d
//!
//! They put a real window on the desktop. A test suite that flashes windows over
//! whatever the developer is doing is a suite people stop running, and a window
//! test is also the only kind that cannot be made deterministic on a machine with
//! no interactive desktop. Run them deliberately:
//!
//! ```text
//! cargo build -p rusthashtab-shell --release --target x86_64-pc-windows-msvc
//! cargo build -p rusthashtab-standalone --release --target x86_64-pc-windows-msvc
//! cargo test -p rusthashtab-standalone --target x86_64-pc-windows-msvc -- --ignored
//! ```
//!
//! # What is checked, and what is not
//!
//! Checked: the window appears under the expected title, it can be resized, it
//! closes in response to `WM_CLOSE`, and the launcher returns 0 afterwards. What
//! the page *contains* is the UI crate's business and is covered by its own tests;
//! this file only proves that the launcher-to-DLL path works as a whole.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{FALSE, HWND, LPARAM, RECT, TRUE, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    PostMessageW, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOZORDER, SetWindowPos, WM_CLOSE,
};
use windows::core::BOOL;

/// File names of the release pair this crate ships with.
const EXE_NAME: &str = "rusthashtab.exe";
const DLL_NAME: &str = "rusthashtab_shell.dll";

/// The title the DLL gives the standalone window. Matched case-insensitively and
/// by prefix so a build that appends context (a file name, a scope) still matches.
const WINDOW_TITLE: &str = "rustHashTab";

/// How long the window may take to appear. Hashing a two-file manifest is fast,
/// but the DLL is large and the machine may be busy.
const WINDOW_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the launcher may take to exit after `WM_CLOSE`.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// A temporary file plus its manifest; the launcher must open its window for it.
const SAMPLE_CONTENT: &[u8] = b"rustHashTab standalone end-to-end test\n";

/// SHA-256 of [`SAMPLE_CONTENT`], so the manifest is well-formed and its single
/// entry matches the file next to it. Computed with Windows' SHA-256 over exactly
/// the bytes above; it is data for the page, not an assertion of this test.
const SAMPLE_SHA256: &str = "422afe8678539f9766cfceb05ad2c1fdec441f71834c511ac90d08e69a235919";

#[test]
#[ignore = "shows a real window; run with --ignored"]
fn the_launcher_opens_and_closes_a_window_for_a_file() {
    let Some(executable) = release_launcher() else {
        return;
    };

    let scratch = Scratch::new("file");
    let file = scratch.join("sample.txt");
    std::fs::write(&file, SAMPLE_CONTENT)
        .unwrap_or_else(|error| panic!("could not write {}: {error}", file.display()));

    run_case(&executable, &file);
}

#[test]
#[ignore = "shows a real window; run with --ignored"]
fn the_launcher_opens_and_closes_a_window_for_a_checksum_manifest() {
    let Some(executable) = release_launcher() else {
        return;
    };

    let scratch = Scratch::new("manifest");
    let data = scratch.join("sample.txt");
    std::fs::write(&data, SAMPLE_CONTENT)
        .unwrap_or_else(|error| panic!("could not write {}: {error}", data.display()));

    // The `.sha256` extension makes the page interpret the argument as a checksum
    // file, which is the second standalone entry path worth exercising: it has to
    // resolve the entries in the manifest, not just hash the named file.
    let manifest = scratch.join("sample.txt.sha256");
    std::fs::write(&manifest, format!("{SAMPLE_SHA256}  sample.txt\n"))
        .unwrap_or_else(|error| panic!("could not write {}: {error}", manifest.display()));

    run_case(&executable, &manifest);
}

/// Launch `executable` with `argument`, close its window, and require a clean exit.
fn run_case(executable: &Path, argument: &Path) {
    let mut child = Command::new(executable)
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start {}: {error}", executable.display()));
    let process = child.id();

    let window = match wait_for_window(process, WINDOW_TIMEOUT) {
        Some(window) => window,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{} (pid {process}) did not open a visible top-level window titled `{WINDOW_TITLE}` \
                 for {} within {} s",
                executable.display(),
                argument.display(),
                WINDOW_TIMEOUT.as_secs()
            );
        }
    };

    resize(window);
    close(window);
    wait_for_exit(&mut child, executable);
}

/// Poll for the first visible top-level window of `process` whose title starts
/// with [`WINDOW_TITLE`].
fn wait_for_window(process: u32, timeout: Duration) -> Option<HWND> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(window) = matching_window_of(process) {
            return Some(window);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Resize the window to a fixed size so a layout regression on resize is at least
/// exercised on the manual run. The result is asserted; the new geometry is not,
/// because a window manager is free to adjust it.
fn resize(window: HWND) {
    // SAFETY: `window` came from a live enumeration of the child's windows and the
    // call only requests a size; the flags leave position, activation and z-order
    // alone. `None` for the insert-after handle is required for SWP_NOZORDER.
    let resized = unsafe {
        SetWindowPos(
            window,
            None,
            0,
            0,
            900,
            600,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    resized.unwrap_or_else(|error| panic!("could not resize {window:?}: {error}"));

    // Read the geometry back so a resize that was silently ignored fails here
    // rather than making the "resize" step vacuous.
    let mut rectangle = RECT::default();
    // SAFETY: `rectangle` is a live local that the API fills with the window's
    // screen rectangle.
    unsafe { GetWindowRect(window, &mut rectangle) }
        .unwrap_or_else(|error| panic!("could not read the rectangle of {window:?}: {error}"));
    let width = rectangle.right - rectangle.left;
    let height = rectangle.bottom - rectangle.top;
    assert!(
        width > 0 && height > 0,
        "resizing {window:?} produced an empty rectangle {width}x{height}"
    );
}

/// Ask the window to close. `WM_CLOSE` is the same message the title bar's close
/// button sends, so the DLL's normal teardown path runs.
fn close(window: HWND) {
    // SAFETY: `window` is a live window of the child; PostMessageW only queues the
    // message and returns without waiting for it to be processed.
    let posted = unsafe { PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    posted.unwrap_or_else(|error| panic!("could not post WM_CLOSE to {window:?}: {error}"));
}

/// Wait for the launcher to exit after its window closed and require code 0.
fn wait_for_exit(child: &mut Child, executable: &Path) {
    let deadline = Instant::now() + CLOSE_TIMEOUT;
    loop {
        match child
            .try_wait()
            .expect("a spawned process can always be polled")
        {
            Some(status) => {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "{} exited with {status} after its window was closed; the standalone entry \
                     must return 0 for a normal close",
                    executable.display()
                );
                return;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{} still did not exit {} s after its window received WM_CLOSE; the window \
                     thread or the scan teardown is hanging",
                    executable.display(),
                    CLOSE_TIMEOUT.as_secs()
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The first visible top-level window owned by `process` whose title starts with
/// [`WINDOW_TITLE`].
fn matching_window_of(process: u32) -> Option<HWND> {
    /// Enumeration state handed to the callback through `lParam`.
    struct Search {
        process: u32,
        found: Option<HWND>,
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

        if title
            .to_ascii_lowercase()
            .starts_with(&WINDOW_TITLE.to_ascii_lowercase())
        {
            search.found = Some(window);
            // Stop the enumeration: the first match is the window under test.
            return FALSE;
        }
        TRUE
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

/// The release `rusthashtab.exe`, or `None` (with a printed reason) when this test
/// run has no release pair to launch.
fn release_launcher() -> Option<PathBuf> {
    let directory = release_directory();
    let executable = directory.join(EXE_NAME);
    let dll = directory.join(DLL_NAME);

    if !executable.is_file() {
        println!(
            "SKIP: no release launcher at {}; build it with \
             `cargo build -p rusthashtab-standalone --release --target <triple>` first",
            executable.display()
        );
        return None;
    }
    if !dll.is_file() {
        println!(
            "SKIP: no release shell DLL at {}; the launcher has no window without it",
            dll.display()
        );
        return None;
    }
    Some(executable)
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

/// A temporary directory that removes itself when the test ends, pass or fail.
struct Scratch(PathBuf);

impl Scratch {
    /// Create a uniquely named scratch directory under the system temp directory.
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rusthashtab-standalone-{name}-{}",
            std::process::id()
        ));
        // A previous failed run may have left the same path behind; start clean.
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap_or_else(|error| {
            panic!(
                "could not create the scratch directory {}: {error}",
                directory.display()
            )
        });
        Self(directory)
    }

    /// Path of a file inside the scratch directory.
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
