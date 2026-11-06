//! The export the standalone launcher calls.
//!
//! # Why this lives in the DLL
//!
//! `rusthashtab.exe` is a few hundred lines whose only job is to load this DLL
//! and call [`StandaloneEntryW`]. The window, the page, and every dialog template
//! stay in this module, so an installed build has exactly one copy of the UI
//! resources -- the DLL's. The launcher exists only because a `regsvr32`-style
//! shell extension cannot also be a program with its own command line.
//!
//! # What it deliberately does not promise
//!
//! This is not a `rundll32` entry point and carries none of that calling
//! convention's guarantees. Its caller is our own launcher, which looks the export
//! up by name after loading the DLL from its own directory; the signature below is
//! the contract between those two files and nothing else.
//!
//! # The launch has two outcomes
//!
//! With no file arguments the export returns success without creating a window:
//! a launcher started with nothing to hash is a no-op, not an error dialog. With
//! files it enters a single-threaded apartment, creates the window, and runs its
//! message loop until the user closes it; a start failure shows a message box and
//! returns a non-zero exit code.

#![cfg(windows)]
// The export is reached through the DLL's export table, not through Rust's module
// graph, so `pub` is required by `#[unsafe(no_mangle)]` rather than by a caller
// inside this crate.
#![allow(unreachable_pub)]

use rusthashtab_abi::{Guarded, guarded};
use rusthashtab_ui::strings::{self, Key};
use rusthashtab_ui::window;
use windows::Win32::Foundation::{HINSTANCE, HWND};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
use windows::core::PCWSTR;

/// Entry point for `rusthashtab.exe`: open a window over the files on the command
/// line.
///
/// # Return value
///
/// `0` when the window ran and was closed, and also when there was nothing to do
/// (no file arguments). `1` when the command line could not be parsed or the
/// window could not be opened; the process exits with the same value, so a
/// launcher failure is visible to whatever started it.
///
/// # Safety
///
/// Called by a host that has loaded this DLL and looked the export up by name. The
/// launcher passes the full command line it received, so `cmdline` is either null
/// or a NUL-terminated wide string that stays valid for the call, exactly as
/// `GetCommandLineW`'s result does. Calling it on a thread that already owns a
/// window message loop would nest loops this function does not expect; the
/// launcher calls it from its main thread.
#[unsafe(no_mangle)]
pub extern "system" fn StandaloneEntryW(
    _hwnd: HWND,
    _hinst: HINSTANCE,
    cmdline: PCWSTR,
    show: i32,
) -> i32 {
    let result: Guarded<i32> = guarded(|| {
        let paths = match window::command_line_paths(cmdline) {
            Ok(paths) => paths,
            Err(error) => {
                show_error(&strings::text(Key::WindowOpenFailed).replace("{}", &error.to_string()));
                return Ok(1);
            }
        };

        // Started with no file arguments: there is nothing to show. Returning
        // success keeps a bare launch from being an error the user has to dismiss.
        if paths.is_empty() {
            return Ok(0);
        }

        crate::module::ensure_recorded();
        crate::module::initialise();
        let Some(instance) = crate::module::instance() else {
            show_error(
                &strings::text(Key::WindowOpenFailed)
                    .replace("{}", "the extension module handle is not recorded"),
            );
            return Ok(1);
        };

        // The launcher's thread is not a COM thread; the window and the shell
        // controls it creates need an apartment to live in.
        let _apartment = crate::com::Apartment::new();

        let settings = rusthashtab_ui::load_settings();
        match window::run(instance, paths, settings, show) {
            Ok(()) => Ok(0),
            Err(error) => {
                show_error(&strings::text(Key::WindowOpenFailed).replace("{}", &error.to_string()));
                Ok(1)
            }
        }
    });

    // The guard contained a panic and already reported it through the debug
    // channel; the process exit code is the only thing left to make honest.
    result.unwrap_or(1)
}

/// Show a start failure to the user, with no window to own the box.
fn show_error(message: &str) {
    let text = wide(message);
    let caption = wide(strings::text(Key::WindowTitle));

    // SAFETY: both buffers are NUL-terminated and outlive the call, and a null
    // owner is allowed for a message box opened before any of our windows exist.
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

/// NUL-terminate a Rust string into a UTF-16 buffer for a Win32 call.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
    use windows::core::w;

    /// The class name the UI crate gives its host window.
    ///
    /// A rename there would make the absence check below vacuous rather than
    /// wrong; the export's no-argument path returns before any window code runs,
    /// so the check is corroboration rather than the only guard.
    const HOST_CLASS: PCWSTR = w!("rustHashTabWindow");

    /// True when a host window exists in this process.
    fn a_host_window_exists() -> bool {
        // SAFETY: the class name is a NUL-terminated literal and no window title is
        // requested, so the call only looks the window up.
        unsafe { FindWindowW(HOST_CLASS, PCWSTR::null()).is_ok() }
    }

    /// The no-argument launch is a success with no window: `rusthashtab.exe` on its
    /// own must not put an empty window on screen or an error box in front of the
    /// user.
    ///
    /// The path deliberately contains no spaces. `CommandLineToArgvW` splits an
    /// unquoted command line on whitespace, so a program-only command line with a
    /// space in it is not a program-only command line at all -- and the first
    /// version of this test passed `C:\Program Files\...`, which the parser turned
    /// into a file argument and a real window on an unattended test thread.
    #[test]
    fn a_command_line_with_only_the_program_name_returns_zero_without_a_window() {
        let program = wide(r"C:\rusthashtab.exe");
        assert!(
            !a_host_window_exists(),
            "a host window exists before the export was called"
        );

        let code = StandaloneEntryW(
            HWND(core::ptr::null_mut()),
            HINSTANCE(core::ptr::null_mut()),
            PCWSTR(program.as_ptr()),
            1,
        );
        assert_eq!(code, 0, "a bare launch must be a successful no-op");
        assert!(
            !a_host_window_exists(),
            "the no-argument path opened a window"
        );
    }

    /// A null command line is treated the same way: parsing it must not be
    /// attempted by Win32, and the result is a successful no-op.
    #[test]
    fn a_null_command_line_returns_zero_without_a_window() {
        let code = StandaloneEntryW(
            HWND(core::ptr::null_mut()),
            HINSTANCE(core::ptr::null_mut()),
            PCWSTR::null(),
            1,
        );
        assert_eq!(code, 0, "a null command line must be a successful no-op");
        assert!(
            !a_host_window_exists(),
            "the null-command-line path opened a window"
        );
    }
}
