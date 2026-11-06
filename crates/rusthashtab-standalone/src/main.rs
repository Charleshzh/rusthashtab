//! `rusthashtab.exe` -- the standalone launcher for rustHashTab.
//!
//! # What this crate is, and what it deliberately is not
//!
//! The standalone mode is not a second implementation of the UI. The window, its
//! controls and the whole hashing pipeline live in `rusthashtab_shell.dll`, the
//! same artifact that hosts the property page and the context menu. This crate
//! is only a launcher, and it is deliberately tiny:
//!
//! 1. opt into per-monitor DPI awareness v2 (the manifest does this too; this is
//!    the runtime fallback for the case where the loader did not apply it);
//! 2. find `rusthashtab_shell.dll` next to its own executable;
//! 3. load that DLL and look up the exported `StandaloneEntryW`;
//! 4. hand it the full command line, a null owner window and a null instance,
//!    and exit with the code it returns.
//!
//! Keeping this separate and thin has three concrete benefits:
//!
//! * **One copy of every resource.** Dialog templates and the version resource
//!   are resources of the DLL, so there is exactly one file to sign, register and
//!   diagnose. An EXE that linked the UI would need its own copy and could drift.
//! * **No link-time dependency on the DLL.** Nothing is imported from
//!   `rusthashtab_shell.dll`; if it is missing, the launcher can say exactly which
//!   path failed and with which Win32 error, instead of the loader failing the
//!   process before `main` runs with a generic "code execution cannot proceed".
//! * **The pair stays relocatable.** The DLL is loaded by its absolute path from
//!   the launcher's own directory, so the two files can be copied anywhere
//!   together without touching `PATH`, the registry or the working directory.
//!
//! # What it does not do
//!
//! * No hashing, no UI code, no registry access: all of that is the DLL's job.
//! * No console window: the binary is a GUI-subsystem executable.
//! * No `FreeLibrary` after a successful call. `StandaloneEntryW` returns once the
//!   window has closed, and the process exits immediately after that; unloading a
//!   DLL that has just finished tearing down its last window only adds a path that
//!   can run code when nothing is left to run it for.

#![windows_subsystem = "windows"]

use windows::Win32::Foundation::{FARPROC, GetLastError, HINSTANCE, HWND};
use windows::Win32::System::Environment::GetCommandLineW;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryW};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MB_ICONERROR, MB_OK, MessageBoxW, SW_SHOWNORMAL, SetProcessDPIAware,
};
use windows::core::PCWSTR;

/// The DLL that carries the standalone window and the hashing pipeline.
const SHELL_DLL: &str = "rusthashtab_shell.dll";

/// The export the DLL must provide, and the ABI it must use.
///
/// The launcher does not link the DLL, so this signature is the only contract
/// between the two crates. It is a plain `extern "system"` function -- no COM, no
/// vtable -- because the launcher has no COM apartment and no object lifetime to
/// manage: it calls the function once and exits.
type StandaloneEntry = unsafe extern "system" fn(HWND, HINSTANCE, PCWSTR, i32) -> i32;

fn main() {
    std::process::exit(run());
}

/// Everything the launcher does, in order; the return value becomes the process
/// exit code.
fn run() -> i32 {
    become_dpi_aware();

    let executable = match executable_path() {
        Ok(path) => path,
        Err(error) => {
            return fatal(&format!(
                "rustHashTab could not determine the path of its own executable.\r\n\r\n\
                 Win32 error {error}."
            ));
        }
    };

    let Some(dll_path) = shell_dll_path(&executable) else {
        return fatal(
            "rustHashTab could not work out the directory it was loaded from.\r\n\r\n\
             Its executable path contains no directory separator.",
        );
    };
    let dll_display = text_from_wide(&dll_path);

    // SAFETY: `dll_path` is NUL-terminated and lives for the whole call. The path
    // is absolute, so the loader cannot resolve a different DLL with the same name
    // from the working directory, `PATH` or the application directory.
    let module = unsafe { LoadLibraryW(PCWSTR::from_raw(dll_path.as_ptr())) };
    // SAFETY: GetLastError has no preconditions and returns the calling thread's
    // last-error value. Reading it immediately after the failing call above is
    // what makes it mean "why did that call fail".
    let load_error = unsafe { GetLastError() };
    let module = match module {
        Ok(module) => module,
        Err(_) => {
            return fatal(&format!(
                "rustHashTab could not load its window component.\r\n\r\n{dll_display}\r\n\r\n\
                 Win32 error {}. The launcher and the DLL are installed as a pair; \
                 if that file is missing or damaged, reinstall rustHashTab.",
                load_error.0
            ));
        }
    };

    // SAFETY: `module` is a live module handle returned by LoadLibraryW above, and
    // the name is a static NUL-terminated ASCII literal. GetProcAddress does not
    // take ownership of the module.
    let procedure: FARPROC =
        unsafe { GetProcAddress(module, windows::core::s!("StandaloneEntryW")) };

    // SAFETY: `StandaloneEntry` and the raw `FARPROC` are both plain function
    // pointers (an `Option<extern "system" fn() -> isize>` is a nullable pointer),
    // so the sizes match; `None` maps to `None`. The DLL's Rust source declares
    // `StandaloneEntryW` with exactly the signature of `StandaloneEntry`. Doing the
    // conversion in one step keeps the null case impossible to forget: there is no
    // intermediate non-null function pointer that could be fabricated from `None`.
    let entry: Option<StandaloneEntry> =
        unsafe { std::mem::transmute::<FARPROC, Option<StandaloneEntry>>(procedure) };
    let Some(entry) = entry else {
        // SAFETY: as above -- read immediately after the failing lookup.
        let error = unsafe { GetLastError() };
        return fatal(&format!(
            "rustHashTab loaded its window component but could not find the entry point.\r\n\r\n\
             {dll_display}\r\n\r\nWin32 error {}. The DLL is not a rustHashTab build this \
             launcher understands.",
            error.0
        ));
    };

    // SAFETY: the DLL was loaded successfully and its export was found, so calling
    // the function is the documented use of that export. The command-line pointer
    // from GetCommandLineW is owned by the process and valid until exit. A null
    // owner window and instance are correct for a top-level window whose state is
    // owned by the DLL's own module, and `SW_SHOWNORMAL` is the show command the
    // contract specifies.
    unsafe {
        entry(
            HWND::default(),
            HINSTANCE::default(),
            GetCommandLineW(),
            SW_SHOWNORMAL.0,
        )
    }
}

/// Opt into per-monitor DPI awareness v2 if the process is not already aware.
///
/// The manifest asks for the same thing, and when it was applied the API call
/// fails with `ERROR_ACCESS_DENIED` because DPI awareness can only be set once.
/// That failure is the expected case and is ignored. The runtime call matters for
/// the case where the external manifest was not found -- for example a bare EXE
/// copied without its `.manifest` neighbor -- where it would otherwise run
/// system-DPI aware and blur on a scaled monitor.
fn become_dpi_aware() {
    // SAFETY: both functions only set the DPI awareness of the calling process and
    // are documented to be called before any window is created; this runs before
    // the DLL is loaded, so no window exists yet. Their return values are ignored
    // on purpose: "already set" is a success for the launcher's purposes.
    unsafe {
        if SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2).is_err() {
            let _ = SetProcessDPIAware();
        }
    }
}

/// The full path of the running executable, as UTF-16 without a trailing NUL.
///
/// The buffer is sized for the long-path limit (32,767 units plus the NUL) because
/// the manifest declares `longPathAware`. A full buffer means the path did not
/// fit, which is reported as an error rather than silently truncated to something
/// that points at the wrong directory.
fn executable_path() -> Result<Vec<u16>, u32> {
    const CAPACITY: usize = 32_768;
    let mut buffer = vec![0u16; CAPACITY];

    // SAFETY: `buffer` is a live, writable slice of CAPACITY u16 units, which is
    // the buffer and size the API requires. `None` asks for the path of the
    // current executable's module; the pointer returned is into `buffer`.
    let length = unsafe { GetModuleFileNameW(None, &mut buffer) } as usize;
    // SAFETY: GetLastError has no preconditions; it is read immediately after the
    // call whose failure it describes.
    let error = unsafe { GetLastError() };

    if length == 0 || length >= CAPACITY {
        return Err(error.0);
    }
    buffer.truncate(length);
    Ok(buffer)
}

/// The absolute, NUL-terminated path of `rusthashtab_shell.dll` beside the
/// executable at `executable`.
///
/// `None` when the executable path has no directory separator, which cannot happen
/// for a path returned by `GetModuleFileNameW` and is therefore treated as a bug
/// rather than as a recoverable condition.
fn shell_dll_path(executable: &[u16]) -> Option<Vec<u16>> {
    let separator = u16::from(b'\\');
    let directory_length = executable.iter().rposition(|&unit| unit == separator)? + 1;

    let mut path = Vec::with_capacity(directory_length + SHELL_DLL.len() + 1);
    path.extend_from_slice(&executable[..directory_length]);
    path.extend(SHELL_DLL.encode_utf16());
    path.push(0);
    Some(path)
}

/// Show an error to the user and return the failure exit code.
///
/// A GUI-subsystem process has no console, so a message box is the only channel
/// that reaches the person who double-clicked the EXE. The box is application
/// modal on purpose: `None` owner rather than a window the launcher does not have.
fn fatal(message: &str) -> i32 {
    let text = wide(message);
    let caption = wide("rustHashTab");

    // SAFETY: both buffers are NUL-terminated, live across the call, and are only
    // read by the API. A null owner window is allowed and makes the box
    // application modal.
    unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(text.as_ptr()),
            PCWSTR::from_raw(caption.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
    1
}

/// `text` as a NUL-terminated UTF-16 buffer for the Win32 wide-character APIs.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A UTF-16 buffer, with any trailing NUL removed, as a display string.
fn text_from_wide(units: &[u16]) -> String {
    let length = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    String::from_utf16_lossy(&units[..length])
}
