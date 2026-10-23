//! A real settings dialog, checked for the colour sample.
//!
//! The sample is not a label that happens to have text: its foreground comes
//! from `WM_CTLCOLORSTATIC` and its background is the brush that handler
//! returns. This test opens the shipping DLL's settings template, asks the
//! dialog for the sample's DC colours, and checks both. It is `#[ignore]`d
//! because it creates and shows a real window.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetDC, GetObjectW, GetTextColor, HGDIOBJ, LOGBRUSH, ReleaseDC,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetDlgItem, GetWindowTextW, PostMessageW, WM_COMMAND, WM_CTLCOLORSTATIC,
};
use windows::core::{PCWSTR, w};

fn target_triple() -> std::ffi::OsString {
    let exe = std::env::current_exe().expect("a running test knows its own path");
    exe.ancestors()
        .nth(3)
        .and_then(|dir| dir.file_name())
        .expect("the test executable lives under target/<triple>/<profile>/deps/")
        .to_os_string()
}

fn dll_path() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the crate is inside the workspace");
    workspace
        .join("target")
        .join(target_triple())
        .join("release")
        .join("rusthashtab_shell.dll")
}

fn wide_path(path: &std::path::Path) -> Vec<u16> {
    std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect()
}

#[test]
#[ignore = "shows a real window; run with --ignored"]
fn the_colour_sample_has_the_selected_colours() {
    let dll = dll_path();
    assert!(dll.is_file(), "build the DLL first: {}", dll.display());
    let wide = wide_path(&dll);
    // SAFETY: the path is NUL-terminated and outlives the call.
    let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }.expect("the DLL must load");
    // SAFETY: a null module name asks for this process's own module.
    let _this = unsafe { GetModuleHandleW(None) }.expect("the test binary has a module");

    let settings = rusthashtab_settings::Settings::default();
    let instance = module.0 as isize;
    let worker = std::thread::spawn(move || {
        rusthashtab_ui::settings_dialog::show(
            HWND::default(),
            windows::Win32::Foundation::HINSTANCE(instance as *mut core::ffi::c_void),
            &settings,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut dialog = HWND::default();
    while Instant::now() < deadline {
        // SAFETY: both class and title are optional; the title is a static wide
        // string and the call only reads it.
        dialog =
            unsafe { FindWindowW(PCWSTR::null(), w!("rustHashTab Settings")) }.unwrap_or_default();
        if !dialog.is_invalid() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!dialog.is_invalid(), "the settings dialog never appeared");

    // SAFETY: `dialog` is the live settings dialog and both ids name controls
    // its template declares.
    let sample = unsafe { GetDlgItem(Some(dialog), 2116) }.expect("the sample control exists");
    // SAFETY: as above.
    let label = unsafe { GetDlgItem(Some(dialog), 2122) }.expect("the label control exists");
    let mut label_text = [0u16; 128];
    // SAFETY: the buffer is a live local and the call writes at most its length.
    let label_len = unsafe { GetWindowTextW(label, &mut label_text) };
    let label = String::from_utf16_lossy(&label_text[..label_len as usize]);
    assert!(
        label.contains("#2DAA17"),
        "the label should show the default matched background, got {label:?}"
    );

    // SAFETY: `sample` is a child of `dialog`; the DC is released below.
    let dc = unsafe { GetDC(Some(sample)) };
    assert!(!dc.is_invalid(), "the sample has no DC");
    // SAFETY: the dialog is live, `dc` is a display DC, and the sample handle is
    // the child the message is about.
    let brush = unsafe {
        windows::Win32::UI::WindowsAndMessaging::SendMessageW(
            dialog,
            WM_CTLCOLORSTATIC,
            Some(WPARAM(dc.0 as usize)),
            Some(LPARAM(sample.0 as isize)),
        )
    };
    // SAFETY: `dc` is a live display DC obtained for the sample.
    let text = unsafe { GetTextColor(dc) };
    assert_eq!(text, COLORREF(0x00FF_FFFF), "matched text should be white");

    let mut logbrush = LOGBRUSH::default();
    // SAFETY: `brush` is the HBRUSH returned by the handler; `logbrush` is a
    // live local of the right size.
    let copied = unsafe {
        GetObjectW(
            HGDIOBJ(brush.0 as *mut core::ffi::c_void),
            core::mem::size_of::<LOGBRUSH>() as i32,
            Some(&mut logbrush as *mut LOGBRUSH as *mut core::ffi::c_void),
        )
    };
    assert_eq!(copied as usize, core::mem::size_of::<LOGBRUSH>());
    assert_eq!(
        logbrush.lbColor,
        COLORREF(0x0017_AA2D),
        "matched background should be the green fill"
    );

    // SAFETY: the DC came from GetDC for this sample and is released once.
    unsafe {
        let _ = ReleaseDC(Some(sample), dc);
    }
    // IDCANCEL = 2. The dialog is modal on the worker thread.
    // SAFETY: `dialog` is live until the worker returns.
    unsafe {
        let _ = PostMessageW(Some(dialog), WM_COMMAND, WPARAM(2), LPARAM(0));
    }
    let _ = worker.join();
}
