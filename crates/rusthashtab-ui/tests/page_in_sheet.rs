//! Does the page initialise inside a REAL property sheet that this process owns?
//!
//! # The question this answers
//!
//! The trace from inside `explorer.exe` reads:
//!
//! ```text
//! AddPages: page handed over
//! ui: page callback message PSPCB_MESSAGE(1)      <- PSPCB_RELEASE
//! ```
//!
//! with **no `WM_INITDIALOG`** anywhere. So `comctl32` created the page, the shell
//! accepted the handle, and the page was released without a window ever being built
//! for it. Two very different faults look like that from the outside:
//!
//!   * our page is malformed, so no sheet can build a window for it; or
//!   * the shell accepted the handle into a sheet it never displayed.
//!
//! This test puts the page into a property sheet that this process owns and drives,
//! which removes the shell from the equation. If `WM_INITDIALOG` arrives here, the
//! page is fine.
//!
//! It is `#[ignore]`d because it creates and shows a real window, which is not
//! something a test suite should do behind someone's back. Run it with:
//!
//! ```text
//! cargo test -p rusthashtab-ui --target x86_64-pc-windows-msvc \
//!     --test page_in_sheet -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// A resource id is passed as a pointer, which is what MAKEINTRESOURCE means. The
// pointer is never dereferenced, so the lint's concern does not apply.
#![allow(clippy::manual_dangling_ptr)]

use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows::Win32::UI::Controls::{
    CreatePropertySheetPageW, HPROPSHEETPAGE, PROPSHEETHEADERW_V2, PROPSHEETHEADERW_V2_0,
    PROPSHEETHEADERW_V2_1, PROPSHEETHEADERW_V2_2, PROPSHEETPAGEW, PROPSHEETPAGEW_0,
    PROPSHEETPAGEW_1, PROPSHEETPAGEW_2, PSH_MODELESS, PSH_NOAPPLYNOW, PSP_USECALLBACK,
    PSP_USEREFPARENT, PSP_USETITLE, PSPCB_MESSAGE, PropertySheetW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
};
use windows::core::{PCWSTR, w};

/// Set when the page's dialog procedure sees `WM_INITDIALOG`.
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// Where the release build of the shell extension is, for the target this test is
/// built for.
///
/// # Why this is derived rather than written down
///
/// The gate runs this test binary on **two** targets -- x86_64 and i686 -- and a DLL
/// has to match the architecture of the process that loads it. A path with
/// `x86_64-pc-windows-msvc` baked into it makes the i686 run load a 64-bit DLL into a
/// 32-bit process, which fails, and the failure looks like a missing resource rather
/// than an architecture mismatch.
///
/// The target triple is read out of the test executable's own path, which is
/// `target/<triple>/<profile>/deps/<name>.exe`. That is the same triple cargo built
/// this binary for, so it cannot disagree with the DLL it then looks for.
fn target_triple() -> std::ffi::OsString {
    let exe = std::env::current_exe().expect("a running test knows its own path");
    // `ancestors()` starts at the path itself, so `deps` is 1, `<profile>` is 2 and
    // `<triple>` is 3. Measured against a real path rather than counted from the
    // string, because getting it wrong yields `target` and the failure then reads as
    // "the DLL has no dialog template".
    let triple = exe
        .ancestors()
        .nth(3)
        .and_then(|dir| dir.file_name())
        .expect("the test executable lives under target/<triple>/<profile>/deps/")
        .to_os_string();

    assert!(
        triple.to_string_lossy().contains('-'),
        "derived `{}` from {}, which is not a target triple",
        triple.to_string_lossy(),
        exe.display()
    );
    triple
}

/// Where the release build of the shell extension is for this target.
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

/// The page's dialog procedure.
///
/// It answers `WM_INITDIALOG` by recording that it was called and returning TRUE, so
/// the sheet keeps the window. Everything else is left to `DefDlgProc` by returning
/// FALSE, which is all this diagnostic needs.
unsafe extern "system" fn dlg_proc(
    _hwnd: HWND,
    message: u32,
    _wparam: WPARAM,
    _lparam: LPARAM,
) -> isize {
    const WM_INITDIALOG: u32 = 0x0110;
    if message == WM_INITDIALOG {
        INITIALISED.store(true, Ordering::SeqCst);
        eprintln!("  >>> our dialog procedure received WM_INITDIALOG");
        return 1;
    }
    0
}

/// Records what `comctl32` does to the page.
extern "system" fn page_callback(
    _hwnd: HWND,
    message: PSPCB_MESSAGE,
    _ppsp: *mut PROPSHEETPAGEW,
) -> u32 {
    eprintln!("  [page callback] message {message:?}");
    1
}

/// The dialog template must be **in the DLL**.
///
/// # Why this is its own test, and why it is not ignored
///
/// `ui.rc` is compiled by this crate's build script, but a `rustc-link-arg` emitted
/// from a **library's** build script only applies to that library's own artifact --
/// an `.rlib`, where a `.res` file has no symbols and is therefore dropped when the
/// `cdylib` is linked. The result was a DLL with the version resource and **no dialog
/// template at all**: `AddPages` returned `S_OK`, the shell accepted the page, and no
/// window was ever built for it, so the Hashes tab simply never appeared.
///
/// Nothing caught it, because:
///
///   * `resource.rs`'s test parses `ui.rc` as **text** with `include_str!`, which says
///     the identifiers agree and nothing about whether the file was compiled;
///   * `tests/property_sheet_page.rs` creates the dialog from `rustc`'s **own**
///     generated resource in the test binary, which is a different module;
///   * `tests/dll_activation.rs` checks the page is created and handed over, which it
///     was.
///
/// So this asks the one question none of them asked: is the template reachable through
/// the module the page actually uses? It is cheap, it needs no window, and it is the
/// check that would have caught this before it reached `explorer.exe`.
#[test]
fn the_dll_contains_the_pages_dialog_template() {
    let dll = dll_path();
    assert!(dll.is_file(), "build the DLL first: {}", dll.display());

    // A real resource name, not `MAKEINTRESOURCE`: the `windows` crate's raw-pointer
    // signature cannot express an integer id, and a small integer reinterpreted as a
    // pointer that is never dereferenced is exactly the sentinel `FindResourceW`
    // documents. This mirrors what `page.rs` does for the same reason.
    fn resource_name(id: usize) -> PCWSTR {
        PCWSTR(id as *const u16)
    }

    // The wide path has to outlive the call: `PCWSTR` borrows it, and binding the
    // `Vec` here rather than letting a temporary drop at the end of the statement is
    // what keeps that true.
    let wide = wide_path(&dll);
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let module = unsafe {
        windows::Win32::System::LibraryLoader::LoadLibraryExW(
            PCWSTR(wide.as_ptr()),
            None,
            windows::Win32::System::LibraryLoader::LOAD_LIBRARY_AS_DATAFILE,
        )
    }
    .expect("the DLL must be loadable for resource access");

    const IDD_HASH_PROPPAGE: usize = 101;
    const RT_DIALOG: usize = 5;
    const RT_VERSION: usize = 16;

    // SAFETY: `module` is a live module handle and `resource_name` produces the
    // `MAKEINTRESOURCE` sentinel the API documents for the integer forms.
    let dialog = unsafe {
        windows::Win32::System::LibraryLoader::FindResourceW(
            Some(module),
            resource_name(IDD_HASH_PROPPAGE),
            resource_name(RT_DIALOG),
        )
    };
    // SAFETY: as above.
    let version = unsafe {
        windows::Win32::System::LibraryLoader::FindResourceW(
            Some(module),
            resource_name(1),
            resource_name(RT_VERSION),
        )
    };

    // SAFETY: `module` came from `LoadLibraryExW` and is released once.
    unsafe {
        let _ = windows::Win32::Foundation::FreeLibrary(module);
    }

    assert!(
        !version.is_invalid(),
        "the DLL has no version resource either, so its resources were not compiled \
         into it at all -- check the build scripts"
    );
    assert!(
        !dialog.is_invalid(),
        "IDD_HASH_PROPPAGE is not in the DLL. The page can be created and handed to \
         the shell, but no window can ever be built for it, so the tab never appears. \
         A resource compiled by a library's build script does not reach the cdylib: \
         the dialog template has to be linked into the DLL itself."
    );
}

/// A NUL-terminated wide version of `path`.
fn wide_path(path: &std::path::Path) -> Vec<u16> {
    std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect()
}

#[test]
#[ignore = "shows a real window; run with --ignored"]
fn the_page_initialises_inside_a_real_property_sheet() {
    // 1. Load the real DLL, so the module that the dialog template lives in is the
    //    shipping one rather than this test binary.
    let dll = dll_path();
    assert!(dll.is_file(), "build the DLL first: {}", dll.display());
    let wide = wide_path(&dll);
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }.expect("the DLL must load");
    println!("loaded {}", dll.display());

    // 2. Read the dialog template straight out of the DLL, the way `comctl32` will,
    //    so the test cannot accidentally use the test binary's own resources.
    let template_id = 101usize; // IDD_HASH_PROPPAGE
    // SAFETY: `module` is a live module handle and 101 is the template the page asks
    // for. A null `lpType` means `RT_DIALOG`.
    let template = unsafe {
        windows::Win32::System::LibraryLoader::FindResourceW(
            Some(module),
            PCWSTR(template_id as *const u16),
            PCWSTR(5 as *const u16), // RT_DIALOG
        )
    };
    assert!(
        !template.is_invalid(),
        "IDD_HASH_PROPPAGE is not in the DLL -- the page would have no template at all"
    );
    println!("dialog template found in the DLL");

    // 3. Build the page exactly as `page::add_page` does.
    let mut page_template = PROPSHEETPAGEW {
        dwSize: core::mem::size_of::<PROPSHEETPAGEW>() as u32,
        dwFlags: PSP_USETITLE | PSP_USECALLBACK | PSP_USEREFPARENT,
        hInstance: module.into(),
        Anonymous1: PROPSHEETPAGEW_0 {
            pszTemplate: PCWSTR(template_id as *const u16),
        },
        Anonymous2: PROPSHEETPAGEW_1::default(),
        pszTitle: w!("Hashes"),
        pfnDlgProc: Some(dlg_proc),
        lParam: LPARAM(0),
        pfnCallback: Some(page_callback),
        pcRefParent: core::ptr::null_mut(),
        pszHeaderTitle: PCWSTR::null(),
        pszHeaderSubTitle: PCWSTR::null(),
        hActCtx: Default::default(),
        Anonymous3: PROPSHEETPAGEW_2::default(),
    };

    // SAFETY: `page_template` is fully initialised and `dwSize` is its own size.
    let page: HPROPSHEETPAGE = unsafe { CreatePropertySheetPageW(&mut page_template) };
    println!(
        "CreatePropertySheetPageW -> {}",
        if page.is_invalid() {
            "FAILED"
        } else {
            "a page handle"
        }
    );
    assert!(!page.is_invalid(), "the page could not be created at all");

    // 4. Put it in a sheet this process owns and drives.
    //
    // `PROPSHEETHEADERW_V2` rather than the older shapes: `PropertySheetW` in
    // `windows` 0.62 takes exactly this type, and it is the one whose size matches
    // the `dwSize` the API validates against.
    let mut pages = [page];
    // SAFETY: a null module name asks for this process's own module, which always
    // exists. It is used only as the sheet's resource scope, and the sheet does not
    // outlive this function.
    let this_module = unsafe { GetModuleHandleW(None) }.expect("the test binary has a module");

    let mut header = PROPSHEETHEADERW_V2 {
        dwSize: core::mem::size_of::<PROPSHEETHEADERW_V2>() as u32,
        dwFlags: PSH_MODELESS | PSH_NOAPPLYNOW,
        hwndParent: HWND::default(),
        hInstance: this_module.into(),
        Anonymous1: PROPSHEETHEADERW_V2_0 {
            pszIcon: PCWSTR::null(),
        },
        pszCaption: w!("rustHashTab page diagnostic"),
        nPages: 1,
        Anonymous2: PROPSHEETHEADERW_V2_1 { nStartPage: 0 },
        Anonymous3: PROPSHEETHEADERW_V2_2 {
            phpage: pages.as_mut_ptr(),
        },
        pfnCallback: None,
        Anonymous4: Default::default(),
        hplWatermark: Default::default(),
        Anonymous5: Default::default(),
    };

    // SAFETY: `header` is fully initialised, `dwSize` is its own size, and `pages`
    // outlives the call.
    let sheet = unsafe { PropertySheetW(&mut header) };
    println!("PropertySheetW -> {sheet}  (-1 means failure)");
    assert_ne!(sheet, -1, "the property sheet could not be created");

    // 5. Pump, so the page's `WM_INITDIALOG` has somewhere to arrive.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    // SAFETY: `msg` is a live local for the whole loop.
    unsafe {
        let mut msg = MSG::default();
        while std::time::Instant::now() < deadline && !INITIALISED.load(Ordering::SeqCst) {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    println!(
        "WM_INITDIALOG seen by our page: {}",
        INITIALISED.load(Ordering::SeqCst)
    );
    println!("sheet window: {sheet:#x}");

    // 6. Show what it looks like, so the result is a picture rather than an inference.
    // SAFETY: the sheet is a live window this process owns.
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::ShowWindow(
            HWND(sheet as *mut core::ffi::c_void),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOW,
        );
    }
    std::thread::sleep(std::time::Duration::from_millis(600));
    let mut class_name = [0u16; 256];
    // SAFETY: the buffer is `MAX_PATH` wide chars, which is what the call expects.
    let len = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetClassNameW(
            HWND(sheet as *mut core::ffi::c_void),
            &mut class_name,
        )
    };
    println!(
        "sheet class: {}",
        String::from_utf16_lossy(&class_name[..len as usize])
    );

    assert!(
        INITIALISED.load(Ordering::SeqCst),
        "the page's dialog procedure never saw WM_INITDIALOG, so no sheet can display \
         this page -- the fault is in the page, not in the shell"
    );

    // Teardown. The sheet is modeless, so it is this process's job.
    // SAFETY: the sheet window is live and owned here.
    unsafe {
        let _ = DestroyWindow(HWND(sheet as *mut core::ffi::c_void));
    }
    println!("done; if you saw a window with a Hashes page, the page works.");
}
