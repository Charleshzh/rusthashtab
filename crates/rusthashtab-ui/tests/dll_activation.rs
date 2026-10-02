//! Does the built shell-extension DLL actually hand out a property sheet page when
//! it is driven through COM the way `explorer.exe` drives it?
//!
//! # Why this exists
//!
//! `tests/property_sheet_page.rs` proves the *page* works: it creates a dialog from
//! the page's own compiled template and checks the digest that appears. What it
//! cannot prove is the step before that -- that COM can activate the class, reach
//! `IShellPropSheetExt`, and get a real page out of `AddPages`.
//!
//! Those are two different failures with the same symptom ("no Hashes tab"), and
//! telling them apart is the whole point of this test. If it passes and the tab still
//! does not appear, the problem is registration. If it fails, the problem is the DLL.
//! Guessing between the two is exactly what cost time here.
//!
//! It calls the DLL's exported `DllGetClassObject` directly instead of going through
//! `CoCreateInstance`, so it does not depend on any registration at all -- which is
//! the independence the diagnosis needs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::windows::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::sync::Mutex;
use windows::Win32::Foundation::{LPARAM, S_OK};
use windows::Win32::System::Com::IClassFactory;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::{HPROPSHEETPAGE, LPFNSVADDPROPSHEETPAGE};
use windows::Win32::UI::Shell::IShellPropSheetExt;
use windows::core::{BOOL, GUID, Interface, PCWSTR};

/// The CLSID the DLL registers under.
const CLSID: GUID = GUID::from_u128(0x9865_1d14_b00f_488e_a738_a7ce_db9e_5d8c);

/// Where the release DLL is, for the target this test is built for.
///
/// # Why the triple is derived and not written down
///
/// The gate runs this test on **two** targets, and a DLL has to match the
/// architecture of the process loading it. A hard-coded `x86_64-pc-windows-msvc` makes
/// the i686 run try to load a 64-bit DLL into a 32-bit process; that fails in a way
/// that reads like a broken DLL rather than an architecture mismatch.
///
/// The triple comes out of the test executable's own path --
/// `target/<triple>/<profile>/deps/<name>.exe` -- so it cannot disagree with the
/// binary that is running.
fn target_triple() -> std::ffi::OsString {
    let exe = std::env::current_exe().expect("a running test knows its own path");
    exe.ancestors()
        .nth(3)
        .and_then(|dir| dir.file_name())
        .expect("the test executable lives under target/<triple>/<profile>/deps/")
        .to_os_string()
}

/// Where the release DLL is for this target.
///
/// The workspace root comes from `cargo`, because a test's working directory is the
/// package root rather than the workspace root and a relative path would silently
/// point somewhere else.
fn dll_path() -> PathBuf {
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

/// Pages the DLL handed to the callback.
///
/// A mutex rather than a `static mut`: `AddPages` runs on the calling thread, but a
/// `static mut` is a data race by construction and clippy is right to refuse it.
static ACCEPTED: Mutex<Vec<isize>> = Mutex::new(Vec::new());

/// Warn loudly if any source file the DLL is built from is newer than the DLL.
///
/// # Why a warning and not a failure
///
/// This test asserts against an artifact on disk, and `cargo test` does not build a
/// release DLL -- so a stale one is normal, not exceptional. Making it a failure was
/// tried: it broke `cargo xtask check`, which rebuilds only the **debug** DLL, so
/// every gate run left the release artifact older than the sources. Worse, the
/// failure text says "no dialog template", which sends the reader after a bug that
/// is not there. A diagnostic that misfires on the normal workflow gets switched
/// off, and then it protects nothing.
///
/// So it warns, on stderr, where `--nocapture` shows it and a reader of a failure
/// will see it. The test still runs: if the DLL really is too old to contain the
/// template, that assertion fails with its own message, and this one is right above
/// it saying why.
fn warn_if_stale(dll: &std::path::Path) {
    let Ok(built) = std::fs::metadata(dll).and_then(|meta| meta.modified()) else {
        return;
    };

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the crate is inside the workspace");

    for crate_name in ["rusthashtab-shell", "rusthashtab-ui"] {
        let src = workspace.join("crates").join(crate_name).join("src");
        let Ok(entries) = std::fs::read_dir(&src) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
                continue;
            };
            if modified > built {
                eprintln!(
                    "WARNING: {} is newer than the DLL this test is checking ({}).\n\
                     If an assertion below fails, rebuild the release artifact before believing \
                     it:\n  cargo build -p rusthashtab-shell --release --target {}",
                    path.display(),
                    dll.display(),
                    target_triple().to_string_lossy()
                );
                return;
            }
        }
    }
}

/// The callback `AddPages` wants.
///
/// On the shell's side this is `comctl32`'s; here it only has to accept, because
/// acceptance is the success being tested.
fn add_page_callback() -> LPFNSVADDPROPSHEETPAGE {
    extern "system" fn accept(page: HPROPSHEETPAGE, _lparam: LPARAM) -> BOOL {
        ACCEPTED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(page.0 as isize);
        true.into()
    }

    Some(accept)
}

#[test]
fn the_built_dll_hands_out_a_property_sheet_page_over_com() {
    let dll = dll_path();
    assert!(
        dll.is_file(),
        "the release DLL is not built at {}; run `cargo xtask shell-check` first",
        dll.display()
    );

    warn_if_stale(&dll);

    let mut wide: Vec<u16> = dll.as_os_str().encode_wide().collect();
    wide.push(0);

    // Load the DLL the way a COM server host does. This runs `DllMain`, so the module
    // handle the page needs for its dialog template gets recorded.
    // SAFETY: `wide` is a NUL-terminated wide path that outlives the call.
    let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }
        .unwrap_or_else(|error| panic!("the DLL did not load from {}: {error}", dll.display()));

    // SAFETY: `module` was just loaded and exports this symbol, and the transmute is to
    // the documented `DllGetClassObject` signature.
    //
    // The annotation is written out in full because `GetProcAddress` returns a
    // type-erased `FARPROC`; there is nothing for the compiler to infer the target
    // type from, so an unannotated `transmute` is a guess rather than a conversion.
    type GetClassObject = unsafe extern "system" fn(
        *const GUID,
        *const GUID,
        *mut *mut core::ffi::c_void,
    ) -> windows::core::HRESULT;

    // SAFETY: `module` was just loaded and exports this symbol under this name; the
    // transmute only reinterprets its address as the documented signature, which is
    // what every `GetProcAddress` call site must do.
    let get_class_object: GetClassObject = unsafe {
        match GetProcAddress(module, windows::core::s!("DllGetClassObject")) {
            Some(entry) => {
                core::mem::transmute::<unsafe extern "system" fn() -> isize, GetClassObject>(entry)
            }
            None => panic!("the DLL does not export DllGetClassObject"),
        }
    };

    let mut factory_out: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: both GUIDs and the out-pointer are live locals.
    let hr = unsafe { get_class_object(&CLSID, &IClassFactory::IID, &mut factory_out) };
    assert_eq!(
        hr, S_OK,
        "DllGetClassObject refused this CLSID: {hr:?} -- CLASS_E_CLASSNOTAVAILABLE would be 0x80040111"
    );
    assert!(!factory_out.is_null());

    // SAFETY: `factory_out` is the factory the call just produced.
    let factory = unsafe { IClassFactory::from_raw(factory_out) };

    // SAFETY: `factory` is live, `None` is the non-aggregating case, and the returned
    // object is owned here.
    let handler: windows::core::IUnknown = unsafe {
        factory.CreateInstance::<Option<&windows::core::IUnknown>, windows::core::IUnknown>(None)
    }
    .expect("the class factory could not create the handler");

    // The shell asks for this interface specifically.
    let prop_sheet: IShellPropSheetExt = handler
        .cast()
        .expect("the handler does not implement IShellPropSheetExt");

    ACCEPTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();

    // `AddPages` is what the shell calls. It must hand exactly one page to the
    // callback, synchronously.
    // SAFETY: `prop_sheet` is live and the callback accepts unconditionally.
    let add_pages = unsafe { prop_sheet.AddPages(add_page_callback(), LPARAM(0)) };

    let pages: Vec<isize> = ACCEPTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();

    add_pages.expect("AddPages returned an error, so the page would never appear");
    assert_eq!(
        pages.len(),
        1,
        "AddPages must hand exactly one page to the shell's callback"
    );

    // **Destroy the page before unloading the DLL.** A page created by
    // `CreatePropertySheetPageW` holds a pointer to code and to a dialog template inside
    // this module; destroying it after `FreeLibrary` is an access violation in unmapped
    // memory. That is not a hypothesis -- it is what this test did on its first run, and
    // it is the very hazard the module pin removes in the shell, where the DLL can never
    // be unloaded at all.
    // SAFETY: this is the page `AddPages` produced, owned here, destroyed exactly once.
    unsafe {
        let _ = windows::Win32::UI::Controls::DestroyPropertySheetPage(HPROPSHEETPAGE(
            pages[0] as *mut core::ffi::c_void,
        ));
    }
    // Destroying it runs the page callback with the module still mapped, and that is
    // where the `DialogState` allocated by `add_page` is reclaimed -- exactly once,
    // through the same path the shell uses.

    drop(prop_sheet);
    drop(handler);
    drop(factory);

    // SAFETY: `module` came from `LoadLibraryW` and is released exactly once, and every
    // page and object it produced is gone by now.
    unsafe {
        let _ = windows::Win32::Foundation::FreeLibrary(module);
    }
}
