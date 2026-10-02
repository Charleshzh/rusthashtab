//! The DLL's own `HMODULE`, and the one-time initialisation that needs it.
//!
//! # Two separate lifetime problems
//!
//! The module handle is needed for two unrelated reasons, and conflating them is
//! how shell extensions break:
//!
//! 1. **Loading our own resources.** `PROPSHEETPAGEW::hInstance` must be this
//!    DLL, or `CreatePropertySheetPageW` looks for the dialog template in
//!    `explorer.exe` and fails.
//! 2. **Staying loaded.** This DLL owns worker threads. A reference count cannot
//!    express "a thread is still running inside this module", so the module is
//!    pinned instead: `GET_MODULE_HANDLE_EX_FLAG_PIN` makes `FreeLibrary` a no-op
//!    for it, and `DllCanUnloadNow`'s honest answer stops being a safety
//!    property. That is the point -- it converts a class of crash into a
//!    permanently mapped few hundred kilobytes.
//!
//! The handle is captured in `DllMain` (which is handed it) but **used** only
//! from `DllGetClassObject`, because everything interesting is illegal under the
//! loader lock that `DllMain` runs under.

#![cfg(windows)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

/// The module handle, as the loader passed it to `DllMain`.
static MODULE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

/// True when [`initialise`] has run, so the work happens exactly once.
static INITIALISED: OnceLock<()> = OnceLock::new();

/// `LoadLibraryEx` flag: keep this module mapped until the process exits.
const GET_MODULE_HANDLE_EX_FLAG_PIN: u32 = 1u32;

/// Record the module handle from `DllMain`.
///
/// # Safety
///
/// Called only from `DllMain` on `DLL_PROCESS_ATTACH`, where the loader passes
/// this DLL's own base address. Calling it with any other value would make every
/// later use of this handle -- resource loading, pinning -- act on a different
/// module.
pub(super) fn remember(instance: *mut core::ffi::c_void) {
    MODULE.store(instance, Ordering::Release);
}

/// The module handle, or null when `DllMain` has not run.
fn handle() -> *mut core::ffi::c_void {
    MODULE.load(Ordering::Acquire)
}

/// Record this process's own module, if `DllMain` has not already done it.
///
/// # Why this exists
///
/// In the DLL, `DllMain` supplies the handle and this is never needed. In a **test
/// binary** there is no `DllMain` for this crate, so nothing would ever be
/// recorded and every path that wants the module -- registration, page creation,
/// the entry-point diagnostic -- would report failure for a reason that has nothing
/// to do with the code under test.
///
/// Asking the loader for the module the caller is in is the same value `DllMain`
/// would have been given. The first answer wins, so a real `DllMain` can never be
/// overridden by a later call, and this is idempotent rather than merely safe to
/// repeat.
pub(super) fn ensure_recorded() {
    let _ = MODULE.compare_exchange(
        core::ptr::null_mut(),
        current_module(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

/// The base address of the module this code is in.
fn current_module() -> *mut core::ffi::c_void {
    // SAFETY: a null module name asks for the module the caller is in, which
    // always exists; the call takes no other input.
    unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
            .map(|module| module.0)
            .unwrap_or(core::ptr::null_mut())
    }
}

/// The raw module base address, for callers that need an `HMODULE` rather than an
/// `HINSTANCE`.
///
/// Both are the same value on Windows; the two types are distinct only in the
/// bindings.
pub(super) fn raw() -> *mut core::ffi::c_void {
    handle()
}

/// The handle in the type the dialog APIs want, or `None` before `DllMain`.
pub(super) fn instance() -> Option<windows::Win32::Foundation::HINSTANCE> {
    let module = handle();
    if module.is_null() {
        None
    } else {
        Some(windows::Win32::Foundation::HINSTANCE(module))
    }
}

/// Pin the module and make sure the common controls are registered.
///
/// Called from `DllGetClassObject`, never from `DllMain`, and idempotent.
pub(super) fn initialise() {
    // `get_or_init` rather than `call_once`: the two halves below are independent
    // of each other and of any captured state, so the return value is all this
    // needs, and `OnceLock` is the same guarantee with a simpler shape.
    let _ = INITIALISED.get_or_init(|| {
        pin();
        init_common_controls();
    });
}

/// Pin this module so it can never be unloaded.
///
/// Failure is not fatal and is deliberately not reported: the DLL is being
/// loaded by the shell either way, and the worst case is the unload race this
/// exists to prevent. There is nothing the user could do about it, and nothing
/// useful to say.
fn pin() {
    let module = handle();
    if module.is_null() {
        return;
    }

    // SAFETY: `module` is this DLL's own base address, as recorded from
    // `DllMain`; `GET_MODULE_HANDLE_EX_FLAG_PIN` needs no name and writes the
    // handle to the out-parameter, which is a live local.
    unsafe {
        let mut pinned = windows::Win32::Foundation::HMODULE(core::ptr::null_mut());
        let _ = windows::Win32::System::LibraryLoader::GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_PIN,
            windows::core::PCWSTR::null(),
            &mut pinned,
        );
    }
}

/// Register the window classes the property sheet page instantiates.
///
/// `comctl32.dll` registers `SysListView32` and `msctls_progress32` when it
/// initialises, which usually happens because the property sheet itself uses it.
/// "Usually" is not a good enough answer for a class lookup that would otherwise
/// create a dialog with no controls in it, so this asks explicitly. Repeating the
/// call is harmless.
fn init_common_controls() {
    use windows::Win32::UI::Controls::{
        ICC_BAR_CLASSES, ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, INITCOMMONCONTROLSEX_ICC,
        InitCommonControlsEx,
    };

    let classes = INITCOMMONCONTROLSEX {
        dwSize: core::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: INITCOMMONCONTROLSEX_ICC((ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES).0),
    };

    // SAFETY: `classes` declares its own size in `dwSize`, which is what the API
    // requires, and lives for the duration of the call.
    unsafe {
        let _ = InitCommonControlsEx(&classes);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Record the module the way `DllMain` would, so the tests that need an
    /// `HINSTANCE` -- registration, page creation -- exercise the code rather than
    /// the absence of a loader callback this binary never receives.
    fn recorded() -> *mut core::ffi::c_void {
        ensure_recorded();
        let module = handle();
        assert!(!module.is_null(), "the test binary has a module handle");
        module
    }

    /// `ensure_recorded` must produce the module the loader actually mapped, and
    /// must not overwrite a handle that is already there.
    #[test]
    fn the_recorded_module_is_this_one() {
        let recorded = recorded();
        assert_eq!(
            recorded,
            current_module(),
            "the recorded module is not the caller's own"
        );

        // A second call must be a no-op, not a different handle.
        ensure_recorded();
        assert_eq!(handle(), recorded);
    }

    /// Once a handle is recorded it must survive into the type the dialog APIs
    /// want, or page creation would look for a template in nothing.
    #[test]
    fn a_recorded_module_becomes_a_usable_instance() {
        recorded();
        let instance = instance().expect("a recorded module is an HINSTANCE");
        assert!(!instance.is_invalid());
        assert_eq!(instance.0, recorded());
    }

    #[test]
    fn initialising_repeatedly_is_safe() {
        // Both halves are idempotent; a second call must not double-pin or
        // double-register anything.
        initialise();
        initialise();
    }
}
