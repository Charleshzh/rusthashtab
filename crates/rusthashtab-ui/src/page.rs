//! Construction of the property sheet page, and the ownership contract that goes
//! with it.
//!
//! # Ownership, stated once
//!
//! A `PROPSHEETPAGEW` hands the shell a raw `lParam` pointer to a
//! `Box<DialogState>`. Deciding who frees it is the single most dangerous part of
//! a property sheet handler, because getting it wrong is either a leak or a
//! double free inside `explorer.exe`. Three cases exist, and they are not
//! symmetric:
//!
//! | Case | Who frees the state | Who destroys the page |
//! |---|---|---|
//! | `CreatePropertySheetPageW` fails | we do, immediately | no page exists |
//! | `lpfnAddPage` returns FALSE | **nobody** -- the shell still does | we call `DestroyPropertySheetPage` |
//! | success | the shell, on `PSPCB_RELEASE` | the shell, when the sheet closes |
//!
//! The middle row is the trap. Once the page exists, the shell owns it and will
//! call the page callback with `PSPCB_RELEASE`; freeing the state ourselves as
//! well is a double free. `SHELL-EXTENSION-NOTES.md` records this path as
//! unverified, and `tests/page_ownership.rs` verifies it.

#![cfg(windows)]

use crate::resource::IDD_HASH_PROPPAGE;
use crate::{DialogState, UiError};
use std::path::PathBuf;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    CreatePropertySheetPageW, DestroyPropertySheetPage, HPROPSHEETPAGE, PROPSHEETPAGEW,
    PROPSHEETPAGEW_0, PROPSHEETPAGEW_1, PROPSHEETPAGEW_2, PSP_USECALLBACK, PSP_USEREFPARENT,
    PSP_USETITLE,
};
use windows::core::{BOOL, PCWSTR, w};

/// The page's title in the property sheet tab strip.
const PAGE_TITLE: PCWSTR = w!("Hashes");

/// The shell's "add this page to my sheet" callback.
///
/// `windows-rs` names this `LPFNSVADDPROPSHETTYPAGE`; the Win32 documentation
/// calls the same thing `LPFNADDPROPSHEETPAGE`. It is an `Option` because that is
/// how the vtable slot is declared, and it must be called **synchronously, once
/// per page** -- a page added later would arrive at a sheet that has already been
/// laid out.
pub type AddPageCallback = Option<unsafe extern "system" fn(HPROPSHEETPAGE, LPARAM) -> BOOL>;

/// The page's real dialog procedure, reachable through a plain dialog.
///
/// # Why a wrapper is needed at all
///
/// [`crate::dialog::dlg_proc`] reads the state out of a `PROPSHEETPAGEW` on
/// `WM_INITDIALOG`, because that is what `comctl32` hands a property sheet page. A
/// dialog created directly gets the caller's `lParam` instead, so this wraps it in the
/// very structure the real procedure expects.
///
/// Everything a test then exercises -- the template, the controls, the message
/// routing, the hashing thread, the teardown -- is the same code the shell reaches.
/// What a test **cannot** reach this way is the property sheet itself: `PropertySheetW`
/// is modal, and the page only has to receive messages. The sheet's half is the part
/// the manual check covers.
///
/// The state stays **borrowed**: the caller owns the `Box` and reclaims it. The page
/// callback is deliberately not invoked on this path, because there is no page for it
/// to release.
///
/// # Why this is public
///
/// It exists so the hosted-page test can reach the real dialog procedure without a
/// property sheet. Making it `pub` rather than `pub(crate)` is what lets an
/// integration test -- a separate crate -- call it at all. Nothing in the DLL uses it:
/// `AddPages` goes through [`add_page`], which builds a real `PROPSHEETPAGEW`.
///
/// # Safety
///
/// Called by `comctl32` for a dialog created with this as its procedure. On
/// `WM_INITDIALOG`, `lparam` must be the address of the `DialogState` the caller
/// owns, and that state must outlive the window.
pub extern "system" fn test_dlg_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> isize {
    let mut page = PROPSHEETPAGEW {
        lParam: lparam,
        ..Default::default()
    };
    // `on_init` reads `(*page).lParam`, which is what this arranges. The local is
    // borrowed only for the duration of the call.
    let translated = LPARAM((&mut page as *mut PROPSHEETPAGEW) as isize);
    crate::dialog::dlg_proc(hwnd, message, wparam, translated)
}

/// Build the page and hand it to the shell in one step.
///
/// This is the whole of what `IShellPropSheetExt::AddPages` does, kept in the
/// library rather than in the DLL so it can be called from a test.
///
/// # Errors
///
/// [`UiError::MissingResource`] when the dialog template cannot be created -- the
/// template id is wrong, or `hinstance` is not this module. Handing back an error
/// means the shell shows the Properties dialog without our page, which is the
/// right failure: a page with no controls in it is worse than no page.
pub fn add_page(
    hinstance: HINSTANCE,
    roots: Vec<PathBuf>,
    settings: &rusthashtab_settings::Settings,
    add_page_callback: AddPageCallback,
    lparam: LPARAM,
) -> Result<(), UiError> {
    let Some(add_page_callback) = add_page_callback else {
        // `AddPages` must call this synchronously, once per page, and the shell
        // does. Refusing here rather than dereferencing is the difference between
        // a page that does not appear and a crash in the host.
        return Err(UiError::PageRefused);
    };

    if hinstance.is_invalid() {
        // A null `HINSTANCE` means `DllMain` never recorded the module handle, so
        // no dialog template can be found in it. Failing here rather than passing
        // it to `CreatePropertySheetPageW` keeps the diagnosis in the error
        // instead of leaving it as "the page would not appear".
        return Err(UiError::MissingResource(IDD_HASH_PROPPAGE));
    }

    let state = Box::new(DialogState::new(roots, settings.clone()));
    let state_pointer = Box::into_raw(state);

    let mut template = PROPSHEETPAGEW {
        dwSize: core::mem::size_of::<PROPSHEETPAGEW>() as u32,
        // `PSP_USEREFPARENT` points the sheet at the module lock count, so the
        // DLL cannot be unloaded while the page is up. Without it the only thing
        // keeping the DLL alive is COM's object count, and the object is released
        // before the sheet closes.
        dwFlags: PSP_USETITLE | PSP_USECALLBACK | PSP_USEREFPARENT,
        hInstance: hinstance,
        Anonymous1: PROPSHEETPAGEW_0 {
            pszTemplate: PCWSTR(IDD_HASH_PROPPAGE as usize as *const u16),
        },
        Anonymous2: PROPSHEETPAGEW_1::default(),
        pszTitle: PAGE_TITLE,
        pfnDlgProc: Some(crate::dialog::dlg_proc),
        lParam: LPARAM(state_pointer as isize),
        pfnCallback: crate::dialog::page_callback(),
        // SAFETY of the cast: `AtomicU32` is guaranteed to have the same size and
        // alignment as `u32`, which is what `PROPSHEETPAGEW` requires of this
        // field. The sheet increments and decrements it *without* atomics -- it
        // is an ATL-era `UINT` contract -- so the atomic here is a formality for
        // our own reads. The project's contributor notes record this, and the
        // alignment is asserted by a test.
        pcRefParent: rusthashtab_abi::MODULE_LOCKS.as_ptr().cast::<u32>(),
        pszHeaderTitle: PCWSTR::null(),
        pszHeaderSubTitle: PCWSTR::null(),
        hActCtx: Default::default(),
        Anonymous3: PROPSHEETPAGEW_2::default(),
    };

    // SAFETY: `template` is a fully initialised `PROPSHEETPAGEW` whose `dwSize`
    // is its own size, which is what the API requires. On success the returned
    // page owns the template's contents for as long as it lives.
    let page: HPROPSHEETPAGE = unsafe { CreatePropertySheetPageW(&mut template) };

    if page.is_invalid() {
        // No page, so no `PSPCB_RELEASE` will ever arrive: the state is ours to
        // free. Dropping the `Box` we made is the only correct action here.
        // SAFETY: `state_pointer` came from `Box::into_raw` above and has not been
        // given to anyone else.
        drop(unsafe { Box::from_raw(state_pointer) });
        return Err(UiError::MissingResource(IDD_HASH_PROPPAGE));
    }

    // SAFETY: `page` is a live page handle from `CreatePropertySheetPageW` and
    // `lparam` is the shell's own parameter, passed straight back to the callback
    // the shell gave us. This is the call `AddPages` exists to make.
    if unsafe { add_page_callback(page, lparam) }.as_bool() {
        return Ok(());
    }

    // The shell refused the page. It still owns it -- `DestroyPropertySheetPage`
    // is ours to call, and the callback will still be invoked with
    // `PSPCB_RELEASE`, which is what frees the state. Freeing it here as well
    // would be a double free, so this deliberately does not.
    // SAFETY: `page` is a live page handle from `CreatePropertySheetPageW` and has
    // not been destroyed.
    let _ = unsafe { DestroyPropertySheetPage(page) };
    Err(UiError::PageRefused)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// `GetModuleHandleW(None)` is this test binary's own module, which is a real
    /// `HINSTANCE` that simply has no `IDD_HASH_PROPPAGE` in it.
    fn this_module() -> HINSTANCE {
        // SAFETY: a null module name asks for the module the caller is in, which
        // always exists.
        unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
                .expect("the test binary has a module handle")
        }
        .into()
    }

    /// A callback that refuses every page.
    extern "system" fn refusing_callback(_page: HPROPSHEETPAGE, _lparam: LPARAM) -> BOOL {
        false.into()
    }

    /// A callback that accepts every page.
    extern "system" fn accepting_callback(_page: HPROPSHEETPAGE, _lparam: LPARAM) -> BOOL {
        true.into()
    }

    /// A null `HINSTANCE` means `DllMain` never recorded the module, so there is
    /// nowhere for the template to come from.
    #[test]
    fn a_page_with_no_module_is_reported_as_a_missing_resource() {
        let result = add_page(
            HINSTANCE(core::ptr::null_mut()),
            Vec::new(),
            &rusthashtab_settings::Settings::default(),
            Some(refusing_callback),
            LPARAM(0),
        );

        match result {
            Err(UiError::MissingResource(id)) => assert_eq!(id, IDD_HASH_PROPPAGE),
            other => panic!("expected a missing-resource failure, got {other:?}"),
        }
    }

    /// A module that does not contain the template cannot produce a page.
    ///
    /// Either failure is correct here, and which one arrives depends on the target:
    /// `CreatePropertySheetPageW` either refuses the null page itself
    /// (`MissingResource`) or returns a page anyway and rejects it when it is added
    /// (`PageRefused`). Both mean the same thing to the shell -- the page does not
    /// appear -- so the assertion is that *a* failure is reported, and that nothing
    /// was handed over.
    #[test]
    fn a_module_without_the_template_is_reported_rather_than_handed_over() {
        let result = add_page(
            this_module(),
            Vec::new(),
            &rusthashtab_settings::Settings::default(),
            Some(refusing_callback),
            LPARAM(0),
        );

        match result {
            Err(UiError::MissingResource(id)) => assert_eq!(id, IDD_HASH_PROPPAGE),
            Err(UiError::PageRefused) => {}
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// A missing callback is refused rather than dereferenced: `AddPages` must
    /// call it synchronously, and a null one is a shell bug that must not take
    /// the host down.
    #[test]
    fn a_missing_add_page_callback_is_refused() {
        let result = add_page(
            this_module(),
            Vec::new(),
            &rusthashtab_settings::Settings::default(),
            None,
            LPARAM(0),
        );
        match result {
            Err(UiError::PageRefused) => {}
            other => panic!("expected a refused page, got {other:?}"),
        }
    }

    /// The refusal path is the middle row of the ownership table in the module
    /// documentation, and the dangerous one: the page existed, so the shell will
    /// still call `PSPCB_RELEASE` on it, which is where the state is freed. This
    /// must not free it as well -- a double free inside `explorer.exe`.
    ///
    /// It needs a page that can be created without a dialog template, which this
    /// test binary does not have. `tests/property_sheet_page.rs` hosts a real
    /// property sheet for that; the accepting callback is exercised there too.
    #[test]
    fn the_accepting_callback_is_reachable_only_from_a_real_page() {
        let _ = accepting_callback;
    }
}
