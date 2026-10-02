//! The shell extension object: the selection, and the property sheet page.
//!
//! # The two interfaces, and why they are one object
//!
//! `explorer.exe` activates this class per property dialog, hands the selection
//! to `IShellExtInit::Initialize`, and then calls
//! `IShellPropSheetExt::AddPages`. One object serves both because the selection
//! is the only state `AddPages` needs.
//!
//! # What `AddPages` is not allowed to do
//!
//! It runs on the thread that owns the Properties dialog, and everything the user
//! sees is blocked while it runs. It therefore does **no file system work at
//! all**: it records the paths, asks `rusthashtab-ui` for a page, and returns.
//! Expanding a directory selection and hashing the contents happen on a thread
//! the page owns.

#![cfg(windows)]

use rusthashtab_abi::{GuardError, Guarded, guarded};
use std::path::PathBuf;
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, LPARAM};
use windows::Win32::System::Com::{
    DVASPECT_CONTENT, FORMATETC, IDataObject, STGMEDIUM, TYMED_HGLOBAL,
};
use windows::Win32::System::Ole::{CF_HDROP, ReleaseStgMedium};
use windows::Win32::System::Registry::HKEY;
use windows::Win32::UI::Controls::LPFNSVADDPROPSHEETPAGE;
use windows::Win32::UI::Shell::Common::ITEMIDLIST;
use windows::Win32::UI::Shell::{
    DragQueryFileW, HDROP, IShellExtInit, IShellExtInit_Impl, IShellPropSheetExt,
    IShellPropSheetExt_Impl,
};
use windows::core::{GUID, Ref, Result, implement};

/// Identifies this shell extension.
///
/// Generated for this project; it is not copied from the implementation this one
/// replaces, which matters -- a shared CLSID would make two extensions fight over
/// one registration.
pub const CLSID: GUID = GUID::from_u128(0x9865_1d14_b00f_488e_a738_a7ce_db9e_5d8c);

/// The `IShellExtInit` / `IShellPropSheetExt` implementation.
#[implement(IShellExtInit, IShellPropSheetExt, Agile = false)]
pub(super) struct HashPropSheet {
    /// Paths the shell says are selected: the roots to hash.
    ///
    /// Stored as handed over, not resolved: resolving here would stat the file
    /// system on the dialog's thread.
    selection: std::sync::Mutex<Vec<PathBuf>>,
}

impl HashPropSheet {
    /// A handler with no selection yet.
    ///
    /// Raises [`rusthashtab_abi::OBJECT_COUNT`], which [`HashPropSheet::drop`]
    /// lowers. The pair is what `DllCanUnloadNow` reports on.
    ///
    /// # Why the counter is here and not in `AddRef`/`Release`
    ///
    /// `#[implement]` generates `IUnknownImpl` for the wrapper type, and a second
    /// implementation is a coherence error, so there is no place to hook the
    /// reference count without wrapping the generated object in another layer.
    /// There is also no need: `DllCanUnloadNow`'s contract is "no objects and no
    /// locks", and the number of *objects* is exactly what construction and
    /// destruction measure. Counting references instead would make the answer
    /// depend on how many times a client happened to call `QueryInterface`.
    pub(super) fn new() -> Self {
        rusthashtab_abi::add_object();
        Self {
            selection: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// The recorded selection, cloned out from under the lock.
    fn take_selection(&self) -> Vec<PathBuf> {
        // A poisoned mutex means a previous caller panicked while holding it,
        // which cannot leave the vector inconsistent. Refusing to proceed would
        // turn one contained panic into a page that never appears.
        self.selection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Lower [`rusthashtab_abi::OBJECT_COUNT`] when the last reference goes away.
///
/// This is where the object stops being live, which is the moment COM will next
/// ask whether the DLL may be unloaded.
impl Drop for HashPropSheet {
    fn drop(&mut self) {
        rusthashtab_abi::release_object();
    }
}

impl IShellExtInit_Impl for HashPropSheet_Impl {
    /// Record which files the user selected.
    ///
    /// Everything comes out of the `IDataObject` as a `CF_HDROP` list. A
    /// selection that has no `CF_HDROP` -- a virtual item such as a file inside a
    /// compressed folder -- is refused, and the shell then simply does not add
    /// the page.
    fn Initialize(
        &self,
        _pidlfolder: *const ITEMIDLIST,
        pdtobj: Ref<IDataObject>,
        _hkeyprogid: HKEY,
    ) -> Result<()> {
        let result: Guarded<()> = guarded(|| {
            let Some(data_object) = pdtobj.as_ref() else {
                return Err(E_INVALIDARG.into());
            };

            let paths = read_hdrop(data_object).ok_or(E_INVALIDARG)?;

            let mut selection = self
                .selection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *selection = paths;
            Ok(())
        });

        result.map_err(to_com_error)
    }
}

impl IShellPropSheetExt_Impl for HashPropSheet_Impl {
    /// Build the page and hand it to the shell.
    ///
    /// `#[implement]` generates an `extern "system"` vtable slot for this method,
    /// so the body runs inside [`guarded`]: an unwind reaching that slot would
    /// abort `explorer.exe` rather than our own process.
    fn AddPages(&self, pfnaddpage: LPFNSVADDPROPSHEETPAGE, lparam: LPARAM) -> Result<()> {
        let result: Guarded<()> = guarded(|| {
            let Some(add_page) = pfnaddpage else {
                return Err(E_INVALIDARG.into());
            };

            let roots = self.take_selection();
            // Read once, here, on the dialog's thread: `RegGetValueW` is a
            // handful of microseconds and the alternative -- loading settings on
            // the hashing thread -- would let the user's first view of the page
            // show defaults that then change under them.
            let settings = rusthashtab_settings::Settings::default().load();
            let instance = crate::module::instance()
                .ok_or_else(|| windows::core::Error::from(E_INVALIDARG))?;

            rusthashtab_ui::page::add_page(instance, roots, &settings, Some(add_page), lparam)
                .map_err(to_guard_error)?;
            Ok(())
        });

        result.map_err(to_com_error)
    }

    /// Never called for a file-type handler, so there is nothing to replace.
    fn ReplacePage(
        &self,
        _upageid: u32,
        _pfnreplacewith: LPFNSVADDPROPSHEETPAGE,
        _lparam: LPARAM,
    ) -> Result<()> {
        Err(E_NOTIMPL.into())
    }
}

/// Pull the selected paths out of a `CF_HDROP` on `data_object`.
///
/// Returns `None` when there is no `CF_HDROP`, which is not an error condition so
/// much as "this selection is not a set of files".
fn read_hdrop(data_object: &IDataObject) -> Option<Vec<PathBuf>> {
    let format = FORMATETC {
        cfFormat: CF_HDROP.0,
        ptd: core::ptr::null_mut(),
        dwAspect: DVASPECT_CONTENT.0,
        lindex: -1,
        tymed: TYMED_HGLOBAL.0 as u32,
    };

    // SAFETY: `format` describes a `CF_HDROP` and lives for the call, which is
    // all `GetData` requires. The returned medium belongs to us until released.
    let mut medium: STGMEDIUM = unsafe { data_object.GetData(&format).ok()? };
    let paths = extract_paths(&medium);

    // SAFETY: `medium` was filled in by `GetData` and has not been released yet,
    // which is exactly `ReleaseStgMedium`'s precondition. This runs on every
    // exit path below, so the clipboard's shared memory is never leaked.
    unsafe { ReleaseStgMedium(&mut medium) };

    paths
}

/// Read the file list out of a `CF_HDROP` medium.
fn extract_paths(medium: &STGMEDIUM) -> Option<Vec<PathBuf>> {
    if medium.tymed != TYMED_HGLOBAL.0 as u32 {
        return None;
    }

    let drop = {
        // SAFETY: `tymed` was checked two lines up, so the union's active member
        // is `hGlobal` -- which is what `CF_HDROP` is delivered as, and reading
        // any other member would be reading a pointer as something else.
        unsafe { HDROP(medium.u.hGlobal.0) }
    };

    // An `iFile` of 0xFFFFFFFF asks for the count rather than a path. This is the
    // documented way to size the list, and it is also why the count cannot be
    // obtained from the medium's size: the format is variable-length.
    // SAFETY: `drop` came from a medium the shell produced for `CF_HDROP`, and a
    // null buffer with an out-of-range index is documented to return the count.
    let count = unsafe { DragQueryFileW(drop, u32::MAX, None) };
    if count == 0 {
        return Some(Vec::new());
    }

    let mut paths = Vec::with_capacity(count as usize);
    for index in 0..count {
        // SAFETY: the same `drop` as above; a null buffer asks for the length of
        // the `index`-th name, which is what sizes the buffer next.
        let length = unsafe { DragQueryFileW(drop, index, None) };
        if length == 0 {
            continue;
        }

        let mut buffer = vec![0u16; length as usize + 1];
        // SAFETY: `buffer` has room for `length + 1` UTF-16 units, which is what
        // the API writes including its terminating NUL.
        let written = unsafe { DragQueryFileW(drop, index, Some(&mut buffer)) };
        if written == 0 {
            continue;
        }

        buffer.truncate(written as usize);
        paths.push(PathBuf::from(String::from_utf16_lossy(&buffer)));
    }

    Some(paths)
}

/// Convert a `Guarded` failure into the `HRESULT` COM sees.
///
/// `S_OK` on success; on failure the concrete `HRESULT` the body produced, or
/// `E_UNEXPECTED` for a contained panic -- see `rusthashtab_abi`.
fn to_com_error(error: GuardError) -> windows::core::Error {
    windows::core::HRESULT::from(error).into()
}

/// Turn a `rusthashtab-ui` failure into something the guard can carry.
///
/// The UI's errors are not `HRESULT`s -- a missing dialog resource is not a COM
/// condition -- and the shell has no use for the distinction. What it needs to
/// know is only that the page could not be built. [`rusthashtab_ui::UiError`]
/// decides the code, so that mapping lives with the error rather than with every
/// caller of it.
fn to_guard_error(error: rusthashtab_ui::UiError) -> GuardError {
    GuardError::from(windows::core::Error::from(error.to_hresult()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_clsid_is_a_version_four_uuid() {
        // Not decoration: a v4 UUID has its version and variant nibbles fixed, and
        // a typo there means a GUID that looks generated but may collide with one
        // assigned under a different scheme.
        let bytes = CLSID.to_u128().to_be_bytes();
        assert_eq!(bytes[6] >> 4, 4, "version nibble is not 4");
        assert_eq!(bytes[8] >> 6, 0b10, "variant bits are not RFC 4122");
    }

    #[test]
    fn a_handler_with_no_selection_reports_none() {
        let handler = HashPropSheet::new();
        assert!(handler.take_selection().is_empty());
    }

    /// The selection is shared with the page's worker thread, so reading it must
    /// survive a panic in another thread. Refusing to proceed would turn one
    /// contained panic into a missing page.
    #[test]
    fn a_poisoned_selection_lock_still_reads() {
        let handler = std::sync::Arc::new(HashPropSheet::new());
        *handler.selection.lock().expect("fresh lock") = vec![PathBuf::from(r"C:\x.txt")];

        let poisoner = std::sync::Arc::clone(&handler);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.selection.lock().expect("lock");
            panic!("poison the mutex");
        })
        .join();

        assert_eq!(handler.take_selection(), vec![PathBuf::from(r"C:\x.txt")]);
    }

    /// A medium that is not an `HGLOBAL` is not a `CF_HDROP`, and reading it as
    /// one would dereference whatever else is in the union.
    #[test]
    fn a_non_hglobal_medium_yields_no_paths() {
        let medium = STGMEDIUM::default();
        assert!(extract_paths(&medium).is_none());
    }

    /// `ReplacePage` is never called for a file-type handler; answering
    /// `E_NOTIMPL` is what the documentation prescribes.
    #[test]
    fn replace_page_is_not_implemented() {
        let handler: IShellPropSheetExt = HashPropSheet::new().into();
        // SAFETY: `ReplacePage` with no callback and a zero lparam touches
        // nothing; it returns before looking at either.
        let refused = unsafe { handler.ReplacePage(0, None, LPARAM(0)) };
        assert_eq!(refused.unwrap_err().code(), E_NOTIMPL);
    }
}
