//! The shell extension object: the selection, the property sheet page, and the
//! context-menu command.
//!
//! # Three interfaces, one object
//!
//! `explorer.exe` activates this class per property dialog, hands the selection
//! to `IShellExtInit::Initialize`, and then calls
//! `IShellPropSheetExt::AddPages`. For a right-click it hands the same selection
//! to the same `Initialize` and then calls `IContextMenu::QueryContextMenu`,
//! `GetCommandString`, and `InvokeCommand`. One object serves all three because
//! the selection is the only state any of them needs.
//!
//! # What the shell's threads are not allowed to do
//!
//! `AddPages` and `InvokeCommand` run on the thread that owns the Properties
//! dialog or the context menu, and everything the user sees is blocked while they
//! run. Neither does any file-system work: `AddPages` records the paths, asks
//! `rusthashtab-ui` for a page, and returns. `InvokeCommand` clones the paths and
//! starts a dedicated apartment-threaded window thread, then waits only for that
//! window to exist -- the scan and the message loop belong to the new thread. The
//! property page's scan, as before, happens on a thread the page owns.

#![cfg(windows)]

use crate::com::Apartment;
use rusthashtab_abi::{GuardError, Guarded, guarded};
use rusthashtab_ui::strings::{self, Key};
use rusthashtab_ui::window::{self, HostOptions};
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::Duration;
use windows::Win32::Foundation::{E_FAIL, E_INVALIDARG, E_NOTIMPL, HWND, LPARAM};
use windows::Win32::System::Com::{
    DVASPECT_CONTENT, FORMATETC, IDataObject, STGMEDIUM, TYMED_HGLOBAL,
};
use windows::Win32::System::Ole::{CF_HDROP, ReleaseStgMedium};
use windows::Win32::System::Registry::HKEY;
use windows::Win32::UI::Controls::LPFNSVADDPROPSHEETPAGE;
use windows::Win32::UI::Shell::Common::ITEMIDLIST;
use windows::Win32::UI::Shell::{
    CMF_DEFAULTONLY, CMF_VERBSONLY, CMINVOKECOMMANDINFO, DragQueryFileW, GCS_HELPTEXTA,
    GCS_HELPTEXTW, GCS_VALIDATEA, GCS_VALIDATEW, GCS_VERBA, GCS_VERBW, HDROP, IContextMenu,
    IContextMenu_Impl, IShellExtInit, IShellExtInit_Impl, IShellPropSheetExt,
    IShellPropSheetExt_Impl,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, HMENU, InsertMenuW, IsWindow, MB_ICONERROR, MB_OK, MF_BYPOSITION, MF_STRING,
    MessageBoxW, SW_SHOWNORMAL,
};
use windows::core::{GUID, HRESULT, PCSTR, PCWSTR, PSTR, Ref, Result, implement};

/// Identifies this shell extension.
///
/// Generated for this project; it is not copied from the implementation this one
/// replaces, which matters -- a shared CLSID would make two extensions fight over
/// one registration.
pub const CLSID: GUID = GUID::from_u128(0x9865_1d14_b00f_488e_a738_a7ce_db9e_5d8c);

/// The `IShellExtInit` / `IShellPropSheetExt` / `IContextMenu` implementation.
#[implement(IShellExtInit, IShellPropSheetExt, IContextMenu, Agile = false)]
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

    /// Whether the shell handed us at least one path.
    ///
    /// Separate from [`HashPropSheet::take_selection`]: the menu code only needs
    /// the answer, and copying the paths would be pointless work on the thread
    /// that is drawing the menu.
    fn has_selection(&self) -> bool {
        !self
            .selection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
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
            // show defaults that then change under them. The UI loads with the
            // real algorithm table's names, because the settings layer
            // deliberately does not depend on the hash crate and a shorter list
            // would map flags onto the wrong algorithms.
            let settings = rusthashtab_ui::load_settings();
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

impl IContextMenu_Impl for HashPropSheet_Impl {
    /// Add the Hashes command to the menu the shell is building.
    ///
    /// The vtable slot returns an `HRESULT` the shell reads as a count of inserted
    /// items rather than as a status: `HRESULT(1)` means one item was added and
    /// `HRESULT(0)` means none. Windows-rs models this one method with a raw
    /// `HRESULT` return precisely because the success value carries information.
    fn QueryContextMenu(
        &self,
        hmenu: HMENU,
        indexmenu: u32,
        idcmdfirst: u32,
        idcmdlast: u32,
        uflags: u32,
    ) -> HRESULT {
        let result: Guarded<HRESULT> = guarded(|| {
            if !menu_should_appear(uflags, self.has_selection()) || idcmdfirst > idcmdlast {
                return Ok(HRESULT(0));
            }

            let text = wide(strings::text(Key::ContextMenuHashes));
            // SAFETY: `hmenu` is the menu COM passed for this call and is valid for
            // its duration; `text` is a NUL-terminated buffer that outlives the
            // call. `MF_BYPOSITION` reads `indexmenu` as a position, and the item
            // id is the command id `GetCommandString` and `InvokeCommand` will see.
            let inserted = unsafe {
                InsertMenuW(
                    hmenu,
                    indexmenu,
                    MF_BYPOSITION | MF_STRING,
                    idcmdfirst as usize,
                    PCWSTR(text.as_ptr()),
                )
            };

            // A failed insertion is `0` items, not a failure code the shell could
            // show: the menu simply does not contain the command.
            Ok(if inserted.is_ok() {
                HRESULT(1)
            } else {
                HRESULT(0)
            })
        });

        match result {
            Ok(count) => count,
            Err(error) => error.into(),
        }
    }

    /// Start the dedicated window thread for an invocation of the Hashes command.
    ///
    /// Nothing that can block happens on the shell's thread: the selection is
    /// cloned, the thread is started, and this call waits only for the window to
    /// exist. Settings are loaded and the window is built on the new thread.
    fn InvokeCommand(&self, pici: *const CMINVOKECOMMANDINFO) -> Result<()> {
        let result: Guarded<()> = guarded(|| {
            // A null `pici`, a string verb, or a command id other than the one this
            // handler inserted are all "not our command".
            let Some(command) = menu_command_id(pici) else {
                return Err(E_INVALIDARG.into());
            };
            if command != 0 {
                return Err(E_INVALIDARG.into());
            }

            let roots = self.take_selection();
            if roots.is_empty() {
                // The shell should not have offered the command for an empty
                // selection, but the menu is the shell's: refuse rather than open
                // a window with nothing to hash.
                return Err(E_FAIL.into());
            }

            // SAFETY: `menu_command_id` only returns a value for a non-null `pici`,
            // and COM guarantees the structure is valid for the duration of the
            // call. Only the window handle is read.
            let owner = unsafe { (*pici).hwnd };

            // The object count is raised before the thread exists; the thread takes
            // ownership of the release so a panic inside it can neither leak the
            // count nor let COM unload the DLL under a live window.
            rusthashtab_abi::add_object();
            let hold = ObjectHold;

            let (sender, receiver) = std::sync::mpsc::sync_channel::<Readiness>(1);
            let spawned = std::thread::Builder::new()
                .name(String::from("rusthashtab-context-window"))
                .spawn(move || context_window_thread(hold, roots, sender));

            if spawned.is_err() {
                // `spawn` dropped the closure, and with it the object hold. There
                // is no window to report on, so the closest honest message is the
                // timeout one: the window never opened.
                show_error(owner, strings::text(Key::WindowStartTimeout));
                return Err(E_FAIL.into());
            }

            // Ten seconds is far longer than creating a dialog takes; a timeout
            // means the window thread is wedged, not that the machine is slow.
            match receiver.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(message)) => {
                    show_error(
                        owner,
                        &strings::text(Key::WindowOpenFailed).replace("{}", &message),
                    );
                    Err(E_FAIL.into())
                }
                Err(_) => {
                    // Drop the receiver before showing the box: a worker that has
                    // not reached its `send` yet must fail it, tear down the host
                    // it created, and exit, so the user cannot get a window after
                    // being told it did not open in time.
                    drop(receiver);
                    show_error(owner, strings::text(Key::WindowStartTimeout));
                    Err(E_FAIL.into())
                }
            }
        });

        result.map_err(to_com_error)
    }

    /// Describe the command to the shell: its verb, help text, or validity.
    fn GetCommandString(
        &self,
        idcmd: usize,
        utype: u32,
        _preserved: *const u32,
        pszname: PSTR,
        cchmax: u32,
    ) -> Result<()> {
        let result: Guarded<()> = guarded(|| {
            // `idcmd` is an offset from `idCmdFirst`; this handler inserted exactly
            // one command, at offset zero.
            if idcmd != 0 {
                return Err(E_INVALIDARG.into());
            }

            // The low word is the request. The high bits are flags such as
            // `GCS_UNICODE`, which the `_W` constants below already encode.
            match utype & 0xffff {
                GCS_VALIDATEA | GCS_VALIDATEW => Ok(()),
                GCS_VERBW => write_command_string(
                    pszname,
                    cchmax,
                    true,
                    strings::text(Key::ContextMenuHashes),
                ),
                GCS_VERBA => write_command_string(
                    pszname,
                    cchmax,
                    false,
                    strings::text(Key::ContextMenuHashes),
                ),
                GCS_HELPTEXTW => {
                    write_command_string(pszname, cchmax, true, strings::text(Key::ContextMenuHelp))
                }
                GCS_HELPTEXTA => write_command_string(
                    pszname,
                    cchmax,
                    false,
                    strings::text(Key::ContextMenuHelp),
                ),
                _ => Err(E_INVALIDARG.into()),
            }
        });

        result.map_err(to_com_error)
    }
}

/// Whether the Hashes command belongs in the menu being built.
///
/// `CMF_DEFAULTONLY` and `CMF_VERBSONLY` are not the ordinary selection menu: the
/// first asks only for the default verb, and the second is a menu for a shortcut
/// to the object rather than a selection of files. Neither is a place for an extra
/// command, and an empty selection has nothing to hash.
fn menu_should_appear(uflags: u32, has_selection: bool) -> bool {
    has_selection && (uflags & (CMF_DEFAULTONLY | CMF_VERBSONLY)) == 0
}

/// The command offset an invocation names, or `None` when it names none.
///
/// A shell verb is either an integer resource id (a pointer value whose high word
/// is zero) or a pointer to a string. Only the integer form addresses the item
/// this handler inserted; a string pointer read as a number could accidentally
/// match the command id.
fn menu_command_id(pici: *const CMINVOKECOMMANDINFO) -> Option<u32> {
    if pici.is_null() {
        return None;
    }

    // SAFETY: `pici` is non-null, and COM guarantees an `InvokeCommand` pointer is
    // valid for the duration of the call. Only one plain-pointer field is read.
    let verb = unsafe { (*pici).lpVerb };
    command_id_from_verb(verb)
}

/// Decode one shell verb into the command offset it names.
fn command_id_from_verb(verb: PCSTR) -> Option<u32> {
    let address = verb.as_ptr().addr();

    // `MAKEINTRESOURCEA` truncates an integer id to 16 bits, so an integer verb's
    // pointer value is at most `u16::MAX`; anything larger is a real string
    // pointer. A null pointer is `MAKEINTRESOURCEA(0)`.
    if address > usize::from(u16::MAX) {
        return None;
    }

    Some(address as u32)
}

/// Write a command string into the buffer the shell supplied.
///
/// The shell documents `cchMax` as a character count for the wide requests and a
/// byte count for the ANSI ones, and it always includes room for the terminator.
/// A null buffer is rejected by the shell's contract for anything but a validate
/// request, which never reaches this function.
fn write_command_string(
    destination: PSTR,
    capacity: u32,
    unicode: bool,
    text: &str,
) -> Guarded<()> {
    if destination.is_null() || capacity == 0 {
        return Err(E_INVALIDARG.into());
    }

    if unicode {
        write_wide_string(destination, capacity, text);
    } else {
        write_ansi_string(destination, capacity, text);
    }

    Ok(())
}

/// Copy `text` into the caller's ANSI buffer, truncated and NUL-terminated.
fn write_ansi_string(destination: PSTR, capacity: u32, text: &str) {
    // The caller checked `capacity != 0`, so the subtraction cannot underflow.
    let capacity = capacity as usize;
    let bytes = text.as_bytes();
    let count = bytes.len().min(capacity - 1);

    // SAFETY: `GetCommandString` documents `pszname` as a writable buffer of
    // `cchmax` bytes for an ANSI request. `count + 1 <= capacity`, so the copy and
    // the terminator both stay inside it.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.as_ptr(), count);
        *destination.as_ptr().add(count) = 0;
    }
}

/// Copy `text` into the caller's wide buffer, truncated and NUL-terminated.
fn write_wide_string(destination: PSTR, capacity: u32, text: &str) {
    // The caller checked `capacity != 0`, so the subtraction cannot underflow.
    let capacity = capacity as usize;
    let units: Vec<u16> = text.encode_utf16().collect();
    let count = units.len().min(capacity - 1);
    let target = destination.as_ptr().cast::<u16>();

    // SAFETY: for a `GCS_*W` request, `GetCommandString` documents `pszname` as a
    // writable buffer of `cchmax` UTF-16 units. `count + 1 <= capacity`, so the
    // copy and the terminator both stay inside it.
    unsafe {
        core::ptr::copy_nonoverlapping(units.as_ptr(), target, count);
        *target.add(count) = 0;
    }
}

/// What the window thread reports once the window is open, or why it is not.
///
/// `Err` carries the user-facing text of the UI's start failure; the receiver
/// turns it into a message box rather than returning COM an error string.
///
/// `std::result::Result` is spelled out because this module imports the
/// `windows` crate's one-parameter `Result`, whose error type is fixed to
/// `windows_core::Error`.
type Readiness = std::result::Result<(), String>;

/// Keeps this DLL's object count raised for as long as the window thread lives.
///
/// Raised by `InvokeCommand` before the thread is spawned, and released by the
/// thread on every exit path including a panic, so `DllCanUnloadNow` cannot report
/// the DLL unloadable while a context window still uses it.
struct ObjectHold;

impl Drop for ObjectHold {
    fn drop(&mut self) {
        rusthashtab_abi::release_object();
    }
}

/// Destroys a host window when dropped, including while a panic unwinds.
///
/// The message loop normally destroys its window before returning; this guard
/// covers the failure and panic paths, where nothing else would.
struct HostWindow(HWND);

impl Drop for HostWindow {
    fn drop(&mut self) {
        if self.0.is_invalid() {
            return;
        }

        // SAFETY: the window was created on this thread, which is the thread that
        // owns it, so destroying it here is allowed even during unwinding. An
        // already destroyed handle is refused by `IsWindow`, and the result is
        // ignored because there is no one left to report a teardown failure to.
        unsafe {
            if IsWindow(Some(self.0)).as_bool() {
                let _ = DestroyWindow(self.0);
            }
        }
    }
}

/// The body of the dedicated context-menu window thread.
///
/// Owns the object-count hold and drops it on every exit path, catches a panic so
/// it cannot escape a thread start, and reports a start failure to the caller
/// instead of letting it wait for the full timeout.
fn context_window_thread(hold: ObjectHold, roots: Vec<PathBuf>, sender: SyncSender<Readiness>) {
    let _hold = hold;

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_context_window(roots, &sender)
    }));

    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            // The receiver may already have timed out and gone away; a failed
            // second send costs nothing and there is no one else to tell.
            let _ = sender.send(Err(message));
        }
        Err(_) => {
            // The guard contained the panic. A host window that already existed was
            // destroyed by its own guard during the unwind. Reporting the failure
            // keeps `InvokeCommand` from waiting out its timeout for a thread that
            // is already gone.
            let _ = sender.send(Err(String::from(
                "the context window thread panicked while starting",
            )));
        }
    }
}

/// Open the context window and run its message loop.
///
/// Runs entirely on the dedicated thread. The window is shown as soon as it
/// exists, and readiness is reported before the message loop starts, so the shell
/// thread is released as early as possible.
fn run_context_window(
    roots: Vec<PathBuf>,
    sender: &SyncSender<Readiness>,
) -> std::result::Result<(), String> {
    // Enter the apartment before anything that could create a COM object. A
    // failure is tolerated by the guard; if it matters, the window host reports it.
    let _apartment = Apartment::new();

    let settings = rusthashtab_ui::load_settings();
    let instance = crate::module::instance()
        .ok_or_else(|| String::from("the extension module handle is not recorded"))?;

    let options = HostOptions {
        show: SW_SHOWNORMAL.0,
        quit_on_close: true,
    };
    let host =
        window::open(instance, roots, settings, options).map_err(|error| error.to_string())?;

    // From here on the window is destroyed on every exit, including an unwind, so
    // a panic cannot leave an ownerless window behind.
    let host = HostWindow(host);

    // The caller is waiting for exactly this: the window exists now, so it may
    // return S_OK. If it has stopped waiting, do not enter a loop nothing owns.
    if sender.send(Ok(())).is_err() {
        return Ok(());
    }

    window::message_loop(host.0).map_err(|error| error.to_string())
}

/// Show an error box owned by the window the shell handed us.
///
/// Runs on the shell's thread only after a command has failed. The result is
/// ignored because there is nowhere left to report a failed message box.
fn show_error(owner: HWND, message: &str) {
    let text = wide(message);
    let caption = wide(strings::text(Key::WindowTitle));
    let parent = (!owner.is_invalid()).then_some(owner);

    // SAFETY: both buffers are NUL-terminated and outlive the call, and a null
    // owner is allowed. A message box is modal to the shell's thread, which is why
    // it is only reached from a path that has already failed.
    unsafe {
        let _ = MessageBoxW(
            parent,
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
    use windows::Win32::UI::Shell::{CMF_EXTENDEDVERBS, CMF_NODEFAULT, CMF_NORMAL};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreatePopupMenu, DestroyMenu, GetMenuItemCount, GetMenuItemID, GetMenuStringW,
    };

    /// A handler whose selection is `paths`.
    fn handler_with(paths: &[&str]) -> HashPropSheet {
        let handler = HashPropSheet::new();
        *handler.selection.lock().expect("a fresh selection lock") =
            paths.iter().map(PathBuf::from).collect();
        handler
    }

    /// The text in a NUL-terminated UTF-16 buffer.
    fn text(units: &[u16]) -> String {
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16_lossy(&units[..length])
    }

    /// The text in a NUL-terminated ANSI buffer.
    fn ansi(bytes: &[u8]) -> String {
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..length]).into_owned()
    }

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

    // ---- QueryContextMenu -------------------------------------------------

    /// The command is a single ordinary menu item, carrying the id the shell
    /// chose for this handler and the string the catalog supplies.
    #[test]
    fn the_context_menu_adds_exactly_one_hashes_item() {
        let handler = handler_with(&[r"C:\a.txt"]);
        let context: IContextMenu = handler.into();

        // SAFETY: a fresh popup menu this test owns and destroys below.
        let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");

        // SAFETY: `menu` and `context` are live for the call, the flags describe an
        // ordinary selection menu, and the handler adds at most one item.
        let added = unsafe { context.QueryContextMenu(menu, 0, 7, 0x7fff, CMF_NORMAL) };
        assert_eq!(added, HRESULT(1), "the Hashes command was not added");

        // SAFETY: `menu` is still live; both calls only read it.
        unsafe {
            assert_eq!(
                GetMenuItemCount(Some(menu)),
                1,
                "the command must be exactly one item"
            );
            assert_eq!(
                GetMenuItemID(menu, 0),
                7,
                "the item must carry idCmdFirst as its id"
            );
        }

        let mut buffer = [0u16; 64];
        // SAFETY: `buffer` is writable for its whole length and `menu` is live;
        // `MF_BYPOSITION` addresses the item by position.
        let written = unsafe { GetMenuStringW(menu, 0, Some(&mut buffer), MF_BYPOSITION) };
        assert!(written > 0, "the menu item has no text");
        assert_eq!(
            String::from_utf16_lossy(&buffer[..written as usize]),
            strings::text(Key::ContextMenuHashes)
        );

        // SAFETY: `menu` was created by this test and is destroyed exactly once.
        unsafe {
            let _ = DestroyMenu(menu);
        }
    }

    /// The two flag values that name a menu other than the ordinary selection
    /// menu must suppress the command instead of adding it anyway.
    #[test]
    fn the_context_menu_is_suppressed_for_special_menus() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        for flags in [
            CMF_DEFAULTONLY,
            CMF_VERBSONLY,
            CMF_DEFAULTONLY | CMF_VERBSONLY,
        ] {
            // SAFETY: a fresh popup menu this test owns.
            let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
            // SAFETY: `menu` and `context` are live, and the flags under test are
            // exactly what is being passed through.
            let added = unsafe { context.QueryContextMenu(menu, 0, 7, 0x7fff, flags) };
            assert_eq!(
                added,
                HRESULT(0),
                "flags {flags:#x} must suppress the command"
            );

            // SAFETY: `menu` is live and destroyed exactly once.
            unsafe {
                assert_eq!(GetMenuItemCount(Some(menu)), 0);
                let _ = DestroyMenu(menu);
            }
        }
    }

    /// An empty selection has nothing to hash, so no command is offered.
    #[test]
    fn an_empty_selection_gets_no_context_menu_command() {
        let context: IContextMenu = HashPropSheet::new().into();

        // SAFETY: a fresh popup menu this test owns and destroys below.
        let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
        // SAFETY: `menu` and `context` are live for the call.
        let added = unsafe { context.QueryContextMenu(menu, 0, 7, 0x7fff, CMF_NORMAL) };
        assert_eq!(added, HRESULT(0));

        // SAFETY: `menu` is live and destroyed exactly once.
        unsafe {
            assert_eq!(GetMenuItemCount(Some(menu)), 0);
            let _ = DestroyMenu(menu);
        }
    }

    /// The shell allocates a range of command ids; a range that is already
    /// exhausted must not be written past.
    #[test]
    fn an_exhausted_command_id_range_gets_no_command() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        // SAFETY: a fresh popup menu this test owns and destroys below.
        let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
        // SAFETY: `menu` and `context` are live; `idcmdlast < idcmdfirst` is the
        // case under test.
        let added = unsafe { context.QueryContextMenu(menu, 0, 9, 8, CMF_NORMAL) };
        assert_eq!(added, HRESULT(0));

        // SAFETY: `menu` is live and destroyed exactly once.
        unsafe {
            assert_eq!(GetMenuItemCount(Some(menu)), 0);
            let _ = DestroyMenu(menu);
        }
    }

    // ---- GetCommandString -------------------------------------------------

    /// The verb and the help text come from the string catalog, in both the ANSI
    /// and the wide encoding the shell may ask for.
    #[test]
    fn the_command_strings_come_from_the_catalog_in_both_encodings() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        let mut wide_buffer = [0xffffu16; 64];
        // SAFETY: `wide_buffer` is writable for all 64 UTF-16 units, which is what
        // a wide request expects.
        let status = unsafe {
            context.GetCommandString(
                0,
                GCS_VERBW,
                None,
                PSTR(wide_buffer.as_mut_ptr().cast()),
                wide_buffer.len() as u32,
            )
        };
        assert!(status.is_ok(), "GCS_VERBW failed: {status:?}");
        assert_eq!(text(&wide_buffer), strings::text(Key::ContextMenuHashes));

        let mut ansi_buffer = [0xffu8; 64];
        // SAFETY: `ansi_buffer` is writable for all 64 bytes.
        let status = unsafe {
            context.GetCommandString(
                0,
                GCS_VERBA,
                None,
                PSTR(ansi_buffer.as_mut_ptr()),
                ansi_buffer.len() as u32,
            )
        };
        assert!(status.is_ok(), "GCS_VERBA failed: {status:?}");
        assert_eq!(ansi(&ansi_buffer), strings::text(Key::ContextMenuHashes));

        let mut wide_buffer = [0xffffu16; 128];
        // SAFETY: as above, with room for the longer help text.
        let status = unsafe {
            context.GetCommandString(
                0,
                GCS_HELPTEXTW,
                None,
                PSTR(wide_buffer.as_mut_ptr().cast()),
                wide_buffer.len() as u32,
            )
        };
        assert!(status.is_ok(), "GCS_HELPTEXTW failed: {status:?}");
        assert_eq!(text(&wide_buffer), strings::text(Key::ContextMenuHelp));

        let mut ansi_buffer = [0xffu8; 128];
        // SAFETY: as above, with room for the longer help text.
        let status = unsafe {
            context.GetCommandString(
                0,
                GCS_HELPTEXTA,
                None,
                PSTR(ansi_buffer.as_mut_ptr()),
                ansi_buffer.len() as u32,
            )
        };
        assert!(status.is_ok(), "GCS_HELPTEXTA failed: {status:?}");
        assert_eq!(ansi(&ansi_buffer), strings::text(Key::ContextMenuHelp));
    }

    /// A validate request only asks whether the command exists, and must accept a
    /// null buffer.
    #[test]
    fn a_validate_request_needs_no_buffer() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        for kind in [GCS_VALIDATEA, GCS_VALIDATEW] {
            // SAFETY: a validate request is documented not to touch the buffer, so
            // the null pointer is never dereferenced.
            let status = unsafe { context.GetCommandString(0, kind, None, PSTR::null(), 0) };
            assert!(
                status.is_ok(),
                "GCS_VALIDATEW/A failed for id 0: {status:?}"
            );
        }
    }

    /// A command id this handler did not insert is refused rather than answered
    /// with another command's text.
    #[test]
    fn an_unknown_command_id_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let mut buffer = [0u16; 8];

        // SAFETY: `buffer` is writable; the call must reject the id before it
        // writes anything.
        let status = unsafe {
            context.GetCommandString(
                1,
                GCS_VERBW,
                None,
                PSTR(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
            )
        };
        assert_eq!(
            status.expect_err("id 1 is not a command").code(),
            E_INVALIDARG
        );
    }

    /// A request constant that is not one of the documented ones is invalid, not
    /// silently treated as a verb.
    #[test]
    fn an_unknown_command_string_type_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let mut buffer = [0u16; 8];

        // SAFETY: `buffer` is writable; the call must reject the request before it
        // writes anything.
        let status = unsafe {
            context.GetCommandString(
                0,
                3,
                None,
                PSTR(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
            )
        };
        assert_eq!(
            status.expect_err("type 3 is not a request").code(),
            E_INVALIDARG
        );
    }

    /// The shell must supply a buffer and room for the terminator on anything but
    /// a validate request.
    #[test]
    fn a_missing_buffer_or_zero_capacity_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let mut buffer = [0u16; 8];

        for kind in [GCS_VERBW, GCS_VERBA, GCS_HELPTEXTW, GCS_HELPTEXTA] {
            // SAFETY: a null buffer must be rejected before it is written through.
            let status = unsafe { context.GetCommandString(0, kind, None, PSTR::null(), 8) };
            assert_eq!(
                status.expect_err("a null buffer is invalid").code(),
                E_INVALIDARG
            );

            // SAFETY: a zero capacity must be rejected before it is written
            // through; the buffer itself is valid.
            let status = unsafe {
                context.GetCommandString(0, kind, None, PSTR(buffer.as_mut_ptr().cast()), 0)
            };
            assert_eq!(
                status.expect_err("a zero capacity is invalid").code(),
                E_INVALIDARG
            );
        }
    }

    /// Text longer than the caller's buffer is truncated and terminated instead of
    /// overrunning it, and nothing past `cchMax` is touched.
    #[test]
    fn the_command_string_is_truncated_and_terminated() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        let mut wide_buffer = [0xffffu16; 6];
        // SAFETY: `wide_buffer` is writable for its whole length; a capacity of 3
        // means two characters plus the terminator.
        let status = unsafe {
            context.GetCommandString(0, GCS_VERBW, None, PSTR(wide_buffer.as_mut_ptr().cast()), 3)
        };
        assert!(status.is_ok());
        assert_eq!(
            &wide_buffer[..3],
            &[u16::from(b'H'), u16::from(b'a'), 0],
            "the truncation is not two characters plus a terminator"
        );
        assert_eq!(wide_buffer[3], 0xffff, "wrote past cchMax");

        let mut ansi_buffer = [0xffu8; 6];
        // SAFETY: `ansi_buffer` is writable for its whole length.
        let status = unsafe {
            context.GetCommandString(0, GCS_VERBA, None, PSTR(ansi_buffer.as_mut_ptr()), 3)
        };
        assert!(status.is_ok());
        assert_eq!(&ansi_buffer[..3], b"Ha\0");
        assert_eq!(ansi_buffer[3], 0xff, "wrote past cchMax");

        // A capacity of one has room only for the terminator.
        let mut terminator_only = [0xffffu16; 2];
        // SAFETY: `terminator_only` is writable, and one unit is enough for the
        // terminator.
        let status = unsafe {
            context.GetCommandString(
                0,
                GCS_VERBW,
                None,
                PSTR(terminator_only.as_mut_ptr().cast()),
                1,
            )
        };
        assert!(status.is_ok());
        assert_eq!(terminator_only[0], 0);
        assert_eq!(terminator_only[1], 0xffff, "wrote past cchMax");
    }

    /// The request is the low word; the higher bits are flag space that the `_W`
    /// constants already encode.
    #[test]
    fn the_request_is_masked_to_its_low_word() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let mut buffer = [0u16; 16];

        // SAFETY: `buffer` is writable for its whole length.
        let status = unsafe {
            context.GetCommandString(
                0,
                // A flag above the low word must be masked away rather than
                // changing the request.
                GCS_VERBW | 0x1_0000,
                None,
                PSTR(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
            )
        };
        assert!(status.is_ok());
        assert_eq!(text(&buffer), strings::text(Key::ContextMenuHashes));
    }

    // ---- InvokeCommand ----------------------------------------------------

    #[test]
    fn a_null_invocation_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();

        // SAFETY: the implementation checks `pici` for null before reading through
        // it, which is exactly the case under test.
        let refused = unsafe { context.InvokeCommand(core::ptr::null()) };
        assert_eq!(
            refused.expect_err("a null pici is invalid").code(),
            E_INVALIDARG
        );
    }

    #[test]
    fn a_string_verb_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let info = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR(c"open".as_ptr().cast()),
            ..Default::default()
        };

        // SAFETY: `info` is a live, fully initialised structure for the duration of
        // the call.
        let refused = unsafe { context.InvokeCommand(&info) };
        assert_eq!(
            refused
                .expect_err("a string verb is not our command")
                .code(),
            E_INVALIDARG
        );
    }

    #[test]
    fn a_command_offset_other_than_zero_is_rejected() {
        let context: IContextMenu = handler_with(&[r"C:\a.txt"]).into();
        let info = CMINVOKECOMMANDINFO {
            // An integer verb one past ours: MAKEINTRESOURCEA(1) is the address 1
            // with no provenance, which is how the shell encodes an integer id.
            lpVerb: PCSTR(core::ptr::without_provenance::<u8>(1)),
            ..Default::default()
        };

        // SAFETY: `info` is a live, fully initialised structure for the duration of
        // the call.
        let refused = unsafe { context.InvokeCommand(&info) };
        assert_eq!(
            refused.expect_err("offset 1 is not our command").code(),
            E_INVALIDARG
        );
    }

    /// An invocation with nothing selected fails without starting a thread or
    /// opening a window.
    #[test]
    fn invoking_with_an_empty_selection_fails() {
        let context: IContextMenu = HashPropSheet::new().into();
        let info = CMINVOKECOMMANDINFO {
            // MAKEINTRESOURCEA(0): the command this handler inserted.
            lpVerb: PCSTR::null(),
            ..Default::default()
        };

        // SAFETY: `info` is a live, fully initialised structure for the duration of
        // the call; the empty selection is refused before anything reads the
        // window handle or starts a thread.
        let refused = unsafe { context.InvokeCommand(&info) };
        assert_eq!(refused.expect_err("nothing to hash").code(), E_FAIL);
    }

    // ---- pure helpers -----------------------------------------------------

    #[test]
    fn the_command_is_offered_only_for_a_selection_menu() {
        assert!(menu_should_appear(CMF_NORMAL, true));
        assert!(!menu_should_appear(CMF_NORMAL, false));
        assert!(!menu_should_appear(CMF_DEFAULTONLY, true));
        assert!(!menu_should_appear(CMF_VERBSONLY, true));
        assert!(!menu_should_appear(CMF_DEFAULTONLY | CMF_VERBSONLY, true));
        // Flags that do not single out another menu leave the command in place.
        assert!(menu_should_appear(CMF_EXTENDEDVERBS, true));
        assert!(menu_should_appear(CMF_NODEFAULT, true));
    }

    #[test]
    fn the_command_id_is_decoded_from_the_verb() {
        let ours = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR::null(),
            ..Default::default()
        };
        assert_eq!(menu_command_id(&ours), Some(0));

        let next = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR(core::ptr::without_provenance::<u8>(1)),
            ..Default::default()
        };
        assert_eq!(menu_command_id(&next), Some(1));

        let highest = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR(core::ptr::without_provenance::<u8>(usize::from(u16::MAX))),
            ..Default::default()
        };
        assert_eq!(menu_command_id(&highest), Some(u32::from(u16::MAX)));

        // A real pointer cannot be an integer resource id: its high word is not
        // zero on any supported image base.
        let string = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR(c"open".as_ptr().cast()),
            ..Default::default()
        };
        assert_eq!(menu_command_id(&string), None);

        let high_word = CMINVOKECOMMANDINFO {
            lpVerb: PCSTR(core::ptr::without_provenance::<u8>(0x1_0000)),
            ..Default::default()
        };
        assert_eq!(menu_command_id(&high_word), None);

        // A null `pici` names no command and must not be dereferenced.
        assert_eq!(menu_command_id(core::ptr::null()), None);
    }
}
