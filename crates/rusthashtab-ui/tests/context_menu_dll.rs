//! Does the built shell-extension DLL actually deliver the right-click command, end
//! to end and through COM?
//!
//! # What this proves that `dll_activation.rs` does not
//!
//! `dll_activation.rs` proves the class can be activated and that
//! `IShellPropSheetExt::AddPages` produces a property sheet page. The right-click
//! command is a different interface on the same object, reached through a different
//! data flow: the shell hands the handler an `IDataObject` carrying the selection,
//! asks it to insert menu items, then describes and finally invokes the chosen item.
//! A bug in that chain is invisible from the property-sheet test and cannot be seen
//! from the shell's unit tests either, because those never load the DLL.
//!
//! # No registration, no registry writes
//!
//! The test calls the DLL's exported `DllGetClassObject` directly, so it never needs
//! the class registered and never writes to `HKCU`. `IShellExtInit::Initialize` only
//! copies the `CF_HDROP` paths out of the data object; `QueryContextMenu` and
//! `GetCommandString` only read the menu and the string catalog. The only path that
//! reads the registry is `InvokeCommand`'s window thread, which calls
//! `load_settings()` -- a read, and only in the `#[ignore]`d window test.
//!
//! # The data object
//!
//! A real shell selection arrives as an `IDataObject` whose `GetData` produces a
//! `CF_HDROP` medium: a `DROPFILES` structure followed by UTF-16 file names, each
//! NUL-terminated, with one extra NUL closing the whole list, all in an `HGLOBAL`
//! the receiver frees with `ReleaseStgMedium`. The handler genuinely parses that
//! format with `DragQueryFileW`, so the test object has to produce the same bytes;
//! returning a shortcut would test a path the shell never takes. The ownership rule
//! is the one that matters: `GetData` transfers the `HGLOBAL` to the receiver, and
//! the handler releases it, so the object must not free it as well.

// Test code is allowed to fail loudly: a panic here is a test failure, not a
// process that takes the user's shell down with it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_ui::strings::{self, Key};
use std::os::windows::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    DV_E_FORMATETC, E_INVALIDARG, E_NOTIMPL, GlobalFree, HMODULE, HWND, LPARAM, POINT, S_OK, WPARAM,
};
use windows::Win32::System::Com::{
    FORMATETC, IAdviseSink, IClassFactory, IDataObject, IDataObject_Impl, IEnumFORMATETC,
    IEnumSTATDATA, STGMEDIUM, STGMEDIUM_0, TYMED_HGLOBAL,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalUnlock,
};
use windows::Win32::System::Ole::CF_HDROP;
use windows::Win32::UI::Shell::{
    CMF_DEFAULTONLY, CMF_NORMAL, CMINVOKECOMMANDINFO, DROPFILES, GCS_HELPTEXTW, GCS_VALIDATEW,
    GCS_VERBA, GCS_VERBW, IContextMenu, IShellExtInit,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreatePopupMenu, DestroyMenu, DispatchMessageW, EnumWindows, GetMenuItemCount, GetMenuItemID,
    GetMenuStringW, GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible,
    MF_BYPOSITION, MSG, PM_REMOVE, PeekMessageW, PostMessageW, SW_SHOWNORMAL, SWP_NOACTIVATE,
    SWP_NOZORDER, SetWindowPos, TranslateMessage, WM_CLOSE,
};
use windows::core::{
    BOOL, GUID, HRESULT, Interface, PCSTR, PCWSTR, PSTR, Ref, Result as WinResult, implement, s,
};

/// The CLSID the DLL registers under.
const CLSID: GUID = GUID::from_u128(0x9865_1d14_b00f_488e_a738_a7ce_db9e_5d8c);

/// The command id offset the DLL inserted, and therefore the item id the shell sees
/// when it uses `idcmdFirst` as the menu id base.
const COMMAND_ID: u32 = 1;

/// Where the release DLL is, for the target this test is built for.
///
/// The triple comes out of the test executable's own path --
/// `target/<triple>/<profile>/deps/<name>.exe` -- so it cannot disagree with the
/// architecture of the process that loads the DLL.
fn target_triple() -> std::ffi::OsString {
    let exe = std::env::current_exe().expect("a running test knows its own path");
    exe.ancestors()
        .nth(3)
        .and_then(|dir| dir.file_name())
        .expect("the test executable lives under target/<triple>/<profile>/deps/")
        .to_os_string()
}

/// Where the release DLL is for this target.
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

/// The DLL's `DllGetClassObject`, as the export table spells it.
type GetClassObject =
    unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut core::ffi::c_void) -> HRESULT;

/// The DLL's `DllCanUnloadNow`, used to wait for the window thread to finish.
type CanUnloadNow = unsafe extern "system" fn() -> HRESULT;

/// A loaded copy of the release DLL and its class factory.
struct Dll {
    /// The loaded module, kept for exports that are looked up by name later.
    module: HMODULE,
    /// The class factory `DllGetClassObject` handed out.
    factory: IClassFactory,
}

impl Dll {
    /// Load the release DLL and ask it for the class factory.
    ///
    /// Returns `None` when the release artifact has not been built, which is the
    /// normal state after a bare `cargo test`: the pre-commit gate builds it first,
    /// and failing here would make an ordinary test run red for a build-profile
    /// reason. The caller treats `None` as a skip.
    fn load() -> Option<Self> {
        let dll = dll_path();
        if !dll.is_file() {
            eprintln!(
                "SKIP: the release DLL is not built at {}; run `cargo build -p \
                 rusthashtab-shell --release` (or `cargo xtask check`) first",
                dll.display()
            );
            return None;
        }

        let mut wide: Vec<u16> = dll.as_os_str().encode_wide().collect();
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated and outlives the call; loading the DLL
        // runs its `DllMain`, which records the module handle the page needs.
        let module = unsafe { LoadLibraryW(PCWSTR(wide.as_ptr())) }
            .unwrap_or_else(|error| panic!("the DLL did not load from {}: {error}", dll.display()));

        // SAFETY: `module` is the live DLL. The name is the documented export, and
        // the transmute reinterprets the type-erased address as the signature the
        // COM documentation gives for `DllGetClassObject`.
        let get_class_object: GetClassObject = unsafe {
            let entry = GetProcAddress(module, s!("DllGetClassObject"))
                .expect("the DLL does not export DllGetClassObject, so COM could never use it");
            core::mem::transmute::<unsafe extern "system" fn() -> isize, GetClassObject>(entry)
        };

        let mut factory_out: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: both GUIDs and the out-pointer are live locals.
        let hr = unsafe { get_class_object(&CLSID, &IClassFactory::IID, &mut factory_out) };
        assert_eq!(
            hr, S_OK,
            "DllGetClassObject refused the class factory: {hr:?}"
        );
        assert!(
            !factory_out.is_null(),
            "a successful activation returned no factory"
        );

        // SAFETY: `factory_out` is the factory the call just produced, and the
        // interface owns that reference from here on.
        let factory = unsafe { IClassFactory::from_raw(factory_out) };

        // The DLL pins itself on the first activation, so it is deliberately not
        // unloaded here: `FreeLibrary` would be a no-op, and a test that unloaded
        // the module while another test's interfaces were alive would be wrong in
        // exactly the way the module pin exists to prevent.
        Some(Self { module, factory })
    }

    /// Create one handler and query the two interfaces the context-menu path uses.
    fn handler(&self) -> (windows::core::IUnknown, IShellExtInit, IContextMenu) {
        // SAFETY: the factory is live, `None` is the non-aggregating case, and the
        // returned object is owned here.
        let handler: windows::core::IUnknown = unsafe {
            self.factory
                .CreateInstance::<Option<&windows::core::IUnknown>, windows::core::IUnknown>(None)
        }
        .expect("the class factory could not create the handler");

        let shell_init: IShellExtInit = handler
            .cast()
            .expect("the handler does not implement IShellExtInit");
        let context_menu: IContextMenu = handler
            .cast()
            .expect("the handler does not implement IContextMenu");
        (handler, shell_init, context_menu)
    }

    /// Look up one of the DLL's diagnostic exports.
    fn can_unload_now(&self) -> CanUnloadNow {
        // SAFETY: `module` is the live DLL and the name is the documented export.
        unsafe {
            let entry = GetProcAddress(self.module, s!("DllCanUnloadNow"))
                .expect("the DLL does not export DllCanUnloadNow");
            core::mem::transmute::<unsafe extern "system" fn() -> isize, CanUnloadNow>(entry)
        }
    }
}

/// A uniquely named temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusthashtab-context-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temporary directory must be creatable");
        Self(path)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("the test file must be writable");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A minimal `IDataObject` that answers `CF_HDROP` with the given file list.
///
/// Everything else is `E_NOTIMPL`: the shell's context-menu path only ever calls
/// `GetData`, and an object that pretends to support drag-and-drop would have to
/// implement the advisory half as well for no test value.
#[implement(IDataObject)]
struct HdropDataObject {
    paths: Vec<PathBuf>,
}

impl IDataObject_Impl for HdropDataObject_Impl {
    fn GetData(&self, pformatetcin: *const FORMATETC) -> WinResult<STGMEDIUM> {
        if pformatetcin.is_null() {
            return Err(E_INVALIDARG.into());
        }

        // SAFETY: `GetData` documents `pformatetcin` as a pointer to a caller-owned
        // `FORMATETC` valid for the duration of the call.
        let format = unsafe { *pformatetcin };
        if format.cfFormat != CF_HDROP.0 {
            return Err(DV_E_FORMATETC.into());
        }

        build_hdrop_medium(&self.paths)
    }

    fn QueryGetData(&self, pformatetc: *const FORMATETC) -> HRESULT {
        if pformatetc.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: as in `GetData`; the call only reads the format.
        let format = unsafe { *pformatetc };
        if format.cfFormat == CF_HDROP.0 {
            S_OK
        } else {
            DV_E_FORMATETC
        }
    }

    fn GetCanonicalFormatEtc(
        &self,
        _pformatectin: *const FORMATETC,
        _pformatetcout: *mut FORMATETC,
    ) -> HRESULT {
        E_NOTIMPL
    }

    fn SetData(
        &self,
        _pformatetc: *const FORMATETC,
        _pmedium: *const STGMEDIUM,
        _frelease: BOOL,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetDataHere(
        &self,
        _pformatetc: *const FORMATETC,
        _pmedium: *mut STGMEDIUM,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn EnumFormatEtc(&self, _dwdirection: u32) -> WinResult<IEnumFORMATETC> {
        Err(E_NOTIMPL.into())
    }

    fn DAdvise(
        &self,
        _pformatetc: *const FORMATETC,
        _advf: u32,
        _padvsink: Ref<'_, IAdviseSink>,
    ) -> WinResult<u32> {
        Err(E_NOTIMPL.into())
    }

    fn DUnadvise(&self, _dwconnection: u32) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn EnumDAdvise(&self) -> WinResult<IEnumSTATDATA> {
        Err(E_NOTIMPL.into())
    }
}

/// Build the `CF_HDROP` medium for `paths`.
///
/// The layout is the one `DragQueryFileW` and the shell's own `read_hdrop` parse:
/// `DROPFILES` with `pFiles` pointing just past the structure and `fWide` set,
/// followed by every path as UTF-16 plus a NUL, and a final NUL that closes the
/// list. The `HGLOBAL` is created here and transferred to the caller inside the
/// `STGMEDIUM`; `ReleaseStgMedium` on the receiving side is what frees it.
fn build_hdrop_medium(paths: &[PathBuf]) -> WinResult<STGMEDIUM> {
    let mut names: Vec<u16> = Vec::new();
    for path in paths {
        names.extend(path.as_os_str().encode_wide());
        names.push(0);
    }
    // The double-NUL terminator: every name already ends in one, so one more closes
    // the list. An empty list is therefore two NULs, which `DragQueryFileW` reports
    // as zero files rather than as garbage.
    names.push(0);

    let size = core::mem::size_of::<DROPFILES>() + names.len() * core::mem::size_of::<u16>();
    // SAFETY: `size` is the exact number of bytes this function will write below,
    // and `GMEM_MOVEABLE` is the allocation type `CF_HDROP` requires.
    let block = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, size) }?;

    // SAFETY: `block` came from `GlobalAlloc` just above and is locked exactly once
    // here; `GlobalUnlock` balances it before the handle is returned.
    let pointer = unsafe { GlobalLock(block) };
    if pointer.is_null() {
        // SAFETY: `block` is still owned here, was never locked successfully, and
        // is freed exactly once on this failure path.
        unsafe {
            let _ = GlobalFree(Some(block));
        }
        return Err(windows::core::Error::from_thread());
    }

    // SAFETY: `pointer` is the base of an allocation of `size` bytes; the structure
    // and the name list together are exactly `size` bytes, and the name list starts
    // at a `u16`-aligned offset after the structure.
    unsafe {
        let header = pointer.cast::<DROPFILES>();
        header.write(DROPFILES {
            pFiles: core::mem::size_of::<DROPFILES>() as u32,
            pt: POINT::default(),
            fNC: false.into(),
            fWide: true.into(),
        });
        let destination = pointer
            .cast::<u8>()
            .add(core::mem::size_of::<DROPFILES>())
            .cast::<u16>();
        core::ptr::copy_nonoverlapping(names.as_ptr(), destination, names.len());
        let _ = GlobalUnlock(block);
    }

    Ok(STGMEDIUM {
        tymed: TYMED_HGLOBAL.0 as u32,
        u: STGMEDIUM_0 { hGlobal: block },
        pUnkForRelease: core::mem::ManuallyDrop::new(None),
    })
}

/// The text in a NUL-terminated UTF-16 buffer.
fn wide_text(units: &[u16]) -> String {
    let length = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    String::from_utf16_lossy(&units[..length])
}

/// The text in a NUL-terminated ANSI buffer.
fn ansi_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

/// Ask a handler to describe the command id it inserted.
fn command_string(
    context_menu: &IContextMenu,
    idcmd: usize,
    kind: u32,
    buffer: PSTR,
    capacity: u32,
) -> WinResult<()> {
    // SAFETY: every caller passes a live interface, a buffer of `capacity` bytes or
    // units as `kind` documents, and a capacity that matches the buffer.
    unsafe { context_menu.GetCommandString(idcmd, kind, None, buffer, capacity) }
}

#[test]
fn the_dll_inserts_the_hashes_command_and_describes_it() {
    let Some(dll) = Dll::load() else {
        return;
    };
    let (_handler, shell_init, context_menu) = dll.handler();

    // A selection for `Initialize`. The paths do not have to exist: `Initialize`
    // only copies them out of the `CF_HDROP`, and nothing in this test runs a scan.
    let selection = vec![PathBuf::from(r"C:\temp\a.bin")];
    let data_object: IDataObject = HdropDataObject {
        paths: selection.clone(),
    }
    .into();

    // SAFETY: the interface is live, there is no parent folder id list, the data
    // object outlives the call, and the progid key is unused for a file selection.
    unsafe { shell_init.Initialize(None, Some(&data_object), None) }
        .expect("Initialize must accept a CF_HDROP selection");

    // SAFETY: a fresh popup menu owned by this test and destroyed before it ends.
    let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");

    // SAFETY: the handler and menu are live, the ids describe the slot the shell
    // offered, and an ordinary selection menu (`CMF_NORMAL`) is where the command
    // belongs.
    let added = unsafe { context_menu.QueryContextMenu(menu, 0, COMMAND_ID, 0x7fff, CMF_NORMAL) };
    assert_eq!(
        added,
        HRESULT(1),
        "QueryContextMenu must report exactly one inserted item"
    );

    // SAFETY: `menu` is live; the calls only read it.
    unsafe {
        assert_eq!(
            GetMenuItemCount(Some(menu)),
            1,
            "the command must be exactly one menu item"
        );
        assert_eq!(
            GetMenuItemID(menu, 0),
            COMMAND_ID,
            "the item id must be the idCmdFirst the shell passed"
        );
    }

    let mut item_text = [0u16; 64];
    // SAFETY: `item_text` is writable for its whole length, `menu` is live, and
    // `MF_BYPOSITION` addresses the item by its position.
    let written = unsafe { GetMenuStringW(menu, 0, Some(&mut item_text), MF_BYPOSITION) };
    assert!(
        written > 0,
        "the inserted menu item has no text and would be invisible"
    );
    assert_eq!(
        wide_text(&item_text),
        strings::text(Key::ContextMenuHashes),
        "the menu item must carry the catalog's command label"
    );

    let mut verb = [0u16; 64];
    command_string(
        &context_menu,
        0,
        GCS_VERBW,
        PSTR(verb.as_mut_ptr().cast::<u8>()),
        verb.len() as u32,
    )
    .expect("GCS_VERBW must be answered");
    assert_eq!(
        wide_text(&verb),
        strings::text(Key::ContextMenuHashes),
        "the command's canonical verb is its label"
    );

    let mut ansi_verb = [0u8; 64];
    command_string(
        &context_menu,
        0,
        GCS_VERBA,
        PSTR(ansi_verb.as_mut_ptr()),
        ansi_verb.len() as u32,
    )
    .expect("GCS_VERBA must be answered");
    assert_eq!(ansi_text(&ansi_verb), strings::text(Key::ContextMenuHashes));

    let mut help = [0u16; 256];
    command_string(
        &context_menu,
        0,
        GCS_HELPTEXTW,
        PSTR(help.as_mut_ptr().cast::<u8>()),
        help.len() as u32,
    )
    .expect("GCS_HELPTEXTW must be answered");
    assert_eq!(
        wide_text(&help),
        strings::text(Key::ContextMenuHelp),
        "the help text is the tooltip the shell shows for the command"
    );

    // Validation writes nothing and succeeds for the id this handler inserted.
    command_string(&context_menu, 0, GCS_VALIDATEW, PSTR::null(), 0)
        .expect("GCS_VALIDATEW for the inserted command must succeed");

    // A second command id is not ours, and the shell must not be told otherwise.
    let mut rejected = [0u16; 16];
    assert!(
        command_string(
            &context_menu,
            7,
            GCS_VERBW,
            PSTR(rejected.as_mut_ptr().cast::<u8>()),
            rejected.len() as u32,
        )
        .is_err(),
        "GetCommandString must reject a command id this handler never inserted"
    );

    // SAFETY: `menu` is the popup created above and is destroyed exactly once.
    unsafe {
        let _ = DestroyMenu(menu);
    }

    // A multi-file selection must take the same path: the count comes from the
    // `CF_HDROP`, so one file and several files must both produce the command.
    let data_object: IDataObject = HdropDataObject {
        paths: vec![
            PathBuf::from(r"C:\temp\a.bin"),
            PathBuf::from(r"C:\temp\b.bin"),
        ],
    }
    .into();
    // SAFETY: as above; the previous data object is still alive but a fresh
    // selection replaces it.
    unsafe { shell_init.Initialize(None, Some(&data_object), None) }
        .expect("Initialize must accept a multi-file selection");
    // SAFETY: a fresh popup menu, destroyed below.
    let multi_menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
    // SAFETY: the handler and menu are live and the flags ask for the ordinary menu.
    let added =
        unsafe { context_menu.QueryContextMenu(multi_menu, 0, COMMAND_ID, 0x7fff, CMF_NORMAL) };
    assert_eq!(
        added,
        HRESULT(1),
        "a multi-file selection must still add one item"
    );
    // SAFETY: `multi_menu` is live and destroyed exactly once.
    unsafe {
        let _ = DestroyMenu(multi_menu);
    }
}

#[test]
fn the_command_is_suppressed_without_a_selection() {
    let Some(dll) = Dll::load() else {
        return;
    };
    let (_handler, shell_init, context_menu) = dll.handler();

    // An empty `CF_HDROP` is what a selection with no files produces. The handler
    // refuses it rather than offering a command that would open a window over
    // nothing.
    let data_object: IDataObject = HdropDataObject { paths: Vec::new() }.into();
    // SAFETY: the interface is live, the data object outlives the call, and the
    // remaining parameters are unused for a file selection.
    unsafe { shell_init.Initialize(None, Some(&data_object), None) }
        .expect("an empty CF_HDROP is still a valid selection list");

    // SAFETY: a fresh popup menu, destroyed exactly once below.
    let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
    // SAFETY: the handler and menu are live.
    let added = unsafe { context_menu.QueryContextMenu(menu, 0, COMMAND_ID, 0x7fff, CMF_NORMAL) };
    assert_eq!(
        added,
        HRESULT(0),
        "an empty selection must produce no command"
    );
    // SAFETY: `menu` is live; `GetMenuItemCount` only reads it.
    let item_count = unsafe { GetMenuItemCount(Some(menu)) };
    assert_eq!(item_count, 0, "the menu must stay empty");
    // SAFETY: `menu` is destroyed exactly once.
    unsafe {
        let _ = DestroyMenu(menu);
    }
}

#[test]
fn the_command_is_suppressed_for_a_default_only_menu() {
    let Some(dll) = Dll::load() else {
        return;
    };
    let (_handler, shell_init, context_menu) = dll.handler();

    let data_object: IDataObject = HdropDataObject {
        paths: vec![PathBuf::from(r"C:\temp\a.bin")],
    }
    .into();
    // SAFETY: as in the selection test.
    unsafe { shell_init.Initialize(None, Some(&data_object), None) }
        .expect("Initialize must accept the selection");

    // SAFETY: a fresh popup menu, destroyed exactly once below.
    let menu = unsafe { CreatePopupMenu() }.expect("a popup menu must be creatable");
    // `CMF_DEFAULTONLY` is the shell asking for the default verb only; an extra
    // command there would be wrong.
    // SAFETY: the handler and menu are live.
    let added =
        unsafe { context_menu.QueryContextMenu(menu, 0, COMMAND_ID, 0x7fff, CMF_DEFAULTONLY) };
    assert_eq!(
        added,
        HRESULT(0),
        "the command must not appear in a default-only menu"
    );
    // SAFETY: `menu` is destroyed exactly once.
    unsafe {
        let _ = DestroyMenu(menu);
    }
}

/// Run `condition` until it yields a window or the deadline passes.
fn wait_for_window(mut condition: impl FnMut() -> Option<HWND>) -> Option<HWND> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(found) = condition() {
            return Some(found);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The first top-level window of **this process** whose title is `title`.
///
/// The process filter matters: a real user may have a rustHashTab window open, and a
/// test that grabbed it would resize and close someone else's window.
fn find_window_titled(title: &str) -> Option<HWND> {
    struct Search {
        process: u32,
        wanted: Vec<u16>,
        found: Option<HWND>,
    }

    unsafe extern "system" fn callback(window: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: `lparam` is the `&mut Search` passed below, which outlives the
        // enumeration.
        let search = unsafe { &mut *(lparam.0 as *mut Search) };

        let mut process = 0u32;
        // SAFETY: `window` is a window being enumerated and `process` is a live
        // local the call writes into.
        unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
        if process != search.process {
            return true.into();
        }

        let mut buffer = [0u16; 128];
        // SAFETY: `buffer` is writable for its whole length and the call copies at
        // most that many units, NUL-terminated.
        let length = unsafe { GetWindowTextW(window, &mut buffer) };
        let length = usize::try_from(length).unwrap_or(0).min(buffer.len());
        if &buffer[..length] == search.wanted.as_slice() {
            search.found = Some(window);
            return false.into();
        }
        true.into()
    }

    let mut search = Search {
        process: std::process::id(),
        wanted: title.encode_utf16().collect(),
        found: None,
    };
    // SAFETY: the callback has the shape `EnumWindows` calls and `search` outlives
    // the enumeration; a null parent handle means "every top-level window".
    unsafe {
        let _ = EnumWindows(
            Some(callback),
            LPARAM((&mut search as *mut Search) as isize),
        );
    }
    search.found
}

/// Pump this thread's queue until `condition` holds or the deadline passes.
///
/// The context window's thread owns its own loop, but `InvokeCommand` sends the
/// readiness signal from that thread and the COM calls return to this one; pumping
/// here keeps any messages this thread produced (from `SetWindowPos` on a window it
/// does not own) from piling up.
fn pump_until(condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a live local for the whole loop.
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            // SAFETY: the message came from `PeekMessageW`; this is its dispatch pair.
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// End-to-end: invoke the command and drive the real window it opens.
///
/// This is `#[ignore]`d because it puts a real window on the desktop. It is the only
/// test in this repository that exercises the entire context-menu path -- DLL, COM,
/// dedicated STA window thread, the UI host, and teardown -- through the interface
/// `explorer.exe` actually uses.
#[test]
#[ignore = "shows a real window; run with --ignored"]
fn invoking_the_command_opens_and_closes_the_window() {
    let Some(dll) = Dll::load() else {
        return;
    };
    let (handler, shell_init, context_menu) = dll.handler();

    let dir = TempDir::new("window");
    let file = dir.file("payload.bin", b"hash me");
    let data_object: IDataObject = HdropDataObject {
        paths: vec![file.clone()],
    }
    .into();
    // SAFETY: as in the menu tests; the data object outlives the COM call.
    unsafe { shell_init.Initialize(None, Some(&data_object), None) }
        .expect("Initialize must accept the selection");

    // `lpVerb` is `MAKEINTRESOURCEA(0)`, i.e. a null pointer, which is how the shell
    // passes an integer verb naming the first item this handler inserted.
    let info = CMINVOKECOMMANDINFO {
        cbSize: core::mem::size_of::<CMINVOKECOMMANDINFO>() as u32,
        hwnd: HWND::default(),
        lpVerb: PCSTR(core::ptr::null()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    // SAFETY: the interface is live and `info` is a fully initialised command-info
    // structure that outlives the call. `InvokeCommand` returns once the window
    // thread has reported readiness, not when the window closes.
    unsafe { context_menu.InvokeCommand(&info) }.expect(
        "InvokeCommand must start the window; a message box on failure would block this test",
    );

    let window = wait_for_window(|| find_window_titled(strings::text(Key::WindowTitle)))
        .expect("the context-menu command did not open a rustHashTab window within 10 seconds");
    // SAFETY: `window` is a live top-level window of this process; the call only
    // reads its visibility state.
    let visible = unsafe { IsWindowVisible(window) }.as_bool();
    assert!(
        visible,
        "the opened window must be visible, not a hidden one"
    );

    // Resize the way a user would; the window's own thread must handle `WM_SIZE`
    // while this thread keeps its handles.
    // SAFETY: `window` is a live top-level window of this process; moving and
    // resizing a window from another thread is allowed.
    unsafe {
        SetWindowPos(
            window,
            None,
            120,
            120,
            760,
            640,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    }
    .expect("the context window must be resizable");

    // SAFETY: posting `WM_CLOSE` to another thread's window is allowed, and that is
    // how the close button reaches it.
    unsafe { PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0)) }
        .expect("posting WM_CLOSE to the context window must succeed");

    let closed = pump_until(|| {
        // SAFETY: `window` is a handle whose lifetime this test owns; `IsWindow`
        // only reads the handle table and accepts an already-destroyed handle.
        !unsafe { IsWindow(Some(window)) }.as_bool()
    });
    assert!(
        closed,
        "the context window did not disappear after WM_CLOSE"
    );

    // Release the COM interfaces first, then wait for the DLL to report that nothing
    // is live: the window thread's object hold is released when it exits, so
    // `DllCanUnloadNow` reaching S_OK proves the thread is gone. The DLL itself is
    // pinned, so this is about ownership, not about unloading.
    drop(context_menu);
    drop(shell_init);
    drop(handler);

    let can_unload_now = dll.can_unload_now();
    assert!(
        pump_until(|| {
            // SAFETY: the export takes no arguments and touches only counters.
            unsafe { can_unload_now() == S_OK }
        }),
        "the window thread still holds the extension object after the window closed"
    );
}
