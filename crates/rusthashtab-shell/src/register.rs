//! `regsvr32` entry points: writing and removing this extension's per-user
//! registration.
//!
//! # Where it registers, and why that is a choice
//!
//! Everything goes under `HKCU\Software\Classes`, which is the per-user view of
//! `HKEY_CLASSES_ROOT`. Registering there needs no elevation, so `regsvr32` run
//! as a normal user actually succeeds, and the extension becomes visible only to
//! the user who installed it. A machine-wide install is the installer's job;
//! doing it here would make the DLL demand administrator rights to register.
//!
//! # What has to be written
//!
//! | Key | Value | Why |
//! |---|---|---|
//! | `CLSID\{clsid}\InProcServer32` | default = DLL path | where COM looks |
//! | `CLSID\{clsid}\InProcServer32` | `ThreadingModel` = `Apartment` | the handler holds an `HWND`, so it must be created per apartment |
//! | `AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}` | default = CLSID | the hook that makes the page appear for every filesystem object |
//! | `AllFilesystemObjects\shellex\ContextMenuHandlers\{clsid}` | default = CLSID | the hook that makes the context-menu item appear |
//! | `Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved` | `{clsid}` = product name | only if the key already exists; deliberately not under the classes root |
//! | `Applications\rusthashtab.exe` | friendly name, icon, command, supported types | the launcher's entry in the shell's "Open with" list |
//! | `rustHashTab.ChecksumFile` | description, icon, command | the ProgId a checksum file opens through |
//! | `.<ext>\OpenWithProgids` | `rustHashTab.ChecksumFile` = empty `REG_NONE` | offers the product for each checksum-file type |
//!
//! `AllFilesystemObjects` rather than `*`: both are documented, but
//! `AllFilesystemObjects` also covers things that are not files, and this page
//! only ever appears where the shell decided to offer a Properties dialog.
//!
//! # File associations: Open With only
//!
//! The registering process may not have installed the product, and the
//! user may have chosen a program for `.sha256` on purpose. So the association
//! half writes **only** the Open With entries above: it never writes a default
//! value for any `.<ext>` key, and unregistration only removes this product's own
//! values. Taking over the default would silently change what double-clicking a
//! checksum file does, which is the user's decision and not ours.
//!
//! The extension set comes from [`rusthashtab_ui::associations`] rather than being
//! listed here, so it can never disagree with the formats the product actually
//! reads and writes.
//!
//! # The tests never touch the real class tree
//!
//! Every class path here is built from a `classes_root` parameter, and the one
//! policy path from a separate `approved_root`: the `Approved` list does not live
//! under the classes root, so deriving it from that root wrote a value nothing
//! reads (see `PRODUCTION_APPROVED_ROOT`). [`DllRegisterServer`] passes both
//! production roots; the tests pass scratch roots under `HKCU\Software` that a
//! `Drop` guard deletes, so a test run cannot change what the machine's Properties
//! dialogs and double-clicks do.

#![cfg(windows)]
// `DllRegisterServer` and `DllUnregisterServer` are called by `regsvr32` through
// the DLL's export table, so they must stay `extern "system"` and exported. They
// are `pub` because `#[unsafe(no_mangle)]` requires it, not because any Rust code
// outside this crate calls them.
#![allow(unreachable_pub)]

use crate::ext::CLSID;
use rusthashtab_ui::associations::{PROG_ID, extensions};
use rusthashtab_ui::strings::{self, Key};
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{ERROR_SUCCESS, HMODULE};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_NONE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW,
};
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
use windows::core::{HRESULT, PCWSTR, w};

/// The per-user view of `HKEY_CLASSES_ROOT`, where a normal user may write.
///
/// Production only. The tests are handed a scratch root instead, so that a test
/// run cannot register the extension on the machine running it.
pub(crate) const PRODUCTION_ROOT: &str = r"Software\Classes";

/// The per-user `Approved` shell-extension policy list, as the root of
/// [`approved_key_path`].
///
/// This is deliberately **not** derived from [`PRODUCTION_ROOT`]: the `Approved`
/// list is not part of the classes root. The shell reads it at
/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`,
/// while per-user class registration lives under `HKCU\Software\Classes`.
/// Deriving the policy path from the classes root wrote a value where no shell
/// component looks for it, which is why the roots are separate parameters of
/// [`register_with`].
pub(crate) const PRODUCTION_APPROVED_ROOT: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions";

/// `S_OK`, and the two failure codes `regsvr32` understands.
///
/// `SELFREG_E_CLASS` is the documented answer a self-registering server gives
/// when it cannot write its own registration. The `windows` crate does not expose
/// it, so it is declared here rather than adding a feature for one constant.
const S_OK: HRESULT = HRESULT(0);
const E_FAIL: HRESULT = HRESULT(0x8000_4005u32 as i32);
const SELFREG_E_CLASS: HRESULT = HRESULT(0x8004_0201u32 as i32);

/// The product name, as the user sees it: the `Approved` value and the
/// `Applications` entry's friendly name.
const PRODUCT_NAME: &str = "rustHashTab";

/// File name of the standalone launcher that the associations point at.
///
/// It sits beside this DLL in an installed build. The `Applications` key is named
/// after this file, so the path and the key name come from one constant rather
/// than two literals that can drift apart.
const APPLICATION_FILE: &str = "rusthashtab.exe";

/// The registry key that names this extension's COM class.
fn clsid_key_path(classes_root: &str, clsid: &str) -> String {
    format!(r"{classes_root}\CLSID\{clsid}")
}

/// Where COM finds the DLL that implements the class.
fn inproc_server_key_path(classes_root: &str, clsid: &str) -> String {
    format!(r"{}\InProcServer32", clsid_key_path(classes_root, clsid))
}

/// The property sheet hook: the key that makes the Hashes tab appear.
fn property_sheet_handler_key_path(classes_root: &str, clsid: &str) -> String {
    format!(r"{classes_root}\AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}")
}

/// The context menu hook: the key that makes the context-menu command appear.
fn context_menu_handler_key_path(classes_root: &str, clsid: &str) -> String {
    format!(r"{classes_root}\AllFilesystemObjects\shellex\ContextMenuHandlers\{clsid}")
}

/// The per-user `Approved` list: `<approved_root>\Approved`.
///
/// This takes its own root rather than the classes root on purpose: the policy
/// list lives next to the class tree, not inside it (see
/// [`PRODUCTION_APPROVED_ROOT`]), and deriving the path from the classes root
/// silently wrote a value nothing reads.
fn approved_key_path(approved_root: &str) -> String {
    format!(r"{approved_root}\Approved")
}

/// The ProgId every checksum-file extension is registered against.
fn prog_id_key_path(classes_root: &str) -> String {
    format!(r"{classes_root}\{PROG_ID}")
}

/// The icon the shell shows for a checksum file.
fn prog_id_icon_key_path(classes_root: &str) -> String {
    format!(r"{}\DefaultIcon", prog_id_key_path(classes_root))
}

/// The command that opens a checksum file.
fn prog_id_command_key_path(classes_root: &str) -> String {
    format!(r"{}\shell\open\command", prog_id_key_path(classes_root))
}

/// The application entry that puts the product in the shell's "Open with" list.
fn applications_key_path(classes_root: &str) -> String {
    format!(r"{classes_root}\Applications\{APPLICATION_FILE}")
}

/// The launcher's icon, in the `Applications` entry.
fn application_icon_key_path(classes_root: &str) -> String {
    format!(r"{}\DefaultIcon", applications_key_path(classes_root))
}

/// The launcher's open command, in the `Applications` entry.
fn application_command_key_path(classes_root: &str) -> String {
    format!(
        r"{}\shell\open\command",
        applications_key_path(classes_root)
    )
}

/// The file types the `Applications` entry declares it can open.
fn supported_types_key_path(classes_root: &str) -> String {
    format!(r"{}\SupportedTypes", applications_key_path(classes_root))
}

/// The per-extension key listing the ProgIds the shell may offer for it.
fn open_with_progids_key_path(classes_root: &str, extension: &str) -> String {
    format!(r"{classes_root}\.{extension}\OpenWithProgids")
}

/// The CLSID in its registry string form, e.g. `{98651D14-...}`.
///
/// Not hand-formatted: `StringFromCLSID` is the authority on the spelling, and a
/// `format!` that quietly dropped a leading zero would produce a registration COM
/// never finds.
fn clsid_text() -> Option<String> {
    // SAFETY: `CLSID` is a plain value with no pointers, and the returned string
    // is a fresh `CoTaskMemAlloc` allocation this function then owns.
    let raw = unsafe { windows::Win32::System::Com::StringFromCLSID(&CLSID) }.ok()?;

    // SAFETY: the returned buffer is NUL-terminated and contiguous, so walking it
    // to the terminator stays inside the allocation, and the slice built from it
    // lives only until the string is copied out below.
    let text = unsafe {
        let start = raw.0;
        let mut length = 0usize;
        while *start.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(start, length))
    };

    // SAFETY: the pointer came from `CoTaskMemAlloc` via `StringFromCLSID`, and
    // the text has been copied out, so this releases it exactly once.
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(raw.0.cast())) };

    Some(text)
}

/// The full path of the loaded module, as UTF-16 units **without** a terminator.
///
/// The registry wants the terminator on every string it stores, and leaving it out
/// of the returned value keeps that conversion explicit at the point of writing
/// rather than accidental.
fn module_path() -> Option<Vec<u16>> {
    let module = HMODULE(crate::module::raw());
    if module.is_invalid() {
        return None;
    }

    // `GetModuleFileNameW` truncates rather than failing when the buffer is too
    // small, so the length it returns is the only safe way to size the result.
    // The buffer starts at the documented maximum path and is sized from what the
    // API reports; a path longer than `MAX_PATH` therefore survives.
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: `buffer` is a live, writable slice of the declared length, and the
    // API writes at most that many units.
    let written = unsafe { GetModuleFileNameW(Some(module), &mut buffer) };
    if written == 0 {
        return None;
    }

    buffer.truncate(written as usize);
    Some(buffer)
}

/// NUL-terminate a Rust string into a UTF-16 buffer for the registry API.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// A path as UTF-16 units, without a terminator.
///
/// Windows paths are UTF-16 already. Round-tripping one through `String` would
/// either lose unpaired surrogates (`from_utf16_lossy`) or need a failure path a
/// registry write cannot use; `encode_wide` preserves exactly the units the
/// filesystem handed us.
fn path_units(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().collect()
}

/// Append the terminator a `REG_SZ` value carries.
///
/// The registry stores the byte count it is given, so a string written without
/// its terminator comes back to the next reader with whatever follows the last
/// character.
fn terminated(units: &[u16]) -> Vec<u16> {
    let mut value = Vec::with_capacity(units.len() + 1);
    value.extend_from_slice(units);
    value.push(0);
    value
}

/// Quote a path as one command-line argument: `"path"`.
fn quote(units: &[u16]) -> Vec<u16> {
    let mut value = Vec::with_capacity(units.len() + 2);
    value.push(u16::from(b'"'));
    value.extend_from_slice(units);
    value.push(u16::from(b'"'));
    value
}

/// The `DefaultIcon` spelling: `"path",0` -- quoted, then the icon index.
fn icon_value(executable: &[u16]) -> Vec<u16> {
    let mut value = quote(executable);
    value.extend(",0".encode_utf16());
    value.push(0);
    value
}

/// The `shell\open\command` spelling: `"path" "%1"`.
///
/// Both sides are quoted: the launcher may live under `C:\Program Files`, and the
/// file name may contain a space, so leaving either unquoted would split the
/// command into the wrong arguments.
fn open_command_value(executable: &[u16]) -> Vec<u16> {
    let mut value = quote(executable);
    // `quote` has already closed the executable's quotes, so this starts with the
    // separator and opens the placeholder's quotes.
    value.extend(r#" "%1""#.encode_utf16());
    value.push(0);
    value
}

/// Create (or open) `path` under `HKCU`.
fn create_key(path: &str) -> Option<HKEY> {
    let path = wide(path);
    let mut key = HKEY::default();

    // SAFETY: `path` is a NUL-terminated wide string that outlives the call, and
    // `key` is a live local. `None` for the disposition is allowed and this does
    // not need it -- it only distinguishes "created" from "opened", and both are
    // success here.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut key,
            None,
        )
    };

    (status == ERROR_SUCCESS).then_some(key)
}

/// Open an existing key under `HKCU`, or `None` if it is not there.
///
/// Used where creating the key would be a policy change rather than part of the
/// registration -- notably the `Approved` list.
fn open_key(path: &str) -> Option<HKEY> {
    let path = wide(path);
    let mut key = HKEY::default();

    // SAFETY: `path` is a NUL-terminated wide string that outlives the call, and
    // `key` is a live local the API writes on success.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            None,
            KEY_ALL_ACCESS,
            &mut key,
        )
    };

    (status == ERROR_SUCCESS).then_some(key)
}

/// Write a `REG_SZ` value.
///
/// The byte count is the buffer's own length, so the terminating NUL is included
/// -- which is what `REG_SZ` expects, and what a `String`-length calculation
/// would get wrong.
fn set_string(key: HKEY, name: PCWSTR, value: &[u16]) -> bool {
    let bytes: Vec<u8> = value.iter().flat_map(|unit| unit.to_ne_bytes()).collect();

    // SAFETY: `key` is an open key, `name` is a NUL-terminated wide string or
    // null, and `bytes` is a live slice whose length is taken from it.
    let status = unsafe { RegSetValueExW(key, name, None, REG_SZ, Some(&bytes)) };
    status == ERROR_SUCCESS
}

/// Write an empty `REG_NONE` value.
///
/// `REG_NONE` with no data is the conventional way to list a name -- an
/// `OpenWithProgids` ProgId or a `SupportedTypes` extension -- without giving it a
/// value another registry client could mistake for one.
fn set_none(key: HKEY, name: PCWSTR) -> bool {
    // SAFETY: `key` is an open key and `name` is a NUL-terminated wide string that
    // outlives the call. No data is passed, which with `REG_NONE` is an empty
    // value.
    let status = unsafe { RegSetValueExW(key, name, None, REG_NONE, None) };
    status == ERROR_SUCCESS
}

/// Close a key opened or created by the functions above.
fn close(key: HKEY) {
    // SAFETY: `key` was opened or created by one of the functions above and is
    // closed exactly once, by the caller, on every path.
    unsafe {
        let _ = RegCloseKey(key);
    }
}

/// Delete `path` and everything under it, if it exists.
///
/// Deleting a key that is not there is not an error for unregistration's purpose,
/// so the answer is deliberately ignored.
fn delete_tree(path: &str) {
    let path = wide(path);

    // SAFETY: `path` is a NUL-terminated wide string that outlives the call, and
    // the function only reads it.
    unsafe {
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
    }
}

/// Delete one value from `path`, when the key and the value exist.
///
/// Used where the containing key belongs to the user or to another application
/// and only this product's value may go -- the `.ext` keys and the `Approved`
/// policy key.
fn delete_value(path: &str, name: &[u16]) {
    let Some(key) = open_key(path) else {
        return;
    };

    // SAFETY: `key` is open, and `name` is a NUL-terminated wide string that
    // outlives the call.
    unsafe {
        let _ = RegDeleteValueW(key, PCWSTR(name.as_ptr()));
    }
    close(key);
}

/// Register this DLL as a per-user property sheet and context-menu handler, and
/// advertise the launcher in "Open with".
///
/// # Safety
///
/// Called by `regsvr32`, and by `cargo xtask shell-check`. It touches the
/// registry and notifies the shell; it has no pointer arguments and no other
/// preconditions.
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    let executable = sibling_executable();
    let result = register_with(
        PRODUCTION_ROOT,
        PRODUCTION_APPROVED_ROOT,
        executable.as_deref(),
    );

    // The shell caches which handlers exist and which applications may open a
    // type, so it is told only after a registration that succeeded.
    if result == S_OK {
        notify_shell();
    }

    result
}

/// Remove the registration written by [`DllRegisterServer`].
///
/// # Safety
///
/// As above. Deleting a key that is not there succeeds, so this is idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    let result = unregister_with(PRODUCTION_ROOT, PRODUCTION_APPROVED_ROOT);

    if result == S_OK {
        notify_shell();
    }

    result
}

/// Write the registration under `classes_root`, and the `Approved` value under
/// `approved_root`.
///
/// The two roots are separate because the `Approved` policy list is not part of
/// the classes root; see [`PRODUCTION_APPROVED_ROOT`]. `executable` is the
/// standalone launcher the Open With associations point at. Production passes the
/// sibling of this DLL when it exists; tests pass a scratch path. `None` means no
/// launcher is installed, and then the associations are skipped while the
/// property sheet and context menu are still registered -- a missing launcher
/// must not cost the user the Hashes tab.
///
/// Does **not** notify the shell: [`DllRegisterServer`] does that, so that the
/// tests can exercise a scratch root without waking `explorer.exe`.
fn register_with(classes_root: &str, approved_root: &str, executable: Option<&Path>) -> HRESULT {
    // In the DLL, DllMain has already recorded this. In a test binary it never
    // runs, and the module handle is still the right one -- see module.
    crate::module::ensure_recorded();

    let Some(module) = module_path() else {
        return E_FAIL;
    };
    let Some(clsid) = clsid_text() else {
        return E_FAIL;
    };
    let clsid_units = wide(&clsid);

    if !write_inproc_server(classes_root, &clsid, &module) {
        return SELFREG_E_CLASS;
    }
    if !write_handler_key(
        &property_sheet_handler_key_path(classes_root, &clsid),
        &clsid_units,
    ) {
        return SELFREG_E_CLASS;
    }
    if !write_handler_key(
        &context_menu_handler_key_path(classes_root, &clsid),
        &clsid_units,
    ) {
        return SELFREG_E_CLASS;
    }

    approve(approved_root, &clsid_units);

    if let Some(executable) = executable
        && !write_associations(classes_root, &path_units(executable))
    {
        return SELFREG_E_CLASS;
    }

    S_OK
}

/// Remove this product's registration under `classes_root` and its `Approved`
/// value under `approved_root`.
///
/// Idempotent: every deletion is of something that may already be absent. Only
/// this product's own keys and values are removed -- the `.ext` keys, their
/// default values, other `OpenWithProgids` entries and the `Approved` policy key
/// itself belong to the user or to another application.
fn unregister_with(classes_root: &str, approved_root: &str) -> HRESULT {
    let Some(clsid) = clsid_text() else {
        return E_FAIL;
    };
    let clsid_units = wide(&clsid);
    let prog_id_units = wide(PROG_ID);

    for path in [
        applications_key_path(classes_root),
        prog_id_key_path(classes_root),
        property_sheet_handler_key_path(classes_root, &clsid),
        context_menu_handler_key_path(classes_root, &clsid),
        clsid_key_path(classes_root, &clsid),
    ] {
        delete_tree(&path);
    }

    // The `.ext` keys must survive: they are the user's, and other applications
    // may have values in the same `OpenWithProgids` key. Only our own value goes.
    for extension in extensions() {
        delete_value(
            &open_with_progids_key_path(classes_root, extension),
            &prog_id_units,
        );
    }

    // The `Approved` key is a policy list this product only ever adds one entry
    // to, and only when it already existed; deleting the key would take the
    // policy with it.
    delete_value(&approved_key_path(approved_root), &clsid_units);

    S_OK
}

/// Tell the shell that handler registrations and file associations changed.
fn notify_shell() {
    // SAFETY: no pointers are passed and no window is involved; the item id list
    // is null, which `SHCNF_IDLIST` permits.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
}

/// The standalone launcher installed next to this DLL, if there is one.
///
/// Derived from the DLL's own location so that a registration can never point
/// the association at a different installation than the one `regsvr32` was
/// invoked for. A development build that has no launcher yet gets `None`, and
/// the associations are then skipped rather than pointed at a path that does not
/// exist.
fn sibling_executable() -> Option<PathBuf> {
    // A test binary has no `DllMain`; production has already recorded the handle
    // before any export is reached, so this is a no-op there.
    crate::module::ensure_recorded();

    let module = module_path()?;
    let module = PathBuf::from(OsString::from_wide(&module));
    executable_beside(&module)
}

/// `module`'s sibling launcher, when it exists.
fn executable_beside(module: &Path) -> Option<PathBuf> {
    let executable = module.parent()?.join(APPLICATION_FILE);
    executable.is_file().then_some(executable)
}

/// Create `InProcServer32` under the class key and write both of its values.
fn write_inproc_server(classes_root: &str, clsid: &str, module: &[u16]) -> bool {
    let Some(key) = create_key(&inproc_server_key_path(classes_root, clsid)) else {
        return false;
    };

    // The default value is the DLL path; `ThreadingModel` is mandatory for an
    // in-process handler that holds a window, because the shell must create it in
    // an apartment it will call it from.
    let written = set_string(key, PCWSTR::null(), &terminated(module))
        && set_string(key, w!("ThreadingModel"), &wide("Apartment"));
    close(key);

    written
}

/// Create one of the `shellex` handler hooks under the class key.
///
/// The key's presence is the registration; the default value is informational
/// and makes the registration legible in `regedit`.
fn write_handler_key(path: &str, clsid: &[u16]) -> bool {
    let Some(key) = create_key(path) else {
        return false;
    };

    let written = set_string(key, PCWSTR::null(), clsid);
    close(key);

    written
}

/// Ask the shell to treat this extension as approved.
///
/// Only written when the `Approved` key already exists. Some Windows
/// configurations refuse to load extensions that are not listed there, and
/// creating the key when it is absent would be writing a policy nobody asked for.
/// Failure is not an error: the registration itself is complete either way.
fn approve(approved_root: &str, clsid: &[u16]) {
    // `open_key`, not `create_key`: an absent policy key stays absent.
    let Some(key) = open_key(&approved_key_path(approved_root)) else {
        return;
    };

    let _ = set_string(key, PCWSTR(clsid.as_ptr()), &wide(PRODUCT_NAME));
    close(key);
}

/// Write the Open With entries that let the launcher open checksum files.
///
/// Everything points at `executable`, never at this DLL: double-clicking a
/// checksum file must start the standalone window, not load the extension into a
/// shell process.
fn write_associations(classes_root: &str, executable: &[u16]) -> bool {
    write_prog_id(classes_root, executable)
        && write_application(classes_root, executable)
        && write_open_with_progids(classes_root)
}

/// Advertise the checksum-file ProgId and the command that opens it.
fn write_prog_id(classes_root: &str, executable: &[u16]) -> bool {
    let Some(key) = create_key(&prog_id_key_path(classes_root)) else {
        return false;
    };
    let described = set_string(
        key,
        PCWSTR::null(),
        &wide(strings::text(Key::ChecksumFileType)),
    );
    close(key);
    if !described {
        return false;
    }

    let Some(icon) = create_key(&prog_id_icon_key_path(classes_root)) else {
        return false;
    };
    let iconed = set_string(icon, PCWSTR::null(), &icon_value(executable));
    close(icon);
    if !iconed {
        return false;
    }

    let Some(command) = create_key(&prog_id_command_key_path(classes_root)) else {
        return false;
    };
    let commanded = set_string(command, PCWSTR::null(), &open_command_value(executable));
    close(command);

    commanded
}

/// Register the launcher under `Applications`, including the types it can open.
fn write_application(classes_root: &str, executable: &[u16]) -> bool {
    let Some(key) = create_key(&applications_key_path(classes_root)) else {
        return false;
    };
    let named = set_string(key, w!("FriendlyAppName"), &wide(PRODUCT_NAME));
    close(key);
    if !named {
        return false;
    }

    let Some(icon) = create_key(&application_icon_key_path(classes_root)) else {
        return false;
    };
    let iconed = set_string(icon, PCWSTR::null(), &icon_value(executable));
    close(icon);
    if !iconed {
        return false;
    }

    let Some(command) = create_key(&application_command_key_path(classes_root)) else {
        return false;
    };
    let commanded = set_string(command, PCWSTR::null(), &open_command_value(executable));
    close(command);
    if !commanded {
        return false;
    }

    let Some(types) = create_key(&supported_types_key_path(classes_root)) else {
        return false;
    };
    let mut listed = true;
    for extension in extensions() {
        let name = wide(&format!(".{extension}"));
        listed &= set_none(types, PCWSTR(name.as_ptr()));
    }
    close(types);

    listed
}

/// List this product's ProgId under every checksum-file extension's
/// `OpenWithProgids` key.
///
/// This is what makes the product appear in the "Open with" list and in the
/// "How do you want to open this file?" prompt. It deliberately writes nothing
/// else for the extension: no default value, no `Content Type`, no `PerceivedType`.
/// Creating the `.ext` key itself was the one visible side effect the design
/// accepts, and unregistration leaves it in place.
fn write_open_with_progids(classes_root: &str) -> bool {
    let prog_id = wide(PROG_ID);
    let mut listed = true;

    for extension in extensions() {
        let Some(key) = create_key(&open_with_progids_key_path(classes_root, extension)) else {
            return false;
        };
        listed &= set_none(key, PCWSTR(prog_id.as_ptr()));
        close(key);
    }

    listed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows::Win32::System::Registry::{REG_VALUE_TYPE, RRF_RT_ANY, RegGetValueW};

    /// A process-unique serial for scratch names.
    fn next_serial() -> u32 {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    /// A throwaway classes root under `HKCU`, removed when the guard drops.
    ///
    /// Every test that observes what registration wrote gets its own root, so
    /// tests can run in parallel and none of them can see another's keys. The
    /// real `HKCU\Software\Classes` is never written by these tests.
    struct ScratchRoot {
        /// The root passed to `register_with`, e.g.
        /// `Software\rustHashTab-test-classes-1234-0`.
        path: String,
    }

    impl ScratchRoot {
        fn new() -> Self {
            Self {
                path: format!(
                    r"Software\rustHashTab-test-classes-{}-{}",
                    std::process::id(),
                    next_serial()
                ),
            }
        }

        /// The root a registration test should write under.
        fn root(&self) -> &str {
            &self.path
        }

        /// A key path inside this root.
        fn key(&self, suffix: &str) -> String {
            format!(r"{}\{suffix}", self.path)
        }

        /// The scratch root for the `Approved` policy list.
        ///
        /// Production keeps this list outside the classes root, so the tests do
        /// too: one root standing in for both would hide a path that pointed at
        /// the wrong place.
        fn approved_root(&self) -> String {
            format!(r"{}\approved-policy", self.path)
        }

        /// Register into this scratch classes root and its policy root.
        fn register(&self, executable: Option<&Path>) -> HRESULT {
            register_with(self.root(), &self.approved_root(), executable)
        }

        /// Unregister from both scratch roots.
        fn unregister(&self) -> HRESULT {
            unregister_with(self.root(), &self.approved_root())
        }
    }

    impl Drop for ScratchRoot {
        fn drop(&mut self) {
            // Best effort, and deliberately not asserted: a panic in `Drop` while
            // a test is already unwinding aborts the harness, and a leftover key
            // under `HKCU\Software` with this name is harmless and identifiable.
            // The dedicated cleanup test checks the successful path.
            let path = wide(&self.path);

            // SAFETY: `path` is a NUL-terminated wide string that outlives the
            // call.
            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
            }
        }
    }

    /// One registry value, exactly as stored.
    struct Stored {
        kind: REG_VALUE_TYPE,
        data: Vec<u8>,
    }

    /// Read a value of any type from `HKCU\key_path`, or `None` if absent.
    fn read_value(key_path: &str, name: &str) -> Option<Stored> {
        let key_path = wide(key_path);
        let name = wide(name);
        let mut kind = REG_NONE;
        let mut size = 0u32;

        // SAFETY: both wide strings are NUL-terminated and outlive the call; a
        // null data buffer with a size of zero is the documented way to ask for
        // the room the value needs, and `size` is a live local.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(key_path.as_ptr()),
                PCWSTR(name.as_ptr()),
                RRF_RT_ANY,
                Some(&mut kind),
                None,
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        if size == 0 {
            return Some(Stored {
                kind,
                data: Vec::new(),
            });
        }

        let mut data = vec![0u8; size as usize];
        // SAFETY: `data` is a live buffer of exactly the byte count the first
        // call reported, which is what this call expects.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(key_path.as_ptr()),
                PCWSTR(name.as_ptr()),
                RRF_RT_ANY,
                Some(&mut kind),
                Some(data.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        data.truncate(size as usize);

        Some(Stored { kind, data })
    }

    /// Read a `REG_SZ` value, dropping its terminator.
    fn read_string(key_path: &str, name: &str) -> Option<String> {
        let value = read_value(key_path, name)?;
        let (pairs, remainder) = value.data.as_chunks::<2>();
        if value.kind != REG_SZ || !remainder.is_empty() {
            return None;
        }

        let units: Vec<u16> = pairs
            .iter()
            .map(|pair| u16::from_ne_bytes(*pair))
            .take_while(|unit| *unit != 0)
            .collect();

        String::from_utf16(&units).ok()
    }

    /// True when the value exists as an empty `REG_NONE` entry.
    fn is_empty_none_value(key_path: &str, name: &str) -> bool {
        read_value(key_path, name)
            .is_some_and(|value| value.kind == REG_NONE && value.data.is_empty())
    }

    /// True when the key exists.
    fn key_exists(key_path: &str) -> bool {
        let Some(key) = open_key(key_path) else {
            return false;
        };
        close(key);
        true
    }

    /// A wide string as text, for comparing values the registration wrote.
    fn text(units: &[u16]) -> String {
        let without_terminator = units.strip_suffix(&[0u16]).unwrap_or(units);
        String::from_utf16(without_terminator).expect("the value is valid UTF-16")
    }

    /// The registration layout is a protocol, so the paths are asserted rather
    /// than eyeballed: a typo here installs cleanly and never appears.
    ///
    /// This is the only test that names the production root. Every other test
    /// writes to a scratch root, which is what keeps `cargo test` from changing
    /// this machine's real associations.
    #[test]
    fn the_registration_paths_are_the_documented_ones() {
        let clsid = clsid_text().expect("StringFromCLSID always succeeds for a valid GUID");

        assert_eq!(
            clsid_key_path(PRODUCTION_ROOT, &clsid),
            format!(r"Software\Classes\CLSID\{clsid}")
        );
        assert_eq!(
            inproc_server_key_path(PRODUCTION_ROOT, &clsid),
            format!(r"Software\Classes\CLSID\{clsid}\InProcServer32")
        );
        assert_eq!(
            property_sheet_handler_key_path(PRODUCTION_ROOT, &clsid),
            format!(r"Software\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}")
        );
        assert_eq!(
            context_menu_handler_key_path(PRODUCTION_ROOT, &clsid),
            format!(r"Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{clsid}")
        );
        assert_eq!(
            approved_key_path(PRODUCTION_APPROVED_ROOT),
            r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
        );
        assert_eq!(
            prog_id_key_path(PRODUCTION_ROOT),
            r"Software\Classes\rustHashTab.ChecksumFile"
        );
        assert_eq!(
            prog_id_icon_key_path(PRODUCTION_ROOT),
            r"Software\Classes\rustHashTab.ChecksumFile\DefaultIcon"
        );
        assert_eq!(
            prog_id_command_key_path(PRODUCTION_ROOT),
            r"Software\Classes\rustHashTab.ChecksumFile\shell\open\command"
        );
        assert_eq!(
            applications_key_path(PRODUCTION_ROOT),
            r"Software\Classes\Applications\rusthashtab.exe"
        );
        assert_eq!(
            supported_types_key_path(PRODUCTION_ROOT),
            r"Software\Classes\Applications\rusthashtab.exe\SupportedTypes"
        );
        assert_eq!(
            open_with_progids_key_path(PRODUCTION_ROOT, "sha256"),
            r"Software\Classes\.sha256\OpenWithProgids"
        );
    }

    /// The CLSID has to survive the trip through `StringFromCLSID` unchanged, or
    /// the `Approved` entry and the `CLSID` key would name different classes.
    ///
    /// The comparison is built from the GUID's own fields rather than parsed back
    /// through a `FromStr` implementation: that way a wrong byte order in the
    /// formatting is caught here rather than by the shell refusing to load the
    /// extension, and the expected spelling is visible in the test.
    #[test]
    fn the_clsid_text_is_the_braced_canonical_spelling() {
        let text = clsid_text().expect("a valid GUID");
        let expected = format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            CLSID.data1,
            CLSID.data2,
            CLSID.data3,
            CLSID.data4[0],
            CLSID.data4[1],
            CLSID.data4[2],
            CLSID.data4[3],
            CLSID.data4[4],
            CLSID.data4[5],
            CLSID.data4[6],
            CLSID.data4[7],
        );
        assert_eq!(text, expected);
    }

    /// `wide` must produce exactly one terminating NUL and no interior ones.
    #[test]
    fn wide_terminates_exactly_once() {
        assert_eq!(
            wide("abc"),
            vec![u16::from(b'a'), u16::from(b'b'), u16::from(b'c'), 0]
        );
        assert_eq!(wide("").len(), 1);
    }

    /// A `REG_SZ` carries its terminating NUL, and a byte count that omitted it
    /// would produce a value the registry truncates. `terminated` has to agree
    /// with the spelling the encoded strings already use.
    #[test]
    fn a_registry_string_includes_its_terminator() {
        let word = wide("Apartment");
        // Nine characters plus the terminator, two bytes each.
        assert_eq!(word.len(), 10);

        let units = path_units(Path::new("Apartment"));
        assert_eq!(terminated(&units), word);
    }

    /// Both command-line spellings quote the executable, because it may live in a
    /// directory whose name contains a space.
    #[test]
    fn the_open_command_quotes_the_executable_and_the_file() {
        let executable: Vec<u16> = r"C:\Program Files\rustHashTab\rusthashtab.exe"
            .encode_utf16()
            .collect();

        assert_eq!(
            text(&open_command_value(&executable)),
            r#""C:\Program Files\rustHashTab\rusthashtab.exe" "%1""#
        );
        assert_eq!(
            text(&icon_value(&executable)),
            r#""C:\Program Files\rustHashTab\rusthashtab.exe",0"#
        );
    }

    /// Registering writes the keys COM and the shell look for, under the injected
    /// root rather than the real one.
    #[test]
    fn registering_writes_the_com_and_shell_keys() {
        let scratch = ScratchRoot::new();
        let executable = Path::new(r"C:\Program Files\rustHashTab\rusthashtab.exe");

        assert_eq!(scratch.register(Some(executable)), S_OK);

        let clsid = clsid_text().expect("a valid GUID");
        let inproc = inproc_server_key_path(scratch.root(), &clsid);

        // `ThreadingModel` is what makes the shell create the handler in an
        // apartment it will call it from. Without it COM would treat the object as
        // apartment-neutral and could call it from any thread.
        assert_eq!(
            read_string(&inproc, "ThreadingModel").as_deref(),
            Some("Apartment"),
            "InProcServer32\\ThreadingModel is missing or wrong"
        );

        // The default value is the DLL path, and it has to point at a real file or
        // the shell will fail to load the extension with no visible reason.
        let module = read_string(&inproc, "").expect("InProcServer32 has a default value");
        assert!(
            Path::new(&module).is_file(),
            "InProcServer32 points at `{module}`, which is not a file"
        );

        // Both hooks have to be there: one for the property page, one for the
        // context-menu command. Their presence is the registration.
        for handler in [
            property_sheet_handler_key_path(scratch.root(), &clsid),
            context_menu_handler_key_path(scratch.root(), &clsid),
        ] {
            assert!(
                read_string(&handler, "").as_deref() == Some(clsid.as_str()),
                "the handler key `{handler}` was not written"
            );
        }
    }

    /// With a launcher, the association half writes the ProgId, the application
    /// entry, and one `OpenWithProgids` value per advertised extension.
    #[test]
    fn associating_writes_the_open_with_entries() {
        let scratch = ScratchRoot::new();
        let executable = Path::new(r"C:\Program Files\rustHashTab\rusthashtab.exe");

        assert_eq!(scratch.register(Some(executable)), S_OK);

        assert_eq!(
            read_string(&prog_id_key_path(scratch.root()), "").as_deref(),
            Some(strings::text(Key::ChecksumFileType)),
            "the ProgId's description is not the user-facing type name"
        );
        assert_eq!(
            read_string(&prog_id_icon_key_path(scratch.root()), "").as_deref(),
            Some(r#""C:\Program Files\rustHashTab\rusthashtab.exe",0"#)
        );
        assert_eq!(
            read_string(&prog_id_command_key_path(scratch.root()), "").as_deref(),
            Some(r#""C:\Program Files\rustHashTab\rusthashtab.exe" "%1""#)
        );

        assert_eq!(
            read_string(&applications_key_path(scratch.root()), "FriendlyAppName").as_deref(),
            Some(PRODUCT_NAME)
        );
        assert_eq!(
            read_string(&application_icon_key_path(scratch.root()), "").as_deref(),
            Some(r#""C:\Program Files\rustHashTab\rusthashtab.exe",0"#)
        );
        assert_eq!(
            read_string(&application_command_key_path(scratch.root()), "").as_deref(),
            Some(r#""C:\Program Files\rustHashTab\rusthashtab.exe" "%1""#)
        );

        let types = supported_types_key_path(scratch.root());
        for extension in extensions() {
            let suffix = format!(".{extension}");
            assert!(
                is_empty_none_value(&types, &suffix),
                "SupportedTypes has no `{suffix}` entry"
            );
            assert!(
                is_empty_none_value(
                    &open_with_progids_key_path(scratch.root(), extension),
                    PROG_ID
                ),
                "OpenWithProgids has no `{PROG_ID}` entry for `.{extension}`"
            );
        }
    }

    /// A checksum file may have a non-ASCII path, and the association has to carry
    /// the real units rather than a lossy UTF-8 approximation.
    #[test]
    fn a_non_ascii_launcher_path_survives_registration() {
        let scratch = ScratchRoot::new();
        let executable = Path::new(r"C:\Program Files\rustHashTab\工具.exe");

        assert_eq!(scratch.register(Some(executable)), S_OK);
        assert_eq!(
            read_string(&prog_id_command_key_path(scratch.root()), "").as_deref(),
            Some(r#""C:\Program Files\rustHashTab\工具.exe" "%1""#)
        );
    }

    /// No launcher means no associations -- but the property page and the context
    /// menu still get registered, and the call still succeeds.
    #[test]
    fn without_a_launcher_the_associations_are_skipped() {
        let scratch = ScratchRoot::new();

        assert_eq!(scratch.register(None), S_OK);

        assert!(
            !key_exists(&prog_id_key_path(scratch.root())),
            "a ProgId was written without a launcher to point at"
        );
        assert!(
            !key_exists(&applications_key_path(scratch.root())),
            "an Applications entry was written without a launcher"
        );

        let clsid = clsid_text().expect("a valid GUID");
        assert!(
            key_exists(&property_sheet_handler_key_path(scratch.root(), &clsid)),
            "the property sheet handler was skipped along with the associations"
        );
        assert!(
            key_exists(&context_menu_handler_key_path(scratch.root(), &clsid)),
            "the context menu handler was skipped along with the associations"
        );
    }

    /// The extension keys belong to the user. Registration must not write a
    /// default value for any of them, and must leave a default the user already
    /// chose exactly as it was -- on both register and unregister.
    #[test]
    fn an_extension_default_value_is_never_written() {
        let scratch = ScratchRoot::new();
        let chosen = "some other program";

        // Pretend the user already chose a program for `.sha256`: writing the
        // default here would silently take over file opening.
        let sha256 = scratch.key(r".sha256");
        {
            let key = create_key(&sha256).expect("the scratch key must be creatable");
            assert!(set_string(key, PCWSTR::null(), &wide(chosen)));
            close(key);
        }

        let executable = Path::new(r"C:\Program Files\rustHashTab\rusthashtab.exe");
        assert_eq!(scratch.register(Some(executable)), S_OK);

        assert_eq!(
            read_string(&sha256, "").as_deref(),
            Some(chosen),
            "registration overwrote the user's `.sha256` default"
        );
        for extension in extensions() {
            if extension == "sha256" {
                continue;
            }
            assert!(
                read_string(&scratch.key(&format!(".{extension}")), "").is_none(),
                "registration wrote a default value for `.{extension}`"
            );
        }

        assert_eq!(scratch.unregister(), S_OK);
        assert_eq!(
            read_string(&sha256, "").as_deref(),
            Some(chosen),
            "unregistration removed the user's `.sha256` default"
        );
    }

    /// An extension key that exists only because of the `OpenWithProgids` entry
    /// stays behind on unregistration; the entry inside it does not.
    #[test]
    fn unregistering_leaves_the_extension_key_but_removes_our_value() {
        let scratch = ScratchRoot::new();
        let executable = Path::new(r"C:\Program Files\rustHashTab\rusthashtab.exe");

        assert_eq!(scratch.register(Some(executable)), S_OK);
        assert_eq!(scratch.unregister(), S_OK);

        for extension in extensions() {
            let open_with = open_with_progids_key_path(scratch.root(), extension);
            assert!(
                read_value(&open_with, PROG_ID).is_none(),
                "unregistration left this product's OpenWithProgids entry for `.{extension}`"
            );
        }
    }

    /// An absent `Approved` key is a policy decision someone else has not made;
    /// registration must not make it.
    #[test]
    fn the_approved_key_is_never_created() {
        let scratch = ScratchRoot::new();
        let approved = approved_key_path(&scratch.approved_root());
        assert!(
            !key_exists(&approved),
            "the scratch root is not empty before the test starts"
        );

        assert_eq!(scratch.register(None), S_OK);
        assert!(
            !key_exists(&approved),
            "registration created the Approved policy key"
        );
    }

    /// An existing `Approved` key gets our entry, and unregistration removes the
    /// entry but not the policy key.
    #[test]
    fn an_existing_approved_key_gets_our_value_and_loses_it_again() {
        let scratch = ScratchRoot::new();
        let approved = approved_key_path(&scratch.approved_root());
        {
            let key = create_key(&approved).expect("the scratch Approved key must be creatable");
            close(key);
        }

        assert_eq!(scratch.register(None), S_OK);

        let clsid = clsid_text().expect("a valid GUID");
        assert_eq!(
            read_string(&approved, &clsid).as_deref(),
            Some(PRODUCT_NAME),
            "the extension was not added to the existing Approved list"
        );

        assert_eq!(scratch.unregister(), S_OK);
        assert!(
            read_string(&approved, &clsid).is_none(),
            "unregistration left the Approved value behind"
        );
        assert!(
            key_exists(&approved),
            "unregistration deleted the user's Approved key"
        );
    }

    /// Registering and unregistering are run on every install and every upgrade,
    /// so neither may fail the second time, and after unregistration nothing this
    /// product wrote may remain.
    #[test]
    fn registering_and_unregistering_are_idempotent() {
        let scratch = ScratchRoot::new();
        let executable = Path::new(r"C:\Program Files\rustHashTab\rusthashtab.exe");

        assert_eq!(scratch.register(Some(executable)), S_OK);
        assert_eq!(
            scratch.register(Some(executable)),
            S_OK,
            "registering twice must succeed"
        );

        assert_eq!(scratch.unregister(), S_OK);
        assert_eq!(
            scratch.unregister(),
            S_OK,
            "unregistering twice must succeed"
        );

        let clsid = clsid_text().expect("a valid GUID");
        let ours = [
            clsid_key_path(scratch.root(), &clsid),
            inproc_server_key_path(scratch.root(), &clsid),
            property_sheet_handler_key_path(scratch.root(), &clsid),
            context_menu_handler_key_path(scratch.root(), &clsid),
            prog_id_key_path(scratch.root()),
            applications_key_path(scratch.root()),
        ];
        for path in ours {
            assert!(!key_exists(&path), "unregistration left `{path}` behind");
        }
    }

    /// Unregistering something that was never registered has to be harmless:
    /// users uninstall twice, and an error dialog there is a bug report.
    #[test]
    fn unregistering_an_unregistered_extension_succeeds() {
        let scratch = ScratchRoot::new();
        assert_eq!(scratch.unregister(), S_OK);
    }

    /// The scratch root is removed by its guard, so the test suite leaves no keys
    /// of its own behind.
    #[test]
    fn the_scratch_root_is_cleaned_up_on_drop() {
        let path = {
            let scratch = ScratchRoot::new();
            assert_eq!(scratch.register(None), S_OK);
            scratch.root().to_owned()
        };

        assert!(
            !key_exists(&path),
            "the scratch classes root survived its guard"
        );
    }

    /// The launcher is looked for beside the module, and only there.
    #[test]
    fn the_launcher_is_discovered_only_beside_the_module() {
        let directory =
            std::env::temp_dir().join(format!("rusthashtab-launcher-test-{}", next_serial()));
        std::fs::create_dir_all(&directory).expect("the temp directory must be creatable");
        let module = directory.join("rusthashtab_shell.dll");

        assert!(
            executable_beside(&module).is_none(),
            "found a launcher that is not there"
        );

        let launcher = directory.join(APPLICATION_FILE);
        std::fs::write(&launcher, []).expect("the fake launcher must be creatable");
        assert_eq!(
            executable_beside(&module).as_deref(),
            Some(launcher.as_path())
        );

        std::fs::remove_dir_all(&directory).expect("the temp directory must be removable");
    }
}
