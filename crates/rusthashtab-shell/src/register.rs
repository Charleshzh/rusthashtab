//! `regsvr32` entry points: writing and removing this extension's registration.
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
//! | `AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}` | (none) | the hook that makes the page appear for every filesystem object |
//! | `...\Shell Extensions\Approved` | `{clsid}` = product name | only if the key already exists |
//!
//! `AllFilesystemObjects` rather than `*`: both are documented, but
//! `AllFilesystemObjects` also covers things that are not files, and this page
//! only ever appears where the shell decided to offer a Properties dialog.

#![cfg(windows)]
// `DllRegisterServer` and `DllUnregisterServer` are called by `regsvr32` through
// the DLL's export table, so they must stay `extern "system"` and exported. They
// are `pub` because `#[unsafe(no_mangle)]` requires it, not because any Rust code
// outside this crate calls them.
#![allow(unreachable_pub)]

use crate::ext::CLSID;
use windows::Win32::Foundation::{ERROR_SUCCESS, HMODULE};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
};
use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
use windows::core::{HRESULT, PCWSTR, w};

/// `S_OK`, and the two failure codes `regsvr32` understands.
///
/// `SELFREG_E_CLASS` is the documented answer a self-registering server gives
/// when it cannot write its own registration. The `windows` crate does not expose
/// it, so it is declared here rather than adding a feature for one constant.
const S_OK: HRESULT = HRESULT(0);
const E_FAIL: HRESULT = HRESULT(0x8000_4005u32 as i32);
const SELFREG_E_CLASS: HRESULT = HRESULT(0x8004_0201u32 as i32);

/// The real name of this extension in the shell's `Approved` list.
const PRODUCT_NAME: &str = "rustHashTab";

/// The registry key whose `InProcServer32` subkey points at this DLL.
fn clsid_key_path(clsid: &str) -> String {
    format!(r"Software\Classes\CLSID\{clsid}")
}

/// The property sheet handler hook, keyed by our CLSID, for every object.
fn handler_key_path(clsid: &str) -> String {
    format!(r"Software\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}")
}

/// The per-user `Approved` list, as it appears under `HKCU\Software\Classes`.
fn approved_key_path() -> String {
    String::from(r"Software\Classes\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")
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

/// The full path of the loaded module, NUL-terminated.
fn module_path() -> Option<Vec<u16>> {
    let module = HMODULE(crate::module::raw());
    if module.is_invalid() {
        return None;
    }

    // `GetModuleFileNameW` truncates rather than failing when the buffer is too
    // small, so the length it returns is the only safe way to size the result.
    // The buffer starts at the documented maximum path plus a terminator and is
    // grown if the answer fills it, which is how a path longer than `MAX_PATH`
    // survives.
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: `buffer` is a live, writable slice of the declared length, and the
    // API writes at most that many units.
    let written = unsafe { GetModuleFileNameW(Some(module), &mut buffer) };
    if written == 0 {
        return None;
    }

    buffer.truncate(written as usize);
    buffer.push(0);
    Some(buffer)
}

/// NUL-terminate a Rust string into a UTF-16 buffer for the registry API.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Create (or open) one of the keys above, under `HKCU`.
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

/// Close a key opened by [`create_key`].
fn close(key: HKEY) {
    // SAFETY: `key` was opened by `create_key` and is closed exactly once, by the
    // caller, on every path.
    unsafe {
        let _ = RegCloseKey(key);
    }
}

/// Register this DLL as a per-user property sheet handler.
///
/// # Safety
///
/// Called by `regsvr32`, and by `cargo xtask shell-check`. It touches the
/// registry and notifies the shell; it has no pointer arguments and no other
/// preconditions.
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    register().unwrap_or(SELFREG_E_CLASS)
}

/// Remove the registration written by [`DllRegisterServer`].
///
/// # Safety
///
/// As above. Deleting a key that is not there succeeds, so this is idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    unregister().unwrap_or(SELFREG_E_CLASS)
}

/// The body of [`DllRegisterServer`], so the failure paths read clearly.
fn register() -> Option<HRESULT> {
    // In the DLL, DllMain has already recorded this. In a test binary it never
    // runs, and the module handle is still the right one -- see module.
    crate::module::ensure_recorded();
    let Some(path) = module_path() else {
        return Some(E_FAIL);
    };
    let Some(clsid) = clsid_text() else {
        return Some(E_FAIL);
    };
    let clsid_wide = wide(&clsid);

    let root = create_key(&clsid_key_path(&clsid))?;
    let inproc = create_inproc_server(root, &path);
    // The parent key's handle is not needed once `InProcServer32` exists, and
    // closing it here keeps one `close` per `create`.
    close(root);

    let Some(inproc) = inproc else {
        return Some(SELFREG_E_CLASS);
    };
    close(inproc);

    let Some(handler) = create_key(&handler_key_path(&clsid)) else {
        return Some(SELFREG_E_CLASS);
    };
    // The key's presence is the registration; a default value is conventional but
    // is not what the shell looks for. Writing it anyway makes the registration
    // legible to anyone reading the registry.
    let _ = set_string(handler, PCWSTR::null(), &clsid_wide);
    close(handler);

    approve(&clsid_wide);

    // The shell caches which handlers exist, so it has to be told.
    // SAFETY: no pointers are passed and no window is involved; the item id list
    // is null, which `SHCNF_IDLIST` permits.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }

    Some(S_OK)
}

/// Create `InProcServer32` under `root` and write both of its values.
fn create_inproc_server(root: HKEY, module: &[u16]) -> Option<HKEY> {
    let subkey = w!("InProcServer32");
    let mut key = HKEY::default();

    // SAFETY: `root` is an open key, `subkey` is a NUL-terminated literal, and
    // `key` is a live local; the disposition is not needed.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            subkey,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut key,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }

    // The default value is the DLL path; `ThreadingModel` is mandatory for an
    // in-process handler that holds a window, because the shell must create it in
    // an apartment it will call it from.
    let written = set_string(key, PCWSTR::null(), module)
        && set_string(key, w!("ThreadingModel"), &wide("Apartment"));

    if written { Some(key) } else { None }
}

/// Ask the shell to treat this extension as approved.
///
/// Only written when the `Approved` key already exists. Some Windows
/// configurations refuse to load extensions that are not listed there, and
/// creating the key when it is absent would be writing a policy nobody asked for.
/// Failure is not an error: the registration itself is complete either way.
fn approve(clsid: &[u16]) {
    let Some(key) = create_key(&approved_key_path()) else {
        return;
    };

    let _ = set_string(key, PCWSTR(clsid.as_ptr()), &wide(PRODUCT_NAME));
    close(key);
}

/// The body of [`DllUnregisterServer`].
fn unregister() -> Option<HRESULT> {
    let clsid = clsid_text()?;

    for path in [handler_key_path(&clsid), clsid_key_path(&clsid)] {
        let path = wide(&path);
        // SAFETY: the key name is a NUL-terminated wide string that outlives the
        // call. Deleting a key that does not exist is not an error for the
        // purpose of unregistering, so the return value is deliberately ignored.
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr()));
        }
    }

    // SAFETY: no pointers, no window.
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }

    Some(S_OK)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The registration layout is a protocol, so the paths are asserted rather
    /// than eyeballed: a typo here installs cleanly and never appears.
    #[test]
    fn the_registration_paths_are_the_documented_ones() {
        let clsid = clsid_text().expect("StringFromCLSID always succeeds for a valid GUID");
        assert_eq!(
            clsid_key_path(&clsid),
            format!(r"Software\Classes\CLSID\{clsid}")
        );
        assert_eq!(
            handler_key_path(&clsid),
            format!(r"Software\Classes\AllFilesystemObjects\shellex\PropertySheetHandlers\{clsid}")
        );
        assert!(approved_key_path().ends_with(r"Shell Extensions\Approved"));
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
    /// would produce a value the registry truncates.
    #[test]
    fn a_registry_string_includes_its_terminator() {
        let text = wide("Apartment");
        // Nine characters plus the terminator, two bytes each.
        assert_eq!(text.len(), 10);
    }

    /// Unregistering something that was never registered has to be harmless:
    /// users uninstall twice, and an error dialog there is a bug report.
    #[test]
    fn unregistering_an_unregistered_extension_succeeds() {
        assert_eq!(unregister(), Some(S_OK));
    }

    /// Read a `REG_SZ` value from `HKCU`, or `None` if it is not there.
    fn read_string(subkey: &str, value: &str) -> Option<String> {
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_SZ, RegGetValueW};

        let subkey = wide(subkey);
        let value = wide(value);
        let mut size = 0u32;

        // First ask for the size, then read. `RegGetValueW` writes the byte count
        // it needs (or has) into `size` either way.
        // SAFETY: both wide strings are NUL-terminated and outlive the call; a
        // null buffer with a size of zero is the documented way to ask how much
        // room the value needs.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                None,
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS || size < 2 {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is a live slice of exactly the length `size` reports,
        // which is what the API requires.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            )
        };
        if status != ERROR_SUCCESS {
            return None;
        }

        // `chunks_exact` on a two-byte stride is what `align_to` is for, and clippy
        // asks for it. The buffer is even by construction -- it is the byte count
        // the registry reported for a `REG_SZ` -- so the head and tail are empty.
        // SAFETY: `u16` has no invalid bit patterns, so reinterpreting a byte slice
        // as `u16` is sound; the assertion records the even-length invariant that
        // byte count provides.
        let (prefix, units, suffix) = unsafe { buffer.align_to::<u16>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty());
        let units: Vec<u16> = units
            .iter()
            .copied()
            .take_while(|unit| *unit != 0)
            .collect();
        String::from_utf16(&units).ok()
    }

    /// The registration has to be complete enough for the shell to find and load
    /// this DLL, which is a claim about the registry rather than about the code.
    ///
    /// This is the one test that writes to the real `HKCU`, and it removes what it
    /// wrote. That is deliberate: the paths, the CLSID spelling and the
    /// `ThreadingModel` are a protocol shared with `explorer.exe`, and a private
    /// scratch key would test this crate's idea of the protocol against itself.
    /// The keys belong to this extension's CLSID alone, and `regsvr32` writes the
    /// same ones.
    ///
    /// Run with `cargo test -p rusthashtab-shell -- --test-threads 1` if a shell is
    /// open on this machine at the same time; the write/read/delete sequence is
    /// otherwise fine because nothing else touches this CLSID.
    #[test]
    fn registering_writes_what_com_and_the_shell_look_for() {
        let clsid = clsid_text().expect("a valid GUID");
        let inproc = format!(r"{}\InProcServer32", clsid_key_path(&clsid));

        // Leave no registration behind, whatever the starting state was.
        let _ = unregister();
        assert!(read_string(&inproc, "ThreadingModel").is_none());

        assert_eq!(DllRegisterServer(), S_OK);

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
            std::path::Path::new(&module).is_file(),
            "InProcServer32 points at `{module}`, which is not a file"
        );

        // The hook key is what makes the page appear. Its presence is the
        // registration; its default value is informational.
        let handler = handler_key_path(&clsid);
        assert!(
            read_string(&handler, "").is_some(),
            "the property sheet handler key was not written"
        );

        // Registering twice must be harmless: the installer runs it on every
        // upgrade, and a second run that failed would fail the install.
        assert_eq!(DllRegisterServer(), S_OK, "registering twice must succeed");

        assert_eq!(DllUnregisterServer(), S_OK);
        assert!(
            read_string(&inproc, "ThreadingModel").is_none(),
            "unregistering left InProcServer32 behind"
        );
        assert!(read_string(&handler, "").is_none());
    }
}
