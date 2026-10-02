//! The rustHashTab shell extension DLL.
//!
//! # What this crate is, and what it deliberately is not
//!
//! A shell extension is loaded *into* `explorer.exe`, so every protocol the host
//! enforces is a correctness requirement here rather than a nicety. This crate
//! therefore contains **only** the things that require being a COM server in the
//! shell:
//!
//! * `DllMain`, and the four standard exports `DllGetClassObject`,
//!   `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer`;
//! * the class factory;
//! * `IShellExtInit` (the selection) and `IShellPropSheetExt` (the page).
//!
//! Everything else -- the Win32 dialog, the list view, the worker that owns the
//! scan -- lives in `rusthashtab-ui`, which is an ordinary library and can
//! therefore be tested by an ordinary test binary. A tree of COM code that can
//! only be exercised by loading it into the shell is effectively untestable, so
//! the split is a testability boundary, not just a layering preference.
//!
//! # The module is pinned
//!
//! [`rusthashtab_abi`] tracks module locks and object counts so
//! `DllCanUnloadNow` can answer honestly, but an honest answer is not the same as
//! a safe one: this DLL starts worker threads, and a thread that outlives its
//! module is a crash that no reference count can prevent. So the module is pinned
//! with `GET_MODULE_HANDLE_EX_FLAG_PIN` on the first `DllGetClassObject`, which
//! makes `FreeLibrary` a no-op for it. That is the mitigation the project's
//! contributor notes call for when state can outlive a COM object.

#![cfg_attr(not(windows), allow(unused))]
#![warn(missing_docs)]

#[cfg(windows)]
mod class_factory;
#[cfg(windows)]
mod ext;
#[cfg(windows)]
mod module;
#[cfg(windows)]
mod register;

#[cfg(windows)]
pub use ext::CLSID;

#[cfg(windows)]
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_POINTER, S_FALSE, S_OK};
#[cfg(windows)]
use windows::core::{GUID, HRESULT};

/// Entry point of the DLL, called by the loader.
///
/// # Why it is written by hand, and why it does so little
///
/// A `cdylib` is not a program: nothing runs until the loader calls this, so a
/// Rust `cdylib` without `DllMain` would never record its own `HMODULE` and could
/// never load a dialog template out of its own resource section.
///
/// `DllMain` runs **under the loader lock**, which makes almost everything
/// illegal here: no COM, no shell calls, no registry, no file I/O, no
/// allocation, nothing that can panic or touch thread-local storage. It stores
/// the module handle and calls `DisableThreadLibraryCalls`, and that is all it
/// may ever do. The registry reads and the module pinning happen in
/// `DllGetClassObject`, which the loader lock is not held for.
///
/// # Safety
///
/// Called by the Windows loader with the module handle, a reason code, and, for
/// `DLL_PROCESS_ATTACH` on a `cdylib`, a null reserved pointer. It must not be
/// called by hand: the loader lock is held for the duration, so calling it from
/// ordinary code deadlocks on the first allocation.
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(
    instance: *mut core::ffi::c_void,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // DLL_PROCESS_ATTACH. The other reasons are deliberately ignored: the only
    // state this DLL owns is the module handle, which does not change.
    if reason == windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH {
        module::remember(instance);
        // Nothing in this crate creates threads during DllMain, and the loader
        // does not need to notify us about them.
        // SAFETY: the loader passes this DLL's own handle, so it is a valid
        // module handle by construction.
        unsafe {
            let _ = windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls(
                windows::Win32::Foundation::HMODULE(instance),
            );
        }
    }

    // TRUE, i.e. "the DLL loaded".
    1
}

/// Reports whether COM may unload this DLL.
///
/// The answer is computed by [`rusthashtab_abi`] from two counters, and the DLL
/// is additionally pinned, so in practice this returns `S_OK` only in a state
/// where unload would be safe anyway. Returning `S_FALSE` while anything is live
/// is the contract COM relies on.
///
/// # Safety
///
/// Called by COM on any thread. Takes no arguments and has no preconditions.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if rusthashtab_abi::can_unload() {
        S_OK
    } else {
        S_FALSE
    }
}

/// Returns a class factory for `rclsid`, if this DLL implements it.
///
/// # Safety
///
/// `rclsid` and `riid` must point to readable `GUID`s (or be null, which is
/// rejected), and `ppv` must point to a writable `*mut c_void` that COM owns.
/// This is the contract in the `DllGetClassObject` documentation, and COM
/// upholds it.
#[unsafe(no_mangle)]
unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HRESULT {
    // SAFETY: the contract above promises `ppv` is writable, and a null value
    // cannot be written through at all.
    if ppv.is_null() {
        return E_POINTER;
    }
    // "If an error occurs, the interface pointer is NULL." -- clear it before
    // anything can fail, so COM never sees a stale pointer from its own buffer.
    // SAFETY: `ppv` was just checked against null, and the contract above promises
    // it points at a writable slot COM owns.
    unsafe { *ppv = core::ptr::null_mut() };

    if rclsid.is_null() || riid.is_null() {
        return E_POINTER;
    }

    // SAFETY: non-null and, per the contract, readable.
    let requested = unsafe { *rclsid };
    if requested != CLSID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    match class_factory::create(riid, ppv) {
        Ok(()) => S_OK,
        Err(error) => error.code(),
    }
}

/// Reports whether `DllMain` has run and recorded this module's handle.
///
/// # Why this exists as an export
///
/// Everything the DLL does with its own resources needs `hInstance`, which only
/// `DllMain` is given. Whether `DllMain` was called is therefore the difference
/// between a working property sheet page and a page that silently never appears,
/// and it is **not** observable from the export table: the loader reads the entry
/// point from the PE header, so a DLL whose entry point is never called exports
/// exactly the same names as one whose entry point works.
///
/// That is not hypothetical on 32-bit targets. The x86 loader looks up
/// `_DllMain@12`, the stdcall-decorated spelling, where `rustc` exports the
/// undecorated `DllMain` -- so the entry point is present, exported, and never
/// called. `build.rs` adds the decorated alias, and
/// `tests::the_loader_calls_our_entry_point` loads this DLL and calls *this*
/// function to prove it landed.
///
/// It ships because it costs one `BOOL` and turns an otherwise invisible failure
/// into a one-line check from a debugger, `rundll32`, or a diagnostic script.
/// `1` means the entry point ran; `0` means it did not, and nothing else in the
/// DLL will work.
///
/// # Safety
///
/// Called by name from a host that has loaded this DLL. It takes no arguments and
/// touches one atomic.
#[unsafe(no_mangle)]
pub extern "system" fn RustHashTabEntryPointReady() -> i32 {
    if module::raw().is_null() { 0 } else { 1 }
}

/// The recorded module handle, for diagnostics.
///
/// See [`RustHashTabEntryPointReady`]. Returning the value rather than a boolean
/// makes a failure unambiguous from a debugger: a non-null value is the loader's
/// own base address for this DLL, and zero means the entry point did not run.
///
/// # Safety
///
/// Called by name from a host that has loaded this DLL. It takes no arguments and
/// reads one atomic.
#[unsafe(no_mangle)]
pub extern "system" fn RustHashTabModuleBase() -> usize {
    module::raw() as usize
}

#[cfg(windows)]
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_ui::{MESSAGE_MAGIC, PROGRESS_RESOLUTION};
    use windows::Win32::UI::Shell::IShellPropSheetExt;
    // `IID` and `from_raw` are provided by these traits, not by the generated
    // interface structs.
    use windows::core::Interface as _;

    /// `rclsid` and `riid` are allowed to be null, and COM does pass null when it
    /// is probing. A dereference there would take the shell down, so the guard is
    /// worth a test of its own.
    #[test]
    fn a_null_argument_is_rejected_rather_than_dereferenced() {
        // SAFETY: `ppv` points at a local, and the other two arguments are null
        // -- which is exactly the case under test, and is checked before use.
        unsafe {
            let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
            assert_eq!(
                DllGetClassObject(core::ptr::null(), core::ptr::null(), &mut out),
                E_POINTER
            );
        }
    }

    #[test]
    fn an_unknown_clsid_is_reported_as_such() {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let stranger = GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);
        // SAFETY: all three pointers refer to live locals for the duration.
        let result = unsafe { DllGetClassObject(&stranger, &stranger, &mut out) };
        assert_eq!(result, CLASS_E_CLASSNOTAVAILABLE);
        assert!(
            out.is_null(),
            "a failed call must not leave a pointer behind"
        );
    }

    /// A null `ppv` is the one case where COM's own buffer cannot be cleared, so
    /// it has to be caught first.
    #[test]
    fn a_null_out_pointer_is_rejected() {
        // SAFETY: the function rejects a null `ppv` before writing through it.
        let result = unsafe { DllGetClassObject(&CLSID, &CLSID, core::ptr::null_mut()) };
        assert_eq!(result, E_POINTER);
    }

    /// The known CLSID is the one that produces a factory, and the returned
    /// pointer is a real object COM can use.
    #[test]
    fn the_registered_clsid_produces_a_class_factory() {
        let mut out: *mut core::ffi::c_void = core::ptr::null_mut();
        let iid = windows::Win32::System::Com::IClassFactory::IID;
        // SAFETY: all three pointers refer to live values for the duration.
        let result = unsafe { DllGetClassObject(&CLSID, &iid, &mut out) };
        assert_eq!(result, S_OK);
        assert!(!out.is_null(), "a successful call must produce a pointer");

        // SAFETY: `out` is the `IClassFactory` the call just produced, so taking
        // ownership of it is correct and dropping it releases the reference.
        let factory = unsafe { windows::Win32::System::Com::IClassFactory::from_raw(out) };
        drop(factory);
    }

    /// The CLSID the shell activates must produce an object the handler interfaces
    /// can be reached through -- and `DllCanUnloadNow` must answer `S_FALSE` while
    /// that object lives.
    ///
    /// # Why the count assertions are not here
    ///
    /// `DllCanUnloadNow` reads process-wide counters, and a test that zeroes them to
    /// establish a baseline races with every sibling test that creates an object. That
    /// race was measured, not assumed: see the note on
    /// `class_factory::tests::the_module_lock_count_moves_independently_of_the_object_count`,
    /// which is the one test allowed to observe absolute counter values, and which
    /// covers this same activation path for that reason.
    ///
    /// What is left here is the part that holds whatever the counters say: the
    /// activation succeeds, the interfaces are reachable, and releasing the last
    /// reference is not itself a failure.
    #[test]
    fn the_registered_clsid_activates_a_handler() {
        let mut factory_out: *mut core::ffi::c_void = core::ptr::null_mut();
        let factory_iid = windows::Win32::System::Com::IClassFactory::IID;
        // SAFETY: all three pointers refer to live values for the duration.
        let got = unsafe { DllGetClassObject(&CLSID, &factory_iid, &mut factory_out) };
        assert_eq!(got, S_OK);

        // SAFETY: `factory_out` is the factory the call just produced, so taking
        // ownership of it is correct.
        let factory = unsafe { windows::Win32::System::Com::IClassFactory::from_raw(factory_out) };

        // The safe wrapper resolves `riid` to `IUnknown` itself, which is the
        // interface the shell asks for first. `None` is the outer object: this
        // handler is not aggregated.
        // SAFETY: `factory` is live for the duration of the call.
        let handler = unsafe {
            factory
                .CreateInstance::<Option<&windows::core::IUnknown>, windows::core::IUnknown>(None)
        }
        .expect("the factory must be able to create the handler");

        // The handler must answer for the interfaces the shell asks it for.
        let mut shell_ext: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `handler` is a live object, and both pointers are live locals for
        // the duration of the call.
        let queried = unsafe {
            windows::core::Interface::query(&handler, &IShellPropSheetExt::IID, &mut shell_ext)
        };
        assert_eq!(
            queried, S_OK,
            "the handler does not implement IShellPropSheetExt"
        );
        assert!(!shell_ext.is_null());

        // SAFETY: `shell_ext` is the interface the query just produced.
        drop(unsafe { IShellPropSheetExt::from_raw(shell_ext) });
        drop(handler);
    }

    /// The `DllMain` entry point must actually be called by the loader.
    ///
    /// This is the one thing about the entry point that cannot be checked by
    /// reading the export table, and it is not the same question on every target.
    /// The 32-bit loader looks up `_DllMain@12`, the stdcall-decorated spelling,
    /// while `rustc` exports `DllMain` undecorated -- so on i686 a DLL whose entry
    /// point is never called looks perfectly fine in `dumpbin /exports` and simply
    /// loses everything `DllMain` does.
    ///
    /// The DLL's entry point must actually be reached after the loader maps it.
    ///
    /// # What this does and does not prove
    ///
    /// It proves the entry point is called and that it recorded the module the
    /// loader actually mapped, which is what every dialog-template lookup depends
    /// on. It is checked on every target, and it is the reason the check is worth
    /// having: the failure it guards against is invisible from the outside -- a
    /// DLL whose entry point never runs exports exactly the same names as one whose
    /// entry point works.
    ///
    /// It does **not** isolate *why* the entry point is called, and it was measured
    /// that it cannot: with `build.rs`'s decorated-name alias removed, the i686
    /// build still reached the entry point on this machine's Windows. So the alias
    /// is a named safety margin, not a proven requirement at the time of writing --
    /// see the note in `build.rs`. Recording that honestly matters more than a test
    /// whose comment claims a causal link it never established.
    #[test]
    fn the_loader_reaches_our_entry_point() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let triple = if cfg!(target_pointer_width = "64") {
            "x86_64-pc-windows-msvc"
        } else {
            "i686-pc-windows-msvc"
        };
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the crate is inside the workspace");
        let dll = workspace
            .join("target")
            .join(triple)
            .join(profile)
            .join("rusthashtab_shell.dll");

        let status = std::process::Command::new(env!("CARGO"))
            .current_dir(workspace)
            .args([
                "build",
                "--package",
                "rusthashtab-shell",
                "--target",
                triple,
            ])
            .args(if cfg!(debug_assertions) {
                &[][..]
            } else {
                &["--release"][..]
            })
            .status()
            .expect("cargo must be runnable");
        assert!(
            status.success(),
            "could not build the shell DLL for {triple}"
        );
        assert!(
            dll.is_file(),
            "cargo reported success but produced no DLL at {}",
            dll.display()
        );

        let mut wide_path: Vec<u16> = dll.as_os_str().encode_wide().collect();
        wide_path.push(0);

        // SAFETY: `wide_path` is a NUL-terminated wide string that outlives the
        // call. The handle this returns is freed below, on every path.
        let module = unsafe { LoadLibraryW(windows::core::PCWSTR(wide_path.as_ptr())) }
            .expect("the DLL built for this target must load");

        // Ask the loaded DLL whether its own entry point ran. This is the whole
        // point of the test: on i686 the export the loader looks for is absent
        // unless `build.rs` adds it, and nothing else in the DLL works if the entry
        // point was never called.
        // SAFETY: `module` is loaded, and both symbols are ones this crate exports.
        let (ready, base) = unsafe {
            let ready =
                match GetProcAddress(module, windows::core::s!("RustHashTabEntryPointReady")) {
                    Some(entry) => {
                        let entry: extern "system" fn() -> i32 = core::mem::transmute(entry);
                        entry()
                    }
                    None => panic!("the loaded DLL does not export its entry-point check"),
                };
            let base = match GetProcAddress(module, windows::core::s!("RustHashTabModuleBase")) {
                Some(entry) => {
                    let entry: extern "system" fn() -> usize = core::mem::transmute(entry);
                    entry()
                }
                None => panic!("the loaded DLL does not export its module base"),
            };
            (ready, base)
        };

        // SAFETY: `module` came from `LoadLibraryW` and is released exactly once.
        unsafe {
            let _ = windows::Win32::Foundation::FreeLibrary(module);
        }

        assert_eq!(
            ready,
            1,
            "DllMain was never called for {}: the loader did not find the entry point",
            dll.display()
        );
        // The recorded handle must be where the loader actually put the DLL. If
        // `DllMain` ran but recorded the wrong thing -- or ran for a *different*
        // module than the one just loaded -- this is what catches it.
        assert_eq!(
            base, module.0 as usize,
            "the module recorded by DllMain is not the module the loader loaded"
        );
    }

    /// `MESSAGE_MAGIC` is what authenticates the page's own window messages, and
    /// `PROGRESS_RESOLUTION` is the divisor in its progress router. Both are
    /// defined by the UI crate -- this only pins that they are reachable from the
    /// shell crate, which is where any worker posting them would live.
    ///
    /// `const` blocks rather than plain assertions: these are compile-time facts,
    /// so a failure should be a build error rather than a test failure that only
    /// appears when someone runs the suite.
    #[test]
    fn the_ui_message_contract_is_reachable_from_the_shell() {
        const { assert!(MESSAGE_MAGIC > 0xffff) };
        const { assert!(PROGRESS_RESOLUTION > 0) };
    }
}
