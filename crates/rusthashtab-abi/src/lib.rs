//! COM/HRESULT plumbing and **panic containment** for the rustHashTab shell
//! extension.
//!
//! # Why this crate exists
//!
//! A shell extension is loaded *into* `explorer.exe`. Two failure modes are
//! therefore fatal to the user's desktop rather than to our process:
//!
//! 1. **An unwind crossing a COM boundary.** Since Rust 1.81 the non-unwinding
//!    ABIs (`"system"`, `"C"`) abort on an uncaught unwind. An `extern "system"`
//!    vtable slot that panics therefore terminates the host process.
//! 2. **A module-lock leak.** If [`DllCanUnloadNow`] reports "unloadable" while
//!    the shell still holds a property sheet page, the DLL is unmapped out from
//!    under live state.
//!
//! This crate centralises both, so that no individual COM implementation has to
//! get them right by hand.
//!
//! [`DllCanUnloadNow`]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-dllcanunloadnow

#![cfg_attr(not(windows), allow(unused))]

use core::sync::atomic::{AtomicU32, Ordering};

/// Module lock count, mirrored from the `PSP_USEREFPARENT` / `pcRefParent`
/// contract.
///
/// The property sheet increments and decrements this directly (through a raw
/// pointer handed to the shell), so it must be a bare static with a stable
/// address — **not** an `AtomicU32` wrapper newtype, and never a thread-local.
pub static MODULE_LOCKS: AtomicU32 = AtomicU32::new(0);

/// Live COM object count, tracked separately from [`MODULE_LOCKS`].
///
/// These must never share a counter: `LockServer(FALSE)` can be delivered
/// without a matching `LockServer(TRUE)`, and folding an unmatched decrement
/// into the object count is a known way to let COM `FreeLibrary` the DLL while
/// it is still in use.
pub static OBJECT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Increment [`MODULE_LOCKS`].
pub fn lock_module() {
    MODULE_LOCKS.fetch_add(1, Ordering::SeqCst);
}

/// Decrement [`MODULE_LOCKS`], saturating at zero.
///
/// Saturating rather than wrapping is deliberate: an unmatched unlock must be
/// harmless, not a wrap to `u32::MAX` that pins the DLL in memory forever.
pub fn unlock_module() {
    let _ = MODULE_LOCKS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_sub(1))
    });
}

/// Increment [`OBJECT_COUNT`].
pub fn add_object() {
    OBJECT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Decrement [`OBJECT_COUNT`], saturating at zero.
pub fn release_object() {
    let _ = OBJECT_COUNT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_sub(1))
    });
}

/// True when no live objects and no outstanding module locks remain.
pub fn can_unload() -> bool {
    OBJECT_COUNT.load(Ordering::SeqCst) == 0 && MODULE_LOCKS.load(Ordering::SeqCst) == 0
}

/// Outcome of a guarded COM entry point: either a value, or a `HRESULT` to
/// return to the shell.
pub type Guarded<T> = core::result::Result<T, GuardError>;

/// A failure that has already been converted into something COM can carry.
///
/// Not `Copy`: `windows_core::Error` carries a heap-allocated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// The body panicked. The panic message has been logged; the shell only
    /// needs a failure code.
    Panicked,
    /// The body returned a `windows_core::Error`.
    #[cfg(windows)]
    Com(windows_core::Error),
}

#[cfg(windows)]
impl From<windows_core::Error> for GuardError {
    fn from(e: windows_core::Error) -> Self {
        GuardError::Com(e)
    }
}

#[cfg(windows)]
impl From<GuardError> for windows_core::HRESULT {
    fn from(e: GuardError) -> Self {
        match e {
            GuardError::Panicked => windows::Win32::Foundation::E_UNEXPECTED,
            GuardError::Com(e) => e.code(),
        }
    }
}

/// Run a COM method body with panic containment.
///
/// **Every** externally reachable COM entry point must go through this. The
/// closure is `FnOnce` and its panic is caught before it can reach the vtable
/// slot's `extern "system"` boundary.
///
/// # Example
///
/// ```no_run
/// use rusthashtab_abi::{guarded, Guarded};
///
/// fn add_pages() -> Guarded<()> {
///     guarded(|| {
///         // ... build the PROPSHEETPAGEW and hand it to the shell ...
///         Ok(())
///     })
/// }
/// ```
pub fn guarded<T, F>(body: F) -> Guarded<T>
where
    F: FnOnce() -> Guarded<T>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(result) => result,
        Err(_payload) => {
            report_panic();
            Err(GuardError::Panicked)
        }
    }
}

/// Emit a diagnostic for a contained panic.
///
/// Deliberately minimal: inside `explorer.exe` there is no console and no
/// sensible place to write a log file from a recovering-by-definition path.
/// `OutputDebugStringW` is the only channel that is safe here.
fn report_panic() {
    #[cfg(windows)]
    {
        use windows::core::w;
        // SAFETY: OutputDebugStringW takes a NUL-terminated wide string and has
        // no other preconditions. The literal outlives the call.
        unsafe {
            windows::Win32::System::Diagnostics::Debug::OutputDebugStringW(w!(
                "rustHashTab: panic contained at a COM entry point\n"
            ))
        };
    }
}

/// Install the process-wide panic hook. Call once, from `DllMain`'s
/// `DLL_PROCESS_ATTACH`.
///
/// The hook only records; it must not allocate, take locks, or call into COM,
/// because it may run while the loader lock is held.
pub fn install_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            report_panic();
            // Still delegate, so `cargo test` keeps printing useful panics.
            previous(info);
        }));
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_are_saturating() {
        // Unbalanced unlocks must not wrap.
        unlock_module();
        unlock_module();
        assert_eq!(MODULE_LOCKS.load(Ordering::SeqCst), 0);

        lock_module();
        lock_module();
        assert_eq!(MODULE_LOCKS.load(Ordering::SeqCst), 2);
        unlock_module();
        unlock_module();
        unlock_module();
        assert_eq!(MODULE_LOCKS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn counts_are_independent() {
        lock_module();
        add_object();
        assert!(!can_unload());
        unlock_module();
        // Still one live object, so still not unloadable. If the two counters
        // were shared this would wrongly report unloadable.
        assert!(!can_unload());
        release_object();
        assert!(can_unload());
    }

    #[test]
    fn panics_are_contained_not_propagated() {
        let result: Guarded<()> = guarded(|| panic!("boom"));
        assert_eq!(result, Err(GuardError::Panicked));
    }

    #[test]
    fn success_passes_through() {
        let result: Guarded<u32> = guarded(|| Ok(0x5EED));
        assert_eq!(result, Ok(0x5EED));
    }
}
