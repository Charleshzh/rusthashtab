//! The COM apartment the context-menu window thread owns.
//!
//! # Why a guard rather than a pair of calls
//!
//! `IContextMenu::InvokeCommand` cannot host a window on `explorer.exe`'s UI
//! thread: that thread belongs to the shell's message loop, and a window that
//! needs its own loop has to run on a thread that owns one. The thread started
//! for that window must therefore enter COM as a single-threaded apartment first
//! -- the shell dialogs, drag and drop, and the clipboard all refuse to run
//! outside one.
//!
//! Entering is not the hard part; leaving is. `CoUninitialize` must run exactly
//! once per successful `CoInitializeEx`, on the same thread, after every COM
//! object that thread created has been released. A guard makes that balance a
//! property of the thread's scope instead of something every early return has to
//! remember.

#![cfg(windows)]

use windows::Win32::Foundation::{S_FALSE, S_OK};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};

/// A single-threaded apartment held for as long as the value lives.
///
/// Construct it once at the top of a thread and let it drop at the end: the drop
/// is what calls `CoUninitialize`, and it only does so when the initialisation
/// actually added a reference.
pub(crate) struct Apartment {
    /// Whether `CoInitializeEx` added an apartment reference this guard owns.
    initialised: bool,
}

impl Apartment {
    /// Enter a single-threaded apartment on the calling thread.
    ///
    /// `S_OK` is a fresh initialisation; `S_FALSE` means COM was already
    /// initialised on this thread with the same model. Both add a reference that
    /// [`Apartment::drop`] must release.
    ///
    /// Any other answer -- most often `RPC_E_CHANGED_MODE` because the thread is
    /// already in a multi-threaded apartment -- is tolerated rather than fatal,
    /// for two reasons:
    ///
    /// * the caller cannot fix it. The thread was handed to us in a state we did
    ///   not choose, and refusing to continue would turn that into a context
    ///   menu that silently does nothing;
    /// * balancing a failure with `CoUninitialize` is the unsafe option: only a
    ///   successful call added a reference, so an unmatched decrement corrupts
    ///   the thread's apartment count for whatever code runs on it next.
    ///
    /// If the apartment could not be entered, the window host reports the failure
    /// through its own channel; this guard stays out of the way.
    pub(crate) fn new() -> Self {
        // SAFETY: `CoInitializeEx` takes an optional reserved pointer, for which
        // null is the documented value, and an apartment-model constant. It has
        // no other preconditions, and every failure comes back as an `HRESULT`
        // rather than as an unwind.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        let initialised = result == S_OK || result == S_FALSE;

        Self { initialised }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if !self.initialised {
            return;
        }

        // SAFETY: the guard is constructed and dropped inside one thread function
        // and is not stored anywhere that outlives it, so this is the same thread
        // that called `CoInitializeEx`. `initialised` says that call returned one
        // of the two success codes, which is exactly the condition
        // `CoUninitialize` expects to be matching.
        unsafe {
            CoUninitialize();
        }
    }
}
