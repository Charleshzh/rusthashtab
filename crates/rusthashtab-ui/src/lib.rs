//! Win32 dialog UI for the rustHashTab property sheet page.
//!
//! # Hard constraint
//!
//! The page is a **child dialog created by the shell** and hosted in the file
//! Properties sheet. Every message arrives at our `DLGPROC` on the shell's STA.
//! There is no supported way to host a GPU-rendered toolkit here, so the UI is
//! raw Win32 common controls, exactly as the upstream implementation is:
//!
//! * `SysListView32` in report mode, owner-drawn for the match/mismatch colours
//! * `msctls_progress32`
//! * `EDITTEXT` for the comparison field
//! * standard push buttons and an icon button row
//!
//! # Lifetime
//!
//! The state object behind the dialog is handed to the shell through
//! `PROPSHEETPAGEW::lParam` as a raw `Box::into_raw` pointer. The shell calls
//! the page callback with `PSPCB_ADDREF` / `PSPCB_CREATE` / `PSPCB_RELEASE`;
//! the pointer is reclaimed **exactly once**, on `PSPCB_RELEASE`.
//!
//! # Not yet implemented
//!
//! This module is scaffolding. It defines the state types and the message-router
//! shape so the shell layer can be written against them.

#![warn(missing_docs)]

use rusthashtab_hash::Algorithm;
use rusthashtab_scan::MatchState;

/// One row in the results list.
#[derive(Debug, Clone)]
pub struct ListRow {
    /// File this row describes.
    pub file_index: usize,
    /// Index into the algorithm table.
    pub algorithm: usize,
    /// Uppercase or lowercase hex, per the display setting — already formatted,
    /// because the list is owner-drawn and must not format on the paint path.
    pub digest_hex: String,
    /// How this digest compares to any expected value.
    pub match_state: MatchState,
    /// Set when the file could not be read; shown in place of the digest.
    pub error: Option<u32>,
}

/// Counters shown in the status line, in the order the UI displays them.
///
/// The status text reads `(matched / mismatched / nothing to check / error)`,
/// which is why the field order here is load-bearing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Files whose digest matched an expected value under some algorithm.
    pub matched: u32,
    /// Files that had an expected digest and matched none of them.
    pub mismatched: u32,
    /// Files hashed with no expected digest to compare against.
    pub nothing_to_check: u32,
    /// Files that could not be read, or whose hash failed.
    pub error: u32,
}

/// Everything the dialog needs while it is open.
///
/// This is the object stored in `GWLP_USERDATA`. It is created in
/// `WM_INITDIALOG` and destroyed on `WM_NCDESTROY`.
#[derive(Debug)]
pub struct DialogState {
    /// `HWND` of the page dialog.
    pub hwnd: isize,
    /// Algorithm table, already filtered to the enabled set.
    pub algorithms: Vec<Algorithm>,
    /// Rows currently displayed.
    pub rows: Vec<ListRow>,
    /// Status counters.
    pub counters: Counters,
    /// Monospace font handle, for the digest column.
    pub mono_font: isize,
    /// UI font handle.
    pub ui_font: isize,
}

/// User window messages the scan thread posts to the page.
///
/// They start at `WM_USER`, and carry [`MESSAGE_MAGIC`] in `wParam` so that a
/// stray `WM_USER`-range message from an unrelated control is ignored rather
/// than misinterpreted as progress.
pub const WM_ALL_FILES_FINISHED: u32 = 0x0400; // WM_USER
/// Progress update; `lParam` is a fraction of [`PROGRESS_RESOLUTION`].
pub const WM_FILE_PROGRESS: u32 = 0x0401;

/// Progress is quantised to this many steps, so a 10 GB scan does not post a
/// message per byte.
pub const PROGRESS_RESOLUTION: u64 = 256;

/// Magic value carried in `wParam` to authenticate our own messages.
///
/// `wParam` is `WPARAM`, which is pointer-sized, so on a 32-bit build only the low
/// half of the 64-bit constant fits. That is a property of the platform, not a
/// choice: the upstream C++ had the same split, and the truncation is what its
/// 32-bit build produced.
///
/// Both values are deliberately odd and high-entropy in their low 32 bits. The
/// check only ever compares against this constant, so what matters is that a
/// stray `WM_USER`-range message from an unrelated control is extremely unlikely
/// to match — not which particular number is used.
#[cfg(target_pointer_width = "64")]
pub const MESSAGE_MAGIC: usize = 0x1c72_5fcf_dcbf_5843;
/// See the 64-bit definition. Truncated to the low 32 bits because `WPARAM` is
/// 32-bit here and the full constant does not fit.
#[cfg(target_pointer_width = "32")]
pub const MESSAGE_MAGIC: usize = 0xdcbf_5843;

/// Errors the UI layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum UiError {
    /// A Win32 call failed.
    #[error("win32 error {code}: {context}")]
    Win32 {
        /// `GetLastError()` value.
        code: u32,
        /// What we were trying to do.
        context: &'static str,
    },
    /// The dialog template resource is missing from the module.
    #[error("dialog resource {0} not found")]
    MissingResource(u16),
}
