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
//! * a status line
//! * a push button that copies the selected rows
//!
//! # Lifetime
//!
//! The state object behind the dialog is handed to the shell through
//! `PROPSHEETPAGEW::lParam` as a raw `Box::into_raw` pointer. The shell calls
//! the page callback with `PSPCB_ADDREF` / `PSPCB_CREATE` / `PSPCB_RELEASE`;
//! the pointer is reclaimed **exactly once**, on `PSPCB_RELEASE`. [`page`]
//! documents the three-way ownership table, including the failure path where the
//! shell takes the page but rejects it.
//!
//! # Why the scan is not run from here
//!
//! `AddPages` and the dialog procedure both run on the thread that owns the
//! Properties dialog. Expanding a directory selection or hashing a file there
//! would freeze the dialog, and the project forbids blocking the UI thread
//! outright. The hashing therefore lives on a thread the page owns, and reports
//! back through posted window messages authenticated by [`MESSAGE_MAGIC`].

#![warn(missing_docs)]

#[cfg(windows)]
pub mod clipboard;
#[cfg(windows)]
pub mod dialog;
#[cfg(windows)]
pub mod listview;
#[cfg(windows)]
pub mod page;
pub mod readout;
pub mod resource;
#[cfg(windows)]
mod route;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
mod window_data;

use rusthashtab_hash::Algorithm;
use rusthashtab_scan::MatchState;

/// One row in the results list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    /// Job this row belongs to: an index into the scan's job list, which is what
    /// the file column displays.
    ///
    /// Carried on the row rather than looked up from a map, so a row is
    /// self-describing: a repaint, a copy of the selection, and the row's own
    /// colouring all have to answer "which file is this", and three lookups that
    /// could disagree are three chances to be wrong.
    pub job_index: usize,
    /// Index into the algorithm table.
    ///
    /// [`usize::MAX`] on a row that stands for a whole file rather than for one
    /// algorithm, which is the row an unreadable file produces.
    pub algorithm: usize,
    /// Uppercase or lowercase hex, per the display setting -- already formatted,
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
/// which is why the field order here is load-bearing:
/// [`resource::status_finished`] formats them positionally.
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
/// This is the object stored in `GWLP_USERDATA`, created in `WM_INITDIALOG` and
/// destroyed on `PSPCB_RELEASE`.
#[derive(Debug)]
pub struct DialogState {
    /// Paths the shell said were selected, unresolved.
    pub roots: Vec<std::path::PathBuf>,
    /// Settings as read when the page was built.
    pub settings: rusthashtab_settings::Settings,
    /// Which algorithms to hash with, indexed like
    /// [`rusthashtab_hash::ALGORITHMS`].
    ///
    /// Stored rather than recomputed so that every row and the scan itself agree
    /// on the same set even if the settings changed while the page was open.
    pub enabled: Vec<bool>,
    /// Every row the page has displayed, in display order.
    ///
    /// The list view holds the same information, but the view is not the source of
    /// truth: a copy of the selection has to map a list item back to a row, and
    /// rebuilding rows from a control is exactly the kind of round trip that goes
    /// wrong when the control is empty or mid-update.
    pub rows: Vec<ListRow>,
    /// The hashing thread, until teardown takes it.
    #[cfg(windows)]
    pub session: Option<session::ReadoutSession>,
    /// The page's list view, once `WM_INITDIALOG` has found it.
    #[cfg(windows)]
    pub list: Option<windows::Win32::Foundation::HWND>,
    /// The page's status line, once `WM_INITDIALOG` has found it.
    #[cfg(windows)]
    pub status: Option<windows::Win32::Foundation::HWND>,
    /// The page's window handle, or `None` before `WM_INITDIALOG`.
    #[cfg(windows)]
    pub hwnd: Option<windows::Win32::Foundation::HWND>,
}

impl DialogState {
    /// State for a page about to be created.
    pub fn new(roots: Vec<std::path::PathBuf>, settings: rusthashtab_settings::Settings) -> Self {
        let enabled = crate::enabled_algorithms(&settings);
        Self {
            roots,
            settings,
            enabled,
            rows: Vec::new(),
            #[cfg(windows)]
            session: None,
            #[cfg(windows)]
            list: None,
            #[cfg(windows)]
            status: None,
            #[cfg(windows)]
            hwnd: None,
        }
    }

    /// The algorithms this page hashes with, in table order.
    pub fn algorithms(&self) -> impl Iterator<Item = (usize, &'static Algorithm)> + '_ {
        rusthashtab_hash::ALGORITHMS
            .iter()
            .enumerate()
            .filter(|(index, _)| self.enabled.get(*index).copied().unwrap_or(false))
    }

    /// Record the window handle, once it exists.
    #[cfg(windows)]
    pub(crate) fn attach(&mut self, hwnd: windows::Win32::Foundation::HWND) {
        self.hwnd = Some(hwnd);
    }
}

/// Files the page will hash, at most.
///
/// A cap rather than a limit the user is expected to hit: the list view holds one
/// row per file per enabled algorithm, so a directory of a hundred thousand files
/// with all 31 algorithms on is three million items in a control that is not
/// virtual. The page hashes the first [`MAX_HASHED_FILES`] and says how many it
/// left out, which is a visible, honest truncation rather than a hang.
pub const MAX_HASHED_FILES: usize = 1000;

/// Which algorithms to hash with, given the settings.
///
/// Indexed like [`rusthashtab_hash::ALGORITHMS`], which is the shape
/// [`rusthashtab_scan::ScanConfig`] wants. The decision is delegated to
/// [`rusthashtab_settings::Settings::is_enabled`] rather than read out of the
/// flag vector here, so that "the user has never chosen" resolves to the default
/// set in exactly one place.
pub(crate) fn enabled_algorithms(settings: &rusthashtab_settings::Settings) -> Vec<bool> {
    let names: Vec<&str> = rusthashtab_hash::ALGORITHMS
        .iter()
        .map(|algorithm| algorithm.name)
        .collect();

    rusthashtab_hash::ALGORITHMS
        .iter()
        .enumerate()
        .map(|(index, algorithm)| settings.is_enabled(index, &names) && algorithm.is_implemented())
        .collect()
}

/// Errors the UI layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum UiError {
    /// A Win32 call failed.
    #[error("{context}: {source}")]
    Win32 {
        /// What we were trying to do.
        context: &'static str,
        /// The underlying failure, message included.
        #[source]
        source: windows::core::Error,
    },
    /// The dialog template resource is missing from the module.
    #[error("dialog resource {0} not found in this module")]
    MissingResource(u16),
    /// The shell accepted the page handle and then refused the page.
    #[error("the shell refused the property sheet page")]
    PageRefused,
}

impl UiError {
    /// The `HRESULT` COM should see for this failure.
    ///
    /// The mapping lives here rather than at each call site so that a new failure
    /// mode cannot be added without deciding what the shell is told about it.
    pub fn to_hresult(&self) -> windows::core::HRESULT {
        match self {
            UiError::Win32 { source, .. } => source.code(),
            UiError::MissingResource(_) | UiError::PageRefused => {
                windows::Win32::Foundation::E_FAIL
            }
        }
    }
}

/// User window messages the scan thread posts to the page.
///
/// They start at `WM_APP`, and carry [`MESSAGE_MAGIC`] in `wParam` so that a
/// stray message from an unrelated control is ignored rather than misinterpreted
/// as progress. [`route::route`] is the only place that decision is made, and it
/// is a pure function so it can be tested without a window.
pub use dialog::{WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_SCAN_FINISHED};

/// Progress is quantised to this many steps, so a 10 GB scan does not post a
/// message per byte.
pub const PROGRESS_RESOLUTION: u64 = 256;

/// Magic value carried in `wParam` to authenticate our own messages.
///
/// `wParam` is `WPARAM`, which is pointer-sized, so on a 32-bit build only the low
/// half of the 64-bit constant fits. That is a property of the platform, not a
/// choice, and it is why the gate compiles i686: a 64-bit literal here is a plain
/// `error: literal out of range for 'usize'` on 32-bit targets and invisible to an
/// x86_64-only build.
///
/// Both values are deliberately odd and high-entropy in their low 32 bits. The
/// check only ever compares against this constant, so what matters is that a
/// stray message from an unrelated control is extremely unlikely to match -- not
/// which particular number is used.
#[cfg(target_pointer_width = "64")]
pub const MESSAGE_MAGIC: usize = 0x1c72_5fcf_dcbf_5843;
/// See the 64-bit definition. Truncated to the low 32 bits because `WPARAM` is
/// 32-bit here and the full constant does not fit.
#[cfg(target_pointer_width = "32")]
pub const MESSAGE_MAGIC: usize = 0xdcbf_5843;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_uses_the_whole_pointer_width_without_overflowing_it() {
        // The 32-bit arm is the one that historically broke the i686 build: a
        // 64-bit literal in a `usize` context is a compile error there. Keeping
        // both arms pinned also documents that the split is intentional.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(MESSAGE_MAGIC, 0x1c72_5fcf_dcbf_5843);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(MESSAGE_MAGIC, 0xdcbf_5843);
    }

    #[test]
    fn the_two_arms_are_the_low_half_of_one_constant() {
        // The truncation is the platform's, not a design choice: the 32-bit value
        // must be what a 64-bit build's constant truncates to, or a 32-bit
        // explorer would ignore a 64-bit process's messages... which is exactly
        // the kind of divergence nobody would notice until it mattered.
        assert_eq!(MESSAGE_MAGIC as u64 & 0xffff_ffff, 0xdcbf_5843);
    }

    /// A page that has just been built has nothing in it and no thread yet: the
    /// scan starts from `WM_INITDIALOG`, not from `add_page`, because `add_page`
    /// runs on the shell's thread and must return immediately.
    #[test]
    fn a_fresh_state_has_no_rows_and_no_session() {
        let state = DialogState::new(Vec::new(), rusthashtab_settings::Settings::default());
        assert!(state.rows.is_empty());
        assert!(state.session.is_none());
        assert!(state.list.is_none());
        assert!(state.status.is_none());
        assert!(state.hwnd.is_none());
    }

    #[test]
    fn the_default_settings_enable_the_four_documented_algorithms() {
        let settings = rusthashtab_settings::Settings::default();
        let enabled = enabled_algorithms(&settings);
        let names: Vec<&str> = rusthashtab_hash::ALGORITHMS
            .iter()
            .enumerate()
            .filter(|(index, _)| enabled[*index])
            .map(|(_, algorithm)| algorithm.name)
            .collect();
        assert_eq!(names, vec!["MD5", "SHA-1", "SHA-256", "SHA-512"]);
    }

    /// Every algorithm this page turns on must have a context, or the scan would
    /// silently drop it and the list would show an empty digest.
    #[test]
    fn every_enabled_algorithm_can_be_constructed() {
        let settings = rusthashtab_settings::Settings {
            algorithms: vec![true; rusthashtab_hash::ALGORITHMS.len()],
            ..rusthashtab_settings::Settings::default()
        };
        let enabled = enabled_algorithms(&settings);
        for (index, algorithm) in rusthashtab_hash::ALGORITHMS.iter().enumerate() {
            assert!(enabled[index], "{} was not enabled", algorithm.name);
            assert!(
                algorithm.is_implemented(),
                "{} is enabled but has no context",
                algorithm.name
            );
        }
    }

    #[test]
    fn an_explicit_all_false_list_selects_nothing() {
        let settings = rusthashtab_settings::Settings {
            algorithms: vec![false; rusthashtab_hash::ALGORITHMS.len()],
            ..rusthashtab_settings::Settings::default()
        };
        assert!(!enabled_algorithms(&settings).iter().any(|on| *on));
    }

    /// A list shorter than the table is settings from an older build: positions
    /// past its end are off, not on.
    #[test]
    fn a_short_algorithm_list_is_disabled_past_its_end() {
        let settings = rusthashtab_settings::Settings {
            algorithms: vec![true, false],
            ..rusthashtab_settings::Settings::default()
        };
        let enabled = enabled_algorithms(&settings);
        assert!(enabled[0]);
        assert!(!enabled[1]);
        assert!(!enabled[2]);
    }

    /// The iterator must agree with the flag vector, since the list view and the
    /// scan are built from different ones.
    #[test]
    fn the_algorithm_iterator_matches_the_flag_vector() {
        let state = DialogState::new(Vec::new(), rusthashtab_settings::Settings::default());
        let from_iterator: Vec<&str> = state.algorithms().map(|(_, a)| a.name).collect();
        let from_flags: Vec<&str> = rusthashtab_hash::ALGORITHMS
            .iter()
            .enumerate()
            .filter(|(index, _)| state.enabled[*index])
            .map(|(_, algorithm)| algorithm.name)
            .collect();
        assert_eq!(from_iterator, from_flags);
        assert_eq!(from_iterator.len(), 4);
    }

    #[test]
    fn a_missing_resource_maps_to_failure_not_success() {
        assert_eq!(
            UiError::MissingResource(101).to_hresult(),
            windows::Win32::Foundation::E_FAIL
        );
        assert_eq!(
            UiError::PageRefused.to_hresult(),
            windows::Win32::Foundation::E_FAIL
        );
    }
}
