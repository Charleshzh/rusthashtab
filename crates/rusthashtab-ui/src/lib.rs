//! Win32 dialog UI for the rustHashTab property sheet page.
//!
//! # Hard constraint
//!
//! The page is a **child dialog created by the shell** and hosted in the file
//! Properties sheet, or by the standalone window host. Every message arrives at
//! our `DLGPROC` on the thread that owns the dialog. There is no supported way to
//! host a GPU-rendered toolkit here, so the UI is raw Win32 common controls:
//!
//! * `SysListView32` in report mode, owner-drawn for the match/mismatch colours
//! * `msctls_progress32`
//! * a status line
//! * a push button that copies the selected rows
//!
//! # Two hosts, one page
//!
//! The shell creates the page as a property sheet page ([`page`]). The context
//! menu and the standalone launcher have no property sheet, so [`window`] wraps
//! the same dialog in a plain resizable top-level window and reflows the controls
//! on `WM_SIZE` from a baseline captured in `WM_INITDIALOG`. Both paths create the
//! dialog from the same compiled template and run the same [`dialog::dlg_proc`];
//! only the code that owns the window differs.
//!
//! # Lifetime
//!
//! On the property sheet path the state object behind the dialog is handed to the
//! shell through `PROPSHEETPAGEW::lParam` as a raw `Box::into_raw` pointer. The
//! shell calls the page callback with `PSPCB_ADDREF` / `PSPCB_CREATE` /
//! `PSPCB_RELEASE`; the pointer is reclaimed **exactly once**, on
//! `PSPCB_RELEASE`. [`page`] documents the three-way ownership table, including
//! the failure path where the shell takes the page but rejects it. On the window
//! path the host owns the same box and frees it on `WM_DESTROY`, after the child
//! dialog has been destroyed.
//!
//! # Why the scan is not run from here
//!
//! `AddPages` and the dialog procedure both run on the thread that owns the
//! dialog. Expanding a directory selection or hashing a file there would freeze
//! it, and the project forbids blocking the UI thread outright. The hashing
//! therefore lives on a thread the page owns, and reports back through posted
//! window messages authenticated by [`MESSAGE_MAGIC`].

#![warn(missing_docs)]

/// Checksum-file extensions the shell may advertise in "Open with".
pub mod associations;
#[cfg(windows)]
pub mod clipboard;
#[cfg(windows)]
pub mod dialog;
pub mod export;
#[cfg(windows)]
mod layout;
#[cfg(windows)]
pub mod listview;
pub mod manifest;
#[cfg(windows)]
pub mod page;
pub mod readout;
pub mod resource;
#[cfg(windows)]
mod route;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod settings_dialog;
pub mod strings;
#[cfg(windows)]
pub mod task;
pub mod verify;
#[cfg(windows)]
pub mod window;
#[cfg(windows)]
mod window_data;

use rusthashtab_hash::Algorithm;
use rusthashtab_scan::MatchState;

/// One file the page is hashing, as the parts of it the UI needs.
///
/// The scanner's [`rusthashtab_scan::FileJob`] carries the same information plus
/// a size and the expected digests, none of which the page retains: the expected
/// digests change while the page is open (a pasted hash, a checksum file), and
/// the size is only used by the scan. Keeping a display path next to the
/// absolute path is what lets the File column and an exported checksum file agree
/// on the name the user saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSpec {
    /// Absolute, normalized path, as the scanner opened it.
    pub path: std::path::PathBuf,
    /// How the file is shown: relative to the scan root when possible.
    pub display_path: String,
}

/// One row in the results list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    /// Stable identity of this row within the page.
    ///
    /// Not the row's position: a row is inserted into job order while earlier
    /// files are still hashing, and the whole list is rebuilt when the scan ends.
    /// Selection and copying must survive both, so they address a row by this
    /// value and each list item's `lParam` carries it.
    pub id: u64,
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
    /// Upper-case or lower-case hex, per the display setting -- already formatted,
    /// because the list is owner-drawn and must not format on the paint path.
    pub digest_hex: String,
    /// How this digest compares to any expected value.
    pub match_state: MatchState,
    /// Set when the file could not be read; shown in place of the digest.
    pub error: Option<u32>,
    /// The file's display path, copied from the job so a row can be shown and
    /// copied without a lookup that could disagree with the list.
    pub display_path: String,
}

/// The stable identity of a row, from its job and algorithm.
///
/// Job indices are bounded by [`MAX_HASHED_FILES`] (1000) and algorithm indices by
/// the table (31), so the packed value is unique on both pointer widths. An error
/// row uses `usize::MAX` as its "algorithm" and therefore gets its own ID per job.
pub fn row_id(job_index: usize, algorithm: usize) -> u64 {
    ((job_index as u64) << 32) | u64::from(algorithm as u32)
}

/// Where the page is in the selection's lifecycle.
///
/// The page is modeless and the scan runs on its own thread, so "which controls
/// are usable" is not derivable from any single flag: discovery, hashing, and the
/// two ways hashing can end all permit different actions. One enum, set at the
/// same points that post the transition messages, keeps those decisions in one
/// place instead of scattered across handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    /// Expanding the selection; no job list yet.
    Discovering,
    /// The job list is published and files are being hashed.
    Hashing,
    /// Every file was hashed.
    Finished,
    /// The user asked to stop, or the scan reported that it could not finish.
    Cancelled,
}

/// How a settings change applies to the page that is already open.
///
/// A settings dialog returns one complete [`rusthashtab_settings::Settings`], but
/// not every difference means the files have to be hashed again: colours, case
/// and the monospace choice only change how the existing rows are drawn. The page
/// asks this classification instead of restarting on every save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsChange {
    /// Nothing the page is currently showing depends on the changed fields.
    None,
    /// Rebuild and repaint the existing rows; the scan keeps running.
    Redraw,
    /// The set of files to hash, or the algorithms to hash them with, changed.
    Rescan,
}

/// Classify what a settings update means for the open page.
///
/// `manifest_mode` is whether the running scan was started by interpreting a
/// checksum file as a manifest. The manifest options are part of the plan that
/// produced the job list, so changing them matters only when such a plan exists;
/// outside a manifest scan they name a future page's behaviour and must not cost
/// a rescan.
#[must_use]
pub fn settings_change(
    current: &rusthashtab_settings::Settings,
    updated: &rusthashtab_settings::Settings,
    manifest_mode: bool,
) -> SettingsChange {
    if enabled_algorithms(current) != enabled_algorithms(updated)
        || current.look_for_sumfiles != updated.look_for_sumfiles
    {
        return SettingsChange::Rescan;
    }

    if manifest_mode
        && (current.hash_sumfile_too != updated.hash_sumfile_too
            || current.sumfile_algorithm_only != updated.sumfile_algorithm_only)
    {
        return SettingsChange::Rescan;
    }

    if current.display_uppercase != updated.display_uppercase
        || current.display_monospace != updated.display_monospace
        || current.colours != updated.colours
    {
        return SettingsChange::Redraw;
    }

    SettingsChange::None
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
    /// Where the selection is in its lifecycle; drives every control's enabled state.
    pub scan_phase: ScanPhase,
    /// Files the scan was given, once the job list is published. Zero before then.
    pub job_count: usize,
    /// Files discovery has found so far, for the status line while expanding.
    pub discovery_files: usize,
    /// Set between the Cancel click and the scan's completion message.
    pub cancelling: bool,
    /// Formats the export selector currently offers.
    pub export_choices: Vec<crate::export::ExportChoice>,
    /// The selected export format, or `None` before the selector is filled.
    pub export_choice: Option<crate::export::ExportChoice>,
    /// Current sort order, or `None` for job order.
    #[cfg(windows)]
    pub sort: Option<crate::listview::SortState>,
    /// Colours resolved from the settings, or from the system in high contrast.
    #[cfg(windows)]
    pub palette: crate::listview::Palette,
    /// The hashing thread, until teardown takes it.
    #[cfg(windows)]
    pub session: Option<session::ReadoutSession>,
    /// The page's list view, once `WM_INITDIALOG` has found it.
    #[cfg(windows)]
    pub list: Option<windows::Win32::Foundation::HWND>,
    /// The page's status line, once `WM_INITDIALOG` has found it.
    #[cfg(windows)]
    pub status: Option<windows::Win32::Foundation::HWND>,
    /// The template geometry of every control, captured in `WM_INITDIALOG`.
    ///
    /// `None` until the controls exist; [`window::open`] then resizes the page to
    /// fill the top-level window, and the page's `WM_SIZE` reflows from this
    /// baseline. A property sheet never resizes its page, so a page that never
    /// leaves the sheet keeps its template geometry and never reads this.
    #[cfg(windows)]
    pub(crate) layout: Option<layout::Baseline>,
    /// The page's window handle, or `None` before `WM_INITDIALOG`.
    #[cfg(windows)]
    pub hwnd: Option<windows::Win32::Foundation::HWND>,
    /// The module the page's resources -- including the settings dialog template
    /// -- live in.
    ///
    /// The page cannot find this on its own: inside `explorer.exe` the process
    /// module is the shell, not this DLL, so `GetModuleHandleW(None)` would hand
    /// `DialogBoxParamW` a module with no template in it. `page::add_page` copies
    /// it here from the `HINSTANCE` the shell supplied.
    #[cfg(windows)]
    pub instance: Option<windows::Win32::Foundation::HINSTANCE>,
    /// The checksum-file read and match in flight, if any.
    #[cfg(windows)]
    pub verify_task: Option<task::Background<Result<crate::verify::SumfileMatch, String>>>,
    /// The export in flight, if any.
    #[cfg(windows)]
    pub export_task: Option<task::Background<Result<usize, String>>>,
    /// A fixed-pitch font for the digest column, when the display setting asks for
    /// one. `0` means none; it is created from the sheet's font in `WM_INITDIALOG`.
    #[cfg(windows)]
    pub mono_font: isize,
    /// Sequence of the newest verification request; a completion with any other
    /// sequence is stale and is ignored.
    #[cfg(windows)]
    pub verify_seq: u32,
    /// Sequence of the newest export request.
    #[cfg(windows)]
    pub export_seq: u32,
    /// The page's tooltip control, once it has been created.
    #[cfg(windows)]
    pub tooltip: Option<windows::Win32::Foundation::HWND>,
    /// The current status text, NUL-terminated, for the status tooltip.
    #[cfg(windows)]
    pub tooltip_status: Vec<u16>,
    /// The status-line label of the verification source currently being loaded.
    ///
    /// Stored on the dialog because the worker owns the file read; the label is
    /// what the status line will show once the match lands.
    #[cfg(windows)]
    pub verify_source: Option<String>,
    /// A digest found on the clipboard when the page opened, waiting for the scan
    /// to finish.
    ///
    /// `None` when the setting is off, the clipboard held no usable digest, or a
    /// complete scan has already consumed it. The page never re-reads the
    /// clipboard: what the user copied when they opened the page is the request.
    pub clipboard_text: Option<String>,
}

impl DialogState {
    /// State for a page about to be created.
    pub fn new(roots: Vec<std::path::PathBuf>, settings: rusthashtab_settings::Settings) -> Self {
        let enabled = crate::enabled_algorithms(&settings);
        #[cfg(windows)]
        let palette =
            crate::listview::Palette::from_settings(&settings, crate::listview::high_contrast());
        Self {
            roots,
            settings,
            enabled,
            rows: Vec::new(),
            scan_phase: ScanPhase::Discovering,
            job_count: 0,
            discovery_files: 0,
            cancelling: false,
            export_choices: Vec::new(),
            export_choice: None,
            #[cfg(windows)]
            sort: None,
            #[cfg(windows)]
            palette,
            #[cfg(windows)]
            session: None,
            #[cfg(windows)]
            list: None,
            #[cfg(windows)]
            status: None,
            #[cfg(windows)]
            layout: None,
            #[cfg(windows)]
            hwnd: None,
            #[cfg(windows)]
            instance: None,
            #[cfg(windows)]
            verify_task: None,
            #[cfg(windows)]
            export_task: None,
            #[cfg(windows)]
            mono_font: 0,
            #[cfg(windows)]
            verify_seq: 0,
            #[cfg(windows)]
            export_seq: 0,
            #[cfg(windows)]
            tooltip: None,
            #[cfg(windows)]
            tooltip_status: Vec::new(),
            #[cfg(windows)]
            verify_source: None,
            clipboard_text: None,
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

/// The algorithm table's names, in table order.
///
/// The one place that turns [`rusthashtab_hash::ALGORITHMS`] into the name list
/// the settings layer indexes by. Loading settings and the settings dialog both
/// need it, and a second spelling of the list would let them disagree about
/// which registry value belongs to which algorithm -- the exact failure that
/// misplaced the default algorithms once already.
pub fn algorithm_names() -> Vec<&'static str> {
    rusthashtab_hash::ALGORITHMS
        .iter()
        .map(|algorithm| algorithm.name)
        .collect()
}

/// The persisted settings, with every algorithm flag loaded.
///
/// The table's names are passed in explicitly because the settings layer
/// deliberately does not depend on the hash crate. Loading with a shorter list
/// is the bug this function exists to prevent: it would map flags onto the wrong
/// algorithms.
pub fn load_settings() -> rusthashtab_settings::Settings {
    rusthashtab_settings::Settings::default().load_with(&algorithm_names())
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
pub use dialog::{
    WM_DISCOVERY_PROGRESS, WM_EXPORT_DONE, WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_JOBS_READY,
    WM_SCAN_FINISHED, WM_SORT_COLUMN, WM_VERIFY_READY,
};

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

    /// The loader must map the stored flags onto **table positions**, with the
    /// missing-value default decided per name.
    ///
    /// This is a regression guard with a specific history: the loader once read
    /// the four default names in `DEFAULT_ALGORITHMS` order and put their flags
    /// in the first four slots of an algorithm-indexed vector. On a fresh install
    /// that enabled CRC32/CRC64/XXH32/XXH3-64 and left MD5/SHA-1/SHA-256/SHA-512
    /// off -- the opposite of the documented default -- and every test that used
    /// a four-name table still passed.
    #[cfg(windows)]
    #[test]
    fn the_real_algorithm_table_loads_the_documented_defaults() {
        let names = algorithm_names();
        // A key that does not exist: the load must fall back per name and must
        // not create anything.
        let scratch = format!(
            r"Software\rustHashTab-test-ui-defaults-{}",
            std::process::id()
        );
        let loaded = rusthashtab_settings::Settings::default()
            .with_key(scratch)
            .load_with(&names);

        let enabled = enabled_algorithms(&loaded);
        let enabled_names: Vec<&str> = names
            .iter()
            .enumerate()
            .filter(|(index, _)| enabled[*index])
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(
            enabled_names,
            vec!["MD5", "SHA-1", "SHA-256", "SHA-512"],
            "the default flags are not on the default algorithms' table positions"
        );
    }

    /// A flag written for an algorithm that is not one of the four defaults must
    /// come back on that same algorithm after a round trip.
    #[cfg(windows)]
    #[test]
    fn every_algorithm_flag_round_trips_through_the_registry() {
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RegDeleteTreeW};
        use windows::core::PCWSTR;

        let names = algorithm_names();
        let scratch = format!(r"Software\rustHashTab-test-ui-flags-{}", std::process::id());
        let wide: Vec<u16> = scratch.encode_utf16().chain(core::iter::once(0)).collect();

        let mut settings = rusthashtab_settings::Settings::default().with_key(&scratch);
        settings.algorithms = vec![false; names.len()];
        for wanted in ["CRC32", "BLAKE3", "GOST 2012 (512)"] {
            let index = names
                .iter()
                .position(|name| *name == wanted)
                .expect("the algorithm is in the table");
            settings.algorithms[index] = true;
        }

        settings
            .save(&names)
            .expect("a scratch settings key must be writable");
        let loaded = rusthashtab_settings::Settings::default()
            .with_key(&scratch)
            .load_with(&names);

        // SAFETY: the key is a NUL-terminated scratch key under HKCU, and the
        // buffer outlives the call; deleting a key that exists is what this is
        // for. The result is checked below rather than ignored.
        let deleted = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(wide.as_ptr())) };
        assert_eq!(deleted, ERROR_SUCCESS, "left a scratch settings key behind");

        assert_eq!(
            loaded.algorithms, settings.algorithms,
            "algorithm flags did not round-trip through their own registry values"
        );
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

    /// A display-only change repaints instead of hashing everything again.
    #[test]
    fn display_only_settings_redraw() {
        let current = rusthashtab_settings::Settings::default();

        let uppercase = rusthashtab_settings::Settings {
            display_uppercase: false,
            ..current.clone()
        };
        assert_eq!(
            settings_change(&current, &uppercase, false),
            SettingsChange::Redraw
        );

        let monospace = rusthashtab_settings::Settings {
            display_monospace: false,
            ..current.clone()
        };
        assert_eq!(
            settings_change(&current, &monospace, false),
            SettingsChange::Redraw
        );

        let default_colours = rusthashtab_settings::RowColours::default();
        let coloured = rusthashtab_settings::Settings {
            colours: rusthashtab_settings::RowColours {
                mismatched: rusthashtab_settings::RowColour {
                    background: 0x0012_3456,
                    ..default_colours.mismatched
                },
                ..default_colours
            },
            ..current.clone()
        };
        assert_eq!(
            settings_change(&current, &coloured, false),
            SettingsChange::Redraw
        );
    }

    /// Changing what is hashed restarts the scan.
    #[test]
    fn scan_affecting_settings_rescan() {
        let current = rusthashtab_settings::Settings::default();

        let mut algorithms = current.algorithms.clone();
        algorithms.resize(rusthashtab_hash::ALGORITHMS.len(), false);
        algorithms[rusthashtab_hash::ALGORITHMS.len() - 1] = true;
        let changed_algorithms = rusthashtab_settings::Settings {
            algorithms,
            ..current.clone()
        };
        assert_eq!(
            settings_change(&current, &changed_algorithms, false),
            SettingsChange::Rescan
        );

        let sidecars = rusthashtab_settings::Settings {
            look_for_sumfiles: true,
            ..current.clone()
        };
        assert_eq!(
            settings_change(&current, &sidecars, false),
            SettingsChange::Rescan
        );
    }

    /// The manifest options only affect a manifest scan; outside one they are a
    /// preference for the next page and must not restart this one.
    #[test]
    fn manifest_options_rescan_only_in_manifest_mode() {
        let current = rusthashtab_settings::Settings::default();
        let updated = rusthashtab_settings::Settings {
            hash_sumfile_too: true,
            sumfile_algorithm_only: false,
            ..current.clone()
        };

        assert_eq!(
            settings_change(&current, &updated, false),
            SettingsChange::None
        );
        assert_eq!(
            settings_change(&current, &updated, true),
            SettingsChange::Rescan
        );
    }

    /// Options that only affect the next Check/Export run do not need any page
    /// work at all.
    #[test]
    fn verification_and_export_options_do_nothing() {
        let current = rusthashtab_settings::Settings::default();
        let updated = rusthashtab_settings::Settings {
            verify_strict: true,
            verify_auto_format: true,
            verify_from_clipboard: true,
            sumfile_uppercase: false,
            sumfile_unix_endings: false,
            sumfile_double_space: true,
            sumfile_forward_slashes: false,
            sumfile_dot_hash_compatible: false,
            sumfile_banner: false,
            sumfile_banner_date: true,
            ..current.clone()
        };

        assert_eq!(
            settings_change(&current, &updated, false),
            SettingsChange::None
        );
        assert_eq!(
            settings_change(&current, &updated, true),
            SettingsChange::None
        );
    }

    /// An unchanged settings object must not trigger work.
    #[test]
    fn unchanged_settings_do_nothing() {
        let current = rusthashtab_settings::Settings::default();
        assert_eq!(
            settings_change(&current, &current, false),
            SettingsChange::None
        );
        assert_eq!(
            settings_change(&current, &current, true),
            SettingsChange::None
        );
    }
}
