//! The results list: columns, rows, and the colours that say whether a digest
//! matched.
//!
//! # Report mode, not virtual
//!
//! A virtual list (`LVS_OWNERDATA`) is the right answer at a hundred thousand rows.
//! It is the wrong answer here: the page holds at most
//! [`crate::MAX_HASHED_FILES`] × 31 rows, and virtual mode would mean handling
//! `LVN_GETDISPINFO`, keeping a parallel backing store, and reimplementing
//! selection and hit-testing by hand -- in exchange for memory the list view was
//! already going to hold.
//!
//! What matters for responsiveness is the other thing: **nothing is formatted while
//! painting**. Every digest is a `String` built once, when the file finished, by
//! [`crate::readout::rows_for`]. The paint path only copies characters out of a
//! buffer that already exists, which is why this module contains no formatting at
//! all.
//!
//! # The row to file mapping
//!
//! Every item's `lParam` is the index of its [`crate::ListRow`] in the page's flat
//! row list. Carrying the index rather than the row itself is what lets a copy
//! iterate the selection without rebuilding anything, and it survives rows being
//! appended while the selection stands.

#![cfg(windows)]

use crate::{ListRow, resource};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
    COLOR_WINDOW, COLOR_WINDOWTEXT, CreateFontIndirectW, DEFAULT_GUI_FONT, DeleteObject, FF_MODERN,
    FIXED_PITCH, GetDC, GetObjectW, GetStockObject, GetSysColor, GetTextExtentPoint32W, HGDIOBJ,
    InvalidateRect, LOGFONTW, ReleaseDC, SelectObject,
};
use windows::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows::Win32::UI::Controls::{
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDDS_SUBITEM, CDIS_SELECTED, CDRF_DODEFAULT, CDRF_NEWFONT,
    CDRF_NOTIFYITEMDRAW, CDRF_NOTIFYSUBITEMDRAW, HDF_SORTDOWN, HDF_SORTUP, HDI_FORMAT, HDITEMW,
    HDM_SETITEMW, HEADER_CONTROL_FORMAT_FLAGS, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH,
    LVCOLUMNW, LVIS_FOCUSED, LVIS_SELECTED, LVITEMW, LVM_GETHEADER, LVM_GETNEXTITEM,
    LVM_INSERTCOLUMNW, LVM_SETCOLUMNW, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMCOUNT,
    LVM_SETITEMSTATE, LVNI_SELECTED, LVS_EX_FULLROWSELECT, NMLVCUSTOMDRAW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    SPI_GETHIGHCONTRAST, SendMessageW, SystemParametersInfoW, WM_GETFONT, WM_SETFONT, WM_SETREDRAW,
};

/// The colour a row is drawn in when a digest matched an expected value: a dark
/// green, `#008B00`, written `0x00BBGGRR` because that is `COLORREF`'s order.
#[cfg(test)]
const MATCHED_COLOR: ColorDef = ColorDef(0x0000_8B00);
/// The colour a row is drawn in when a digest had an expected value and missed it:
/// a dark red, `#C00000`, in `COLORREF` order.
#[cfg(test)]
const MISMATCHED_COLOR: ColorDef = ColorDef(0x0000_00C0);
/// The colour a row is drawn in when an expected value matched only under an
/// algorithm that is not cryptographically secure: dark goldenrod, `#B8860B`, in
/// `COLORREF` order.
///
/// Deliberately neither green nor red. A CRC32 collision is evidence, not proof,
/// and painting it like a SHA-256 match would let a weak check pass for a strong
/// one -- which is the whole reason the comparison layer reports `secure`.
#[cfg(test)]
const WEAK_MATCH_COLOR: ColorDef = ColorDef(0x000B_86B8);

/// A `COLORREF`, spelled `0x00BBGGRR`.
///
/// Wrapped because that byte order is the opposite of how anyone writes a colour,
/// and a bare literal here would be read as `0xRRGGBB` by everyone including the
/// author. It was: the first version of both constants above was in `RGB` order,
/// and [`tests::the_colours_are_spelled_in_colorref_order`] is what caught it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColorDef(u32);

#[cfg(test)]
impl ColorDef {
    /// The `COLORREF` the GDI APIs want.
    fn colorref(self) -> COLORREF {
        COLORREF(self.0)
    }
}

/// Add the page's columns to a list view that already exists.
///
/// Column widths come from the font's own metrics rather than from pixels, so the
/// layout follows the dialog's DPI without any arithmetic from us: the shell scales
/// the dialog because the template is in dialog units, and the font it hands us is
/// the scaled one.
pub fn add_columns(list: HWND) {
    // Four columns: algorithm, digest, match, file. The order is the order the
    // template and the copy format both use.
    let widths = column_widths(list);

    for (index, (heading, width)) in resource::COLUMNS.iter().zip(widths).enumerate() {
        let mut text: Vec<u16> = heading.encode_utf16().collect();
        text.push(0);

        let mut column = LVCOLUMNW {
            mask: LVCF_TEXT | LVCF_WIDTH,
            cx: width,
            pszText: windows::core::PWSTR(text.as_mut_ptr()),
            ..Default::default()
        };

        // SAFETY: `list` is the page's list view, `column` lives for the call, and
        // the string it points at outlives it. `LVM_INSERTCOLUMNW` copies the string
        // into the control, so the buffer need not survive beyond this statement.
        unsafe {
            SendMessageW(
                list,
                LVM_INSERTCOLUMNW,
                Some(WPARAM(index)),
                Some(LPARAM((&mut column as *mut LVCOLUMNW) as isize)),
            );
        }
    }

    // Full-row selection: without it, clicking the digest column selects only that
    // cell, and a copy of "the selected row" would be a copy of one substring.
    // SAFETY: setting an extended style takes the bitmask in `wParam` and the new
    // value in `lParam`; both are plain integers.
    unsafe {
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            Some(WPARAM(LVS_EX_FULLROWSELECT as usize)),
            Some(LPARAM(LVS_EX_FULLROWSELECT as isize)),
        );
    }
}

/// Per-column widths, measured from the control's own font.
///
/// The digest column is sized for the longest digest any supported algorithm
/// produces, not for whichever one happens to be enabled: resizing columns as
/// results arrive would make the list jump around while the user is reading it, and
/// [`rusthashtab_sumfile::MAX_DIGEST_LEN`] is the only width that is right for all
/// of them.
fn column_widths(list: HWND) -> [i32; 4] {
    let text_width = |sample: &str| -> i32 {
        let mut wide: Vec<u16> = sample.encode_utf16().collect();
        let length = wide.len() as i32;
        wide.push(0);

        // SAFETY: `list` is a live list view. The DC is released on every path
        // below, and the font selected into it is restored before that.
        unsafe {
            let dc = GetDC(Some(list));
            if dc.is_invalid() {
                // No DC means no measurements. A fixed fallback is better than a
                // column of zero width, which is what a failed measurement would
                // otherwise produce.
                return length * 7;
            }

            // The control's own font, not the stock GUI font: the property sheet
            // adopts a DPI-scaled status font, and measuring against the stock font
            // would size every column for the wrong typeface at every scale.
            let current =
                SendMessageW(list, WM_GETFONT, Some(WPARAM(0)), Some(LPARAM(0))).0 as isize;
            let font = if current != 0 {
                HGDIOBJ(current as *mut core::ffi::c_void)
            } else {
                GetStockObject(DEFAULT_GUI_FONT)
            };
            let previous: HGDIOBJ = SelectObject(dc, font);
            let mut size = windows::Win32::Foundation::SIZE::default();
            let measured = GetTextExtentPoint32W(dc, &wide[..wide.len() - 1], &mut size);
            if !previous.is_invalid() {
                SelectObject(dc, previous);
            }
            ReleaseDC(Some(list), dc);

            if measured.as_bool() {
                size.cx
            } else {
                length * 7
            }
        }
    };

    let digest_length = rusthashtab_sumfile::MAX_DIGEST_LEN * 2;
    let digest_sample: String = "0".repeat(digest_length);

    [
        text_width("BLAKE3-512") + 24,
        text_width(&digest_sample) + 16,
        text_width("mismatched") + 16,
        text_width(&"x".repeat(48)) + 16,
    ]
}

/// Create a monospace face with the same metrics as `base`.
///
/// `Consolas` is the modern Windows console face; if it is missing, GDI's font
/// mapper substitutes another fixed-pitch face. The exact face matters less than
/// the metrics: the caller uses it only for digest cells, where every character
/// has to line up.
///
/// Returns `0` when the base font is unusable. The caller treats `0` as "no
/// monospace font", which is the graceful path if `GetObjectW` fails.
pub(crate) fn create_monospace_font(base: isize) -> isize {
    if base == 0 {
        return 0;
    }

    // SAFETY: `base` is a font handle owned by the dialog.
    let mut logfont = LOGFONTW::default();
    // SAFETY: `GetObjectW` writes at most `size_of::<LOGFONTW>()` bytes into
    // `logfont`, which is a live local.
    let copied = unsafe {
        GetObjectW(
            HGDIOBJ(base as *mut core::ffi::c_void),
            core::mem::size_of::<LOGFONTW>() as i32,
            Some((&mut logfont as *mut LOGFONTW).cast()),
        )
    };
    if copied == 0 {
        return 0;
    }

    logfont.lfFaceName = [0; 32];
    for (slot, unit) in logfont.lfFaceName.iter_mut().zip("Consolas".encode_utf16()) {
        *slot = unit;
    }
    logfont.lfPitchAndFamily = FIXED_PITCH.0 | FF_MODERN.0;

    // SAFETY: `logfont` is a fully initialised `LOGFONTW` for the duration of the
    // call. The returned handle is owned by the caller and released with
    // [`destroy_font`].
    unsafe { CreateFontIndirectW(&logfont) }.0 as isize
}

/// Release a font created by [`create_monospace_font`].
pub(crate) fn destroy_font(font: isize) {
    if font == 0 {
        return;
    }
    // SAFETY: the handle came from `create_monospace_font`, is owned by the page,
    // and is released exactly once here.
    unsafe {
        let _ = DeleteObject(HGDIOBJ(font as *mut core::ffi::c_void));
    }
}

/// Give a control the font the property sheet chose for the page.
///
/// The property sheet sends `WM_SETFONT` to the page and then to its children, so a
/// control that ignored it would draw in the system font at the wrong size -- the
/// most visible way a page fails to follow the host's DPI.
pub fn adopt_font(control: HWND, font: isize) {
    if font == 0 {
        return;
    }
    // SAFETY: `WM_SETFONT` takes the font handle in `wParam` and a redraw flag in
    // `lParam`; the font is owned by the dialog and outlives the control.
    unsafe {
        SendMessageW(
            control,
            WM_SETFONT,
            Some(WPARAM(font as usize)),
            Some(LPARAM(1)),
        );
    }
}

/// Re-measure the columns against the control's current font.
///
/// Called when the sheet finally sends its font, because the columns were sized
/// against whatever was current when the page was built. Column widths are the one
/// piece of layout this page owns; the rest is the dialog template's, which the
/// sheet scales.
pub fn remeasure_columns(list: HWND) {
    let widths = column_widths(list);
    for (index, width) in widths.into_iter().enumerate() {
        let mut column = LVCOLUMNW {
            mask: LVCF_WIDTH,
            cx: width,
            ..Default::default()
        };
        // SAFETY: `LVM_SETCOLUMNW` with `LVCF_WIDTH` reads only `cx`; `list` is the
        // page's list view and `index` is one of the four columns it has.
        unsafe {
            SendMessageW(
                list,
                LVM_SETCOLUMNW,
                Some(WPARAM(index)),
                Some(LPARAM((&mut column as *mut LVCOLUMNW) as isize)),
            );
        }
    }
}

/// Keep the control from repainting while a batch of items is changed.
///
/// Every row insertion is a window message, and a report-mode list view repaints
/// after each one. At 31,000 rows that is the difference between a visible
/// flicker and no flicker at all. The guard restores redrawing on every exit path,
/// including a panic, because a control left with `WM_SETREDRAW` off looks frozen
/// forever.
pub struct RedrawGuard {
    list: HWND,
}

impl RedrawGuard {
    /// Stop redrawing until the returned guard is dropped.
    pub fn new(list: HWND) -> Self {
        // SAFETY: `list` is the page's list view. `WM_SETREDRAW` takes a BOOL in
        // `wParam` and no pointer.
        unsafe {
            SendMessageW(list, WM_SETREDRAW, Some(WPARAM(0)), Some(LPARAM(0)));
        }
        Self { list }
    }
}

impl Drop for RedrawGuard {
    fn drop(&mut self) {
        // SAFETY: `self.list` was live when the guard was made and the page owns
        // it for at least as long as the guard. The second call re-enables
        // painting; the invalidate is what actually makes the control redraw.
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, Some(WPARAM(1)), Some(LPARAM(0)));
            let _ = InvalidateRect(Some(self.list), None, true);
        }
    }
}

/// Show or hide the File column for a selection of `jobs` files.
///
/// A single file's display path is already the page's subject, and the column
/// costs the Digest column exactly the width it needs. The width is re-measured
/// from the control's font rather than remembered, so this follows a DPI change.
pub fn set_file_column_for_jobs(list: Option<HWND>, jobs: usize) {
    let Some(list) = list else {
        return;
    };
    let widths = column_widths(list);
    let width = if jobs == 1 { 0 } else { widths[3] };
    let mut column = LVCOLUMNW {
        mask: LVCF_WIDTH,
        cx: width,
        ..Default::default()
    };
    // SAFETY: column 3 is the File column the template declares; `list` is the
    // page's list view and `column` lives for the call. `LVM_SETCOLUMNW` with
    // `LVCF_WIDTH` reads only `cx`.
    unsafe {
        SendMessageW(
            list,
            LVM_SETCOLUMNW,
            Some(WPARAM(3)),
            Some(LPARAM((&mut column as *mut LVCOLUMNW) as isize)),
        );
    }
}

/// Replace every row in the list.
///
/// The control is a virtual (`LVS_OWNERDATA`) report view: setting the item count
/// is the whole fill, and the control asks the page for each visible cell through
/// `LVN_GETDISPINFOW`. That is what keeps 31,000 rows from costing 124,000
/// `LVM_INSERTITEMW`/`LVM_SETITEMTEXTW` messages.
pub fn set_rows(list: HWND, rows: &[ListRow]) {
    // SAFETY: `list` is the page's list view; `LVM_SETITEMCOUNT` takes a count and
    // a flags word, neither a pointer.
    unsafe {
        SendMessageW(
            list,
            LVM_SETITEMCOUNT,
            Some(WPARAM(rows.len())),
            Some(LPARAM(0)),
        );
        let _ = InvalidateRect(Some(list), None, true);
    }
}

/// Repaint after the page's row contents changed.
///
/// In virtual mode the control has no per-item text to update; it asks again for
/// the cells it draws, and the page's row list is already the new value.
pub fn update_rows(list: HWND) {
    // SAFETY: `list` is the page's list view; invalidating it takes no pointer.
    unsafe {
        let _ = InvalidateRect(Some(list), None, true);
    }
}

/// The four cells of one row, already formatted.
///
/// Public because the dialog's `LVN_GETDISPINFOW` handler is the virtual list's
/// data source.
pub fn row_cells(row: &ListRow) -> [String; 4] {
    let digest = if let Some(code) = row.error {
        resource::read_error_text(code)
    } else {
        row.digest_hex.clone()
    };
    let algorithm = if row.algorithm == usize::MAX {
        // An em dash: an error belongs to the file, not to any one algorithm.
        String::from("\u{2014}")
    } else {
        rusthashtab_hash::ALGORITHMS
            .get(row.algorithm)
            .map(|algorithm| algorithm.name.to_string())
            .unwrap_or_default()
    };
    let matched = match row.match_state {
        rusthashtab_scan::MatchState::Matched { .. } => "matched",
        rusthashtab_scan::MatchState::Mismatched => "mismatch",
        rusthashtab_scan::MatchState::NotChecked => "not checked",
    };
    [
        algorithm,
        digest,
        matched.to_string(),
        file_column_text(row),
    ]
}

/// What the File column shows for one row.
///
/// The job's display path, which is relative to the scan root when the scan could
/// make it so -- the same name the user saw in the selection, and the same name an
/// exported checksum file records.
///
/// Falls back to `#index` when the path is empty. That only happens before the job
/// list has been published, but an empty cell would read as "this row belongs to no
/// file" rather than as "this row belongs to job zero", and the index is at least
/// true.
fn file_column_text(row: &ListRow) -> String {
    if row.display_path.is_empty() {
        format!("#{}", row.job_index)
    } else {
        row.display_path.clone()
    }
}

/// A sortable column, in template order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// The File column.
    File = 3,
    /// The Algorithm column.
    Algorithm = 0,
    /// The Digest column.
    Digest = 1,
    /// The Match column.
    Match = 2,
}

impl Column {
    /// The column a header index names, if it is one of ours.
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Algorithm),
            1 => Some(Self::Digest),
            2 => Some(Self::Match),
            3 => Some(Self::File),
            _ => None,
        }
    }
}

/// The current sort: which column, and in which direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortState {
    /// Column being sorted.
    pub column: Column,
    /// Ascending when true, descending when false.
    pub ascending: bool,
}

/// The rank a row's match state contributes to Digest/Match ordering.
///
/// Deliberately not alphabetical: an unreadable file is the most important thing
/// in the table, and "not checked" is the least, so the order is by attention
/// required. The same rank is used for both columns so the two cannot disagree.
fn match_rank(row: &ListRow) -> u8 {
    if row.error.is_some() {
        return 0;
    }
    match row.match_state {
        rusthashtab_scan::MatchState::Matched { secure: true, .. } => 1,
        rusthashtab_scan::MatchState::Matched { secure: false, .. } => 2,
        rusthashtab_scan::MatchState::Mismatched => 3,
        rusthashtab_scan::MatchState::NotChecked => 4,
    }
}

/// A row's algorithm name, or an empty string for an error row.
fn algorithm_name(row: &ListRow) -> &'static str {
    rusthashtab_hash::ALGORITHMS
        .get(row.algorithm)
        .map(|algorithm| algorithm.name)
        .unwrap_or("")
}

/// Sort rows in place.
///
/// Stable by design: equal keys keep their job order, and the tie-break is the
/// row's stable ID rather than its position, so repeated sorts cannot shuffle
/// equal rows. `sort_by` is stable, but the explicit tie-break also covers a
/// descending sort, where reversing the whole comparison would otherwise reverse
/// the tie-break too.
pub fn sort_rows(rows: &mut [ListRow], state: SortState) {
    rows.sort_by(|left, right| {
        let ordering = match state.column {
            Column::File => left
                .display_path
                .to_lowercase()
                .cmp(&right.display_path.to_lowercase()),
            Column::Algorithm => algorithm_name(left)
                .to_lowercase()
                .cmp(&algorithm_name(right).to_lowercase()),
            Column::Digest => match_rank(left).cmp(&match_rank(right)).then_with(|| {
                left.digest_hex
                    .to_lowercase()
                    .cmp(&right.digest_hex.to_lowercase())
            }),
            Column::Match => match_rank(left).cmp(&match_rank(right)),
        };

        let ordering = if state.ascending {
            ordering
        } else {
            ordering.reverse()
        };

        // The tie-break is always ascending. A descending sort must not reverse
        // the order of rows that compare equal; job order is the stable answer.
        ordering.then_with(|| left.id.cmp(&right.id))
    });
}

/// Show the sort arrow on the active column, and clear it everywhere else.
pub fn set_sort_indicator(list: HWND, state: Option<SortState>) {
    // SAFETY: `list` is the page's list view; `LVM_GETHEADER` returns its header
    // control or null, and the header is a child of the list.
    let header = unsafe { SendMessageW(list, LVM_GETHEADER, Some(WPARAM(0)), Some(LPARAM(0))) };
    if header.0 == 0 {
        return;
    }
    let header = HWND(header.0 as *mut core::ffi::c_void);

    for index in 0..resource::COLUMNS.len() {
        let active = state.filter(|sort| sort.column as usize == index);
        let flags = match active {
            Some(sort) if sort.ascending => HDF_SORTUP.0,
            Some(_) => HDF_SORTDOWN.0,
            None => 0,
        };
        let mut item = HDITEMW {
            mask: HDI_FORMAT,
            fmt: HEADER_CONTROL_FORMAT_FLAGS(flags),
            ..Default::default()
        };
        // SAFETY: `header` is the list view's header, `index` is one of its
        // columns, and `item` lives for the call.
        unsafe {
            SendMessageW(
                header,
                HDM_SETITEMW,
                Some(WPARAM(index)),
                Some(LPARAM((&mut item as *mut HDITEMW) as isize)),
            );
        }
    }
}

/// The rows currently selected, by stable row ID.
///
/// IDs rather than positions: a row's position changes when an earlier file
/// finishes, and a copy that used positions would silently take the wrong row.
pub fn selected_ids(list: HWND, rows: &[ListRow]) -> Vec<u64> {
    let mut selected = Vec::new();
    // -1 asks for the first item matching the flags; each answer asks for the next
    // one after it. The loop therefore terminates even if the selection changes
    // underneath it, because the search always moves forward.
    let mut after: isize = -1;

    loop {
        // SAFETY: both parameters are plain integers; the control returns -1 when
        // there is no further match.
        let found = unsafe {
            SendMessageW(
                list,
                LVM_GETNEXTITEM,
                Some(WPARAM(after as usize)),
                Some(LPARAM(LVNI_SELECTED as isize)),
            )
        };
        if found.0 < 0 {
            break;
        }
        after = found.0;

        // In owner-data mode the item index is the row index: the page's row list
        // is the data source, and `LVN_GETDISPINFOW` is asked for that same index.
        if let Some(row) = rows.get(found.0 as usize) {
            selected.push(row.id);
        }
    }

    selected
}

/// The stable ID of one list item, if it exists.
pub fn item_id(_list: HWND, item: usize, rows: &[ListRow]) -> Option<u64> {
    rows.get(item).map(|row| row.id)
}

/// Select the items whose IDs are in `ids`, and clear every other selection.
pub fn select_ids(list: HWND, ids: &[u64], rows: &[ListRow]) {
    if ids.is_empty() {
        return;
    }

    // SAFETY: `list` is the page's list view. Every message below takes integers
    // or a pointer to a live local `LVITEMW`.
    unsafe {
        for (index, row) in rows.iter().enumerate() {
            let selected = ids.contains(&row.id);
            let mut state = LVITEMW {
                state: if selected {
                    LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0)
                } else {
                    LIST_VIEW_ITEM_STATE_FLAGS(0)
                },
                stateMask: LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0),
                ..Default::default()
            };
            SendMessageW(
                list,
                LVM_SETITEMSTATE,
                Some(WPARAM(index)),
                Some(LPARAM((&mut state as *mut LVITEMW) as isize)),
            );
        }
    }
}

/// How a row should be drawn, given what its digest compared to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowColour {
    /// An expected digest matched under a cryptographically secure algorithm.
    Matched,
    /// An expected digest matched, but only under a weak algorithm: a warning, not
    /// a confirmation.
    MatchedWeak,
    /// An expected digest did not match.
    Mismatched,
    /// The file could not be read.
    Error,
    /// Nothing to compare against, or no result.
    Neutral,
}

/// The colour a match state maps to.
pub fn colour_for(state: rusthashtab_scan::MatchState, failed: bool) -> RowColour {
    if failed {
        // A file that could not be read is not a mismatch: telling the user their
        // file is corrupt when it was merely unreadable is the one thing the
        // comparison layer deliberately avoids, and the display must not undo it.
        // It is its own class so the user can colour it differently from "not
        // checked".
        return RowColour::Error;
    }
    match state {
        rusthashtab_scan::MatchState::Matched { secure: true, .. } => RowColour::Matched,
        rusthashtab_scan::MatchState::Matched { secure: false, .. } => RowColour::MatchedWeak,
        rusthashtab_scan::MatchState::Mismatched => RowColour::Mismatched,
        rusthashtab_scan::MatchState::NotChecked => RowColour::Neutral,
    }
}

/// Resolved colours for the five row classes.
///
/// Resolved once, not on the paint path: `GetSysColor` and the settings lookup are
/// both cheap but neither belongs in a `CDDS_SUBITEM` handler that can run
/// thousands of times for one scroll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    matched: (COLORREF, COLORREF),
    weak: (COLORREF, COLORREF),
    mismatched: (COLORREF, COLORREF),
    error: (COLORREF, COLORREF),
    neutral: (COLORREF, COLORREF),
}

impl Default for Palette {
    fn default() -> Self {
        Self::from_settings(&rusthashtab_settings::Settings::default(), false)
    }
}

impl Palette {
    /// Resolve the settings into colours the paint path can use.
    ///
    /// High contrast ignores the configured colours: a user who asked the system
    /// for high contrast has already said that arbitrary foreground/background
    /// pairs are less readable than the system's own. The Match column's text
    /// still carries the meaning, so nothing is lost.
    pub fn from_settings(settings: &rusthashtab_settings::Settings, high_contrast: bool) -> Self {
        let system_text = system_colour(COLOR_WINDOWTEXT);
        let system_background = system_colour(COLOR_WINDOW);
        let resolve = |colour: rusthashtab_settings::RowColour| {
            if high_contrast
                || colour.text == rusthashtab_settings::SYSTEM_COLOUR
                || colour.background == rusthashtab_settings::SYSTEM_COLOUR
            {
                let text = if high_contrast || colour.text == rusthashtab_settings::SYSTEM_COLOUR {
                    system_text
                } else {
                    COLORREF(colour.text)
                };
                let background =
                    if high_contrast || colour.background == rusthashtab_settings::SYSTEM_COLOUR {
                        system_background
                    } else {
                        COLORREF(colour.background)
                    };
                (text, background)
            } else {
                (COLORREF(colour.text), COLORREF(colour.background))
            }
        };

        let colours = settings.colours;
        Self {
            matched: resolve(colours.matched),
            weak: resolve(colours.weak),
            mismatched: resolve(colours.mismatched),
            error: resolve(colours.error),
            neutral: resolve(colours.neutral),
        }
    }

    /// The text and background for one class.
    pub fn for_class(&self, class: RowColour) -> (COLORREF, COLORREF) {
        match class {
            RowColour::Matched => self.matched,
            RowColour::MatchedWeak => self.weak,
            RowColour::Mismatched => self.mismatched,
            RowColour::Error => self.error,
            RowColour::Neutral => self.neutral,
        }
    }
}

/// One system colour as a `COLORREF`.
fn system_colour(index: windows::Win32::Graphics::Gdi::SYS_COLOR_INDEX) -> COLORREF {
    // SAFETY: `GetSysColor` reads a system colour table entry; every defined
    // index is valid and the call has no pointer arguments.
    COLORREF(unsafe { GetSysColor(index) })
}

/// Whether the system is in a high-contrast theme.
///
/// A configured foreground/background pair can be unreadable under such a theme;
/// the page then uses the system's own colours and lets the Match column's text
/// carry the verdict.
pub fn high_contrast() -> bool {
    let mut contrast = HIGHCONTRASTW {
        cbSize: core::mem::size_of::<HIGHCONTRASTW>() as u32,
        ..Default::default()
    };
    // SAFETY: `contrast` declares its own size and lives for the call;
    // `SystemParametersInfoW` writes at most `cbSize` bytes into it.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            contrast.cbSize,
            Some((&mut contrast as *mut HIGHCONTRASTW).cast()),
            windows::Win32::UI::WindowsAndMessaging::SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    ok.is_ok() && (contrast.dwFlags.0 & HCF_HIGHCONTRASTON.0) != 0
}

/// Handle a custom-draw notification from the results list.
///
/// Returns the value the dialog procedure must return, or `None` when the
/// notification did not come from this list view (the caller then answers zero,
/// which leaves the control's default handling alone).
///
/// # Why `CDDS_PREPAINT` must answer `CDRF_NOTIFYITEMDRAW`
///
/// A common control only sends `CDDS_ITEMPREPAINT` to a parent that asked for item
/// notifications at the prepaint stage. Answering `CDRF_DODEFAULT` there draws the
/// list correctly but means the item stage never arrives, so `clrText` is never
/// set and every row stays black -- a failure that no unit test of [`colour_for`]
/// can see, because it happens before the code under test is called at all.
///
/// # Safety
///
/// `lparam` must be the `NMHDR` of an `NM_CUSTOMDRAW` notification, which is what
/// the dialog procedure is handed for that message.
pub unsafe fn custom_draw(
    lparam: LPARAM,
    rows: &[ListRow],
    monospace_font: isize,
) -> Option<isize> {
    // SAFETY: the caller promises this is an `NM_CUSTOMDRAW` notification and the
    // default palette owns no resources.
    unsafe { custom_draw_with_palette(lparam, rows, monospace_font, &Palette::default()) }
}

/// Custom draw with an explicit palette.
///
/// # Safety
///
/// `lparam` must be the `NMHDR` of an `NM_CUSTOMDRAW` notification, which is what
/// the dialog procedure is handed for that message.
pub unsafe fn custom_draw_with_palette(
    lparam: LPARAM,
    rows: &[ListRow],
    monospace_font: isize,
    palette: &Palette,
) -> Option<isize> {
    // SAFETY: the caller promises this is an `NM_CUSTOMDRAW` notification.
    let custom = unsafe { &mut *(lparam.0 as *mut NMLVCUSTOMDRAW) };

    // The notification carries the control id. Anything else in the page that
    // custom-draws must be left to the default handler.
    if custom.nmcd.hdr.idFrom != resource::IDC_HASH_LIST as usize {
        return None;
    }

    let stage = custom.nmcd.dwDrawStage.0;
    if stage == CDDS_PREPAINT.0 {
        return Some(CDRF_NOTIFYITEMDRAW as isize);
    }

    if stage == CDDS_ITEMPREPAINT.0 {
        // The colour and the optional monospace face are both applied per subitem:
        // selecting a font for the whole item would also change the algorithm and
        // file columns, and the sheet's font is the right one there.
        return Some(CDRF_NOTIFYSUBITEMDRAW as isize);
    }

    if stage == (CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0) {
        // In owner-data mode the item spec is the row index: the control has no
        // per-item storage, so there is no `lParam` to read.
        let row_index = custom.nmcd.dwItemSpec;
        let mut flags = CDRF_DODEFAULT;

        if let Some(row) = rows.get(row_index) {
            let (text, background) =
                palette.for_class(colour_for(row.match_state, row.error.is_some()));
            custom.clrText = text;
            // A selected row must keep the system highlight; painting a custom
            // background over it would make the selection disappear.
            if (custom.nmcd.uItemState.0 & CDIS_SELECTED.0) == 0 {
                custom.clrTextBk = background;
            }
            flags = CDRF_NEWFONT;
        }

        // Column 1 is Digest; the other columns keep the sheet's UI font.
        if custom.iSubItem == 1 && monospace_font != 0 {
            // SAFETY: `hdc` is the DC the control is painting into, and
            // `monospace_font` is a live font owned by the page.
            unsafe {
                SelectObject(
                    custom.nmcd.hdc,
                    HGDIOBJ(monospace_font as *mut core::ffi::c_void),
                );
            }
            flags = CDRF_NEWFONT;
        }

        return Some(flags as isize);
    }

    // Every other stage still has to be painted. Returning zero here would let the
    // control stop after the notification.
    Some(CDRF_DODEFAULT as isize)
}

/// NUL-terminate a string for a Win32 parameter.
#[cfg(test)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_scan::MatchState;
    use std::cell::Cell;

    // One counter per test thread, so rows created in one test get IDs 0, 1, ...
    // and `custom_draw_at` can address them by position without hand-writing an
    // ID for every call.
    thread_local! {
        static NEXT_ID: Cell<u64> = const { Cell::new(0) };
    }

    /// The colours must be in `COLORREF` order, which is `0x00BBGGRR` -- the
    /// opposite of how a colour is written everywhere else.
    ///
    /// This test is not decoration. The first version of both constants above was
    /// written in `RGB` order, which compiles, draws a plausible colour, and is
    /// simply the wrong one: green became blue. The assertion is on the decoded
    /// channels rather than on the byte pattern, so the intent is visible.
    #[test]
    fn the_colours_are_spelled_in_colorref_order() {
        // A `COLORREF` is decoded as red in the *low* byte.
        let red = |colour: ColorDef| (colour.0 & 0xFF) as u8;
        let green = |colour: ColorDef| ((colour.0 >> 8) & 0xFF) as u8;
        let blue = |colour: ColorDef| ((colour.0 >> 16) & 0xFF) as u8;
        let reserved = |colour: ColorDef| (colour.0 >> 24) as u8;

        assert_eq!(
            reserved(MATCHED_COLOR),
            0,
            "the reserved byte must be clear"
        );
        assert_eq!(
            reserved(MISMATCHED_COLOR),
            0,
            "the reserved byte must be clear"
        );

        // Dark green: green, and only green.
        assert!(
            green(MATCHED_COLOR) > 0x40,
            "the matched colour is not green"
        );
        assert_eq!(red(MATCHED_COLOR), 0);
        assert_eq!(blue(MATCHED_COLOR), 0);

        // Dark red: red, and only red.
        assert!(
            red(MISMATCHED_COLOR) > 0x40,
            "the mismatched colour is not red"
        );
        assert_eq!(green(MISMATCHED_COLOR), 0);
        assert_eq!(blue(MISMATCHED_COLOR), 0);

        assert_ne!(MATCHED_COLOR, MISMATCHED_COLOR);
    }

    /// The weak-match colour is decoded the same way, and has to be a colour that
    /// reads as neither "good" nor "bad": red and green both high, blue low.
    #[test]
    fn the_weak_match_colour_is_a_distinct_goldenrod() {
        let red = (WEAK_MATCH_COLOR.0 & 0xFF) as u8;
        let green = ((WEAK_MATCH_COLOR.0 >> 8) & 0xFF) as u8;
        let blue = ((WEAK_MATCH_COLOR.0 >> 16) & 0xFF) as u8;
        let reserved = (WEAK_MATCH_COLOR.0 >> 24) as u8;

        assert_eq!(reserved, 0, "the reserved byte must be clear");
        assert!(red > 0x40, "dark goldenrod has a strong red channel");
        assert!(green > 0x40, "dark goldenrod has a strong green channel");
        assert!(blue < 0x40, "dark goldenrod has almost no blue");
        assert_ne!(WEAK_MATCH_COLOR, MATCHED_COLOR);
        assert_ne!(WEAK_MATCH_COLOR, MISMATCHED_COLOR);
    }

    /// A weak match and a secure match must be visibly different: conflating them
    /// would let a CRC32 collision read as a SHA-256 verification.
    #[test]
    fn a_weak_match_is_not_coloured_like_a_secure_one() {
        let crc32 = rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == "CRC32")
            .expect("CRC32 is in the table");
        let sha256 = rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == "SHA-256")
            .expect("SHA-256 is in the table");

        assert_eq!(
            colour_for(
                MatchState::Matched {
                    algorithm: crc32,
                    secure: false
                },
                false
            ),
            RowColour::MatchedWeak
        );
        assert_eq!(
            colour_for(
                MatchState::Matched {
                    algorithm: sha256,
                    secure: true
                },
                false
            ),
            RowColour::Matched
        );
    }

    /// The File column shows the job's display path, and falls back to the job index
    /// only when there is no path to show.
    #[test]
    fn the_file_column_shows_the_display_path_with_an_index_fallback() {
        let mut row = ListRow {
            id: crate::row_id(7, usize::MAX),
            job_index: 7,
            algorithm: usize::MAX,
            digest_hex: String::new(),
            match_state: MatchState::NotChecked,
            error: Some(5),
            display_path: String::new(),
        };
        assert_eq!(file_column_text(&row), "#7");

        row.display_path = "nested\\file.bin".to_string();
        assert_eq!(file_column_text(&row), "nested\\file.bin");
    }

    /// A file that could not be read must not be shown as a mismatch. It has its
    /// own class now, so the user can colour it separately from "not checked",
    /// but it is still not red.
    #[test]
    fn an_unreadable_file_is_coloured_as_an_error_not_a_mismatch() {
        assert_eq!(colour_for(MatchState::Mismatched, true), RowColour::Error);
        assert_eq!(
            colour_for(MatchState::Mismatched, false),
            RowColour::Mismatched
        );
    }

    #[test]
    fn a_secure_match_is_coloured_as_a_match() {
        assert_eq!(
            colour_for(
                MatchState::Matched {
                    algorithm: 0,
                    secure: true
                },
                false
            ),
            RowColour::Matched
        );
    }

    /// With nothing to compare against there is nothing to colour: a page that
    /// looked green for every unchecked file would make the colours meaningless.
    #[test]
    fn nothing_to_check_is_neutral() {
        assert_eq!(
            colour_for(MatchState::NotChecked, false),
            RowColour::Neutral
        );
    }

    /// The custom-draw answer must be the one that lets the control keep painting.
    ///
    /// This is a regression test with a specific failure behind it: answering
    /// `CDRF_DODEFAULT` at `CDDS_PREPAINT` draws the list but suppresses
    /// `CDDS_ITEMPREPAINT`, so no row ever gets a `clrText` and the whole colouring
    /// feature is invisible in the real dialog while every colour-mapping unit
    /// test still passes.
    #[test]
    fn the_prepaint_stage_asks_for_item_notifications() {
        let mut draw = custom_draw_at(CDDS_PREPAINT.0, None);
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &[], 0) };
        assert_eq!(answer, Some(CDRF_NOTIFYITEMDRAW as isize));
    }

    /// The item stage only asks for subitem notifications. Colours and the optional
    /// monospace face belong to individual cells: selecting a font for the whole item
    /// would also change the algorithm and file columns.
    #[test]
    fn the_item_stage_asks_for_sub_item_notifications() {
        let mut draw = custom_draw_at(CDDS_ITEMPREPAINT.0, Some(0));
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &[], 0) };
        assert_eq!(answer, Some(CDRF_NOTIFYSUBITEMDRAW as isize));
    }

    /// At the subitem stage the matched row gets the match colour; the answer has to
    /// ask for a repaint (`CDRF_NEWFONT`) or the colour would not take effect.
    #[test]
    fn the_sub_item_stage_sets_the_text_colour() {
        let rows = vec![
            row_for(
                MatchState::Matched {
                    algorithm: 0,
                    secure: true,
                },
                None,
            ),
            row_for(
                MatchState::Matched {
                    algorithm: 0,
                    secure: false,
                },
                None,
            ),
            row_for(MatchState::Mismatched, None),
            row_for(MatchState::NotChecked, None),
        ];

        let palette = Palette::default();
        let expected = [
            (0usize, palette.for_class(RowColour::Matched).0),
            (1, palette.for_class(RowColour::MatchedWeak).0),
            (2, palette.for_class(RowColour::Mismatched).0),
            (3, palette.for_class(RowColour::Neutral).0),
        ];
        for (row, colour) in expected {
            let mut draw = custom_draw_at(CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0, Some(row));
            draw.iSubItem = 1;
            // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
            let answer = unsafe { custom_draw(draw_ptr(&mut draw), &rows, 0) };
            assert_eq!(answer, Some(CDRF_NEWFONT as isize));
            assert_eq!(draw.clrText, colour, "row {row} was not given its colour");
        }
    }

    /// A custom draw from another control must not be answered: answering for it
    /// would paint someone else's control with our colours.
    #[test]
    fn a_notification_from_another_control_is_not_ours() {
        let mut draw = custom_draw_at(CDDS_PREPAINT.0, None);
        draw.nmcd.hdr.idFrom = 0x1234;
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &[], 0) };
        assert_eq!(answer, None);
    }

    /// A row index that no longer exists must not be coloured and must not stop
    /// the control from painting.
    #[test]
    fn a_stale_row_index_is_ignored_but_still_paints() {
        let rows = vec![row_for(MatchState::Mismatched, None)];
        let mut draw = custom_draw_at(CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0, Some(99));
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &rows, 0) };
        assert_eq!(answer, Some(CDRF_DODEFAULT as isize));
        assert_eq!(draw.clrText, ColorDef(0).colorref());
    }

    /// Stages we do not colour must still be answered with default painting.
    #[test]
    fn a_stage_we_do_not_colour_still_paints() {
        let mut draw = custom_draw_at(CDDS_PREPAINT.0 + 1, None);
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW` for this call.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &[], 0) };
        assert_eq!(answer, Some(CDRF_DODEFAULT as isize));
    }

    /// The digest cell is the only one that gets the monospace face; selecting it
    /// for a different column would change the algorithm/file text too.
    #[test]
    fn the_digest_sub_item_uses_the_monospace_font_when_one_is_given() {
        use windows::Win32::Graphics::Gdi::{
            ANSI_FIXED_FONT, CreateCompatibleDC, DeleteDC, GetStockObject as GdiStockObject,
        };

        // SAFETY: a memory DC is a plain GDI object with no window affinity.
        let dc = unsafe { CreateCompatibleDC(None) };
        assert!(!dc.is_invalid(), "a memory DC is needed for this test");
        // SAFETY: the stock object is owned by GDI, so no deletion is required.
        let font = unsafe { GdiStockObject(ANSI_FIXED_FONT) };

        let rows = vec![row_for(
            MatchState::Matched {
                algorithm: 0,
                secure: true,
            },
            None,
        )];
        let mut draw = custom_draw_at(CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0, Some(0));
        draw.iSubItem = 1;
        draw.nmcd.hdc = dc;
        // SAFETY: `draw` is a live `NMLVCUSTOMDRAW`; `font` is a live stock font.
        let answer = unsafe { custom_draw(draw_ptr(&mut draw), &rows, font.0 as isize) };
        assert_eq!(answer, Some(CDRF_NEWFONT as isize));

        // SAFETY: `dc` was created above and is deleted exactly once.
        unsafe {
            let _ = DeleteDC(dc);
        }
    }

    /// A row shaped the way the page stores it.
    fn row_for(state: MatchState, error: Option<u32>) -> ListRow {
        ListRow {
            id: NEXT_ID.with(|next| {
                let id = next.get();
                next.set(id + 1);
                id
            }),
            job_index: 0,
            algorithm: 0,
            digest_hex: String::new(),
            match_state: state,
            error,
            display_path: String::from("file.bin"),
        }
    }

    /// A custom-draw structure for one stage and one row.
    fn custom_draw_at(stage: u32, row: Option<usize>) -> NMLVCUSTOMDRAW {
        let mut draw = NMLVCUSTOMDRAW::default();
        draw.nmcd.hdr.idFrom = resource::IDC_HASH_LIST as usize;
        draw.nmcd.dwDrawStage = windows::Win32::UI::Controls::NMCUSTOMDRAW_DRAW_STAGE(stage);
        if let Some(index) = row {
            draw.nmcd.dwItemSpec = index;
            draw.nmcd.lItemlParam = LPARAM(index as isize);
        }
        draw
    }

    /// The pointer the notification's `lParam` would carry.
    fn draw_ptr(draw: &mut NMLVCUSTOMDRAW) -> LPARAM {
        LPARAM(draw as *mut NMLVCUSTOMDRAW as isize)
    }

    /// `wide` terminates exactly once, so a cell cannot run into the next one.
    #[test]
    fn wide_terminates_exactly_once() {
        assert_eq!(wide(""), vec![0]);
        assert_eq!(wide("ab"), vec![u16::from(b'a'), u16::from(b'b'), 0]);
    }
}
