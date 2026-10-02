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
    DEFAULT_GUI_FONT, GetDC, GetStockObject, GetTextExtentPoint32W, HGDIOBJ, ReleaseDC,
    SelectObject,
};
use windows::Win32::UI::Controls::{
    CDDS_ITEMPREPAINT, CDRF_DODEFAULT, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_PARAM, LVIF_TEXT,
    LVITEMW, LVM_DELETEALLITEMS, LVM_GETITEMW, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETCOLUMNW, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMTEXTW, LVNI_SELECTED,
    LVS_EX_FULLROWSELECT, NMLVCUSTOMDRAW,
};
use windows::Win32::UI::WindowsAndMessaging::{SendMessageW, WM_SETFONT};

/// The colour a row is drawn in when a digest matched an expected value: a dark
/// green, `#008B00`, written `0x00BBGGRR` because that is `COLORREF`'s order.
const MATCHED_COLOR: ColorDef = ColorDef(0x0000_8B00);
/// The colour a row is drawn in when a digest had an expected value and missed it:
/// a dark red, `#C00000`, in `COLORREF` order.
const MISMATCHED_COLOR: ColorDef = ColorDef(0x0000_00C0);

/// A `COLORREF`, spelled `0x00BBGGRR`.
///
/// Wrapped because that byte order is the opposite of how anyone writes a colour,
/// and a bare literal here would be read as `0xRRGGBB` by everyone including the
/// author. It was: the first version of both constants above was in `RGB` order,
/// and [`tests::the_colours_are_spelled_in_colorref_order`] is what caught it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColorDef(u32);

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

            let font = GetStockObject(DEFAULT_GUI_FONT);
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

/// Replace every row in the list.
///
/// Called with the page's whole row list rather than with a delta, because the
/// control is not the source of truth: the rows are owned by the page, and this is a
/// rendering of them. Rebuilding the control on each batch also means a row
/// inserted out of order cannot leave the two disagreeing.
pub fn set_rows(list: HWND, rows: &[ListRow]) {
    // SAFETY: `list` is the page's list view, and clearing it takes no arguments.
    unsafe {
        SendMessageW(list, LVM_DELETEALLITEMS, Some(WPARAM(0)), Some(LPARAM(0)));
    }

    for (row_index, row) in rows.iter().enumerate() {
        insert_row(list, row_index, row);
    }
}

/// Append one row, returning its item index.
///
/// `row_index` is the row's position in the page's row list, which is what the
/// item's `lParam` records so a selection can be turned back into rows.
pub fn insert_row(list: HWND, row_index: usize, row: &ListRow) -> i32 {
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

    let mut algorithm_wide = wide(&algorithm);
    let mut digest_wide = wide(&digest);
    let mut matched_wide = wide(matched);
    let mut file_wide = wide(&format!("#{}", row.job_index));

    let mut item = LVITEMW {
        mask: LVIF_TEXT | LVIF_PARAM,
        // The row's index in the page's list, which is how a selection is turned
        // back into rows. Not the item index: the two are the same only while rows
        // are appended in order, and that is not a property to rely on.
        lParam: LPARAM(row_index as isize),
        pszText: windows::core::PWSTR(algorithm_wide.as_mut_ptr()),
        ..Default::default()
    };

    // SAFETY: `list` is the page's list view, `item` and every string it points at
    // live for the duration of the call, and `LVM_INSERTITEMW` copies what it needs.
    // The column index is carried in `iSubItem` between the two calls below.
    let inserted = unsafe {
        SendMessageW(
            list,
            LVM_INSERTITEMW,
            Some(WPARAM(0)),
            Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
        )
    };
    if inserted.0 < 0 {
        // The control refused the item -- out of memory, in practice. There is
        // nothing to roll back and nothing useful to say; the row simply does not
        // appear, and the status line's count is what disagrees with the list.
        return -1;
    }

    let index = inserted.0 as usize;
    set_sub_item(list, index, 1, &mut digest_wide);
    set_sub_item(list, index, 2, &mut matched_wide);
    set_sub_item(list, index, 3, &mut file_wide);

    index as i32
}

/// Set one cell of an existing item.
fn set_sub_item(list: HWND, item: usize, sub_item: i32, text: &mut [u16]) {
    let mut cell = LVITEMW {
        iSubItem: sub_item,
        pszText: windows::core::PWSTR(text.as_mut_ptr()),
        ..Default::default()
    };

    // SAFETY: the item index came from a successful `LVM_INSERTITEMW`, and `cell`
    // plus the string it points at live for the call. `LVM_SETITEMTEXTW` copies the
    // text into the control's own storage.
    unsafe {
        SendMessageW(
            list,
            LVM_SETITEMTEXTW,
            Some(WPARAM(item)),
            Some(LPARAM((&mut cell as *mut LVITEMW) as isize)),
        );
    }
}

/// The rows currently selected, by their index in the page's row list.
pub fn selected_rows(list: HWND) -> Vec<usize> {
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

        let mut item = LVITEMW {
            mask: LVIF_PARAM,
            iItem: found.0 as i32,
            ..Default::default()
        };
        // SAFETY: `after` is an item index the control just reported, and `item`
        // lives for the call. `LVM_GETITEMW` fills in `lParam` from the item we
        // inserted.
        let copied = unsafe {
            SendMessageW(
                list,
                LVM_GETITEMW,
                Some(WPARAM(0)),
                Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
            )
        };
        // A zero return is failure; the control reports success as non-zero, which
        // is the `BOOL` convention rather than an item index.
        if copied.0 != 0 {
            selected.push(item.lParam.0 as usize);
        }
    }

    selected
}

/// How a row should be drawn, given what its digest compared to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowColour {
    /// An expected digest matched.
    Matched,
    /// An expected digest did not match.
    Mismatched,
    /// Nothing to compare against, or no result.
    Neutral,
}

/// The colour a match state maps to.
pub fn colour_for(state: rusthashtab_scan::MatchState, failed: bool) -> RowColour {
    if failed {
        // A file that could not be read is not a mismatch: telling the user their
        // file is corrupt when it was merely unreadable is the one thing the
        // comparison layer deliberately avoids, and the display must not undo it.
        return RowColour::Neutral;
    }
    match state {
        rusthashtab_scan::MatchState::Matched { .. } => RowColour::Matched,
        rusthashtab_scan::MatchState::Mismatched => RowColour::Mismatched,
        rusthashtab_scan::MatchState::NotChecked => RowColour::Neutral,
    }
}

/// Apply the per-row colour while the control draws.
///
/// Returns `true` when the structure was ours to alter, so the dialog procedure can
/// answer the notification correctly. A `false` return means the caller must let the
/// default handling continue -- swallowing someone else's custom-draw notification
/// would leave a control that never paints.
///
/// # Safety
///
/// `lparam` must be the `NMHDR` of an `NM_CUSTOMDRAW` notification sent by the list
/// view, which is what the dialog procedure is handed for that message.
pub unsafe fn colour_row(lparam: LPARAM, rows: &[ListRow]) -> bool {
    // SAFETY: the caller promises this is our list view's custom-draw structure.
    let custom = unsafe { &mut *(lparam.0 as *mut NMLVCUSTOMDRAW) };
    if custom.nmcd.dwDrawStage.0 != CDDS_ITEMPREPAINT.0 {
        return false;
    }

    let row_index = custom.nmcd.lItemlParam.0 as usize;
    let Some(row) = rows.get(row_index) else {
        return false;
    };

    match colour_for(row.match_state, row.error.is_some()) {
        RowColour::Matched => custom.clrText = MATCHED_COLOR.colorref(),
        RowColour::Mismatched => custom.clrText = MISMATCHED_COLOR.colorref(),
        RowColour::Neutral => {}
    }

    true
}

/// Whether a custom-draw notification should call for the default painting.
///
/// The dialog procedure answers `NM_CUSTOMDRAW` with this: the control still has to
/// draw the text, and returning anything else would let it stop.
pub const fn custom_draw_result() -> isize {
    CDRF_DODEFAULT as isize
}

/// NUL-terminate a string for a Win32 parameter.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(core::iter::once(0)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_scan::MatchState;

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

    /// A file that could not be read must not be shown as a mismatch. That
    /// distinction is made deliberately in the comparison layer, and the display
    /// undoing it would tell the user their file is corrupt.
    #[test]
    fn an_unreadable_file_is_not_coloured_as_a_mismatch() {
        assert_eq!(colour_for(MatchState::Mismatched, true), RowColour::Neutral);
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
    #[test]
    fn the_custom_draw_answer_asks_for_default_painting() {
        assert_eq!(custom_draw_result(), CDRF_DODEFAULT as isize);
    }

    /// `wide` terminates exactly once, so a cell cannot run into the next one.
    #[test]
    fn wide_terminates_exactly_once() {
        assert_eq!(wide(""), vec![0]);
        assert_eq!(wide("ab"), vec![u16::from(b'a'), u16::from(b'b'), 0]);
    }
}
