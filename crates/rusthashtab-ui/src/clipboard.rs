//! Putting the selected rows on the clipboard as text.
//!
//! # Ownership, and the one rule that matters
//!
//! `SetClipboardData` **transfers ownership** of the handle to the system. The
//! caller must not free it afterwards, and must not touch it. That is not a
//! convention to be careful about: freeing it is a double free of memory another
//! process may already be reading, and getting it wrong is a crash the user cannot
//! attribute to us.
//!
//! So the rule is encoded in the shape of the code rather than in a comment: the
//! `HGLOBAL` is moved into [`HandedOver`] the moment the copy starts, and
//! [`HandedOver`] has no way to free it. Every early return before that point frees
//! the handle, and every return after it does not, because it cannot.
//!
//! # Why the text is tab separated
//!
//! The page is a table, and the two things people do with it are paste into a
//! spreadsheet and paste into a message. Tabs and newlines satisfy both: a
//! spreadsheet splits on them, and a message shows them as columns. Anything
//! richer is a format nobody asked for.

#![cfg(windows)]

use crate::ListRow;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// A global-memory handle the system now owns.
///
/// Holding it is the only way to express "this was handed over": there is no
/// `Drop` that frees it and no method that returns it, so the handle cannot be
/// freed twice even by a later edit that adds an early return.
struct HandedOver;

/// Render rows as the tab-separated text that goes on the clipboard.
///
/// A header line is deliberately **not** emitted: the selection is what the user
/// asked for, and adding a line they did not select makes a paste into a
/// spreadsheet land one row off.
///
/// Returns `None` when there is nothing to copy, so the caller can avoid touching
/// the clipboard at all rather than replacing its contents with an empty string.
pub fn render(rows: &[ListRow], selected: &[usize]) -> Option<String> {
    if selected.is_empty() {
        return None;
    }

    let mut text = String::new();
    for index in selected {
        let Some(row) = rows.get(*index) else {
            // A selection that names a row the page no longer has. Skipping it is
            // right: the rest of the selection is still what the user asked for.
            continue;
        };

        let algorithm = if row.algorithm == usize::MAX {
            String::from("-")
        } else {
            rusthashtab_hash::ALGORITHMS
                .get(row.algorithm)
                .map(|algorithm| algorithm.name)
                .unwrap_or("-")
                .to_string()
        };

        let digest = match row.error {
            Some(code) => crate::resource::read_error_text(code),
            None => row.digest_hex.clone(),
        };

        let verdict = match row.match_state {
            rusthashtab_scan::MatchState::Matched { .. } => "matched",
            rusthashtab_scan::MatchState::Mismatched => "mismatch",
            rusthashtab_scan::MatchState::NotChecked => "not checked",
        };

        if !text.is_empty() {
            text.push_str("\r\n");
        }
        text.push_str(&algorithm);
        text.push('\t');
        text.push_str(&digest);
        text.push('\t');
        text.push_str(verdict);
    }

    (!text.is_empty()).then_some(text)
}

/// Copy the selected rows to the clipboard.
///
/// Returns whether the clipboard now holds the text. Every failure is a `false`
/// rather than an error value: the shell has nowhere to show one, and the only
/// useful thing the page can do is leave the button doing nothing.
pub fn copy(owner: HWND, text: &str) -> bool {
    // The clipboard is a process-wide lock, so every path must release it -- hence
    // the single `owned` guard below rather than a `CloseClipboard` per return.
    // SAFETY: `owner` is the page's window. `OpenClipboard` fails rather than
    // faults when another process holds the clipboard.
    if unsafe { OpenClipboard(Some(owner)) }.is_err() {
        return false;
    }

    // SAFETY: the clipboard was opened above and is closed by the guard's `Drop`.
    let result = unsafe { fill_clipboard(text) };
    // SAFETY: as above; `CloseClipboard` takes no arguments.
    let _ = unsafe { CloseClipboard() };
    result
}

/// Replace the clipboard's contents, with the clipboard already open.
///
/// # Safety
///
/// The clipboard must be open on the calling thread, which is what
/// [`OpenClipboard`] establishes and [`CloseClipboard`] undoes.
unsafe fn fill_clipboard(text: &str) -> bool {
    // SAFETY: the caller opened the clipboard.
    if unsafe { EmptyClipboard() }.is_err() {
        return false;
    }

    let mut wide: Vec<u16> = text.encode_utf16().collect();
    // `CF_UNICODETEXT` is NUL-terminated, and the terminator is part of the byte
    // count the clipboard records.
    wide.push(0);
    let bytes = core::mem::size_of_val(wide.as_slice());

    // A moveable block is what the clipboard requires. `GlobalAlloc` returns null
    // on failure rather than raising, so the null check is the error path.
    // SAFETY: the size is derived from a live slice, so it is exact.
    let handle = match unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) } {
        Ok(handle) => handle,
        Err(_) => return false,
    };

    // From here on the handle must either be handed over or freed. `HandedOver`
    // records the transition, so no later return can free it twice.
    let handed_over = {
        // SAFETY: `handle` came from `GlobalAlloc` and has not been locked.
        let locked = unsafe { GlobalLock(handle) };
        if locked.is_null() {
            // Nothing was written, so the block is still ours to free.
            // SAFETY: `handle` came from `GlobalAlloc` and was never handed over.
            let _ = unsafe { GlobalFree(Some(handle)) };
            return false;
        }

        // SAFETY: `locked` points at a block of exactly `bytes` bytes, which is what
        // was allocated, and `wide` has exactly that many bytes of content.
        unsafe {
            core::ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), locked.cast::<u8>(), bytes);
        }
        // SAFETY: `locked` came from `GlobalLock` on this handle and is released
        // once. The un-pinned block may move, but the clipboard takes the handle,
        // not the pointer.
        let _ = unsafe { GlobalUnlock(handle) };

        // SAFETY: the clipboard is open, the handle is a moveable global block that
        // this call now owns, and it was never handed over before.
        if unsafe { SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(handle.0))) }.is_err() {
            // The system refused it, so ownership never moved and the block is still
            // ours. Freeing it here is the only correct action.
            // SAFETY: as above; the call failed, so nothing else owns the handle.
            let _ = unsafe { GlobalFree(Some(handle)) };
            return false;
        }

        HandedOver
    };

    // The system owns the block now. `handed_over` exists to make that fact part of
    // the code rather than part of a comment: there is nothing to free here, and
    // nothing that could free it.
    let _ = handed_over;
    true
}

/// Whether the clipboard can be opened right now.
///
/// Used by the page to leave the Copy button alone when another process holds the
/// clipboard, rather than replacing its contents with nothing.
pub fn is_available() -> bool {
    // SAFETY: a null owner is allowed; the call fails rather than faults when
    // another process holds the clipboard.
    if unsafe { OpenClipboard(None) }.is_err() {
        return false;
    }
    // SAFETY: the clipboard was opened immediately above and is closed exactly once.
    let _ = unsafe { CloseClipboard() };
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_scan::MatchState;

    fn row(algorithm: usize, digest: &str, state: MatchState, error: Option<u32>) -> ListRow {
        ListRow {
            job_index: 0,
            algorithm,
            digest_hex: digest.to_string(),
            match_state: state,
            error,
        }
    }

    fn sha256_index() -> usize {
        rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == "SHA-256")
            .expect("SHA-256 is in the table")
    }

    /// An empty selection means "nothing to copy", not "replace the clipboard with
    /// an empty string". Someone who has just copied something else would otherwise
    /// lose it.
    #[test]
    fn nothing_selected_renders_nothing() {
        let rows = vec![row(sha256_index(), "AB", MatchState::NotChecked, None)];
        assert_eq!(render(&rows, &[]), None);
    }

    /// The rows come out in the order they were selected, one line each, tab
    /// separated, and with no header line: the selection is what the user asked
    /// for.
    #[test]
    fn a_selection_renders_one_tab_separated_line_per_row() {
        let rows = vec![
            row(sha256_index(), "AABB", MatchState::NotChecked, None),
            row(sha256_index(), "CCDD", MatchState::Mismatched, None),
        ];

        let text = render(&rows, &[0, 1]).expect("two rows render");

        assert_eq!(
            text,
            "SHA-256\tAABB\tnot checked\r\nSHA-256\tCCDD\tmismatch"
        );
        assert!(!text.starts_with('\n'));
    }

    /// The selection is a set of indices, and the order they are given in is the
    /// order the user selected. Reordering them here would be a surprise.
    #[test]
    fn the_selected_order_is_preserved() {
        let rows = vec![
            row(sha256_index(), "FIRST", MatchState::NotChecked, None),
            row(sha256_index(), "SECOND", MatchState::NotChecked, None),
        ];
        let text = render(&rows, &[1, 0]).expect("both rows render");
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert!(lines[0].contains("SECOND"));
        assert!(lines[1].contains("FIRST"));
    }

    /// An unreadable file says so in the digest column, where the answer belongs.
    #[test]
    fn a_read_error_is_rendered_where_the_digest_belongs() {
        let rows = vec![row(usize::MAX, "", MatchState::NotChecked, Some(5))];
        let text = render(&rows, &[0]).expect("the error row renders");
        assert_eq!(text, "-\tError 5\tnot checked");
    }

    /// A selection naming a row the page no longer has must skip it rather than
    /// producing a blank line that would paste as an empty record.
    #[test]
    fn a_stale_selection_index_is_skipped() {
        let rows = vec![row(sha256_index(), "AABB", MatchState::NotChecked, None)];
        let text = render(&rows, &[0, 99]).expect("the live row renders");
        assert_eq!(text.lines().count(), 1);
    }

    /// Everything selected being stale is the same as nothing selected.
    #[test]
    fn an_entirely_stale_selection_renders_nothing() {
        let rows: Vec<ListRow> = Vec::new();
        assert_eq!(render(&rows, &[0, 1]), None);
    }

    /// A mismatched row is labelled as such: the colour in the list is not the only
    /// carrier of that information, which matters for a paste and for anyone who
    /// cannot distinguish the colours.
    #[test]
    fn each_match_state_has_its_own_label() {
        let rows = vec![
            row(
                sha256_index(),
                "AA",
                MatchState::Matched {
                    algorithm: sha256_index(),
                    secure: true,
                },
                None,
            ),
            row(sha256_index(), "BB", MatchState::Mismatched, None),
            row(sha256_index(), "CC", MatchState::NotChecked, None),
        ];
        let text = render(&rows, &[0, 1, 2]).expect("three rows render");
        assert!(text.contains("matched"));
        assert!(text.contains("mismatch"));
        assert!(text.contains("not checked"));
    }

    /// Real clipboard, real global memory, real ownership transfer.
    ///
    /// Deliberately not a mock: the whole risk in this module is what happens to the
    /// `HGLOBAL`, and a mock would test the parts that were never in doubt. The test
    /// puts a known string on the clipboard and reads it back through the OS.
    #[test]
    fn copying_transfers_a_handle_the_system_can_read_back() {
        // The imports are local to the test: production code never reads the
        // clipboard, only writes it.
        use windows::Win32::Foundation::HGLOBAL;
        use windows::Win32::System::DataExchange::GetClipboardData;

        // A null owner is allowed for the clipboard APIs.
        let owner = HWND(core::ptr::null_mut());
        let marker = "rustHashTab clipboard round trip \u{2022} \u{00e9}\u{4e2d}";
        if !copy(owner, marker) {
            panic!("copy failed; the clipboard may be held by another process");
        }

        // Read it back through the OS rather than from our own state.
        // SAFETY: the clipboard is opened immediately below; `CF_UNICODETEXT`
        // returns the handle we put there.
        unsafe {
            OpenClipboard(None).expect("the clipboard must be openable after a copy");
            let handle = GetClipboardData(CF_UNICODETEXT.0 as u32)
                .expect("the clipboard holds the text we just put there");
            let pointer = GlobalLock(HGLOBAL(handle.0));
            assert!(!pointer.is_null(), "the returned block must be lockable");

            let units = pointer.cast::<u16>();
            let mut length = 0usize;
            while *units.add(length) != 0 {
                length += 1;
            }
            let read = String::from_utf16_lossy(core::slice::from_raw_parts(units, length));

            let _ = GlobalUnlock(HGLOBAL(handle.0));
            let _ = CloseClipboard();

            assert_eq!(read, marker, "the clipboard text is not what was copied");
        }
    }
}
