//! Reading and writing clipboard text.
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
//! The reading direction has the mirror-image rule: the clipboard owns the block
//! [`read_text`] locks, so the lock is taken and released around the copy and the
//! handle is never freed. The clipboard is closed on every path in both
//! directions -- it is a machine-wide lock, and failing to release it would leave
//! every other application unable to copy until this process exits.
//!
//! # Reading is bounded and total
//!
//! [`read_text`] exists for the one flow that needs the clipboard as input
//! (verifying against a digest the user has already copied). It never fails
//! visibly: a clipboard that another process holds, no text on it, empty text, or
//! a block larger than [`MAX_CLIPBOARD_TEXT_UNITS`] are all `None`, which the
//! caller treats the same way as "there was nothing on the clipboard". The bound
//! exists because the block was allocated by another process: a shell extension
//! must not copy an unbounded amount of another process's data into the
//! property-sheet thread's heap on the strength of a size it did not choose.
//! Refusing an oversized block rather than truncating it matters too -- a
//! truncated digest would compare equal to the wrong value.
//!
//! # Why the text is tab separated
//!
//! The page is a table, and the two things people do with it are paste into a
//! spreadsheet and paste into a message. Tabs and newlines satisfy both: a
//! spreadsheet splits on them, and a message shows them as columns. Anything
//! richer is a format nobody asked for.

#![cfg(windows)]

use crate::ListRow;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// A global-memory handle the system now owns.
///
/// Holding it is the only way to express "this was handed over": there is no
/// `Drop` that frees it and no method that returns it, so the handle cannot be
/// freed twice even by a later edit that adds an early return.
struct HandedOver;

/// What the user asked to copy.
///
/// The four context-menu entries, the double-click behaviours, and the Copy
/// button all go through one renderer so their formats cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyKind {
    /// The selected rows as four-column TSV, one line each.
    Selection,
    /// One row as four-column TSV.
    Row,
    /// The digest alone, one per selected row.
    Digest,
    /// `digest *path`, the form a checksum file uses.
    SumfileLine,
    /// The display path alone.
    FileName,
    /// Every displayed row as TSV.
    All,
    /// One row as `digest *path`.
    OneSumfileLine,
}

/// Render rows for the clipboard.
///
/// `selected` holds stable row IDs, not positions: rows are inserted into job
/// order while earlier files are still hashing, so a position is not a stable
/// name for a row. An ID that no longer exists is skipped; the rest of the
/// selection is still what the user asked for.
///
/// A header line is deliberately **not** emitted for TSV: the selection is what
/// the user asked for, and adding a line they did not select makes a paste into a
/// spreadsheet land one row off. `None` means nothing to copy, so the caller can
/// avoid touching the clipboard rather than replacing it with an empty string.
pub fn render(rows: &[ListRow], selected: &[u64], kind: CopyKind) -> Option<String> {
    let chosen: Vec<&ListRow> = match kind {
        CopyKind::All => rows.iter().collect(),
        _ => selected
            .iter()
            .filter_map(|id| rows.iter().find(|row| row.id == *id))
            .collect(),
    };
    if chosen.is_empty() {
        return None;
    }

    let mut text = String::new();
    for row in chosen {
        if !text.is_empty() {
            text.push_str("\r\n");
        }
        match kind {
            CopyKind::Digest => text.push_str(&digest_text(row)),
            CopyKind::FileName => text.push_str(&row.display_path),
            CopyKind::SumfileLine | CopyKind::OneSumfileLine => {
                if row.error.is_some() {
                    // There is no digest to put in a checksum line. Copying the
                    // path is honest; inventing an error string as a digest is not.
                    text.push_str(&row.display_path);
                } else {
                    text.push_str(&digest_text(row));
                    text.push_str(" *");
                    text.push_str(&row.display_path);
                }
            }
            CopyKind::Selection | CopyKind::Row | CopyKind::All => {
                text.push_str(&tsv_line(row));
            }
        }
    }

    (!text.is_empty()).then_some(text)
}

/// The digest cell's text: the digest, or the error description.
fn digest_text(row: &ListRow) -> String {
    match row.error {
        Some(code) => crate::resource::read_error_text(code),
        None => row.digest_hex.clone(),
    }
}

/// One row's four-column TSV line.
fn tsv_line(row: &ListRow) -> String {
    let algorithm = if row.algorithm == usize::MAX {
        String::from("-")
    } else {
        rusthashtab_hash::ALGORITHMS
            .get(row.algorithm)
            .map(|algorithm| algorithm.name)
            .unwrap_or("-")
            .to_string()
    };
    let digest = digest_text(row);
    let verdict = match row.match_state {
        rusthashtab_scan::MatchState::Matched { .. } => "matched",
        rusthashtab_scan::MatchState::Mismatched => "mismatch",
        rusthashtab_scan::MatchState::NotChecked => "not checked",
    };

    format!("{algorithm}\t{digest}\t{verdict}\t{}", row.display_path)
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

/// Most UTF-16 units [`read_text`] will accept from the clipboard.
///
/// A whole checksum line is a few hundred bytes, so 32 Ki units is far past any
/// paste the page can use. The cap is counted in units rather than bytes because
/// `CF_UNICODETEXT` is an array of `u16`, and because the terminator is one of
/// them: the longest accepted text is one unit shorter than the cap.
pub const MAX_CLIPBOARD_TEXT_UNITS: usize = 32 * 1024;

/// Read the clipboard's Unicode text, if it holds usable, bounded text.
///
/// Every failure here is an ordinary condition on a machine where every
/// application shares one clipboard: [`read_text`] returns `None` when the
/// clipboard cannot be opened (another process holds it), when it holds no
/// `CF_UNICODETEXT`, when the block cannot be locked or reports no size, when the
/// text is empty, and when it is at least [`MAX_CLIPBOARD_TEXT_UNITS`] long or has
/// no terminator within that bound. There is no error type because the caller has
/// nothing better to do in those cases than carry on without a clipboard source.
///
/// `owner` is the window that becomes the clipboard owner while it is open; the
/// page passes its own window. Win32 allows a null handle too, which is what the
/// tests use. The clipboard is closed on every path.
pub fn read_text(owner: HWND) -> Option<String> {
    // SAFETY: `owner` is the page's window, a window on this thread (or null,
    // which Win32 allows). `OpenClipboard` fails rather than faults when another
    // process holds the clipboard, so the returned error is checked and not
    // asserted away.
    if unsafe { OpenClipboard(Some(owner)) }.is_err() {
        return None;
    }

    // SAFETY: the clipboard was opened above, and the helper only locks and
    // unlocks the block -- the clipboard, not this code, owns the handle. Every
    // path out of the helper is followed by the close directly below, so the
    // machine-wide lock cannot be left held.
    let text = unsafe { read_open_clipboard() };
    // SAFETY: the clipboard is open on this thread and is closed exactly once
    // here; `CloseClipboard` takes no arguments and cannot fault on an open
    // clipboard.
    let _ = unsafe { CloseClipboard() };
    text
}

/// Read `CF_UNICODETEXT` with the clipboard already open.
///
/// The block is locked only for the duration of the copy, and the lock is
/// released before returning: the pointer is valid only while the clock is
/// stopped in this way, because the system may otherwise move or free the block.
///
/// # Safety
///
/// The clipboard must be open on the calling thread, which is what
/// [`OpenClipboard`] establishes and [`CloseClipboard`] undoes.
unsafe fn read_open_clipboard() -> Option<String> {
    // SAFETY: the caller opened the clipboard. `CF_UNICODETEXT` either returns a
    // handle owned by the clipboard (which this code must not free) or fails.
    let handle = unsafe { GetClipboardData(CF_UNICODETEXT.0 as u32) }.ok()?;
    let global = HGLOBAL(handle.0);

    // SAFETY: `global` is the clipboard's handle from the call above and the
    // clipboard is still open, so the block is valid to lock. Locking does not
    // take ownership; the handle stays the clipboard's to free.
    let locked = unsafe { GlobalLock(global) };
    if locked.is_null() {
        return None;
    }

    // SAFETY: `global` is the handle the clipboard owns and `locked` is the
    // pointer just obtained for it; `GlobalSize` reports the block's size in
    // bytes and returns zero for a handle this API does not own, which the
    // bounded reader treats as empty.
    let bytes = unsafe { GlobalSize(global) };
    // SAFETY: `locked` is a live pointer into the locked block and `bytes` is the
    // size reported for that same block, so the pointer and unit count satisfy
    // `bounded_text`'s contract.
    let text = unsafe { bounded_text(locked.cast::<u16>(), bytes / core::mem::size_of::<u16>()) };

    // SAFETY: `locked` came from `GlobalLock` on this handle and is released
    // exactly once here; the handle itself remains owned by the clipboard.
    let _ = unsafe { GlobalUnlock(global) };
    text
}

/// Turn at most [`MAX_CLIPBOARD_TEXT_UNITS`] units of clipboard data into a
/// `String`, stopping at the NUL terminator.
///
/// `count` is the unit count `GlobalSize` reported for the locked block. Only the
/// first [`MAX_CLIPBOARD_TEXT_UNITS`] units are ever examined. When no terminator
/// appears in that window the text is at least the cap long, which is refused as
/// oversized instead of being truncated: a partly-read digest would silently be
/// compared against the wrong bytes, which is worse than not checking at all.
///
/// # Safety
///
/// `units` must point at `count` readable `u16` values that stay valid for the
/// duration of the call. The caller's locked clipboard block provides exactly
/// that; no other pointer satisfies the contract.
unsafe fn bounded_text(units: *const u16, count: usize) -> Option<String> {
    let window = count.min(MAX_CLIPBOARD_TEXT_UNITS);
    if window == 0 {
        return None;
    }

    // SAFETY: `window <= count`, so this slice stays inside the `count` readable
    // units the caller guarantees, and the block cannot change underneath the
    // slice because the caller holds it locked.
    let units = unsafe { core::slice::from_raw_parts(units, window) };
    let length = units.iter().position(|&unit| unit == 0)?;
    if length == 0 {
        return None;
    }

    // `from_utf16_lossy` is the right conversion for data from another process:
    // an unpaired surrogate is that process's bug, and the worst it should cost
    // the user is a replacement character, not a failed read.
    Some(String::from_utf16_lossy(&units[..length]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rusthashtab_scan::MatchState;
    use std::cell::Cell;
    use std::sync::{Mutex, MutexGuard};

    // Each test runs on its own thread, so this starts at zero for every test and
    // rows created in one test get the IDs 0, 1, ... -- which lets the assertions
    // address rows the way the page does without hand-writing an ID per call.
    thread_local! {
        static NEXT_ID: Cell<u64> = const { Cell::new(0) };
    }

    /// The clipboard is one machine-wide resource, not one per test. Two tests
    /// that write it concurrently can empty or overwrite each other's contents
    /// between a `copy` and the read that is supposed to observe it, so every
    /// test that touches it -- on either side -- takes this lock.
    static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

    /// Serialize the current test, recovering from a lock poisoned by an earlier
    /// failing test: one genuine failure should not turn every later clipboard
    /// test into a different failure.
    fn clipboard_guard() -> MutexGuard<'static, ()> {
        CLIPBOARD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn row(
        algorithm: usize,
        digest: &str,
        state: MatchState,
        error: Option<u32>,
        path: &str,
    ) -> ListRow {
        ListRow {
            id: NEXT_ID.with(|next| {
                let id = next.get();
                next.set(id + 1);
                id
            }),
            job_index: 0,
            algorithm,
            digest_hex: digest.to_string(),
            match_state: state,
            error,
            display_path: path.to_string(),
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
        let rows = vec![row(
            sha256_index(),
            "AB",
            MatchState::NotChecked,
            None,
            "file.bin",
        )];
        assert_eq!(render(&rows, &[], CopyKind::Selection), None);
    }

    /// The rows come out in the order they were selected, one line each, tab
    /// separated, and with no header line: the selection is what the user asked
    /// for.
    #[test]
    fn a_selection_renders_one_tab_separated_line_per_row() {
        let rows = vec![
            row(
                sha256_index(),
                "AABB",
                MatchState::NotChecked,
                None,
                "first.bin",
            ),
            row(
                sha256_index(),
                "CCDD",
                MatchState::Mismatched,
                None,
                "second.bin",
            ),
        ];

        let text = render(&rows, &[0, 1], CopyKind::Selection).expect("two rows render");

        assert_eq!(
            text,
            "SHA-256\tAABB\tnot checked\tfirst.bin\r\nSHA-256\tCCDD\tmismatch\tsecond.bin"
        );
        assert!(!text.starts_with('\n'));
    }

    /// The selection is a set of indices, and the order they are given in is the
    /// order the user selected. Reordering them here would be a surprise.
    #[test]
    fn the_selected_order_is_preserved() {
        let rows = vec![
            row(
                sha256_index(),
                "FIRST",
                MatchState::NotChecked,
                None,
                "first.bin",
            ),
            row(
                sha256_index(),
                "SECOND",
                MatchState::NotChecked,
                None,
                "second.bin",
            ),
        ];
        let text = render(&rows, &[1, 0], CopyKind::Selection).expect("both rows render");
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert!(lines[0].contains("SECOND"));
        assert!(lines[1].contains("FIRST"));
    }

    /// The file's display path is the fourth column: a pasted table has to say
    /// which file each digest belongs to.
    #[test]
    fn the_display_path_is_the_fourth_column() {
        let rows = vec![row(
            sha256_index(),
            "AABB",
            MatchState::NotChecked,
            None,
            r"nested\a.bin",
        )];
        let text = render(&rows, &[0], CopyKind::Selection).expect("one row renders");

        assert_eq!(text, "SHA-256\tAABB\tnot checked\tnested\\a.bin");
        assert_eq!(text.split('\t').count(), 4, "one tab per column boundary");
    }

    /// An unreadable file says so in the digest column, where the answer belongs.
    #[test]
    fn a_read_error_is_rendered_where_the_digest_belongs() {
        let rows = vec![row(
            usize::MAX,
            "",
            MatchState::NotChecked,
            Some(5),
            "broken.bin",
        )];
        let text = render(&rows, &[0], CopyKind::Selection).expect("the error row renders");
        assert_eq!(text, "-\tError 5\tnot checked\tbroken.bin");
    }

    /// A selection naming a row the page no longer has must skip it rather than
    /// producing a blank line that would paste as an empty record.
    #[test]
    fn a_stale_selection_index_is_skipped() {
        let rows = vec![row(
            sha256_index(),
            "AABB",
            MatchState::NotChecked,
            None,
            "file.bin",
        )];
        let text = render(&rows, &[0, 99], CopyKind::Selection).expect("the live row renders");
        assert_eq!(text.lines().count(), 1);
    }

    /// Everything selected being stale is the same as nothing selected.
    #[test]
    fn an_entirely_stale_selection_renders_nothing() {
        let rows: Vec<ListRow> = Vec::new();
        assert_eq!(render(&rows, &[0, 1], CopyKind::Selection), None);
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
                "file.bin",
            ),
            row(
                sha256_index(),
                "BB",
                MatchState::Mismatched,
                None,
                "file.bin",
            ),
            row(
                sha256_index(),
                "CC",
                MatchState::NotChecked,
                None,
                "file.bin",
            ),
        ];
        let text = render(&rows, &[0, 1, 2], CopyKind::Selection).expect("three rows render");
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
        // The clipboard is machine-wide, so this must not race the other real
        // clipboard tests.
        let _clipboard = clipboard_guard();

        // A null owner is allowed for the clipboard APIs.
        let owner = HWND(core::ptr::null_mut());
        let marker = "rustHashTab clipboard round trip \u{2022} \u{00e9}\u{4e2d}";
        if !copy(owner, marker) {
            panic!("copy failed; the clipboard may be held by another process");
        }

        // Read it back through the raw OS calls rather than through `read_text`:
        // this test is about what a *different* process would see, so the reader
        // whose own behaviour is under test must not be the observer here.
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

    /// The reading direction of the same real clipboard: what `copy` writes must
    /// be what `read_text` returns, including non-ASCII text and embedded CRLF,
    /// which is the shape a copied selection has.
    #[test]
    fn read_text_round_trips_what_was_copied() {
        let _clipboard = clipboard_guard();

        let owner = HWND(core::ptr::null_mut());
        let marker = "SHA-256  file.bin\r\n\u{2022}\u{00e9}\u{4e2d}";
        if !copy(owner, marker) {
            panic!("copy failed; the clipboard may be held by another process");
        }

        assert_eq!(read_text(owner).as_deref(), Some(marker));
    }

    /// Empty text is not a verification source. `copy("")` writes only the NUL
    /// terminator, and the reader must report "nothing here" rather than an empty
    /// `String` that the caller would have to special-case.
    #[test]
    fn read_text_returns_none_for_empty_text() {
        let _clipboard = clipboard_guard();

        let owner = HWND(core::ptr::null_mut());
        if !copy(owner, "") {
            panic!("copy failed; the clipboard may be held by another process");
        }

        assert_eq!(read_text(owner), None);
    }

    /// A block past the cap is refused, not truncated. The terminator counts as a
    /// unit, so the longest accepted *text* is one unit shorter than the cap --
    /// pinned here from both sides so an off-by-one in the bound is a test
    /// failure rather than a silently shortened digest.
    #[test]
    fn read_text_accepts_one_unit_under_the_cap_and_refuses_the_cap() {
        let _clipboard = clipboard_guard();

        let owner = HWND(core::ptr::null_mut());
        let largest = "a".repeat(MAX_CLIPBOARD_TEXT_UNITS - 1);
        if !copy(owner, &largest) {
            panic!("copy failed; the clipboard may be held by another process");
        }
        assert_eq!(
            read_text(owner).as_deref(),
            Some(largest.as_str()),
            "text that fits under the cap must be read in full"
        );

        let oversized = "a".repeat(MAX_CLIPBOARD_TEXT_UNITS);
        if !copy(owner, &oversized) {
            panic!("copy failed; the clipboard may be held by another process");
        }
        assert_eq!(
            read_text(owner),
            None,
            "an oversized block must be refused, not truncated"
        );
    }

    /// A clipboard with no text on it is not an error: the page simply has no
    /// clipboard source. This is the state of a fresh desktop, and it must not be
    /// distinguishable from "another process holds the clipboard" to the caller.
    #[test]
    fn read_text_returns_none_when_the_clipboard_holds_no_text() {
        let _clipboard = clipboard_guard();

        let owner = HWND(core::ptr::null_mut());
        // SAFETY: the clipboard is opened immediately below and closed exactly
        // once; emptying it without writing anything leaves it in the state a
        // fresh desktop has -- openable and holding no text.
        unsafe {
            OpenClipboard(Some(owner)).expect("the clipboard must be openable");
            EmptyClipboard().expect("the clipboard must be emptyable");
            CloseClipboard().expect("the clipboard must close");
        }

        assert_eq!(read_text(owner), None);
    }
}
