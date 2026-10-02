//! The dialog procedure for the property sheet page.
//!
//! # This is the shell's thread
//!
//! Every message here arrives on the thread that owns the Properties dialog.
//! Blocking that thread freezes the dialog; panicking in it would unwind into a
//! dialog procedure, which `comctl32` calls through an `extern "system"` slot and
//! which would therefore abort `explorer.exe` rather than our own process. So
//! nothing in here does I/O, file system work, or waits on the hashing thread.
//!
//! # Two lifetimes, not one
//!
//! The dialog window and the property sheet *page* are separate objects. The
//! window is destroyed first, and `PSPCB_RELEASE` may arrive later; between the
//! two, messages already in the window's queue are still delivered to a window
//! whose messages are about to mean nothing. Clearing `GWLP_USERDATA` on
//! `WM_NCDESTROY` is what makes those late messages harmless instead of a
//! read of freed memory.
//!
//! # Which message does what, and why each is where it is
//!
//! | Message | Used for | Why not another |
//! |---|---|---|
//! | `WM_APP + n` | our own progress, results and completion | `WM_USER` belongs to the property sheet manager: `PSN_*` starts there and `PSM_*` at `WM_USER + 100` |
//! | `WM_COMMAND` / `WM_NOTIFY` | the Copy button and the list view | the standard route for a child control, and the route `NM_CUSTOMDRAW` arrives through |
//! | `WM_DESTROY` | teardown | **not** `WM_NCDESTROY`: the window has to still exist while the hashing thread is joined |
//! | `WM_NCDESTROY` | clear `GWLP_USERDATA` only | it means the window has gone, so nothing may assume a window handle works afterwards |
//!
//! A property page is a **modeless** dialog: `EndDialog` must never be called from
//! here, and every message that was handled has to return `TRUE`.

#![cfg(windows)]

use crate::session::{ReadoutSession, Shared};
use crate::{DialogState, resource};
use std::sync::Arc;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{
    PBM_SETPOS, PBM_SETRANGE32, PROPSHEETPAGEW, PSPCB_MESSAGE, PSPCB_RELEASE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetDlgItem, GetParent, SendMessageW, SetWindowTextW, WM_APP, WM_COMMAND, WM_DESTROY,
    WM_INITDIALOG, WM_NCDESTROY, WM_NOTIFY, WM_SETFONT,
};
use windows::core::PCWSTR;

/// The page has results waiting for the dialog thread.
///
/// # Why `WM_APP` and not `WM_USER`
///
/// The property sheet manager owns the `WM_USER` range: `PSM_*` starts at
/// `WM_USER + 100` and the `PSN_*` notifications start at `WM_USER`. A private
/// message placed there would collide with the sheet's own traffic, and a handler
/// that acted on someone else's message would be a bug that only shows up on the
/// Windows version that uses that particular value. `WM_APP` is the range
/// reserved for exactly this.
pub const WM_FILE_FINISHED: u32 = WM_APP + 1;
/// Cumulative progress; `lParam` counts steps towards [`crate::PROGRESS_RESOLUTION`].
pub const WM_FILE_PROGRESS: u32 = WM_APP + 2;
/// The scan is over, successfully or not.
pub const WM_SCAN_FINISHED: u32 = WM_APP + 3;

/// The page's dialog procedure.
///
/// # Safety
///
/// Called by `comctl32`, which owns the window and defines the message
/// parameters. `WM_INITDIALOG`'s `lparam` points to the `PROPSHEETPAGEW` copy
/// that API passes for a page created by `CreatePropertySheetPageW`.
pub extern "system" fn dlg_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match message {
        WM_INITDIALOG => on_init(hwnd, lparam),
        WM_DESTROY => {
            // The window still exists here, which is the reason teardown is on this
            // message rather than on `WM_NCDESTROY`: joining the hashing thread
            // wants a window that has not started going away.
            on_destroy(hwnd);
            1
        }
        WM_NCDESTROY => {
            // Runs *before* anything else, because a message already in the queue
            // will still be dispatched here after this returns; it must not find a
            // `DialogState` that the page callback is about to free.
            crate::window_data::store(hwnd, 0);
            0
        }
        WM_SETFONT => {
            on_set_font(hwnd, wparam);
            1
        }
        WM_COMMAND => {
            on_command(hwnd, wparam);
            1
        }
        WM_NOTIFY => on_notify(hwnd, lparam),
        WM_FILE_FINISHED | WM_FILE_PROGRESS | WM_SCAN_FINISHED => {
            on_scan_message(hwnd, message, wparam, lparam);
            1
        }
        _ => 0,
    }
}

/// `WM_INITDIALOG`: take ownership of the state and start hashing.
fn on_init(hwnd: HWND, lparam: LPARAM) -> isize {
    if lparam.0 == 0 {
        return 0;
    }

    // SAFETY: for a property sheet page, `comctl32` passes a *copy of the
    // `PROPSHEETPAGEW`* as `lParam` on `WM_INITDIALOG` -- not the page's own
    // `lParam`. Reading the state out of `(*page).lParam` is the documented
    // route, and taking `lparam` itself as the state pointer is the classic way to
    // crash explorer here.
    let state_pointer = unsafe {
        let page = lparam.0 as *const PROPSHEETPAGEW;
        (*page).lParam.0 as *mut DialogState
    };

    if state_pointer.is_null() {
        return 0;
    }

    // The page owns that allocation and the page outlives this window.
    crate::window_data::store(hwnd, state_pointer as isize);

    // SAFETY: as above. The borrow ends with this function; the window's copy of
    // the pointer is what later messages use.
    let state = unsafe { &mut *state_pointer };
    state.attach(hwnd);

    // The font is adopted before the columns are measured, or they are sized for the
    // wrong typeface. The sheet sends `WM_SETFONT` to the page and then to its
    // children; `on_set_font` re-measures when it arrives.
    let font = dialog_font(hwnd);
    build_controls(hwnd, state, font);
    start_hashing(hwnd, state);

    // TRUE, so the dialog manager keeps the window. Returning FALSE here would let
    // it destroy a window the shell is about to display.
    1
}

/// Find the page's controls and give them their initial content.
fn build_controls(hwnd: HWND, state: &mut DialogState, font: isize) {
    // SAFETY: `hwnd` is the page dialog and the identifiers are the ones the
    // compiled template declares, so each lookup returns that control or nothing.
    unsafe {
        if let Some(list) = control(hwnd, resource::IDC_HASH_LIST) {
            crate::listview::adopt_font(list, font);
            crate::listview::add_columns(list);
            state.list = Some(list);
        }
        if let Some(status) = control(hwnd, resource::IDC_HASH_STATUS) {
            crate::listview::adopt_font(status, font);
            state.status = Some(status);
            set_status(status, resource::STATUS_STARTING);
        }
        if let Some(progress) = control(hwnd, resource::IDC_HASH_PROGRESS) {
            // The bar is reported in steps of `PROGRESS_RESOLUTION`, not in bytes: a
            // byte count does not fit `PBM_SETRANGE32` and would silently wrap.
            SendMessageW(
                progress,
                PBM_SETRANGE32,
                Some(WPARAM(0)),
                Some(LPARAM(crate::PROGRESS_RESOLUTION as isize)),
            );
        }
    }
}

/// Start the scan on the page's own thread.
///
/// Returns immediately: the expansion of the selection and every file read happen on
/// that thread, because this one belongs to the Properties dialog.
fn start_hashing(hwnd: HWND, state: &mut DialogState) {
    let display = crate::session::Display {
        enabled: state.enabled.clone(),
        uppercase: state.settings.display_uppercase,
    };
    let shared = Arc::new(Shared::new());
    let session = ReadoutSession::start(
        state.roots.clone(),
        display,
        hwnd.0 as isize,
        Arc::clone(&shared),
    );
    state.session = Some(session);
}

/// `WM_DESTROY`: stop the hashing thread while the window still exists.
fn on_destroy(hwnd: HWND) {
    // SAFETY: `hwnd` is the page dialog; the pointer was stored by `on_init` and the
    // page owns the allocation until `PSPCB_RELEASE`.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let Some(session) = state.session.take() else {
        return;
    };

    // Retire the generation *before* cancelling: the sink checks this counter before
    // every post, so bumping it first means no post is even attempted for a window
    // that is going away.
    session.shared().retire();

    // Bounded, because the scan cancels its outstanding reads rather than waiting
    // for them to finish.
    let _ = session.finish(std::time::Duration::from_secs(30));
}

/// `WM_SETFONT` from the property sheet manager.
fn on_set_font(hwnd: HWND, wparam: WPARAM) {
    let font = wparam.0 as isize;
    if font == 0 {
        return;
    }

    // SAFETY: the controls belong to this dialog, and the font is the one the sheet
    // selected for it, so it outlives them.
    unsafe {
        for id in [resource::IDC_HASH_LIST, resource::IDC_HASH_STATUS] {
            if let Some(control) = control(hwnd, id) {
                crate::listview::adopt_font(control, font);
            }
        }
    }

    // The columns were measured against whatever font was current when the page was
    // built, which may have been the system font. The sheet's font is authoritative,
    // so they are re-measured -- a column sized for the wrong face shows truncated
    // text, which is the most visible way a page fails to follow the host.
    // SAFETY: `hwnd` is the page dialog.
    let list = unsafe { state(hwnd) }.and_then(|state| state.list);
    if let Some(list) = list {
        crate::listview::remeasure_columns(list);
    }
}

/// `WM_COMMAND`: the Copy button.
fn on_command(hwnd: HWND, wparam: WPARAM) {
    let id = (wparam.0 & 0xFFFF) as i32;
    if id != resource::IDC_HASH_COPY {
        return;
    }

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let Some(list) = state.list else {
        return;
    };

    let selected = crate::listview::selected_rows(list);
    let Some(text) = crate::clipboard::render(&state.rows, &selected) else {
        // Nothing selected. Deliberately not an error, and deliberately not an empty
        // string: replacing the clipboard would destroy whatever the user copied
        // before.
        return;
    };

    let _ = crate::clipboard::copy(hwnd, &text);
}

/// `WM_NOTIFY`: the list view's custom draw.
fn on_notify(hwnd: HWND, lparam: LPARAM) -> isize {
    use windows::Win32::UI::Controls::{NM_CUSTOMDRAW, NMHDR};

    if lparam.0 == 0 {
        return 0;
    }

    // SAFETY: the sender filled in the `NMHDR` at the start of the structure, and the
    // notification code is the documented way to tell which notification this is.
    let code = unsafe { (*(lparam.0 as *const NMHDR)).code };
    if code != NM_CUSTOMDRAW {
        return 0;
    }

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return 0;
    };

    // SAFETY: the notification came from the list view, and `colour_row` checks the
    // draw stage before touching anything.
    let ours = unsafe { crate::listview::colour_row(lparam, &state.rows) };
    if ours {
        crate::listview::custom_draw_result()
    } else {
        // Not a stage we colour. Answering with anything but zero here would tell the
        // control it need not paint itself, which is a list that never draws.
        0
    }
}

/// One of the page's own messages: results, progress, or completion.
fn on_scan_message(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) {
    // The decision belongs to a pure function, so it can be tested without a window
    // and so the rule "ignore anything that is not ours" lives in exactly one place.
    // SAFETY: `hwnd` is the page dialog; a null state is the answer `route` needs.
    let has_state = unsafe { crate::dialog::state(hwnd) }.is_some();

    match crate::route::route(message, wparam.0, lparam.0, has_state) {
        crate::route::Route::NotOurs | crate::route::Route::NoState => {}
        crate::route::Route::Progress(steps) => update_progress(hwnd, steps),
        crate::route::Route::Results => drain_rows(hwnd),
        crate::route::Route::Finished => on_scan_finished(hwnd),
    }
}

/// Move the progress bar.
fn update_progress(hwnd: HWND, steps: u64) {
    // SAFETY: the control belongs to this dialog and is checked before use.
    unsafe {
        if let Some(progress) = control(hwnd, resource::IDC_HASH_PROGRESS) {
            SendMessageW(
                progress,
                PBM_SETPOS,
                Some(WPARAM(steps as usize)),
                Some(LPARAM(0)),
            );
        }
    }
}

/// Append whatever the hashing thread has produced, then rewrite the status line.
fn drain_rows(hwnd: HWND) {
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let Some(shared) = state.session.as_ref().map(ReadoutSession::shared).cloned() else {
        return;
    };

    let readouts = shared.drain();
    if readouts.is_empty() {
        return;
    }

    let list = state.list;
    let first_new_row = state.rows.len();
    for readout in readouts {
        state.rows.extend(readout.rows);
    }

    if let Some(list) = list {
        for (offset, row) in state.rows[first_new_row..].iter().enumerate() {
            crate::listview::insert_row(list, first_new_row + offset, row);
        }
    }

    refresh_status(hwnd, state, &shared);
}

/// The scan is over: a final drain, a full bar, and the finished status line.
fn on_scan_finished(hwnd: HWND) {
    // Drain once more, because completion can arrive with rows still queued -- a page
    // that stopped at "finished" while rows were pending would show a short list.
    drain_rows(hwnd);
    update_progress(hwnd, crate::PROGRESS_RESOLUTION);

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let Some(shared) = state.session.as_ref().map(ReadoutSession::shared).cloned() else {
        return;
    };
    refresh_status(hwnd, state, &shared);
}

/// Rewrite the status line from what the hashing thread reports.
fn refresh_status(hwnd: HWND, state: &DialogState, shared: &Arc<Shared>) {
    let _ = hwnd;
    let Some(status) = state.status else {
        return;
    };

    let text = if shared.is_cancelled() && !shared.is_finished() {
        String::from(resource::STATUS_CANCELLED)
    } else if shared.is_finished() {
        resource::status_finished_with_skipped(&shared.counters(), shared.skipped())
    } else {
        let (done, total) = shared.file_counts();
        resource::status_running(done, total, &shared.counters())
    };

    set_status(status, &text);
}

/// Put text on the status line.
fn set_status(status: HWND, text: &str) {
    // The `Static` is replaced rather than appended: the line is a summary, not a log.
    let wide: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
    // SAFETY: `status` is the page's own static control, and the string outlives the
    // call, which copies it.
    unsafe {
        let _ = SetWindowTextW(status, PCWSTR(wide.as_ptr()));
    }
}

/// The font the property sheet selected for the page.
///
/// `comctl32` sends `WM_SETFONT` to the page and then to its children, so asking the
/// parent is how the page learns the font before it has to measure anything. A font
/// that cannot be determined becomes `0`, and every caller treats that as "use the
/// default".
fn dialog_font(hwnd: HWND) -> isize {
    // SAFETY: both handles are live windows or null, which the API accepts.
    unsafe {
        let parent = GetParent(hwnd).unwrap_or_default();
        if parent.is_invalid() {
            return 0;
        }
        SendMessageW(
            parent,
            windows::Win32::UI::WindowsAndMessaging::WM_GETFONT,
            Some(WPARAM(0)),
            Some(LPARAM(0)),
        )
        .0
    }
}

/// The state behind a window, or `None` once `WM_NCDESTROY` has run.
///
/// # Safety
///
/// `hwnd` must be a page dialog created from a `PROPSHEETPAGEW` this module built,
/// or a window that never had one associated with it.
pub(crate) unsafe fn state(hwnd: HWND) -> Option<&'static mut DialogState> {
    // The slot is only ever written by this module, and `WM_NCDESTROY` clears it,
    // which is what makes the check below mean "the window is gone" rather than "no
    // state was ever set".
    let stored = crate::window_data::load(hwnd);
    if !crate::window_data::holds_address(stored) {
        return None;
    }

    // SAFETY: a non-zero value here was stored by `on_init` from a `lParam` this
    // module created, and the page owns that allocation until `PSPCB_RELEASE`.
    Some(unsafe { &mut *(stored as *mut DialogState) })
}

/// Look up one of the page's controls.
///
/// # Safety
///
/// `hwnd` must be the page dialog, and `id` one the compiled template declares.
unsafe fn control(hwnd: HWND, id: i32) -> Option<HWND> {
    // SAFETY: the caller promises the window and the identifier.
    unsafe { GetDlgItem(Some(hwnd), id) }.ok()
}

/// The page callback's address, as the page structure's `pfnCallback`.
///
/// # Why this is a function rather than the symbol itself
///
/// Clippy denies a safe function that dereferences a raw-pointer argument, and the
/// fix it wants -- declaring the function `unsafe` -- is not available here:
/// `LPFNPSPCALLBACKW` names a plain `extern "system" fn`, and a callback whose
/// signature does not match what `comctl32` calls through is simply the wrong
/// function. Taking the address in a safe function confines the allowance to one
/// line, where the fixed C signature is obvious, instead of spreading it over the
/// body.
pub(crate) fn page_callback() -> windows::Win32::UI::Controls::LPFNPSPCALLBACKW {
    Some(raw_page_callback)
}

/// The page callback: the **only** place the page's state is reclaimed.
///
/// Called by `comctl32`, which passes the page it is releasing. `ppsp` is non-null
/// for the messages this handles, and its `lParam` is the pointer `page::add_page`
/// stored.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "system" fn raw_page_callback(
    _hwnd: HWND,
    message: PSPCB_MESSAGE,
    ppsp: *mut PROPSHEETPAGEW,
) -> u32 {
    if message == PSPCB_RELEASE && !ppsp.is_null() {
        // SAFETY: `comctl32` passed the page structure it is releasing, and the
        // `lParam` in it is the pointer `page::add_page` stored.
        let pointer = unsafe { (*ppsp).lParam.0 as *mut DialogState };

        if !pointer.is_null() {
            // SAFETY: this is the single place the pointer is reclaimed, this message
            // is delivered once per page, and the page is gone by the time it arrives.
            // The allocation came from `Box::into_raw` in `page::add_page`.
            let mut state = unsafe { Box::from_raw(pointer) };

            // Belt and braces. `WM_DESTROY` has normally already joined the thread,
            // but if the window was never created -- the sheet accepted the page
            // handle and then refused the page -- this is the only chance, and a
            // session dropped without being finished would join here instead.
            if let Some(session) = state.session.take() {
                session.shared().retire();
                let _ = session.finish(std::time::Duration::from_secs(30));
            }
        }
    }

    // The return value is ignored for `PSPCB_RELEASE`; 1 is what the other messages
    // expect.
    1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{MESSAGE_MAGIC, PROGRESS_RESOLUTION};

    #[test]
    fn the_private_messages_are_in_the_application_range() {
        // The property sheet manager owns `WM_USER`: `PSN_*` starts there and
        // `PSM_*` at `WM_USER + 100`. A private message placed in that range would
        // fire on the sheet's own traffic.
        for message in [WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_SCAN_FINISHED] {
            assert!(
                (WM_APP..WM_APP + 0x8000).contains(&message),
                "{message:#x} is not in the WM_APP range"
            );
        }
    }

    #[test]
    fn the_private_messages_are_distinct() {
        let mut all = vec![WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_SCAN_FINISHED];
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 3);
    }

    /// The private messages must not be mistakable for the notifications the list
    /// view sends -- those arrive through `WM_NOTIFY`, so a handler that matched on
    /// the wrong one would act on the wrong thing.
    #[test]
    fn the_private_messages_are_not_list_view_notifications() {
        use windows::Win32::UI::Controls::{LVN_ITEMCHANGED, NM_CUSTOMDRAW};
        for message in [WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_SCAN_FINISHED] {
            assert_ne!(message, NM_CUSTOMDRAW);
            assert_ne!(message, LVN_ITEMCHANGED);
        }
    }

    /// `MESSAGE_MAGIC` authenticates our own messages through `wParam`, which is
    /// pointer-width. On a 64-bit build a 32-bit constant would still fit, but on a
    /// 32-bit build a 64-bit one would not -- the failure that made the gate cover
    /// i686 in the first place.
    #[test]
    fn the_magic_fits_the_message_parameter() {
        assert_eq!(
            core::mem::size_of_val(&MESSAGE_MAGIC),
            core::mem::size_of::<isize>()
        );
    }

    /// The resolution is both a divisor in the router and the range of the progress
    /// bar. Zero would be a division by zero on the shell's thread, and a value that
    /// does not fit an `i32` would silently wrap in `PBM_SETRANGE32`.
    #[test]
    fn the_progress_resolution_fits_both_of_its_uses() {
        const { assert!(PROGRESS_RESOLUTION > 0) };
        assert!(
            i32::try_from(PROGRESS_RESOLUTION).is_ok(),
            "the bar is set with PBM_SETRANGE32, which takes an i32"
        );
    }

    /// Teardown is on `WM_DESTROY` and the user-data slot is cleared on
    /// `WM_NCDESTROY`; those are different messages and must stay different, or
    /// either the join happens against a disappearing window or a late message reads
    /// freed state.
    #[test]
    fn teardown_and_the_guard_are_different_messages() {
        use windows::Win32::UI::WindowsAndMessaging::{WM_DESTROY, WM_NCDESTROY};
        assert_ne!(WM_DESTROY, WM_NCDESTROY);
    }
}
