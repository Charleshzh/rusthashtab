//! The dialog procedure for the property sheet page.
//!
//! # This is the shell's thread
//!
//! Every message here arrives on the thread that owns the Properties dialog.
//! Blocking that thread freezes the dialog; panicking in it would unwind into a
//! dialog procedure, which `comctl32` calls through an `extern "system"` slot and
//! which would therefore abort `explorer.exe` rather than our own process. So
//! nothing in here does file system work, and nothing waits on the hashing thread.
//!
//! The two things that *do* run here are deliberate and bounded:
//!
//! * **Modal dialogs.** `GetOpenFileNameW`, `GetSaveFileNameW` and the settings
//!   dialog block the shell's thread because that is what a modal dialog does; the
//!   user chose to open it, and it has its own message loop.
//! * **One registry write.** Saving settings is a handful of `RegSetValueExW`
//!   calls, microseconds, the counterpart of the settings *read* `AddPages`
//!   already performs on this thread. A failure is reported and the old settings
//!   stay in effect.
//!
//! Everything that touches a file -- reading a checksum file, writing an export --
//! runs on a [`crate::task::Background`] worker and reports back through
//! `WM_VERIFY_READY` / `WM_EXPORT_DONE`, each carrying a sequence number so a
//! superseded request's result is ignored.
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
//! | `WM_APP + n` | progress, results, completion, and the two background tasks | `WM_USER` belongs to the property sheet manager: `PSN_*` starts there and `PSM_*` at `WM_USER + 100` |
//! | `WM_COMMAND` / `WM_NOTIFY` | Copy, Check, Verify, Export, Settings, and the list view | the standard route for a child control, and the route `NM_CUSTOMDRAW` arrives through |
//! | `WM_DESTROY` | teardown | **not** `WM_NCDESTROY`: the window has to still exist while the hashing thread and the background tasks are joined |
//! | `WM_NCDESTROY` | clear `GWLP_USERDATA` only | it means the window has gone, so nothing may assume a window handle works afterwards |
//!
//! A property page is a **modeless** dialog: `EndDialog` must never be called from
//! here, and every message that was handled has to return `TRUE`.

#![cfg(windows)]

use crate::DialogState;
use crate::resource;
use crate::session::{ReadoutSession, Shared, VerificationInfo};
use crate::task::{Background, TaskError};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::Win32::UI::Controls::{
    PBM_SETPOS, PBM_SETRANGE32, PROPSHEETPAGEW, PSPCB_MESSAGE, PSPCB_RELEASE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetDlgItem, GetParent, GetWindowTextW, MB_ICONERROR, MB_OK, MessageBoxW, SendMessageW,
    SetWindowTextW, WM_APP, WM_COMMAND, WM_DESTROY, WM_INITDIALOG, WM_NCDESTROY, WM_NOTIFY,
    WM_SETFONT,
};
use windows::core::{PCWSTR, PWSTR, w};

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
/// A checksum file has been read and matched; `lParam` is the request's sequence.
pub const WM_VERIFY_READY: u32 = WM_APP + 4;
/// An export has been written (or failed); `lParam` is the request's sequence.
pub const WM_EXPORT_DONE: u32 = WM_APP + 5;

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
        WM_FILE_FINISHED | WM_FILE_PROGRESS | WM_SCAN_FINISHED | WM_VERIFY_READY
        | WM_EXPORT_DONE => {
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
        look_for_sumfiles: state.settings.look_for_sumfiles,
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

/// `WM_DESTROY`: stop the hashing thread and join any file work.
///
/// The window still exists here, which is why teardown is on this message rather
/// than on `WM_NCDESTROY`: the join wants a window that has not started going
/// away.
fn on_destroy(hwnd: HWND) {
    // SAFETY: `hwnd` is the page dialog; the pointer was stored by `on_init` and the
    // page owns the allocation until `PSPCB_RELEASE`.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };

    // Retiring the generation first is what makes every notification sink -- the
    // scan's and the background tasks' -- stop posting: they all compare against
    // this counter before calling `PostMessageW`.
    if let Some(session) = state.session.take() {
        session.shared().retire();
        // Bounded, because the scan cancels its outstanding reads rather than
        // waiting for them to finish.
        let _ = session.finish(std::time::Duration::from_secs(30));
    }

    // Dropping a task joins its worker. Both are bounded: a checksum file is
    // capped at 16 MiB and an export is a small write, so this cannot turn into an
    // open-ended wait on the shell's thread.
    state.verify_task = None;
    state.export_task = None;
    state.verify_source = None;
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

/// `WM_COMMAND`: the page's buttons.
fn on_command(hwnd: HWND, wparam: WPARAM) {
    let id = (wparam.0 & 0xFFFF) as i32;
    match id {
        resource::IDC_HASH_COPY => copy_selection(hwnd),
        resource::IDC_HASH_CHECK => check_pasted(hwnd),
        resource::IDC_HASH_VERIFY => choose_verification(hwnd),
        resource::IDC_HASH_EXPORT => export_hashes(hwnd),
        resource::IDC_HASH_SETTINGS => open_settings(hwnd),
        _ => {}
    }
}

/// Copy the selected rows to the clipboard.
fn copy_selection(hwnd: HWND) {
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

/// The shared state of the running session, if the page has one.
fn shared_state(hwnd: HWND) -> Option<Arc<Shared>> {
    // SAFETY: `hwnd` is the page dialog.
    let state = unsafe { crate::dialog::state(hwnd) }?;
    state
        .session
        .as_ref()
        .map(|session| Arc::clone(session.shared()))
}

/// `Check`: parse the pasted digest and apply it to one file.
///
/// The target is the file whose row is selected, because a digest belongs to one
/// file. With exactly one file in the page and no selection, that file is the
/// only possible target; with several, guessing would mark unrelated files red.
fn check_pasted(hwnd: HWND) {
    let Some(shared) = shared_state(hwnd) else {
        return;
    };

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let status = state.status;

    // SAFETY: `hwnd` is the page dialog and the identifier is one its template
    // declares.
    let Some(edit) = (unsafe { control(hwnd, resource::IDC_HASH_EXPECTED) }) else {
        return;
    };
    let text = dialog_text(edit);
    let Some(digest) = crate::verify::parse_pasted(&text) else {
        set_status_on(status, resource::STATUS_NOT_HEX);
        return;
    };

    // A digest no enabled algorithm can produce is not a mismatch; applying it
    // would tell the user their file is wrong when the truth is that the two were
    // never comparable.
    let usable = state.enabled.iter().enumerate().any(|(index, enabled)| {
        *enabled
            && rusthashtab_hash::ALGORITHMS
                .get(index)
                .is_some_and(|algorithm| algorithm.output_len == digest.len())
    });
    if !usable {
        set_status_on(status, resource::STATUS_NO_MATCHING_LENGTH);
        return;
    }

    let jobs = shared.jobs();
    let selected = state
        .list
        .map(crate::listview::selected_rows)
        .unwrap_or_default();
    let target = selected
        .first()
        .and_then(|row| state.rows.get(*row))
        .map(|row| row.job_index)
        .or(if jobs.len() == 1 { Some(0) } else { None });
    let Some(target) = target else {
        set_status_on(status, resource::STATUS_SELECT_FILE);
        return;
    };

    let mut expected = shared.expected_all();
    if expected.len() < jobs.len() {
        expected.resize(jobs.len(), Vec::new());
    }
    if let Some(slot) = expected.get_mut(target) {
        *slot = vec![digest];
    }
    shared.set_expected(expected);
    shared.set_verification(VerificationInfo {
        source: resource::PASTED_SOURCE.to_string(),
        unmatched: 0,
        had_error: false,
    });

    rebuild_and_refresh(hwnd);
}

/// `Verify...`: read a checksum file and match it against the hashed files.
fn choose_verification(hwnd: HWND) {
    let Some(shared) = shared_state(hwnd) else {
        return;
    };

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };

    let jobs = shared.jobs();
    if jobs.is_empty() {
        // The scan has not expanded the selection yet, so there is nothing a
        // checksum file could be matched against. Saying so is more useful than
        // reporting every entry as unmatched.
        set_status_on(state.status, resource::STATUS_EMPTY);
        return;
    }

    let Some(path) = open_checksum_file(hwnd) else {
        // Cancelled, or the dialog could not be shown. Neither is an error the
        // user needs to be told about.
        return;
    };

    state.verify_source = Some(resource::sumfile_source(&path));
    state.verify_seq = state.verify_seq.wrapping_add(1);
    let sequence = state.verify_seq;
    let generation = shared.generation.load(Ordering::Acquire);
    let notify = Arc::clone(&shared);
    let hwnd_token = hwnd.0 as isize;

    let task = Background::spawn(
        move || -> Result<crate::verify::SumfileMatch, String> {
            let parsed = crate::verify::read_sumfile(&path).map_err(|error| error.to_string())?;
            Ok(crate::verify::match_sumfile(&parsed, &path, &jobs))
        },
        WM_VERIFY_READY,
        sequence,
        hwnd_token,
        generation,
        notify,
    );

    state.verify_task = Some(task);
    set_status_on(state.status, resource::STATUS_VERIFYING);
}

/// `WM_VERIFY_READY`: apply a finished checksum-file match.
fn on_verify_ready(hwnd: HWND, sequence: u32) {
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    if sequence != state.verify_seq {
        // A superseded request: the user has started another verification since.
        return;
    }
    let Some(task) = state.verify_task.as_mut() else {
        return;
    };
    let Some(outcome) = task.take() else {
        return;
    };
    // Dropping the finished task joins a worker that has already stored its
    // result, which returns immediately.
    state.verify_task = None;

    let source = state
        .verify_source
        .take()
        .unwrap_or_else(|| String::from("checksum file"));
    let Some(shared) = shared_state(hwnd) else {
        return;
    };

    match outcome {
        Ok(Ok(matched)) => {
            shared.set_expected(matched.expected);
            shared.set_verification(VerificationInfo {
                source,
                unmatched: matched.unmatched,
                had_error: matched.had_error,
            });
            rebuild_and_refresh(hwnd);

            // A checksum file that names none of the files is worth saying out
            // loud; the counters alone would read as "everything not checked".
            let anything_expected = shared.expected_all().iter().any(|entry| !entry.is_empty());
            if !anything_expected {
                set_status_on(state.status, resource::STATUS_SUMFILE_NO_MATCH);
            }
        }
        Ok(Err(message)) => {
            set_status_on(state.status, resource::STATUS_SUMFILE_UNREADABLE);
            show_error(hwnd, &message);
        }
        Err(TaskError::Panicked | TaskError::SpawnFailed) => {
            set_status_on(state.status, resource::STATUS_SUMFILE_UNREADABLE);
        }
    }
}

/// `Export...`: write the hashes as a checksum file.
fn export_hashes(hwnd: HWND) {
    let Some(shared) = shared_state(hwnd) else {
        return;
    };

    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };

    let jobs = shared.jobs();
    let results = shared.results();
    if jobs.is_empty() || results.iter().all(Option::is_none) {
        set_status_on(state.status, resource::STATUS_NOTHING_TO_EXPORT);
        return;
    }

    let Some(target) = save_checksum_file(hwnd, &state.enabled) else {
        return;
    };

    let plan = match crate::export::plan(&target, &results, &jobs, &state.settings, &state.enabled)
    {
        Ok(plan) => plan,
        Err(error) => {
            set_status_on(state.status, resource::STATUS_EXPORT_FAILED);
            show_error(hwnd, &error.to_string());
            return;
        }
    };

    state.export_seq = state.export_seq.wrapping_add(1);
    let sequence = state.export_seq;
    let generation = shared.generation.load(Ordering::Acquire);
    let notify = Arc::clone(&shared);
    let task = Background::spawn(
        move || -> Result<usize, String> {
            crate::export::write(&plan).map_err(|error| error.to_string())
        },
        WM_EXPORT_DONE,
        sequence,
        hwnd.0 as isize,
        generation,
        notify,
    );

    state.export_task = Some(task);
    set_status_on(state.status, resource::STATUS_EXPORTING);
}

/// `WM_EXPORT_DONE`: report how the export went.
fn on_export_done(hwnd: HWND, sequence: u32) {
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    if sequence != state.export_seq {
        return;
    }
    let Some(task) = state.export_task.as_mut() else {
        return;
    };
    let Some(outcome) = task.take() else {
        return;
    };
    state.export_task = None;

    match outcome {
        Ok(Ok(count)) => set_status_on(state.status, &resource::status_exported(count)),
        Ok(Err(message)) => {
            set_status_on(state.status, resource::STATUS_EXPORT_FAILED);
            show_error(hwnd, &message);
        }
        Err(TaskError::Panicked | TaskError::SpawnFailed) => {
            set_status_on(state.status, resource::STATUS_EXPORT_FAILED);
        }
    }
}

/// `Settings...`: show the modal settings dialog and apply what it returns.
fn open_settings(hwnd: HWND) {
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };
    let Some(instance) = state.instance else {
        // Only a page created by `page::add_page` has the module handle; a page
        // hosted by a test does not, and has no template to open.
        set_status_on(state.status, resource::STATUS_SETTINGS_UNAVAILABLE);
        return;
    };
    let current = state.settings.clone();

    let Some(updated) = crate::settings_dialog::show(hwnd, instance, &current) else {
        return;
    };

    match updated.save(&crate::algorithm_names()) {
        Ok(()) => {
            // SAFETY: `hwnd` is the page dialog and still live; `open_settings`
            // was called from its own command handler.
            let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
                return;
            };
            state.settings = updated;
            state.enabled = crate::enabled_algorithms(&state.settings);
            restart_hashing(hwnd);
        }
        Err(error) => show_error(
            hwnd,
            &format!(
                "Could not save settings ({}: error {}).",
                error.value, error.code
            ),
        ),
    }
}

/// Rebuild the rows and counters from the results stored on `Shared`.
///
/// Called after anything that changes the verdicts -- a pasted digest, a
/// checksum file, a settings change -- so the list and the status line describe
/// the same result set.
fn rebuild_and_refresh(hwnd: HWND) {
    let Some(shared) = shared_state(hwnd) else {
        return;
    };
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };

    let jobs = shared.jobs();
    let results = shared.results();
    let expected = shared.expected_all();
    let (rows, counters) = crate::readout::rebuild_rows(
        &jobs,
        &results,
        &expected,
        &state.enabled,
        state.settings.display_uppercase,
    );

    state.rows = rows;
    if let Some(list) = state.list {
        crate::listview::set_rows(list, &state.rows);
    }
    shared.replace_counters(counters);
    refresh_status(hwnd, state, &shared);
}

/// Stop the current scan and start a new one with the current settings.
///
/// Used after the settings dialog returns something new: the algorithm set and
/// the display options are both fixed for the lifetime of a scan session, so the
/// honest way to apply a change is to run the scan again.
fn restart_hashing(hwnd: HWND) {
    // SAFETY: `hwnd` is the page dialog.
    let Some(state) = (unsafe { crate::dialog::state(hwnd) }) else {
        return;
    };

    if let Some(session) = state.session.take() {
        session.shared().retire();
        let _ = session.finish(std::time::Duration::from_secs(30));
    }
    state.verify_task = None;
    state.export_task = None;
    state.verify_source = None;

    state.rows.clear();
    if let Some(list) = state.list {
        crate::listview::set_rows(list, &[]);
    }
    update_progress(hwnd, 0);
    set_status_on(state.status, resource::STATUS_STARTING);
    start_hashing(hwnd, state);
}

/// The text in one of the page's controls.
fn dialog_text(control: HWND) -> String {
    let mut buffer = [0u16; 4096];
    // SAFETY: `control` is one of the page's controls, and `buffer` is a live
    // array of the declared length; the API copies at most that many units and
    // returns how many it copied.
    let length = unsafe { GetWindowTextW(control, &mut buffer) };
    let length = length.max(0) as usize;
    String::from_utf16_lossy(&buffer[..length.min(buffer.len())])
}

/// One entry in a common-dialog filter: a label and the patterns it covers.
type FilterEntry = (String, Vec<String>);

/// The filter for `Verify...`: the formats the parser reads.
fn open_filter_entries() -> Vec<FilterEntry> {
    let mut patterns: Vec<String> = Vec::new();
    for extension in ["sha256", "sha1", "md5", "sha512", "sfv", "hash", "txt"] {
        patterns.push(format!("*.{extension}"));
    }
    vec![
        (String::from("Checksum files"), patterns),
        (String::from("All files"), vec![String::from("*.*")]),
    ]
}

/// The filter for `Export...`, built from the enabled algorithms.
///
/// One entry per enabled algorithm that has a checksum-file extension, plus SFV
/// when CRC32 is enabled and corz `.hash` when any secure algorithm is. The
/// extension the user ends up with is what selects the format -- the filter is a
/// guide, not the decision -- because a Save dialog cannot stop a user from
/// typing a different one.
fn save_filter_entries(enabled: &[bool]) -> Vec<FilterEntry> {
    let mut entries: Vec<FilterEntry> = Vec::new();

    for (index, algorithm) in rusthashtab_hash::ALGORITHMS.iter().enumerate() {
        if !enabled.get(index).copied().unwrap_or(false) || algorithm.extensions.is_empty() {
            continue;
        }
        let patterns = algorithm
            .extensions
            .iter()
            .map(|extension| format!("*.{extension}"))
            .collect();
        entries.push((format!("{} checksums", algorithm.name), patterns));
    }

    let is_enabled = |name: &str| -> bool {
        rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == name)
            .is_some_and(|index| enabled.get(index).copied().unwrap_or(false))
    };
    if is_enabled("CRC32") {
        entries.push((String::from("SFV checksums"), vec![String::from("*.sfv")]));
    }
    let any_secure = rusthashtab_hash::ALGORITHMS
        .iter()
        .enumerate()
        .any(|(index, algorithm)| algorithm.secure && enabled.get(index).copied().unwrap_or(false));
    if any_secure {
        entries.push((String::from("corz .hash"), vec![String::from("*.hash")]));
    }

    entries.push((String::from("All files"), vec![String::from("*.*")]));
    entries
}

/// The extension a Save dialog should append when the user types none.
///
/// The first filter's first pattern, unless that filter is `All files` -- in
/// which case there is no sensible extension and the field stays null.
fn default_extension(entries: &[FilterEntry]) -> Option<String> {
    let (_, patterns) = entries.first()?;
    let first = patterns.first()?;
    let extension = first.strip_prefix("*.")?;
    (extension != "*").then(|| String::from(extension))
}

/// A common-dialog filter block: `label\0patterns\0...\0\0`.
fn filter_block(entries: &[FilterEntry]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();
    for (label, patterns) in entries {
        block.extend(label.encode_utf16());
        block.push(0);
        block.extend(patterns.join(";").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// Show the system file dialog and return the chosen path.
///
/// A null return means cancelled (or a failure the user cannot act on), which is
/// why callers treat it as "do nothing" rather than as an error.
fn run_file_dialog(
    hwnd: HWND,
    save: bool,
    entries: &[FilterEntry],
    initial_name: Option<&str>,
) -> Option<PathBuf> {
    let filter = filter_block(entries);
    let mut file_buffer = vec![0u16; 32_768];
    if let Some(name) = initial_name {
        let units: Vec<u16> = name.encode_utf16().collect();
        let count = units.len().min(file_buffer.len().saturating_sub(1));
        file_buffer[..count].copy_from_slice(&units[..count]);
    }

    let extension = if save {
        default_extension(entries)
    } else {
        None
    };
    let extension_wide = extension.as_ref().map(|extension| {
        extension
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect::<Vec<u16>>()
    });

    let flags = if save {
        OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY
    } else {
        OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY
    };

    let mut dialog = OPENFILENAMEW {
        lStructSize: core::mem::size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: hwnd,
        hInstance: windows::Win32::Foundation::HINSTANCE(core::ptr::null_mut()),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        nFilterIndex: 1,
        lpstrFile: PWSTR(file_buffer.as_mut_ptr()),
        nMaxFile: file_buffer.len() as u32,
        Flags: flags,
        lpstrTitle: if save {
            w!("Export checksum file")
        } else {
            w!("Open checksum file")
        },
        lpstrDefExt: extension_wide
            .as_ref()
            .map_or(PCWSTR::null(), |wide| PCWSTR(wide.as_ptr())),
        ..Default::default()
    };

    // SAFETY: the filter block, `file_buffer` and the extension buffer all
    // outlive the call, every pointer in `dialog` refers to one of them, and
    // `lStructSize` is the structure's own size. `hwnd` is the live page window.
    let shown = unsafe {
        if save {
            GetSaveFileNameW(&mut dialog)
        } else {
            GetOpenFileNameW(&mut dialog)
        }
    };
    if !shown.as_bool() {
        return None;
    }

    let length = file_buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(file_buffer.len());
    Some(PathBuf::from(String::from_utf16_lossy(
        &file_buffer[..length],
    )))
}

/// `Verify...`'s file picker.
fn open_checksum_file(hwnd: HWND) -> Option<PathBuf> {
    run_file_dialog(hwnd, false, &open_filter_entries(), None)
}

/// `Export...`'s Save dialog.
fn save_checksum_file(hwnd: HWND, enabled: &[bool]) -> Option<PathBuf> {
    run_file_dialog(hwnd, true, &save_filter_entries(enabled), Some("checksums"))
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

    // SAFETY: this is an `NM_CUSTOMDRAW` notification. `custom_draw` checks the
    // control id, so another control's custom draw is left to the default handler
    // rather than answered by us.
    match unsafe { crate::listview::custom_draw(lparam, &state.rows) } {
        Some(answer) => {
            // The custom-draw answer is a **message result**, not the dialog
            // procedure's BOOL. A dialog procedure must put it in
            // `DWLP_MSGRESULT` and return TRUE; returning `CDRF_NOTIFYITEMDRAW`
            // directly would reach the control as `TRUE`, the item stage would
            // never be requested, and no row would ever be coloured -- which is
            // exactly how the first fix failed.
            crate::window_data::set_message_result(hwnd, answer);
            1
        }
        None => 0,
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
        crate::route::Route::Verification(sequence) => on_verify_ready(hwnd, sequence),
        crate::route::Route::ExportDone(sequence) => on_export_done(hwnd, sequence),
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
    update_progress(hwnd, crate::PROGRESS_RESOLUTION);

    // Render the finished set once from the stored results rather than appending
    // whatever is still queued. Two things fall out of that:
    //
    // * the list is in job order, which is stable across reruns;
    // * the counters are recounted from the same results as the rows.
    //
    // The recount is what heals a verification that landed while a file was
    // finishing: the rebuild and the worker's own counter update are under
    // different locks, so a result arriving between them could otherwise leave
    // the status line one file short until the next rebuild.
    if let Some(shared) = shared_state(hwnd) {
        // The rows in the queue would be rendered a second time by the rebuild.
        let _ = shared.drain();
    }
    rebuild_and_refresh(hwnd);
}

/// Rewrite the status line from what the hashing thread reports.
fn refresh_status(hwnd: HWND, state: &DialogState, shared: &Arc<Shared>) {
    let _ = hwnd;
    let Some(status) = state.status else {
        return;
    };

    let mut text = if shared.is_cancelled() && !shared.is_finished() {
        String::from(resource::STATUS_CANCELLED)
    } else if shared.is_finished() {
        resource::status_finished_with_skipped(&shared.counters(), shared.skipped())
    } else {
        let (done, total) = shared.file_counts();
        resource::status_running(done, total, &shared.counters())
    };

    // The verdicts' source is part of the summary: "3 matched" against a checksum
    // file is a different statement from "3 matched" against a pasted digest, and
    // the counters stay the first thing on the line.
    if let Some(info) = shared.verification() {
        text = resource::with_verification(text, &info.source, info.unmatched, info.had_error);
    }

    set_status(status, &text);
}

/// Put text on the status line, if the page has found it yet.
fn set_status_on(status: Option<HWND>, text: &str) {
    if let Some(status) = status {
        set_status(status, text);
    }
}

/// Show an error the user has to acknowledge.
///
/// Modal on the dialog's thread on purpose: an export or a checksum file that
/// could not be read is not something a status line can carry, and the message is
/// already written.
fn show_error(hwnd: HWND, message: &str) {
    let wide: Vec<u16> = message.encode_utf16().chain(core::iter::once(0)).collect();
    // SAFETY: the string is NUL-terminated and outlives the call; `hwnd` is the
    // page's live window.
    unsafe {
        let _ = MessageBoxW(
            Some(hwnd),
            PCWSTR(wide.as_ptr()),
            w!("rustHashTab"),
            MB_OK | MB_ICONERROR,
        );
    }
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

    /// Every message the page posts for itself, in one place, so a new one
    /// cannot be added without the range and distinctness checks below seeing it.
    const PRIVATE_MESSAGES: [u32; 5] = [
        WM_FILE_FINISHED,
        WM_FILE_PROGRESS,
        WM_SCAN_FINISHED,
        WM_VERIFY_READY,
        WM_EXPORT_DONE,
    ];

    #[test]
    fn the_private_messages_are_in_the_application_range() {
        // The property sheet manager owns `WM_USER`: `PSN_*` starts there and
        // `PSM_*` at `WM_USER + 100`. A private message placed in that range would
        // fire on the sheet's own traffic.
        for message in PRIVATE_MESSAGES {
            assert!(
                (WM_APP..WM_APP + 0x8000).contains(&message),
                "{message:#x} is not in the WM_APP range"
            );
        }
    }

    #[test]
    fn the_private_messages_are_distinct() {
        let mut all = PRIVATE_MESSAGES.to_vec();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), PRIVATE_MESSAGES.len());
    }

    /// The private messages must not be mistakable for the notifications the list
    /// view sends -- those arrive through `WM_NOTIFY`, so a handler that matched on
    /// the wrong one would act on the wrong thing.
    #[test]
    fn the_private_messages_are_not_list_view_notifications() {
        use windows::Win32::UI::Controls::{LVN_ITEMCHANGED, NM_CUSTOMDRAW};
        for message in PRIVATE_MESSAGES {
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

    /// The Save dialog's filter offers every enabled algorithm that has a
    /// checksum-file extension, plus SFV only when CRC32 is on and corz `.hash`
    /// only when a secure algorithm is on. Offering a format the page cannot
    /// produce would hand the user a file named after an algorithm it does not
    /// contain.
    #[test]
    fn the_export_filter_lists_only_what_the_page_can_produce() {
        let mut enabled = vec![false; rusthashtab_hash::ALGORITHMS.len()];
        let enable = |name: &str| -> usize {
            rusthashtab_hash::ALGORITHMS
                .iter()
                .position(|algorithm| algorithm.name == name)
                .expect("the algorithm is in the table")
        };
        enabled[enable("SHA-256")] = true;
        enabled[enable("CRC32")] = true;

        let entries = save_filter_entries(&enabled);
        assert_eq!(
            entries.first().map(|(label, _)| label.as_str()),
            Some("SHA-256 checksums")
        );
        assert!(entries.iter().any(|(label, _)| label == "SFV checksums"));
        assert!(entries.iter().any(|(label, _)| label == "corz .hash"));
        assert_eq!(
            entries.last().map(|(label, _)| label.as_str()),
            Some("All files")
        );
        assert_eq!(default_extension(&entries).as_deref(), Some("sha256"));

        // Nothing enabled: no format-specific filter, and therefore no extension
        // to append.
        let none = save_filter_entries(&vec![false; rusthashtab_hash::ALGORITHMS.len()]);
        assert_eq!(none.len(), 1);
        assert_eq!(default_extension(&none), None);
    }

    /// SFV needs CRC32 and `.hash` needs a secure algorithm; neither may appear
    /// when the page cannot compute the digest it would contain.
    #[test]
    fn a_filter_never_offers_a_digest_the_page_cannot_produce() {
        let mut enabled = vec![false; rusthashtab_hash::ALGORITHMS.len()];
        // CRC32 disabled, no secure algorithm enabled: only a weak legacy hash.
        let md5 = rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == "MD5")
            .expect("MD5 is in the table");
        enabled[md5] = true;

        let entries = save_filter_entries(&enabled);
        assert!(!entries.iter().any(|(label, _)| label == "SFV checksums"));
        assert!(!entries.iter().any(|(label, _)| label == "corz .hash"));
        assert!(entries.iter().any(|(label, _)| label == "MD5 checksums"));
    }

    /// A filter block is a sequence of NUL-terminated label/pattern pairs ending
    /// with an extra NUL. Getting that shape wrong makes the dialog show no
    /// filters at all.
    #[test]
    fn a_filter_block_is_nul_separated_and_double_terminated() {
        let entries = open_filter_entries();
        let block = filter_block(&entries);
        assert_eq!(block.last(), Some(&0));
        assert_eq!(
            block.iter().rev().take(2).copied().collect::<Vec<u16>>(),
            vec![0, 0],
            "the block must end with an extra NUL"
        );

        let text = String::from_utf16_lossy(&block);
        assert!(text.contains("Checksum files"));
        assert!(text.contains("*.sha256"));
        assert!(text.contains("*.sfv"));
    }
}
