//! The page, hosted the way the shell hosts it.
//!
//! # What this proves that the unit tests cannot
//!
//! The unit tests drive the pieces: the router decides what a message means, the
//! session hashes a selection, the list view renders rows, the clipboard transfers a
//! handle. What none of them establish is that the pieces are **wired together** --
//! that opening a page starts a scan, that the scan's results reach the control, and
//! that closing the page stops the thread and frees the state exactly once.
//!
//! So this creates a real dialog from the page's own compiled template and drives it
//! with real window messages. The dialog procedure under test is
//! `rusthashtab_ui::dialog::dlg_proc` -- the same function `comctl32` calls -- reached
//! through `page::tests::test_dlg_proc`, which only exists because a directly created
//! dialog hands its `WM_INITDIALOG` the caller's `lParam` rather than a
//! `PROPSHEETPAGEW`.
//!
//! # Why not a real property sheet
//!
//! `PropertySheetW` is modal: it runs its own message loop on the calling thread, so
//! a test that called it would have to post itself a close from another thread and
//! would lose control over every intermediate step. The page's own contract is
//! narrower than the sheet's -- it receives messages and does not care what created
//! the window -- so driving the dialog directly tests the part that can be wrong.
//! The sheet's half is the part the manual check covers.

// Test code is allowed to fail loudly: a panic here is a test failure, not a process
// that takes the user's shell down with it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_ui::DialogState;
use rusthashtab_ui::page::test_dlg_proc;
use rusthashtab_ui::resource;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Controls::{LVITEMW, LVM_GETITEMCOUNT, LVM_GETITEMTEXTW};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateDialogParamW, DestroyWindow, GetDlgItem, IsWindow, SendMessageW, WM_CLOSE,
};
use windows::core::{PCWSTR, w};

/// Nothing in this suite should take this long; a page that does is hung, and a hung
/// test binary reports nothing at all.
const DEADLINE: Duration = Duration::from_secs(120);

/// A uniquely named temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusthashtab-page-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temporary directory must be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("the test file must be writable");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A hosted page: its parent window, the dialog, the state behind it, and teardown.
struct HostedPage {
    /// The window the page is a child of.
    ///
    /// The template is `WS_CHILD -- a property sheet page is a child of the sheet --
    /// so it has to be created with a parent, and `Creating a page with no parent
    /// fails with `ERROR_HWND_HAS_CHILD` rather than producing a stray top-level
    /// window. A real sheet would be this window; the page cannot tell the
    /// difference, because it only ever receives messages.
    parent: HWND,
    hwnd: HWND,
    /// The state, as the test's own allocation. The page borrows it.
    state: *mut DialogState,
}

impl HostedPage {
    /// Create a page showing `roots`.
    fn open(roots: Vec<PathBuf>, settings: rusthashtab_settings::Settings) -> Self {
        let state = Box::into_raw(Box::new(DialogState::new(roots, settings)));

        // The template lives in this test binary, because this test binary is what
        // compiled the crate's `ui.rc`.
        // SAFETY: a null module name asks for the module the caller is in.
        let instance = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
                .expect("the test binary has a module handle")
        };

        let parent = create_parent();

        // `CreateDialogParamW`, not `CreateDialogIndirectParamW`: the latter takes an
        // in-memory `DLGTEMPLATE`, and passing a resource id to it is an access
        // violation rather than an error. This one resolves the id through the
        // module's resource section, which is what the shell's own
        // `CreatePropertySheetPageW` does with `pszTemplate`.
        //
        // SAFETY: the template identifier is the one `ui.rc` declares and this module
        // compiled, `parent` is a live window, and `state` outlives the dialog because
        // `close` destroys the windows before reclaiming it.
        let hwnd = unsafe {
            CreateDialogParamW(
                Some(instance.into()),
                PCWSTR(resource::IDD_HASH_PROPPAGE as usize as *const u16),
                Some(parent),
                Some(test_dlg_proc),
                LPARAM(state as isize),
            )
        };

        let hwnd = hwnd.unwrap_or_else(|error| {
            // SAFETY: `state` was never handed to a live window -- creation failed --
            // so nothing else can own it.
            drop(unsafe { Box::from_raw(state) });
            // SAFETY: `parent` was created above and has no child.
            unsafe {
                let _ = DestroyWindow(parent);
            }
            panic!("the page dialog could not be created from its template: {error}")
        });

        Self {
            parent,
            hwnd,
            state,
        }
    }

    /// One of the page's controls.
    fn control(&self, id: i32) -> HWND {
        // SAFETY: the identifier is one the template declares.
        unsafe { GetDlgItem(Some(self.hwnd), id) }.expect("the control exists in the template")
    }

    /// How many items the results list is showing.
    fn row_count(&self) -> usize {
        let list = self.control(resource::IDC_HASH_LIST);
        // SAFETY: `LVM_GETITEMCOUNT` takes no parameters and returns a count.
        unsafe { SendMessageW(list, LVM_GETITEMCOUNT, Some(WPARAM(0)), Some(LPARAM(0))) }.0 as usize
    }

    /// The text of one cell, or an empty string.
    fn cell(&self, row: i32, column: i32) -> String {
        let list = self.control(resource::IDC_HASH_LIST);
        let mut buffer = [0u16; 256];
        let mut item = LVITEMW {
            iSubItem: column,
            pszText: windows::core::PWSTR(buffer.as_mut_ptr()),
            cchTextMax: buffer.len() as i32,
            ..Default::default()
        };

        // SAFETY: `buffer` is a live array of `cchTextMax` units, and `item` lives for
        // the call. The control writes at most that many units plus a terminator.
        unsafe {
            SendMessageW(
                list,
                LVM_GETITEMTEXTW,
                Some(WPARAM(row as usize)),
                Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
            );
        }

        let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(0);
        String::from_utf16_lossy(&buffer[..end])
    }

    /// Wait until the list has at least `expected` rows.
    fn wait_for_rows(&self, expected: usize) {
        let deadline = Instant::now() + DEADLINE;
        while self.row_count() < expected {
            assert!(
                Instant::now() < deadline,
                "only {} of {expected} rows appeared within {DEADLINE:?}",
                self.row_count()
            );
            // Pump, because the page updates the list from posted messages. Without
            // this the test would wait for a window that is not being given the
            // chance to process them.
            pump();
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Close the window and reclaim the state, as the shell's teardown does.
    fn close(self) {
        // SAFETY: `hwnd` is a live window created by `CreateDialogParamW`.
        unsafe {
            let _ = DestroyWindow(self.hwnd);
        }
        // SAFETY: `IsWindow` reads a handle; a destroyed one is exactly the case it
        // answers for, and it takes no pointers.
        let still_alive = unsafe { IsWindow(Some(self.hwnd)) }.as_bool();
        assert!(!still_alive, "the window must be gone after DestroyWindow");

        // SAFETY: the window is destroyed, so nothing can still reach the state
        // through it, and `Drop` is the only owner left.
        drop(unsafe { Box::from_raw(self.state) });

        // SAFETY: `parent` was created by `create_parent`, its child is gone, and it
        // is destroyed exactly once.
        unsafe {
            let _ = DestroyWindow(self.parent);
        }
    }
}

/// A plain window to be the page's parent.
///
/// The **`STATIC` class**, not the default: `CreateWindowExW` with a null class name
/// and a null window name fails with `E_INVALIDARG`, because the system's default
/// class wants a title. `STATIC` is a real predefined class that accepts any style,
/// which is all this needs -- the page never talks to its parent, it only has to have
/// one.
fn create_parent() -> HWND {
    use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, WINDOW_EX_STYLE};

    // SAFETY: `STATIC` is a predefined class, the empty title is legal for it, and
    // every parent and menu parameter is null. The window is never shown.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            w!(""),
            windows::Win32::UI::WindowsAndMessaging::WS_OVERLAPPED,
            0,
            0,
            1,
            1,
            None,
            None,
            None,
            None,
        )
    }
    .expect("the parent window must be creatable")
}

/// Drain the calling thread's message queue.
///
/// A non-blocking pump: this test drives the dialog, so it has to hand it its own
/// messages rather than wait for someone else to.
fn pump() {
    use windows::Win32::UI::WindowsAndMessaging::{MSG, PM_REMOVE, PeekMessageW};

    let mut message = MSG::default();
    // SAFETY: `message` is a live local and the window filter is null, which means
    // "any window on this thread".
    while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
        // SAFETY: the message came from `PeekMessageW`.
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::TranslateMessage(&message);
            windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&message);
        }
    }
}

/// A fresh page has its controls, an empty list, and a status line.
#[test]
fn a_page_shows_its_controls() {
    let dir = TempDir::new("controls");
    let page = HostedPage::open(
        vec![dir.path().to_path_buf()],
        rusthashtab_settings::Settings::default(),
    );

    assert!(page.control(resource::IDC_HASH_LIST).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_STATUS).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_PROGRESS).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_COPY).0 as isize != 0);

    // The columns are the page's own, added at `WM_INITDIALOG`.
    let list = page.control(resource::IDC_HASH_LIST);
    // SAFETY: `LVM_GETHEADER` returns the header control, or null.
    let header = unsafe {
        SendMessageW(
            list,
            windows::Win32::UI::Controls::LVM_GETHEADER,
            Some(WPARAM(0)),
            Some(LPARAM(0)),
        )
    };
    assert!(header.0 != 0, "the list view has no header");

    page.close();
}

/// The whole point of the page: open it on a file, and the digest appears.
#[test]
fn a_file_is_hashed_and_shown() {
    let dir = TempDir::new("one-file");
    let contents: Vec<u8> = (0..8192u32).map(|index| (index % 251) as u8).collect();
    let file = dir.file("payload.bin", &contents);

    // One algorithm, so the assertion is about one row rather than thirty-one.
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file.clone()], settings);
    page.wait_for_rows(1);

    assert_eq!(
        page.row_count(),
        1,
        "one file with one algorithm is one row"
    );
    assert_eq!(page.cell(0, 0), "SHA-256", "wrong algorithm column");

    // The digest on screen must be the algorithm's own answer for the bytes on disk.
    let mut hasher = rusthashtab_hash::registry::make("SHA-256").expect("SHA-256 has a context");
    hasher.update(&std::fs::read(&file).expect("the test file is readable"));
    let expected = rusthashtab_sumfile::export::to_hex(&hasher.finalize(), true);
    assert_eq!(
        page.cell(0, 1),
        expected,
        "the digest shown is not the digest computed"
    );

    // Nothing to compare against, so the verdict says so rather than claiming a match.
    assert_eq!(page.cell(0, 2), "not checked");

    page.close();
}

/// Every enabled algorithm gets a row, which is what makes the page useful.
#[test]
fn every_enabled_algorithm_gets_a_row() {
    let dir = TempDir::new("several");
    let file = dir.file("payload.bin", b"some bytes");

    let enabled = enabled_only_many(&["MD5", "SHA-1", "SHA-256"]);
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled,
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(3);

    assert_eq!(page.row_count(), 3);
    let algorithms: Vec<String> = (0..3).map(|row| page.cell(row, 0)).collect();
    assert!(algorithms.contains(&String::from("MD5")));
    assert!(algorithms.contains(&String::from("SHA-1")));
    assert!(algorithms.contains(&String::from("SHA-256")));

    page.close();
}

/// A directory root is expanded, so selecting a folder shows one row per file per
/// algorithm rather than one row for the folder.
#[test]
fn a_directory_root_shows_every_file_under_it() {
    let dir = TempDir::new("tree");
    dir.file("a.bin", b"aaa");
    dir.file("b.bin", b"bbb");
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).expect("the nested directory must be creatable");
    std::fs::write(nested.join("c.bin"), b"ccc").expect("the nested file must be writable");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("CRC32"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![dir.path().to_path_buf()], settings);
    page.wait_for_rows(3);

    assert_eq!(page.row_count(), 3, "three files under the root");

    page.close();
}

/// Closing the page must stop its thread and free its state exactly once.
///
/// The "exactly once" half is what the whole ownership table in `page` exists for,
/// and a double free here is a crash inside `explorer.exe`. A test that survives
/// teardown under a heap check is the evidence.
#[test]
fn closing_the_page_is_clean() {
    let dir = TempDir::new("teardown");
    let file = dir.file("payload.bin", &vec![0xABu8; 256 * 1024]);

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_one_many(&["SHA-512"]),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);

    // Closing while results may still be arriving: the thread has to be joined, not
    // abandoned, and the posted messages that are already queued have to be harmless.
    let started = Instant::now();
    page.close();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "closing the page took {elapsed:?}; it must cancel and join its thread"
    );

    // Anything still queued must do nothing rather than reach freed state.
    pump();
}

/// Closing immediately, before any result arrives, must also be clean.
#[test]
fn closing_before_any_result_arrives_is_clean() {
    let dir = TempDir::new("early-close");
    // Large enough that the scan is certainly still running when the page closes.
    let path = dir.path().join("big.bin");
    std::fs::File::create(&path)
        .expect("the file must be creatable")
        .set_len(64 * 1024 * 1024)
        .expect("the file must be extendable");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_one_many(&["SHA-512"]),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![path], settings);
    page.close();
    pump();
}

/// The page must refuse a message that is not its own rather than acting on it: the
/// window receives plenty of traffic that is not ours.
#[test]
fn a_stray_message_does_not_disturb_the_page() {
    let dir = TempDir::new("stray");
    let file = dir.file("payload.bin", b"abc");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("CRC32"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);
    let before = page.row_count();

    // A `WM_APP`-range message with the wrong authentication, then one with the right
    // tag but nonsense payload. Neither may add a row or move the bar.
    // SAFETY: `hwnd` is a live window, and both messages carry only integers.
    unsafe {
        use rusthashtab_ui::{MESSAGE_MAGIC, WM_FILE_FINISHED};
        use windows::Win32::UI::WindowsAndMessaging::PostMessageW;

        let _ = PostMessageW(Some(page.hwnd), WM_FILE_FINISHED, WPARAM(0), LPARAM(0));
        let _ = PostMessageW(
            Some(page.hwnd),
            WM_FILE_FINISHED,
            WPARAM(MESSAGE_MAGIC),
            LPARAM(0),
        );
    }
    pump();

    assert_eq!(
        page.row_count(),
        before,
        "a message that was not ours added a row"
    );

    page.close();
}

/// Send `WM_CLOSE` and confirm the page survives it, because a property page is a
/// **modeless** dialog and `EndDialog` must never be called from its procedure.
///
/// This is the check for the one mistake the documentation calls out explicitly: a
/// page procedure that called `EndDialog` would destroy the sheet's window out from
/// under the modal loop that owns it.
#[test]
fn the_page_survives_a_close_request() {
    let dir = TempDir::new("close");
    let file = dir.file("payload.bin", b"abc");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("CRC32"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);

    // SAFETY: the message carries no payload.
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
            Some(page.hwnd),
            WM_CLOSE,
            WPARAM(0),
            LPARAM(0),
        );
    }
    pump();

    // Reaching this line at all is the assertion: an `EndDialog` in the page
    // procedure would have ended a dialog that was never started modally, and the
    // process would not have got here. The state is still the test's to reclaim.
    page.close();
}

/// A settings-shaped vector with exactly one algorithm enabled.
fn enabled_only(name: &str) -> Vec<bool> {
    enabled_only_many(&[name])
}

/// A settings-shaped vector with `names` enabled and nothing else.
fn enabled_only_many(names: &[&str]) -> Vec<bool> {
    let mut enabled = vec![false; rusthashtab_hash::ALGORITHMS.len()];
    for name in names {
        let index = rusthashtab_hash::ALGORITHMS
            .iter()
            .position(|algorithm| algorithm.name == *name)
            .unwrap_or_else(|| panic!("`{name}` is not in the algorithm table"));
        enabled[index] = true;
    }
    enabled
}

/// The same as [`enabled_only_many`], spelled for one name in a slice of one.
fn enabled_one_many(names: &[&str]) -> Vec<bool> {
    enabled_only_many(names)
}
