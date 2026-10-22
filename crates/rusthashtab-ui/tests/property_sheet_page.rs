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
    BM_CLICK, CreateDialogParamW, DestroyWindow, GetDlgItem, IsWindow, SendMessageW,
    SetWindowTextW, WM_CLOSE,
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

    /// Replace the text in one of the page's controls.
    fn set_text(&self, id: i32, text: &str) {
        let control = self.control(id);
        let wide: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
        // SAFETY: `control` belongs to this dialog and the string outlives the call,
        // which copies it.
        unsafe {
            let _ = SetWindowTextW(control, PCWSTR(wide.as_ptr()));
        }
    }

    /// Click one of the page's buttons, the way a user does.
    fn click(&self, id: i32) {
        let control = self.control(id);
        // SAFETY: `control` is a button in this dialog; `BM_CLICK` takes no payload
        // and the control sends the resulting `WM_COMMAND` to its parent.
        unsafe {
            SendMessageW(control, BM_CLICK, Some(WPARAM(0)), Some(LPARAM(0)));
        }
    }

    /// The text of the page's status line.
    fn status_text(&self) -> String {
        let status = self.control(resource::IDC_HASH_STATUS);
        let mut buffer = [0u16; 512];
        // SAFETY: `status` is the page's static control, and `buffer` is a live
        // array of the declared length.
        let length =
            unsafe { windows::Win32::UI::WindowsAndMessaging::GetWindowTextW(status, &mut buffer) };
        let length = length.max(0) as usize;
        String::from_utf16_lossy(&buffer[..length.min(buffer.len())])
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

    /// Wait until the status line contains `needle`.
    ///
    /// The finished status line is written from a posted message, so a test that
    /// only waits for rows can still observe the previous status text.
    fn wait_for_status_contains(&self, needle: &str) {
        let deadline = Instant::now() + DEADLINE;
        while !self.status_text().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "status line never contained {needle:?}; got {:?}",
                self.status_text()
            );
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
    // The Phase 4 controls: expected-hash box, its button, and the three
    // actions. A missing one would make the corresponding feature unreachable
    // without any other test failing.
    assert!(page.control(resource::IDC_HASH_EXPECTED).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_CHECK).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_VERIFY).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_EXPORT).0 as isize != 0);
    assert!(page.control(resource::IDC_HASH_SETTINGS).0 as isize != 0);

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

/// A root that vanished between the shell reading the selection and the page
/// opening it must not stop the scan or leave the page saying "Hashing…" forever.
#[test]
fn a_missing_root_is_reported_and_the_scan_still_finishes() {
    let dir = TempDir::new("missing-root");
    let good = dir.file("good.bin", b"good");
    let missing = dir.path().join("gone.bin");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("MD5"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![good, missing], settings);

    // One row for the readable file, one error row for the missing root.
    page.wait_for_rows(2);
    page.wait_for_status_contains("1 error");

    let digest_cells: Vec<String> = (0..2).map(|row| page.cell(row, 1)).collect();
    assert!(
        digest_cells.iter().any(|cell| cell.starts_with("Error")),
        "the missing root must be visible as an error row, got {digest_cells:?}"
    );

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

/// A checksum file beside the hashed file is an automatic verification source
/// when the setting asks for one.
#[test]
fn a_sidecar_checksum_file_makes_the_row_match() {
    let dir = TempDir::new("sidecar-match");
    let contents = b"the bytes the checksum file describes";
    let file = dir.file("payload.bin", contents);
    std::fs::write(
        dir.path().join("payload.bin.sha256"),
        sumfile_body("SHA-256", contents, "payload.bin"),
    )
    .expect("the sidecar checksum file must be writable");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        look_for_sumfiles: true,
        ..rusthashtab_settings::Settings::default()
    };
    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);

    assert_eq!(
        page.cell(0, 2),
        "matched",
        "the sidecar digest was not used"
    );
    assert_eq!(
        page.cell(0, 3),
        "payload.bin",
        "the File column must show the display path"
    );
    page.close();
}

/// The same path, with a digest that disagrees, must say so instead of quietly
/// treating the file as unchecked.
#[test]
fn a_sidecar_checksum_file_with_a_wrong_digest_is_a_mismatch() {
    let dir = TempDir::new("sidecar-mismatch");
    let contents = b"bytes";
    let file = dir.file("payload.bin", contents);
    std::fs::write(
        dir.path().join("payload.bin.sha256"),
        format!("{}  payload.bin\n", "0".repeat(64)),
    )
    .expect("the sidecar checksum file must be writable");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        look_for_sumfiles: true,
        ..rusthashtab_settings::Settings::default()
    };
    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);

    assert_eq!(page.cell(0, 2), "mismatch");
    page.close();
}

/// A pasted digest is checked against the row that is selected; with one file
/// there is no selection to make.
#[test]
fn pasting_the_right_digest_marks_the_row_matched() {
    let dir = TempDir::new("paste-right");
    let contents = b"pasted digest target";
    let file = dir.file("payload.bin", contents);
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);
    assert_eq!(page.cell(0, 2), "not checked");

    page.set_text(
        resource::IDC_HASH_EXPECTED,
        &digest_hex("SHA-256", contents),
    );
    page.click(resource::IDC_HASH_CHECK);
    pump();

    assert_eq!(page.cell(0, 2), "matched");
    page.close();
}

/// A pasted digest names one algorithm's output; only that algorithm's row is
/// marked. The other rows of the same file were hashed but not compared, so they
/// stay "not checked" rather than inheriting the file's verdict.
#[test]
fn pasting_a_digest_marks_only_the_matching_algorithm_row() {
    let dir = TempDir::new("paste-row");
    let contents = b"row specific bytes";
    let file = dir.file("payload.bin", contents);
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only_many(&["MD5", "SHA-256"]),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(2);
    // Table order: MD5 comes before SHA-256.
    assert_eq!(page.cell(0, 0), "MD5");
    assert_eq!(page.cell(1, 0), "SHA-256");

    page.set_text(
        resource::IDC_HASH_EXPECTED,
        &digest_hex("SHA-256", contents),
    );
    page.click(resource::IDC_HASH_CHECK);
    pump();

    assert_eq!(
        page.cell(0, 2),
        "not checked",
        "the MD5 row was never compared against the pasted digest"
    );
    assert_eq!(page.cell(1, 2), "matched", "the SHA-256 row must match");
    page.close();
}

/// A pasted digest that does not match is a mismatch, not silence.
#[test]
fn pasting_a_wrong_digest_is_a_mismatch() {
    let dir = TempDir::new("paste-wrong");
    let file = dir.file("payload.bin", b"bytes");
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);
    page.set_text(resource::IDC_HASH_EXPECTED, &"AB".repeat(32));
    page.click(resource::IDC_HASH_CHECK);
    pump();

    assert_eq!(page.cell(0, 2), "mismatch");
    page.close();
}

/// Text that is not a digest is refused with a status line, and the row's
/// verdict is left alone: turning "not a digest" into a mismatch would accuse
/// the file.
#[test]
fn pasting_something_that_is_not_a_digest_changes_nothing() {
    let dir = TempDir::new("paste-invalid");
    let file = dir.file("payload.bin", b"bytes");
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);
    page.set_text(resource::IDC_HASH_EXPECTED, "this is not a digest");
    page.click(resource::IDC_HASH_CHECK);
    pump();

    assert_eq!(page.cell(0, 2), "not checked");
    assert!(
        page.status_text().contains("Not a hex digest"),
        "the status line must say why nothing happened, got {:?}",
        page.status_text()
    );
    page.close();
}

/// A digest no enabled algorithm can produce is refused rather than applied: the
/// comparison layer would have nothing to compare it with and would report a
/// mismatch against a perfectly good file.
#[test]
fn pasting_a_digest_of_the_wrong_length_is_refused() {
    let dir = TempDir::new("paste-length");
    let file = dir.file("payload.bin", b"bytes");
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        ..rusthashtab_settings::Settings::default()
    };

    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);
    // An MD5-shaped digest while only SHA-256 is enabled.
    page.set_text(resource::IDC_HASH_EXPECTED, &"AB".repeat(16));
    page.click(resource::IDC_HASH_CHECK);
    pump();

    assert_eq!(page.cell(0, 2), "not checked");
    assert!(
        page.status_text()
            .contains("No enabled algorithm produces that digest length"),
        "got {:?}",
        page.status_text()
    );
    page.close();
}

/// The custom-draw answer must be delivered through `DWLP_MSGRESULT`.
///
/// A dialog procedure's return value is a BOOL. Returning `CDRF_NOTIFYITEMDRAW`
/// from the procedure makes the dialog manager tell the control "handled", and
/// the control never sees the bit that asks for item notifications -- so no row
/// is coloured while every colour-mapping test still passes.
///
/// This sends the notification to the **window**, not to the procedure, so the
/// return value is what the dialog manager hands the control: exactly what
/// comctl32 would read.
#[test]
fn the_custom_draw_answer_travels_through_the_dialog_message_result() {
    use windows::Win32::UI::Controls::{
        CDDS_PREPAINT, CDRF_NOTIFYITEMDRAW, NM_CUSTOMDRAW, NMCUSTOMDRAW_DRAW_STAGE, NMLVCUSTOMDRAW,
    };
    use windows::Win32::UI::WindowsAndMessaging::WM_NOTIFY;

    let dir = TempDir::new("custom-draw");
    let file = dir.file("payload.bin", b"bytes");
    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("CRC32"),
        ..rusthashtab_settings::Settings::default()
    };
    let page = HostedPage::open(vec![file], settings);
    page.wait_for_rows(1);

    let mut draw = NMLVCUSTOMDRAW::default();
    draw.nmcd.hdr.idFrom = resource::IDC_HASH_LIST as usize;
    draw.nmcd.hdr.code = NM_CUSTOMDRAW;
    draw.nmcd.dwDrawStage = NMCUSTOMDRAW_DRAW_STAGE(CDDS_PREPAINT.0);

    // SAFETY: `page.hwnd` is a live dialog whose procedure is the page's, and
    // `draw` outlives the call. This is the message comctl32 sends for the list.
    let answer = unsafe {
        SendMessageW(
            page.hwnd,
            WM_NOTIFY,
            Some(WPARAM(0)),
            Some(LPARAM(&mut draw as *mut NMLVCUSTOMDRAW as isize)),
        )
    };
    assert_eq!(
        answer.0, CDRF_NOTIFYITEMDRAW as isize,
        "the control must receive CDRF_NOTIFYITEMDRAW as the message result; \
         a BOOL returned by the dialog procedure would be lost"
    );

    page.close();
}

/// The finished status line must count every file exactly once, with the verdict
/// each file got from its own sidecar -- one match, one mismatch.
#[test]
fn the_finished_status_counts_each_file_once() {
    let dir = TempDir::new("counters");
    let good = b"good bytes";
    let bad = b"bad bytes";
    dir.file("good.bin", good);
    dir.file("bad.bin", bad);
    std::fs::write(
        dir.path().join("good.bin.sha256"),
        sumfile_body("SHA-256", good, "good.bin"),
    )
    .expect("the sidecar must be writable");
    std::fs::write(
        dir.path().join("bad.bin.sha256"),
        format!("{}  bad.bin\n", "0".repeat(64)),
    )
    .expect("the sidecar must be writable");

    let settings = rusthashtab_settings::Settings {
        algorithms: enabled_only("SHA-256"),
        look_for_sumfiles: true,
        ..rusthashtab_settings::Settings::default()
    };
    let page = HostedPage::open(vec![dir.path().to_path_buf()], settings);
    page.wait_for_rows(2);

    let deadline = Instant::now() + DEADLINE;
    loop {
        let status = page.status_text();
        if status.contains("1 matched") && status.contains("1 mismatched") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the finished status never counted the files: {status:?}"
        );
        pump();
        std::thread::sleep(Duration::from_millis(2));
    }

    page.close();
}

/// A settings-shaped vector with exactly one algorithm enabled.
fn enabled_only(name: &str) -> Vec<bool> {
    enabled_only_many(&[name])
}

/// The digest of `bytes` under one algorithm, as the page displays it.
fn digest_hex(algorithm: &str, bytes: &[u8]) -> String {
    let mut hasher =
        rusthashtab_hash::registry::make(algorithm).expect("the algorithm has a context");
    hasher.update(bytes);
    rusthashtab_sumfile::export::to_hex(&hasher.finalize(), true)
}

/// A checksum file's body for one file, in the GNU two-space style.
fn sumfile_body(algorithm: &str, bytes: &[u8], file_name: &str) -> String {
    format!("{}  {}\n", digest_hex(algorithm, bytes), file_name)
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
