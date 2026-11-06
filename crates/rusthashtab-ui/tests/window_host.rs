//! The page hosted in a real top-level window, the way the standalone mode uses it.
//!
//! # What this proves that the unit tests cannot
//!
//! The window host's own logic -- class registration, page creation, the ownership
//! dance between the host and the child dialog, `WM_SIZE` reflow -- is only real
//! when Win32 is doing the message delivery. So these tests open actual windows
//! (hidden: a test suite must not pop windows on someone's desktop) and drive them
//! with real window messages.
//!
//! # Why hidden windows are still a real test
//!
//! `ShowWindow(SW_HIDE)` only controls whether the window is visible; the window
//! exists, has a client area, receives `WM_SIZE`, and has a child dialog with a
//! live scan behind it. Everything the host does on a message is exercised. What is
//! not exercised is the compositor drawing it, which no automated test in this
//! repository covers.
//!
//! # The no-quit rule
//!
//! A host created with [`HostOptions::quit_on_close`] `false` must never post
//! `WM_QUIT`: the message would end a message loop it does not own, which is
//! exactly what embedding the page would do. Every test that opens such a host
//! fails if `WM_QUIT` shows up. The one test that passes `true` asserts the
//! opposite, so both halves of the contract are pinned.

// Test code is allowed to fail loudly: a panic here is a test failure, not a
// process that takes the user's desktop down with it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rusthashtab_ui::algorithm_names;
use rusthashtab_ui::resource;
use rusthashtab_ui::window::{self, HostOptions};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{HWND, LPARAM, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::MapWindowPoints;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::LVM_GETITEMCOUNT;
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EnumChildWindows, GW_CHILD, GWL_STYLE, GetClassNameW, GetClientRect,
    GetDlgItem, GetWindow, GetWindowLongPtrW, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsWindow, IsWindowVisible, MINMAXINFO, MSG, PM_REMOVE, PeekMessageW,
    PostMessageW, PostThreadMessageW, SW_HIDE, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW,
    SetWindowPos, TranslateMessage, WM_CLOSE, WM_GETMINMAXINFO, WM_QUIT, WS_VISIBLE,
};
use windows::core::{BOOL, PCWSTR};

/// Nothing in this suite should take this long; a host that does is hung, and a
/// hung test binary reports nothing at all.
const DEADLINE: Duration = Duration::from_secs(60);

/// The dialog template's control identifiers, in template order.
const PAGE_CONTROLS: [i32; 13] = [
    resource::IDC_HASH_LIST,
    resource::IDC_HASH_STATUS,
    resource::IDC_HASH_EXPECTED,
    resource::IDC_HASH_CHECK,
    resource::IDC_HASH_CURRENT_ONLY,
    resource::IDC_HASH_EXPORT_FORMAT,
    resource::IDC_HASH_VERIFY,
    resource::IDC_HASH_EXPORT,
    resource::IDC_HASH_EXPORT_CLIPBOARD,
    resource::IDC_HASH_COPY,
    resource::IDC_HASH_SETTINGS,
    resource::IDC_HASH_CANCEL,
    resource::IDC_HASH_PROGRESS,
];

/// A uniquely named temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rusthashtab-window-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temporary directory must be creatable");
        Self(path)
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

/// The module this test binary compiled the dialog template into.
fn this_module() -> windows::Win32::Foundation::HINSTANCE {
    // SAFETY: a null module name asks for the module the caller is in, which
    // always exists, and it is the module the build script linked `ui.rc` into.
    unsafe { GetModuleHandleW(None) }
        .expect("the test binary has a module handle")
        .into()
}

/// Settings with exactly one enabled algorithm, so the expected row count is a
/// property of the file list and not of the user's real registry settings.
fn one_algorithm_settings() -> rusthashtab_settings::Settings {
    let names = algorithm_names();
    let mut algorithms = vec![false; names.len()];
    let sha256 = names
        .iter()
        .position(|name| *name == "SHA-256")
        .expect("SHA-256 is in the algorithm table");
    algorithms[sha256] = true;
    rusthashtab_settings::Settings {
        algorithms,
        ..rusthashtab_settings::Settings::default()
    }
}

/// Open a hidden host that does not own a message loop.
fn open_hidden(roots: Vec<PathBuf>) -> HWND {
    window::open(
        this_module(),
        roots,
        one_algorithm_settings(),
        HostOptions {
            show: SW_HIDE.0,
            quit_on_close: false,
        },
    )
    .expect("the host window must open")
}

/// The page dialog, which is the host's only child.
fn page_of(host: HWND) -> HWND {
    // SAFETY: `host` is a live window and `GW_CHILD` walks its child list.
    unsafe { GetWindow(host, GW_CHILD) }.expect("the page dialog is the host's child")
}

/// One of the page's controls.
fn control(page: HWND, id: i32) -> HWND {
    // SAFETY: `page` is the page dialog and the identifiers come from the template.
    unsafe { GetDlgItem(Some(page), id) }.expect("the control exists in the template")
}

/// How many rows the results list is showing.
fn row_count(page: HWND) -> usize {
    let list = control(page, resource::IDC_HASH_LIST);
    // SAFETY: `LVM_GETITEMCOUNT` takes no parameters and returns a count.
    unsafe { SendMessageW(list, LVM_GETITEMCOUNT, Some(WPARAM(0)), Some(LPARAM(0))).0 as usize }
}

/// A control's rectangle, in page-client coordinates.
fn control_rect(page: HWND, control: HWND) -> RECT {
    let mut rect = RECT::default();
    // SAFETY: `control` is a live child of `page` and `rect` is a live local.
    unsafe { GetWindowRect(control, &mut rect) }.expect("a live control has a rectangle");

    let mut corners = [
        POINT {
            x: rect.left,
            y: rect.top,
        },
        POINT {
            x: rect.right,
            y: rect.bottom,
        },
    ];
    // SAFETY: both handles are live windows of this thread and `corners` is the
    // two-point array the call expects; a null "from" means screen coordinates.
    unsafe { MapWindowPoints(None, Some(page), &mut corners) };

    RECT {
        left: corners[0].x,
        top: corners[0].y,
        right: corners[1].x,
        bottom: corners[1].y,
    }
}

/// A window's client area, in pixels.
fn window_client(hwnd: HWND) -> (i32, i32) {
    let mut rect = RECT::default();
    // SAFETY: `hwnd` is a live window and `rect` is a live local.
    unsafe { GetClientRect(hwnd, &mut rect) }.expect("a live window has a client area");
    (rect.right - rect.left, rect.bottom - rect.top)
}

/// The page's client size.
fn page_client(page: HWND) -> (i32, i32) {
    window_client(page)
}

/// Whether `hwnd` is a live window.
fn is_window(hwnd: HWND) -> bool {
    // SAFETY: `IsWindow` only inspects the handle and accepts any value, including
    // one whose window has already been destroyed.
    unsafe { IsWindow(Some(hwnd)) }.as_bool()
}

/// Whether `hwnd` and all of its ancestors are visible.
fn is_visible(hwnd: HWND) -> bool {
    // SAFETY: `IsWindowVisible` only reads the window's visibility state.
    unsafe { IsWindowVisible(hwnd) }.as_bool()
}

/// Whether a `WM_QUIT` is waiting in this thread's message queue.
fn quit_queued() -> bool {
    let mut message = MSG::default();
    // SAFETY: `message` is a live local and the filter asks only for `WM_QUIT`,
    // which carries no window.
    unsafe { PeekMessageW(&mut message, None, WM_QUIT, WM_QUIT, PM_REMOVE) }.as_bool()
}

/// A window's text.
fn window_text(hwnd: HWND) -> String {
    let mut buffer = [0u16; 256];
    // SAFETY: `buffer` is writable for its whole length and the call NUL-terminates.
    let length = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    let length = usize::try_from(length).unwrap_or(0).min(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

/// A window's class name.
fn class_name(hwnd: HWND) -> String {
    let mut buffer = [0u16; 128];
    // SAFETY: the buffer is as long as the call is told, and the class name is
    // shorter than it for any window this module creates.
    let length = unsafe { GetClassNameW(hwnd, &mut buffer) };
    let length = usize::try_from(length).unwrap_or(0).min(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

/// The first child of `parent` whose window text equals `wanted`.
///
/// Needed only for the template's `IDC_STATIC` labels, which have no usable id.
fn find_child_with_text(parent: HWND, wanted: &str) -> Option<HWND> {
    struct Search {
        wanted: Vec<u16>,
        found: Option<HWND>,
    }

    unsafe extern "system" fn callback(child: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: `lparam` is the `&mut Search` passed below, which outlives the
        // enumeration.
        let search = unsafe { &mut *(lparam.0 as *mut Search) };
        let mut buffer = [0u16; 64];
        // SAFETY: `buffer` is writable for its whole length.
        let length = unsafe { GetWindowTextW(child, &mut buffer) };
        let length = usize::try_from(length).unwrap_or(0).min(buffer.len());
        if &buffer[..length] == search.wanted.as_slice() {
            search.found = Some(child);
            return false.into();
        }
        true.into()
    }

    let mut search = Search {
        wanted: wanted.encode_utf16().collect(),
        found: None,
    };
    // SAFETY: the callback has the shape `EnumChildWindows` calls and `search`
    // outlives the enumeration.
    unsafe {
        let _ = EnumChildWindows(
            Some(parent),
            Some(callback),
            LPARAM((&mut search as *mut Search) as isize),
        );
    }
    search.found
}

/// What a message pump reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pumped {
    /// The condition became true.
    Done,
    /// A `WM_QUIT` was taken out of the queue before the condition held.
    Quit,
    /// The deadline passed.
    TimedOut,
}

/// Dispatch queued messages until `condition` holds, `WM_QUIT` is seen, or time runs out.
fn pump_until(condition: impl Fn() -> bool) -> Pumped {
    let deadline = Instant::now() + DEADLINE;
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a live local for the whole loop.
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            if message.message == WM_QUIT {
                return Pumped::Quit;
            }
            // SAFETY: the message came from `PeekMessageW`; this is the documented
            // dispatch pair.
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        if condition() {
            return Pumped::Done;
        }
        if Instant::now() >= deadline {
            return Pumped::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Dispatch queued messages until `WM_QUIT` arrives, for the host that owns a loop.
fn pump_until_quit() -> bool {
    let deadline = Instant::now() + DEADLINE;
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a live local for the whole loop.
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            if message.message == WM_QUIT {
                return true;
            }
            // SAFETY: as in `pump_until`.
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Close a host by asking its window procedure to, the way the user's close
/// button does, and wait for the window to be gone.
fn close_host(host: HWND) -> Pumped {
    // SAFETY: `host` is a live window of this thread.
    let posted = unsafe { PostMessageW(Some(host), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    assert!(posted.is_ok(), "posting WM_CLOSE must succeed: {posted:?}");

    let pumped = pump_until(|| !is_window(host));
    assert_eq!(pumped, Pumped::Done, "the host did not close");
    pumped
}

#[test]
fn the_host_opens_hidden_with_the_pages_controls() {
    let dir = TempDir::new("surface");
    let file = dir.file("a.txt", b"hello");
    let host = open_hidden(vec![file]);

    // SAFETY: `host` is live until `close_host` runs below.
    assert!(is_window(host));
    // The caller asked for SW_HIDE, so nothing may appear on screen.
    assert!(
        !is_visible(host),
        "a host opened with SW_HIDE must not be visible"
    );
    assert_eq!(window_text(host), "rustHashTab");
    assert_eq!(class_name(host), "rustHashTabWindow");

    let page = page_of(host);
    // SAFETY: the page is the live child dialog the host created.
    assert!(is_window(page));
    // A child cannot be visible while its parent is hidden, which is exactly what
    // `SW_HIDE` asked for. The page's own `WS_VISIBLE` bit is asserted separately,
    // because that is the style the template gives it.
    assert!(
        !is_visible(page),
        "the page cannot be visible inside a hidden host"
    );
    // SAFETY: `page` is live and `GWL_STYLE` reads its style bits.
    let page_style = unsafe { GetWindowLongPtrW(page, GWL_STYLE) } as u32;
    assert_ne!(
        page_style & WS_VISIBLE.0,
        0,
        "the page template is WS_VISIBLE"
    );

    for id in PAGE_CONTROLS {
        // SAFETY: `page` is the page dialog and the ids are the template's.
        let control = unsafe { GetDlgItem(Some(page), id) };
        assert!(control.is_ok(), "control {id} is missing from the template");
    }

    // The two section labels are `IDC_STATIC`; they are found by text exactly as
    // the layout code finds them, and the reflow test asserts they move.
    assert!(find_child_with_text(page, "Expected:").is_some());
    assert!(find_child_with_text(page, "Format:").is_some());

    // `WM_GETMINMAXINFO` reports the template plus the frame, and the window that
    // was just opened is at least that big.
    let mut info = MINMAXINFO::default();
    // SAFETY: `WM_GETMINMAXINFO` documents `lParam` as a pointer to a `MINMAXINFO`
    // owned by the caller; the message procedure only writes into it.
    unsafe {
        SendMessageW(
            host,
            WM_GETMINMAXINFO,
            Some(WPARAM(0)),
            Some(LPARAM((&mut info as *mut MINMAXINFO) as isize)),
        );
    }
    assert!(
        info.ptMinTrackSize.x > 0 && info.ptMinTrackSize.y > 0,
        "the minimum track size must be known: {info:?}"
    );

    let mut outer = RECT::default();
    // SAFETY: `host` is live.
    unsafe { GetWindowRect(host, &mut outer) }.expect("the host has a rectangle");
    let outer_width = outer.right - outer.left;
    let outer_height = outer.bottom - outer.top;
    assert!(
        outer_width >= info.ptMinTrackSize.x,
        "the default window ({outer_width}) is narrower than its own minimum ({})",
        info.ptMinTrackSize.x
    );
    assert!(
        outer_height >= info.ptMinTrackSize.y,
        "the default window ({outer_height}) is shorter than its own minimum ({})",
        info.ptMinTrackSize.y
    );

    // Shrinking to exactly the minimum must still leave every control inside the
    // page: that is what "the template is the minimum" means.
    // SAFETY: `host` is live; `SetWindowPos` on the owning thread.
    unsafe {
        SetWindowPos(
            host,
            None,
            outer.left,
            outer.top,
            info.ptMinTrackSize.x,
            info.ptMinTrackSize.y,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    }
    .expect("the host can be resized to its minimum");

    let (width, height) = page_client(page);
    for id in PAGE_CONTROLS {
        let rect = control_rect(page, control(page, id));
        assert!(
            rect.right <= width && rect.bottom <= height,
            "control {id} is outside the page at its minimum size: {rect:?} in {width}x{height}"
        );
    }

    assert_eq!(
        pump_until(|| row_count(page) == 1),
        Pumped::Done,
        "the one file should produce one row"
    );

    close_host(host);
    // SAFETY: the handles are no longer live; this asserts they were destroyed.
    assert!(!is_window(page), "the child dialog survived");
    assert!(!is_window(host), "the host window survived its close");

    // Embedded mode must not end a message loop it does not own.
    assert!(
        !quit_queued(),
        "a host with quit_on_close == false posted WM_QUIT"
    );
}

#[test]
fn resizing_reflows_the_controls_by_their_anchors() {
    let dir = TempDir::new("resize");
    let one = dir.file("one.txt", b"one");
    let two = dir.file("two.txt", b"two");
    let host = open_hidden(vec![one, two]);
    let page = page_of(host);

    let before = Snapshot::take(page);
    assert!(
        rect_width(&before.list) > 0 && rect_height(&before.list) > 0,
        "the results list must have a real size"
    );

    // Grow the window by a fixed amount. The window manager may clamp the result
    // to the default maximum tracking size of the display (CI runners are
    // 1024x768), so the growth that actually happened is measured from the
    // host's client rect below rather than assumed. What this test proves is that
    // the page and its controls follow the client area, not that a particular
    // window size was accepted.
    let mut outer = RECT::default();
    // SAFETY: `host` is live.
    unsafe { GetWindowRect(host, &mut outer) }.expect("the host has a rectangle");
    let before_host = window_client(host);
    // SAFETY: `host` is live and the new size is derived from its own rectangle.
    unsafe {
        SetWindowPos(
            host,
            None,
            outer.left,
            outer.top,
            (outer.right - outer.left) + 200,
            (outer.bottom - outer.top) + 150,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    }
    .expect("the host can be grown");

    let after_host = window_client(host);
    let grown_width = after_host.0 - before_host.0;
    let grown_height = after_host.1 - before_host.1;
    assert!(
        grown_width > 0 && grown_height > 0,
        "the host did not grow on this display: {before_host:?} -> {after_host:?}"
    );

    let after = Snapshot::take(page);
    assert_eq!(
        after.client_width - before.client_width,
        grown_width,
        "the page's client area must follow the host's"
    );
    assert_eq!(
        after.client_height - before.client_height,
        grown_height,
        "the page's client area must follow the host's"
    );

    // Stretch both ways: both edges follow, the origin does not move.
    assert_near(after.list.left, before.list.left, "list left edge");
    assert_near(after.list.top, before.list.top, "list top edge");
    assert_near(
        rect_width(&after.list) - rect_width(&before.list),
        grown_width,
        "list width follows the window",
    );
    assert_near(
        rect_height(&after.list) - rect_height(&before.list),
        grown_height,
        "list height follows the window",
    );

    // The bottom block moves down without changing height.
    assert_near(
        after.status.top - before.status.top,
        grown_height,
        "the status line moves with the bottom edge",
    );
    assert_near(
        rect_height(&after.status),
        rect_height(&before.status),
        "status height",
    );
    assert_near(
        after.progress.bottom - before.progress.bottom,
        grown_height,
        "the progress bar moves with the bottom edge",
    );
    assert_near(
        rect_width(&after.progress) - rect_width(&before.progress),
        grown_width,
        "the progress bar stretches",
    );

    // The right-hand buttons keep their distance from the right edge.
    for (name, old, new) in [
        ("Check", before.check, after.check),
        ("Verify", before.verify, after.verify),
        ("Export", before.export, after.export),
        ("Settings", before.settings, after.settings),
        ("Cancel", before.cancel, after.cancel),
    ] {
        assert_near(
            new.right - old.right,
            grown_width,
            &format!("{name} right edge follows the window"),
        );
        assert_near(
            after.client_width - new.right,
            before.client_width - old.right,
            &format!("{name} right margin"),
        );
        assert_near(
            new.bottom - old.bottom,
            grown_height,
            &format!("{name} bottom edge follows the window"),
        );
    }

    // The left-hand buttons keep their column and move down.
    for (name, old, new) in [
        (
            "Copy checksums",
            before.copy_checksums,
            after.copy_checksums,
        ),
        ("Copy", before.copy, after.copy),
    ] {
        assert_near(new.left, old.left, &format!("{name} left edge"));
        assert_near(
            new.bottom - old.bottom,
            grown_height,
            &format!("{name} moves with the bottom edge"),
        );
    }

    // The expected-digest edit stretches up to the Check button's column.
    assert_near(
        after.expected.right - before.expected.right,
        grown_width,
        "the expected-digest edit stretches",
    );
    assert!(
        after.expected.right <= after.check.left,
        "the edit box may not overlap the Check button: {:?} vs {:?}",
        after.expected,
        after.check
    );

    // The two `IDC_STATIC` labels follow the rows they label.
    let expected_label = find_child_with_text(page, "Expected:").expect("the label exists");
    let format_label = find_child_with_text(page, "Format:").expect("the label exists");
    assert_near(
        control_rect(page, expected_label).top - before.expected_label_top,
        grown_height,
        "the Expected: label moves down with its row",
    );
    assert_near(
        control_rect(page, format_label).top - before.format_label_top,
        grown_height,
        "the Format: label moves down with its row",
    );

    // No overlap in the lower block, and the list stops above the status line.
    assert!(
        after.list.bottom <= after.status.top,
        "the list overlaps the status line: {:?} vs {:?}",
        after.list,
        after.status
    );
    assert!(
        after.expected.bottom <= after.check.bottom,
        "the edit box is taller than the row it sits in"
    );
    assert!(
        after.progress.bottom <= after.client_height,
        "the progress bar leaves the page"
    );
    assert!(
        after.list.bottom <= after.expected.top,
        "the list overlaps the expected-digest row"
    );

    close_host(host);
}

/// The rectangle of everything the resize test inspects, captured in one pass.
struct Snapshot {
    client_width: i32,
    client_height: i32,
    list: RECT,
    status: RECT,
    progress: RECT,
    expected: RECT,
    check: RECT,
    verify: RECT,
    export: RECT,
    settings: RECT,
    cancel: RECT,
    copy_checksums: RECT,
    copy: RECT,
    expected_label_top: i32,
    format_label_top: i32,
}

impl Snapshot {
    fn take(page: HWND) -> Self {
        let (client_width, client_height) = page_client(page);
        let expected_label =
            find_child_with_text(page, "Expected:").expect("the Expected: label exists");
        let format_label = find_child_with_text(page, "Format:").expect("the Format: label exists");
        Self {
            client_width,
            client_height,
            list: control_rect(page, control(page, resource::IDC_HASH_LIST)),
            status: control_rect(page, control(page, resource::IDC_HASH_STATUS)),
            progress: control_rect(page, control(page, resource::IDC_HASH_PROGRESS)),
            expected: control_rect(page, control(page, resource::IDC_HASH_EXPECTED)),
            check: control_rect(page, control(page, resource::IDC_HASH_CHECK)),
            verify: control_rect(page, control(page, resource::IDC_HASH_VERIFY)),
            export: control_rect(page, control(page, resource::IDC_HASH_EXPORT)),
            settings: control_rect(page, control(page, resource::IDC_HASH_SETTINGS)),
            cancel: control_rect(page, control(page, resource::IDC_HASH_CANCEL)),
            copy_checksums: control_rect(page, control(page, resource::IDC_HASH_EXPORT_CLIPBOARD)),
            copy: control_rect(page, control(page, resource::IDC_HASH_COPY)),
            expected_label_top: control_rect(page, expected_label).top,
            format_label_top: control_rect(page, format_label).top,
        }
    }
}

/// A rectangle's width.
fn rect_width(rect: &RECT) -> i32 {
    rect.right - rect.left
}

/// A rectangle's height.
fn rect_height(rect: &RECT) -> i32 {
    rect.bottom - rect.top
}

/// Assert two layout measurements are within a few pixels.
///
/// The arithmetic itself is exact, but a dialog's pixels come from dialog-unit
/// scaling, and a control may round its own size by a pixel. The rules under test
/// are "did the edge follow" and "did the margin stay", not the exact pixel.
fn assert_near(actual: i32, expected: i32, what: &str) {
    assert!(
        (actual - expected).abs() <= 4,
        "{what}: expected about {expected}, measured {actual}"
    );
}

#[test]
fn two_windows_are_independent_and_close_in_either_order() {
    let first_dir = TempDir::new("first");
    let second_dir = TempDir::new("second");
    let first = open_hidden(vec![first_dir.file("a.txt", b"a")]);
    let second = open_hidden(vec![
        second_dir.file("b.txt", b"b"),
        second_dir.file("c.txt", b"c"),
    ]);

    assert_ne!(first, second);
    let first_page = page_of(first);
    let second_page = page_of(second);
    assert_ne!(first_page, second_page);

    assert_eq!(pump_until(|| row_count(first_page) == 1), Pumped::Done);
    assert_eq!(pump_until(|| row_count(second_page) == 2), Pumped::Done);

    // Resizing one must not touch the other: each window has its own page and its
    // own layout baseline.
    let second_list_before =
        control_rect(second_page, control(second_page, resource::IDC_HASH_LIST));
    let mut outer = RECT::default();
    // SAFETY: `first` is live.
    unsafe { GetWindowRect(first, &mut outer) }.expect("the first host has a rectangle");
    // SAFETY: `first` is live and the new size is derived from its own rectangle.
    unsafe {
        SetWindowPos(
            first,
            None,
            outer.left,
            outer.top,
            (outer.right - outer.left) + 120,
            (outer.bottom - outer.top) + 90,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    }
    .expect("the first host can be grown");
    let (grown_width, _) = page_client(first_page);
    let second_list_after =
        control_rect(second_page, control(second_page, resource::IDC_HASH_LIST));
    assert_eq!(
        second_list_before, second_list_after,
        "the second window moved"
    );
    assert!(grown_width > 0);

    // Close the first while the second keeps scanning; the second must survive.
    close_host(first);
    // SAFETY: `second` is live and `first` has been destroyed.
    assert!(is_window(second));
    assert_eq!(row_count(second_page), 2, "the second window lost its rows");

    close_host(second);
    // SAFETY: both handles are now dead.
    assert!(!is_window(second_page));
    assert!(!quit_queued(), "an embedded host posted WM_QUIT");
}

#[test]
fn closing_while_the_scan_is_running_does_not_wedge() {
    let dir = TempDir::new("busy");
    // Enough files that discovery is still under way when the close arrives. The
    // point is not to prove the scan was mid-file, but that every teardown order is
    // safe: a close that overtakes the scan must still return.
    let mut roots = Vec::new();
    for index in 0..200 {
        roots.push(dir.file(&format!("file-{index:03}.bin"), &[index as u8; 1024]));
    }

    // Close through the window procedure, immediately after `open` has returned.
    let host = open_hidden(roots.clone());
    let page = page_of(host);
    close_host(host);
    assert!(!is_window(page));

    // Destroy the window directly -- the path a shell host takes when it is being
    // torn down rather than closed -- again immediately after opening.
    let host = open_hidden(roots.clone());
    let page = page_of(host);
    // SAFETY: `host` is live, owned by this thread, and destroyed exactly once.
    unsafe { windows::Win32::UI::WindowsAndMessaging::DestroyWindow(host) }
        .expect("the host can be destroyed directly");
    assert!(!is_window(host));
    assert!(!is_window(page));

    // And the ordinary path still works after the abrupt ones.
    let host = open_hidden(roots);
    let page = page_of(host);
    assert_eq!(pump_until(|| row_count(page) == 200), Pumped::Done);
    close_host(host);

    assert!(!quit_queued(), "an embedded host posted WM_QUIT");
}

#[test]
fn a_host_that_owns_its_loop_posts_quit_on_close() {
    let dir = TempDir::new("quit");
    let file = dir.file("a.txt", b"a");
    // The context-menu thread opens a host that owns its message loop, so this is
    // the configuration whose quit behaviour matters to the shipping code.
    let host = window::open(
        this_module(),
        vec![file],
        one_algorithm_settings(),
        HostOptions {
            show: SW_HIDE.0,
            quit_on_close: true,
        },
    )
    .expect("the host window must open");
    let page = page_of(host);
    assert_eq!(pump_until(|| row_count(page) == 1), Pumped::Done);

    // SAFETY: `host` is live.
    unsafe { PostMessageW(Some(host), WM_CLOSE, WPARAM(0), LPARAM(0)) }
        .expect("posting WM_CLOSE must succeed");
    assert!(
        pump_until_quit(),
        "a host with quit_on_close == true must post WM_QUIT"
    );
    // SAFETY: the close destroyed the window; this asserts it.
    assert!(!is_window(host));
}

/// The real message loop the standalone and context-menu paths run must return
/// when the window is closed, rather than waiting for anything else.
///
/// The window is closed from a second thread because the first one is inside
/// `message_loop`. That is exactly the situation in the shipping context-menu
/// path: the window thread runs the loop and the close arrives as a posted
/// message.
#[test]
fn the_message_loop_returns_when_the_window_closes() {
    let dir = TempDir::new("loop");
    let file = dir.file("a.txt", b"a");
    let host = window::open(
        this_module(),
        vec![file],
        one_algorithm_settings(),
        HostOptions {
            show: SW_HIDE.0,
            quit_on_close: true,
        },
    )
    .expect("the host window must open");

    // A handle is just a value; passing it to the closer thread is how a real host
    // posts its close from outside the loop.
    let host_value = host.0 as isize;
    let closer = std::thread::spawn(move || {
        let host = HWND(host_value as *mut core::ffi::c_void);
        std::thread::sleep(Duration::from_millis(150));
        // SAFETY: posting a message to a window owned by another thread is
        // allowed; the thread only posts and never destroys windows. Posting to a
        // window that no longer exists fails harmlessly.
        let _ = unsafe { PostMessageW(Some(host), WM_CLOSE, WPARAM(0), LPARAM(0)) };

        // Watchdog: if the window is still here after a generous wait, post a
        // `WM_QUIT` to the loop's thread so a regression fails the test rather than
        // hanging the whole test binary.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && is_window(host) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if is_window(host) {
            // SAFETY: the call only reads the window's owning thread id.
            let thread = unsafe { GetWindowThreadProcessId(host, None) };
            if thread != 0 {
                // SAFETY: posting `WM_QUIT` to a thread that owns a message queue
                // is allowed, and that thread is blocked in `GetMessageW`.
                let _ = unsafe { PostThreadMessageW(thread, WM_QUIT, WPARAM(0), LPARAM(0)) };
            }
        }
    });

    let result = window::message_loop(host);
    closer.join().expect("the closer thread finished");

    assert!(
        result.is_ok(),
        "closing the window must not be reported as a message-loop error: {result:?}"
    );
    assert!(
        !is_window(host),
        "the message loop returned while the window was still open"
    );
}

#[test]
fn command_line_paths_keep_quoted_and_unicode_arguments() {
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(core::iter::once(0)).collect()
    }

    // The executable name is argv[0] and must not become a path, while the quoted
    // argument with a space stays one path.
    let line = wide(
        r#""C:\Program Files\rustHashTab\rusthashtab.exe" "C:\temp\one file.txt" C:\temp\two.txt"#,
    );
    // SAFETY: the wide string is NUL-terminated and outlives the call.
    let paths = window::command_line_paths(PCWSTR(line.as_ptr())).expect("the line parses");
    assert_eq!(
        paths,
        vec![
            PathBuf::from(r"C:\temp\one file.txt"),
            PathBuf::from(r"C:\temp\two.txt"),
        ]
    );

    // An explicitly empty argument names no file and is dropped.
    let line = wide(r#"rusthashtab.exe "" C:\temp\three.txt"#);
    // SAFETY: as above.
    let paths = window::command_line_paths(PCWSTR(line.as_ptr())).expect("the line parses");
    assert_eq!(paths, vec![PathBuf::from(r"C:\temp\three.txt")]);

    // Non-ASCII names survive because the parser works in UTF-16 throughout.
    let line = wide(r#"rusthashtab.exe "C:\temp\文件.txt""#);
    // SAFETY: as above.
    let paths = window::command_line_paths(PCWSTR(line.as_ptr())).expect("the line parses");
    assert_eq!(paths, vec![PathBuf::from(r"C:\temp\文件.txt")]);

    // No arguments at all is an empty list, not an error.
    let line = wide("rusthashtab.exe");
    // SAFETY: as above.
    let paths = window::command_line_paths(PCWSTR(line.as_ptr())).expect("the line parses");
    assert!(paths.is_empty());
}
