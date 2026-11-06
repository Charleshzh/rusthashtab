//! The resizable top-level window that hosts the property page outside the shell.
//!
//! # Why a host window at all
//!
//! The page was written to be a child of the file Properties sheet: `comctl32`
//! creates it from a dialog template, sends `WM_SETFONT`, and never resizes it.
//! The context menu and the standalone launcher have no sheet to do that, so this
//! module supplies the smallest honest substitute -- a plain `WS_OVERLAPPEDWINDOW`
//! that creates the same dialog as a child, resizes it to fill its client area,
//! and runs the message loop. Everything inside the page (the scan, the list, the
//! buttons) is the shipping code; only the window around it is new.
//!
//! # Threading and quit
//!
//! A window belongs to the thread that created it, and so does its message queue.
//! [`open`] creates the host on the calling thread and never touches another one;
//! [`message_loop`] must run on that same thread. [`HostOptions::quit_on_close`]
//! decides whether closing the window posts `WM_QUIT` to the calling thread. The
//! shell's context-menu path owns a dedicated thread and needs the quit to end its
//! loop; tests and an embedding host that pumps messages itself must not have it,
//! because a stray `WM_QUIT` would end a loop this module does not own.
//!
//! # Ownership
//!
//! The host owns the [`DialogState`] box for exactly as long as the window exists:
//! it is created before the child dialog, handed to the page as a raw pointer, and
//! freed on the host's `WM_DESTROY` *after* the child dialog has been destroyed --
//! the page's own `WM_DESTROY` is where the scan thread is joined, so freeing
//! earlier would let the scan post into freed state. Both the host's and the
//! page's `GWLP_USERDATA` slots are cleared before the corresponding allocation is
//! released, which makes messages already in the queue harmless instead of a read
//! of freed memory.

#![cfg(windows)]

use crate::dialog::direct_dialog_proc;
use crate::resource::IDD_HASH_PROPPAGE;
use crate::{DialogState, UiError};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HINSTANCE, HLOCAL, HWND, LPARAM, LRESULT, LocalFree,
    RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{COLOR_BTNFACE, HBRUSH};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateDialogParamW, CreateWindowExW, DefWindowProcW,
    DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW, GetSystemMetrics, GetWindowRect,
    IDC_ARROW, IDI_APPLICATION, IsDialogMessageW, IsWindow, LoadCursorW, LoadIconW, MINMAXINFO,
    MSG, PostQuitMessage, RegisterClassW, SHOW_WINDOW_CMD, SM_CXSCREEN, SM_CYSCREEN,
    SPI_GETWORKAREA, SW_HIDE, SW_SHOWNORMAL, SWP_NOACTIVATE, SWP_NOZORDER,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SetForegroundWindow, SetWindowPos, ShowWindow,
    SystemParametersInfoW, TranslateMessage, WM_CLOSE, WM_DESTROY, WM_DPICHANGED, WM_GETMINMAXINFO,
    WM_NCDESTROY, WM_SIZE, WNDCLASSW, WS_CLIPCHILDREN, WS_EX_APPWINDOW, WS_EX_CONTROLPARENT,
    WS_OVERLAPPEDWINDOW,
};
use windows::core::{PCWSTR, w};

/// The window class this module registers, once per process.
///
/// One UI module per process is the contract: the shipping DLL is the only module
/// that contains this code, and the test binary is the only module in a test
/// process. Registering the class on first use means a property sheet that was
/// never asked for a standalone window pays nothing for it.
const CLASS_NAME: PCWSTR = w!("rustHashTabWindow");

/// How much wider and taller the default window is than the template, in pixels.
///
/// A property page is designed to fit a sheet's page area; shown on its own it
/// looks cramped at exactly the template size. One and a half times the template,
/// or the template plus this margin, whichever is larger, gives the results list
/// room to show a useful number of rows without filling the screen.
const DEFAULT_EXTRA_WIDTH: i32 = 220;
/// See [`DEFAULT_EXTRA_WIDTH`].
const DEFAULT_EXTRA_HEIGHT: i32 = 160;

/// How a host window behaves once it is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOptions {
    /// The `SW_*` value passed to `ShowWindow`.
    ///
    /// An `i32` rather than `SHOW_WINDOW_CMD` so callers outside the `windows`
    /// crate's type vocabulary (a launcher, a test) can pass the documented
    /// integer without converting.
    pub show: i32,
    /// Whether closing the window posts `WM_QUIT` to the creating thread.
    ///
    /// `true` for a host that owns its message loop (the context-menu thread and
    /// [`run`]); `false` when someone else pumps messages and must not have its
    /// loop ended by a window it did not create.
    pub quit_on_close: bool,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            show: SW_SHOWNORMAL.0,
            quit_on_close: true,
        }
    }
}

/// Everything that can stop the host window from opening or running.
#[derive(Debug, thiserror::Error)]
pub enum WindowError {
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
    ///
    /// A null `HINSTANCE` means the UI module never recorded itself, so there is
    /// nowhere for `CreateDialogParamW` to find the template.
    #[error("dialog resource {0} not found in this module")]
    MissingResource(u16),
    /// The page's own UI layer refused to build.
    #[error("the page could not be built: {0}")]
    Page(#[source] UiError),
}

impl WindowError {
    /// The `HRESULT` a caller that is a COM server should report.
    ///
    /// The mapping lives here rather than at each call site so a new failure mode
    /// cannot be added without deciding what the shell is told about it.
    pub fn to_hresult(&self) -> windows::core::HRESULT {
        match self {
            WindowError::Win32 { source, .. } => source.code(),
            WindowError::MissingResource(_) => windows::Win32::Foundation::E_FAIL,
            WindowError::Page(error) => error.to_hresult(),
        }
    }
}

/// The state a host window's procedure needs, owned by that window.
struct HostState {
    /// The child dialog the page lives in.
    page: HWND,
    /// The page's state, owned by the host and freed on `WM_DESTROY`.
    state: *mut DialogState,
    /// Whether closing this window should end the message loop.
    quit_on_close: bool,
    /// The smallest outer size the user may drag the window to.
    min_track: (i32, i32),
}

/// The window class registration, attempted once per process.
static CLASS_REGISTRATION: OnceLock<Result<(), windows::core::Error>> = OnceLock::new();

/// Create the host window and the page inside it, without running a message loop.
///
/// The returned handle belongs to the calling thread. The window is created hidden
/// and only shown according to [`HostOptions::show`], so a caller that wants to
/// inspect or position it first can do so before anything appears on screen.
///
/// # Errors
///
/// [`WindowError::MissingResource`] when `hinstance` is null, [`WindowError::Page`]
/// when the dialog itself cannot be created, and [`WindowError::Win32`] for a
/// failed Win32 call. On any failure no window is left behind.
pub fn open(
    hinstance: HINSTANCE,
    roots: Vec<PathBuf>,
    settings: rusthashtab_settings::Settings,
    options: HostOptions,
) -> Result<HWND, WindowError> {
    if hinstance.is_invalid() {
        // The page cannot be created without the module its template lives in, and
        // there is no sensible window to show around a page that will not exist.
        return Err(WindowError::MissingResource(IDD_HASH_PROPPAGE));
    }

    ensure_class(hinstance)?;

    let title: Vec<u16> = crate::strings::text(crate::strings::Key::WindowTitle)
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    // SAFETY: the class is registered above, the title is a NUL-terminated buffer
    // that outlives the call, every create parameter this module does not use is
    // null, and the size is the documented `CW_USEDEFAULT` sentinel.
    let host = unsafe {
        CreateWindowExW(
            WS_EX_APPWINDOW | WS_EX_CONTROLPARENT,
            CLASS_NAME,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            None,
            None,
            Some(hinstance),
            None,
        )
    }
    .map_err(|error| WindowError::Win32 {
        context: "creating the host window",
        source: error,
    })?;

    // Every failure from here on must not leave a window behind. By the time an
    // allocation is stored in `host`, the window procedure's teardown owns it, so
    // destroying the window is the whole cleanup.
    if let Err(error) = build_page(host, hinstance, roots, settings, options) {
        // SAFETY: `host` is a live top-level window created by this thread and has
        // not been destroyed; destroying it once is what this is for.
        unsafe {
            let _ = DestroyWindow(host);
        }
        return Err(error);
    }

    Ok(host)
}

/// Run the host's message loop until `WM_QUIT`.
///
/// The loop dispatches keyboard navigation to the page through `IsDialogMessageW`,
/// so tab order, mnemonics and default buttons behave as they do in the shell.
/// `WM_QUIT` normally comes from [`HostOptions::quit_on_close`] when the user
/// closes the window; a caller whose host was created with `quit_on_close: false`
/// is responsible for ending the loop itself (by posting `WM_QUIT`, or by not
/// calling this function at all and pumping messages its own way).
///
/// # Errors
///
/// [`WindowError::Win32`] when the message queue itself fails; that is a broken
/// thread, not a user action.
pub fn message_loop(host: HWND) -> Result<(), WindowError> {
    loop {
        let mut message = MSG::default();
        // SAFETY: `message` is a live local, the filter is "every message for this
        // thread", and the return value is checked below.
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 == 0 {
            break;
        }
        if result.0 == -1 {
            // `GetMessageW` says "error"; the thread's last-error is the only
            // detail Win32 offers.
            return Err(WindowError::Win32 {
                context: "reading the window message queue",
                source: windows::core::Error::from_thread(),
            });
        }

        // SAFETY: the page handle is only used while the host is alive, and
        // `IsDialogMessageW` treats a message that is not for that dialog as
        // not handled.
        let handled = host_page(host)
            .is_some_and(|page| unsafe { IsDialogMessageW(page, &message) }.as_bool());
        if handled {
            continue;
        }

        // SAFETY: `message` was filled by `GetMessageW`; `TranslateMessage` and
        // `DispatchMessageW` are the documented pair for a `GetMessage` loop.
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    // A loop that was ended by something other than closing the window (a posted
    // `WM_QUIT` from a caller) still needs the window torn down on this thread.
    // SAFETY: `host` is a window handle this thread may destroy; destroying an
    // already-destroyed handle is refused by `IsWindow` below.
    unsafe {
        if IsWindow(Some(host)).as_bool() {
            let _ = DestroyWindow(host);
        }
    }

    Ok(())
}

/// Open a host that owns its message loop, run it, and return when it closes.
///
/// This is the whole standalone experience in one call: [`open`] with
/// `quit_on_close: true`, then [`message_loop`]. It must be called on the thread
/// that will run the loop.
///
/// # Errors
///
/// Whatever [`open`] or [`message_loop`] returns.
pub fn run(
    hinstance: HINSTANCE,
    roots: Vec<PathBuf>,
    settings: rusthashtab_settings::Settings,
    show: i32,
) -> Result<(), WindowError> {
    let host = open(
        hinstance,
        roots,
        settings,
        HostOptions {
            show,
            quit_on_close: true,
        },
    )?;
    message_loop(host)
}

/// The file arguments of a command line, with the program name removed.
///
/// # Why `CommandLineToArgvW`
///
/// The command line arrives as one UTF-16 string. Splitting it by hand gets the
/// quoting rules wrong in exactly the cases that matter to a "Open with" handler:
/// a path containing spaces, a path containing quotes, a path ending in a
/// backslash. `CommandLineToArgvW` is the documented parser for the same grammar
/// the C runtime uses, so a file dragged onto the executable and a file passed by
/// the shell both resolve the way the user expects.
///
/// Paths are rebuilt from the original UTF-16 units rather than through a UTF-8
/// `String`: a file name that is not valid Unicode must still be openable, and a
/// lossy conversion would turn it into a different file.
///
/// # Errors
///
/// [`WindowError::Win32`] when the argument list cannot be allocated or parsed.
/// An empty or null command line is not an error; it simply has no file
/// arguments, which is what makes launching the executable with no arguments exit
/// without opening a window instead of failing on a blank file name.
pub fn command_line_paths(cmdline: PCWSTR) -> Result<Vec<PathBuf>, WindowError> {
    if cmdline.is_null() {
        return Ok(Vec::new());
    }

    let mut argument_count: i32 = 0;
    // SAFETY: `cmdline` is a NUL-terminated wide string supplied by the caller (in
    // practice `GetCommandLineW`), and `argument_count` is a local the call writes
    // into. On success the returned block is freed below with `LocalFree`.
    let arguments = unsafe { CommandLineToArgvW(cmdline, &mut argument_count) };
    if arguments.is_null() {
        return Err(WindowError::Win32 {
            context: "parsing the command line",
            source: windows::core::Error::from_thread(),
        });
    }

    let mut paths = Vec::new();
    // `argv[0]` is the program name; the files start at index one. A command line
    // that is only the program name therefore produces no paths.
    for index in 1..argument_count.max(0) {
        // SAFETY: on success `CommandLineToArgvW` returns an array of
        // `argument_count` NUL-terminated wide strings, so this index is in range.
        let argument = unsafe { *arguments.add(index as usize) };
        // SAFETY: the same array guarantees the string is NUL-terminated.
        let wide = unsafe { argument.as_wide() };

        // An explicitly empty argument (`""`) parses as a valid empty argument, not
        // a missing one, but it names no file; dropping it keeps the caller from
        // opening the current directory.
        let path = PathBuf::from(std::ffi::OsString::from_wide(wide));
        if path.as_os_str().is_empty() {
            continue;
        }
        paths.push(path);
    }

    // SAFETY: `arguments` is the block `CommandLineToArgvW` allocated and returned
    // non-null above; it is freed exactly once here.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(arguments as *mut core::ffi::c_void)));
    }

    Ok(paths)
}

/// Register the window class once, however many windows are opened.
fn ensure_class(hinstance: HINSTANCE) -> Result<(), WindowError> {
    match CLASS_REGISTRATION.get_or_init(|| register_class(hinstance)) {
        Ok(()) => Ok(()),
        Err(error) => Err(WindowError::Win32 {
            context: "registering the window class",
            source: error.clone(),
        }),
    }
}

/// Register the host's window class with the module that owns the dialog template.
fn register_class(hinstance: HINSTANCE) -> Result<(), windows::core::Error> {
    // The stock application icon and arrow cursor are shared system resources: a
    // null module asks for them, and they must *not* be destroyed, so the class
    // borrows them for the life of the process.
    // SAFETY: both calls pass a null module, which is the documented way to ask
    // for these predefined resources; neither call fails for them.
    let (icon, cursor) = unsafe {
        (
            LoadIconW(None, IDI_APPLICATION),
            LoadCursorW(None, IDC_ARROW),
        )
    };
    let icon = icon?;
    let cursor = cursor?;

    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: icon,
        hCursor: cursor,
        // The `+ 1` is the documented `COLOR_*`-index convention: a class
        // background brush may be a system colour as long as it is offset by one,
        // and it is then painted by the system rather than owned by us.
        hbrBackground: HBRUSH((COLOR_BTNFACE.0 + 1) as isize as *mut core::ffi::c_void),
        lpszMenuName: PCWSTR::null(),
        lpszClassName: CLASS_NAME,
    };

    // SAFETY: `class` is a fully initialised `WNDCLASSW` whose strings and handles
    // outlive the call: the class name is a `'static` literal and the icon and
    // cursor are shared system resources.
    let atom = unsafe { RegisterClassW(&class) };
    if atom == 0 {
        // A second UI module in one process -- two copies of this crate linked into
        // one executable, or the DLL plus a test binary loading it -- finds the
        // class already registered. That is the state this function exists to
        // produce, so it is success rather than an error.
        // SAFETY: `GetLastError` takes no arguments and reads the calling thread's
        // last-error value.
        if unsafe { GetLastError() } == ERROR_CLASS_ALREADY_EXISTS {
            return Ok(());
        }
        return Err(windows::core::Error::from_thread());
    }

    Ok(())
}

/// Create the page dialog and everything the host needs in order to own it.
fn build_page(
    host: HWND,
    hinstance: HINSTANCE,
    roots: Vec<PathBuf>,
    settings: rusthashtab_settings::Settings,
    options: HostOptions,
) -> Result<(), WindowError> {
    let frame = frame_size(host)?;

    let mut state = Box::new(DialogState::new(roots, settings));
    // Diagnostic dialogs (the settings sheet) live in the same module as the page
    // template, so the page has to carry the module handle.
    state.instance = Some(hinstance);
    let state_pointer = Box::into_raw(state);

    // SAFETY: the template id is the one `ui.rc` declares and `hinstance` owns,
    // `host` is a live parent window, and `direct_dialog_proc` is the dialog
    // procedure that knows the `lParam` is a `DialogState` pointer.
    let page = match unsafe {
        CreateDialogParamW(
            Some(hinstance),
            PCWSTR(IDD_HASH_PROPPAGE as usize as *const u16),
            Some(host),
            Some(direct_dialog_proc),
            LPARAM(state_pointer as isize),
        )
    } {
        Ok(page) => page,
        Err(error) => {
            // The page window never existed, so nothing else can reclaim the state
            // or start a scan against it.
            // SAFETY: `state_pointer` came from `Box::into_raw` above and has not
            // been given to a window.
            drop(unsafe { Box::from_raw(state_pointer) });
            return Err(WindowError::Page(UiError::Win32 {
                context: "creating the page dialog",
                source: error,
            }));
        }
    };

    // The page's template size is its minimum: the sheet was designed to be shown
    // at it, and the controls below the list are placed against the bottom edge.
    let (page_width, page_height) = match client_size(page) {
        Ok(size) => size,
        Err(error) => {
            // The page exists but the host will not take ownership of it; destroy
            // it first so its `WM_DESTROY` joins the scan, then release the state.
            // SAFETY: `page` is the dialog just created and is not owned by any
            // host state yet; it is destroyed exactly once here.
            unsafe {
                let _ = DestroyWindow(page);
            }
            // SAFETY: as in the failure above -- the page is gone, so nothing can
            // reach the state any more.
            drop(unsafe { Box::from_raw(state_pointer) });
            return Err(error);
        }
    };

    let min_track = (page_width + frame.0, page_height + frame.1);
    let (x, y, width, height) = initial_window_rect(page_width, page_height, frame);

    // From this assignment on, the host window owns both allocations: its
    // `WM_DESTROY` destroys the page, frees the state, and posts the quit.
    let host_state = Box::new(HostState {
        page,
        state: state_pointer,
        quit_on_close: options.quit_on_close,
        min_track,
    });
    crate::window_data::store(host, Box::into_raw(host_state) as isize);

    // SAFETY: `host` is a live top-level window of this thread; the position and
    // size are computed from the measured frame and the template, and the caller
    // keeps the window hidden until the `ShowWindow` below.
    if let Err(error) = unsafe {
        SetWindowPos(
            host,
            None,
            x,
            y,
            width,
            height,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    } {
        return Err(WindowError::Win32 {
            context: "sizing the host window",
            source: error,
        });
    }

    // SAFETY: `host` is a live window on this thread; `show` is the caller's
    // documented `SW_*` value and may be `SW_HIDE` when the host is opened for
    // inspection or for an embedding host to position first.
    unsafe {
        let _ = ShowWindow(host, SHOW_WINDOW_CMD(options.show));
    }
    if options.show != SW_HIDE.0 {
        // Best effort: the foreground lock may refuse; that is not an error.
        // SAFETY: `host` is a live window on this thread.
        unsafe {
            let _ = SetForegroundWindow(host);
        }
    }

    Ok(())
}

/// The difference between a window's outer size and its client size.
///
/// Measured from a live window rather than computed from style bits: the frame
/// depends on the theme, the DPI, and the window's styles, and `GetWindowRect`
/// minus `GetClientRect` is exactly the border the user may not drag.
fn frame_size(window: HWND) -> Result<(i32, i32), WindowError> {
    let mut outer = RECT::default();
    let mut client = RECT::default();
    // SAFETY: both calls only write into the two local rectangles.
    unsafe {
        GetWindowRect(window, &mut outer).map_err(|error| WindowError::Win32 {
            context: "measuring the window frame",
            source: error,
        })?;
        GetClientRect(window, &mut client).map_err(|error| WindowError::Win32 {
            context: "measuring the client area",
            source: error,
        })?;
    }

    Ok((
        (outer.right - outer.left) - (client.right - client.left),
        (outer.bottom - outer.top) - (client.bottom - client.top),
    ))
}

/// A window's client width and height.
fn client_size(window: HWND) -> Result<(i32, i32), WindowError> {
    let mut client = RECT::default();
    // SAFETY: the call only writes into the local rectangle.
    unsafe { GetClientRect(window, &mut client) }.map_err(|error| WindowError::Win32 {
        context: "measuring the client area",
        source: error,
    })?;
    Ok((
        (client.right - client.left).max(0),
        (client.bottom - client.top).max(0),
    ))
}

/// The outer rectangle for a window whose page needs `page_width` x `page_height`.
///
/// The default is larger than the template so the results list is useful on its
/// own, but never larger than the desktop's work area (a floating window that
/// opens bigger than the screen is a window the user has to fix by hand), and
/// never smaller than the template.
fn initial_window_rect(
    page_width: i32,
    page_height: i32,
    frame: (i32, i32),
) -> (i32, i32, i32, i32) {
    let work = work_area();
    let work_width = (work.right - work.left).max(1);
    let work_height = (work.bottom - work.top).max(1);

    let minimum = (page_width + frame.0, page_height + frame.1);
    let desired = (
        (page_width * 3 / 2).max(page_width + DEFAULT_EXTRA_WIDTH) + frame.0,
        (page_height * 3 / 2).max(page_height + DEFAULT_EXTRA_HEIGHT) + frame.1,
    );

    let width = desired.0.min(work_width.max(minimum.0)).max(minimum.0);
    let height = desired.1.min(work_height.max(minimum.1)).max(minimum.1);
    let x = work.left + (work_width - width).max(0) / 2;
    let y = work.top + (work_height - height).max(0) / 2;

    (x, y, width, height)
}

/// The desktop work area, or the primary screen if the work area cannot be read.
fn work_area() -> RECT {
    let mut area = RECT::default();
    // SAFETY: `SPI_GETWORKAREA` writes a `RECT` into the provided buffer, and a
    // zero update flag says this is a read.
    let result = unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut area as *mut RECT as *mut core::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if result.is_ok() && area.right > area.left && area.bottom > area.top {
        return area;
    }

    // The work-area query is a read of a system setting and effectively cannot
    // fail, but a window sized against zero would be invisible, so a screen-sized
    // fallback is better than the empty rectangle.
    // SAFETY: `GetSystemMetrics` takes an index and writes nothing.
    let (width, height) = unsafe {
        (
            GetSystemMetrics(SM_CXSCREEN).max(1),
            GetSystemMetrics(SM_CYSCREEN).max(1),
        )
    };
    RECT {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    }
}

/// The host's window procedure.
extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_SIZE => {
            resize_page(hwnd, lparam);
            LRESULT(0)
        }
        WM_GETMINMAXINFO => {
            on_get_min_max_info(hwnd, lparam);
            LRESULT(0)
        }
        WM_CLOSE => {
            // `DestroyWindow`, never `EndDialog`: this is not a modal dialog, and
            // `EndDialog` on a window it does not own is a crash or a leak.
            // SAFETY: `hwnd` is the window this procedure belongs to.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            on_destroy(hwnd);
            // SAFETY: the parameters are the ones the message carries.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
        WM_NCDESTROY => {
            // The window is gone; the slot must not be read after this returns,
            // because the allocation behind it is being freed by `WM_DESTROY`.
            crate::window_data::store(hwnd, 0);
            // SAFETY: the parameters are the ones the message carries.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, lparam);
            LRESULT(0)
        }
        _ => {
            // SAFETY: every message this procedure does not handle belongs to
            // `DefWindowProcW`, with the parameters it was given.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
    }
}

/// `WM_SIZE`: make the page fill the new client area; the page reflows its controls.
fn resize_page(host: HWND, lparam: LPARAM) {
    let width = (lparam.0 as u32 & 0xffff) as i32;
    let height = ((lparam.0 as u32 >> 16) & 0xffff) as i32;

    let _ = with_host_state(host, |state| {
        if state.page.is_invalid() {
            return;
        }
        // SAFETY: `state.page` is the dialog this host created and has not yet
        // destroyed; it belongs to the same thread; `None` leaves the z-order be.
        unsafe {
            let _ = SetWindowPos(
                state.page,
                None,
                0,
                0,
                width,
                height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    });
}

/// `WM_GETMINMAXINFO`: refuse to shrink below the template plus the window frame.
fn on_get_min_max_info(host: HWND, lparam: LPARAM) {
    if lparam.0 == 0 {
        return;
    }

    // SAFETY: `WM_GETMINMAXINFO` documents `lParam` as a pointer to a
    // `MINMAXINFO` the sender owns for the duration of the call.
    let info = unsafe { &mut *(lparam.0 as *mut MINMAXINFO) };
    let _ = with_host_state(host, |state| {
        info.ptMinTrackSize.x = state.min_track.0;
        info.ptMinTrackSize.y = state.min_track.1;
    });
}

/// `WM_DPICHANGED`: move and resize the host to the rectangle the system suggests.
///
/// The controls reflow through `WM_SIZE`, but the font is not rebuilt. That is the
/// known limitation recorded for Phase 7: a per-monitor-DPI host would need a new
/// font and a re-measured list, which is deliberately out of scope for the first
/// windowed version.
fn on_dpi_changed(host: HWND, lparam: LPARAM) {
    if lparam.0 == 0 {
        return;
    }

    // SAFETY: `WM_DPICHANGED` documents `lParam` as a pointer to the suggested
    // window rectangle, owned by the sender for the duration of the call.
    let suggested = unsafe { &*(lparam.0 as *const RECT) };

    // SAFETY: `host` is a live window of this thread; the rectangle is the one the
    // system just suggested for its new DPI.
    unsafe {
        let _ = SetWindowPos(
            host,
            None,
            suggested.left,
            suggested.top,
            (suggested.right - suggested.left).max(1),
            (suggested.bottom - suggested.top).max(1),
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

/// `WM_DESTROY`: release everything this window still owns.
///
/// The order is load-bearing. The user-data slot is cleared first, so a message
/// that is already queued has nothing to find. Windows destroys a window's child
/// windows **before** sending the parent its own `WM_DESTROY`, so the page's
/// teardown -- which is where the hashing thread is joined -- has normally already
/// run by the time this is called. The `IsWindow` check covers the case where the
/// page is still alive, without destroying it twice, and only once the page is
/// gone is the [`DialogState`] freed. `WM_QUIT` is posted last, so the message
/// loop cannot leave before teardown is complete.
fn on_destroy(host: HWND) {
    let stored = crate::window_data::load(host);
    crate::window_data::store(host, 0);
    if !crate::window_data::holds_address(stored) {
        return;
    }

    // SAFETY: `stored` is the `Box<HostState>` pointer `build_page` installed and
    // nothing has freed it, because this is the one place it is reclaimed and the
    // slot was just cleared so this cannot run twice.
    let host_state = unsafe { Box::from_raw(stored as *mut HostState) };

    // SAFETY: the page is the child dialog created for this host. Windows normally
    // destroys it (and sends it `WM_DESTROY`) before this window's own
    // `WM_DESTROY`; the `IsWindow` check is what makes that ordering irrelevant
    // and a double destroy impossible. If the page is still alive, destroying it
    // now runs its teardown, which joins the scan. Either way it is gone before
    // the state below is freed.
    unsafe {
        if IsWindow(Some(host_state.page)).as_bool() {
            let _ = DestroyWindow(host_state.page);
        }
    }

    // SAFETY: `state` came from `Box::into_raw` in `build_page`; it is reclaimed
    // exactly once here, after the page that borrowed it is gone.
    drop(unsafe { Box::from_raw(host_state.state) });

    if host_state.quit_on_close {
        // SAFETY: this procedure runs on the thread that created the window and
        // therefore owns its message queue, which is the only thread that may end
        // it. An embedding host passes `quit_on_close: false` precisely so this is
        // not called under a loop it does not own.
        unsafe {
            PostQuitMessage(0);
        }
    }
}

/// Run `action` with the host's state, if the window still has one.
fn with_host_state<R>(host: HWND, action: impl FnOnce(&HostState) -> R) -> Option<R> {
    let stored = crate::window_data::load(host);
    if !crate::window_data::holds_address(stored) {
        return None;
    }

    // SAFETY: a stored address is the `Box<HostState>` `build_page` installed; the
    // slot is cleared before that box is freed, and window procedures for one
    // window cannot run concurrently on the same thread.
    let state = unsafe { &*(stored as *const HostState) };
    Some(action(state))
}

/// The page dialog hosted by `host`, if it is still open.
fn host_page(host: HWND) -> Option<HWND> {
    with_host_state(host, |state| state.page)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The default window is larger than the page but never larger than the work
    /// area it has to fit on.
    #[test]
    fn the_default_window_fits_the_work_area() {
        let (x, y, width, height) = initial_window_rect(400, 300, (16, 39));
        assert!(width >= 400 + 16, "never narrower than the page");
        assert!(height >= 300 + 39, "never shorter than the page");
        assert!(x >= 0);
        assert!(y >= 0);

        let work = work_area();
        // Centred within the work area, with the frame included in the size.
        assert!(x + width <= work.right.max(width));
        assert!(y + height <= work.bottom.max(height));
    }

    /// A template larger than the work area still gets the template's size: the
    /// window must be usable even if the user has to move it.
    #[test]
    fn a_page_larger_than_the_desktop_keeps_its_minimum() {
        let (_x, _y, width, height) = initial_window_rect(100_000, 100_000, (16, 39));
        assert!(width >= 100_000);
        assert!(height >= 100_000);
    }

    /// A null command line has no file arguments and is not an error.
    ///
    /// The standalone launcher opens a window only when it was given files, so an
    /// empty list must be an ordinary no-arguments result rather than a parse
    /// failure -- and a null pointer must not reach Win32 at all.
    #[test]
    fn a_null_command_line_has_no_paths() {
        let paths = command_line_paths(PCWSTR::null()).expect("a null command line is empty");
        assert!(paths.is_empty());
    }
}
