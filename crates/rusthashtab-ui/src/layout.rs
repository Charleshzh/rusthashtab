//! How the page's controls follow the window when the standalone host resizes it.
//!
//! # Why a captured baseline
//!
//! A property sheet page is laid out once, from its dialog template, by
//! `comctl32`, and the sheet never resizes it. The standalone window can be
//! resized by the user, and the template's coordinates are the only description
//! of the intended geometry there is. So [`capture`] records each control's
//! rectangle **in page-client coordinates** after `WM_INITDIALOG` has built the
//! controls, and [`apply`] re-derives every rectangle from that baseline for the
//! new client size.
//!
//! The arithmetic is a pure function ([`place`]) on purpose. The numbers are
//! pixels, and pixels depend on the DPI the dialog was created at, so only the
//! *rules* -- which margins are fixed and which edges follow the window -- can be
//! asserted portably. The unit tests below assert those rules without a window;
//! `tests/window_host.rs` asserts the same rules against real controls.
//!
//! # Which control follows which edge
//!
//! | Control | Horizontal | Vertical |
//! |---|---|---|
//! | results list | stretch | stretch |
//! | status line, expected-digest edit, progress bar | stretch | pin to the bottom |
//! | Check, Verify, Export, Settings, Cancel | pin to the right | pin to the bottom |
//! | Current-file-only checkbox, Format combo, Copy checksums, Copy | stay put | pin to the bottom |
//!
//! Pinning to an edge keeps that edge's distance from the corresponding page
//! edge fixed; a control that "stays put" horizontally keeps its template column.
//! The two section labels (`Expected:` and `Format:`) follow the rows they label.
//!
//! # What is not handled
//!
//! There is no font rebuild and no per-DPI rescaling here. `WM_DPICHANGED` hands
//! the host a suggested rectangle and the controls reflow in the pixels the
//! baseline was captured at; a font that does not follow the new DPI is the known
//! Phase 7 limitation, not an accident of this module.

#![cfg(windows)]

use crate::resource;
use windows::Win32::Foundation::{HWND, LPARAM, POINT, RECT};
use windows::Win32::Graphics::Gdi::MapWindowPoints;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetClientRect, GetDlgItem, GetWindowRect, GetWindowTextW, SWP_NOACTIVATE,
    SWP_NOZORDER, SetWindowPos,
};
use windows::core::BOOL;

/// The label in front of the expected-digest edit box.
///
/// The template declares both this and [`FORMAT_LABEL_TEXT`] with `IDC_STATIC`
/// (`-1`), and a dialog may contain many controls with that id, so `GetDlgItem`
/// cannot tell them apart. Their text is the only stable identity they have, and
/// it is the same literal the compiled template carries. The window test asserts
/// that both labels are found and follow their rows, so a template edit that
/// changes the text fails a test instead of silently leaving a label behind.
const EXPECTED_LABEL_TEXT: &str = "Expected:";

/// The label in front of the export-format combo box.
const FORMAT_LABEL_TEXT: &str = "Format:";

/// A rectangle in page-client pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl Rect {
    const fn new(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self {
            left,
            top,
            right,
            bottom,
        }
    }

    const fn width(self) -> i32 {
        self.right - self.left
    }

    const fn height(self) -> i32 {
        self.bottom - self.top
    }
}

/// How one control follows the page's client area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// Fixed margins on all four sides: the control grows with the page.
    Stretch,
    /// The left margin, height and bottom margin are fixed; the width follows the
    /// page's right edge.
    StretchWidthBottom,
    /// Fixed size with both right and bottom margins fixed: the control stays in
    /// the bottom-right corner.
    BottomRight,
    /// Fixed size with the left column fixed and the bottom margin fixed: the
    /// control moves down with the page but does not change size.
    BottomLeft,
}

/// One control and the geometry it must keep following.
#[derive(Debug, Clone, Copy)]
struct Placement {
    control: HWND,
    anchor: Anchor,
    rect: Rect,
}

/// The template geometry, captured once, that every resize reflows from.
///
/// The client size is part of the baseline because the margins are derived from
/// it: a control's distance from the right edge is *this* width minus its right
/// coordinate. Capturing the controls alone would not say what those margins
/// were.
#[derive(Debug, Clone)]
pub(crate) struct Baseline {
    client: (i32, i32),
    controls: Vec<Placement>,
}

/// Record the page's template geometry, or `None` if the page cannot be measured.
///
/// Called from `WM_INITDIALOG` after the page has built its controls. A control
/// that is missing from the template is simply absent from the baseline: the page
/// already tolerates controls disappearing (the source is compiled against a
/// template it does not own), and refusing to lay out the rest because one is
/// missing would be worse than laying out what exists.
pub(crate) fn capture(page: HWND) -> Option<Baseline> {
    let mut client = RECT::default();
    // SAFETY: `page` is the dialog whose client area is being measured, and
    // `client` is a local the call writes into.
    unsafe { GetClientRect(page, &mut client) }.ok()?;
    let client = (client.right - client.left, client.bottom - client.top);

    let mut controls = Vec::new();

    // Template order is not required here -- each role is looked up by id -- but
    // the list is kept in the order the template declares so a future control is
    // added next to its neighbours.
    for (anchor, id) in [
        (Anchor::Stretch, resource::IDC_HASH_LIST),
        (Anchor::StretchWidthBottom, resource::IDC_HASH_STATUS),
        (Anchor::StretchWidthBottom, resource::IDC_HASH_EXPECTED),
        (Anchor::BottomRight, resource::IDC_HASH_CHECK),
        (Anchor::BottomLeft, resource::IDC_HASH_CURRENT_ONLY),
        (Anchor::BottomLeft, resource::IDC_HASH_EXPORT_FORMAT),
        (Anchor::BottomRight, resource::IDC_HASH_VERIFY),
        (Anchor::BottomRight, resource::IDC_HASH_EXPORT),
        (Anchor::BottomLeft, resource::IDC_HASH_EXPORT_CLIPBOARD),
        (Anchor::BottomLeft, resource::IDC_HASH_COPY),
        (Anchor::BottomRight, resource::IDC_HASH_SETTINGS),
        (Anchor::BottomRight, resource::IDC_HASH_CANCEL),
        (Anchor::StretchWidthBottom, resource::IDC_HASH_PROGRESS),
    ] {
        let Some(control) = find_control(page, id) else {
            continue;
        };
        let Some(rect) = control_rect(page, control) else {
            continue;
        };
        controls.push(Placement {
            control,
            anchor,
            rect,
        });
    }

    // The section labels are `IDC_STATIC` in the template; see the constants above
    // for why their text is the only way to address them. They sit in the lower
    // block, so they follow the bottom edge exactly like the controls beside them.
    for text in [EXPECTED_LABEL_TEXT, FORMAT_LABEL_TEXT] {
        let Some(control) = find_child_with_text(page, text) else {
            continue;
        };
        let Some(rect) = control_rect(page, control) else {
            continue;
        };
        controls.push(Placement {
            control,
            anchor: Anchor::BottomLeft,
            rect,
        });
    }

    Some(Baseline { client, controls })
}

/// Move every captured control to where the new client size puts it.
///
/// The page has no layout engine of its own: this runs from the page's `WM_SIZE`,
/// which the host produces by resizing the child dialog to its client area.
pub(crate) fn apply(baseline: &Baseline, width: i32, height: i32) {
    let target = (width.max(0), height.max(0));
    for placement in &baseline.controls {
        let placed = place(placement.anchor, placement.rect, baseline.client, target);

        // SAFETY: every `control` in the baseline is a live child of `page`; a
        // control cannot be destroyed before the dialog that owns it. `SetWindowPos`
        // takes the owner's thread -- this is that thread -- and `None` means
        // "leave the z-order alone".
        unsafe {
            let _ = SetWindowPos(
                placement.control,
                None,
                placed.left,
                placed.top,
                placed.width(),
                placed.height(),
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }
}

/// Where one control belongs for a new client size.
///
/// Pure arithmetic, so the anchoring rules are testable without a window. Widths
/// and heights that would go negative are clamped to zero and offsets that would
/// go negative are clamped to the page's edge: the host enforces a minimum size
/// taken from the template, but a message can still arrive before that minimum
/// has been applied, and a zero-sized rectangle is a harmless control rather than
/// an inverted one.
fn place(anchor: Anchor, rect: Rect, baseline: (i32, i32), target: (i32, i32)) -> Rect {
    let (baseline_width, baseline_height) = baseline;
    let (target_width, target_height) = target;

    let left = rect.left.max(0);
    let top = rect.top.max(0);
    let right_margin = baseline_width - rect.right;
    let bottom_margin = baseline_height - rect.bottom;

    match anchor {
        Anchor::Stretch => {
            let right = (target_width - right_margin).max(left);
            let bottom = (target_height - bottom_margin).max(top);
            Rect::new(left, top, right, bottom)
        }
        Anchor::StretchWidthBottom => {
            let right = (target_width - right_margin).max(left);
            let top = (target_height - bottom_margin - rect.height()).max(0);
            Rect::new(left, top, right, top + rect.height())
        }
        Anchor::BottomRight => {
            let left = (target_width - right_margin - rect.width()).max(0);
            let top = (target_height - bottom_margin - rect.height()).max(0);
            Rect::new(left, top, left + rect.width(), top + rect.height())
        }
        Anchor::BottomLeft => {
            let top = (target_height - bottom_margin - rect.height()).max(0);
            Rect::new(left, top, left + rect.width(), top + rect.height())
        }
    }
}

/// One of the page's controls, by dialog id.
fn find_control(page: HWND, id: i32) -> Option<HWND> {
    // SAFETY: `page` is the page dialog and the identifier is one the template
    // declares (a missing control comes back as an error, handled by `ok`).
    unsafe { GetDlgItem(Some(page), id) }
        .ok()
        .filter(|control| !control.is_invalid())
}

/// A control's rectangle, translated from screen coordinates into page-client ones.
fn control_rect(page: HWND, control: HWND) -> Option<Rect> {
    let mut window = RECT::default();
    // SAFETY: `control` is a live child of `page` and `window` is a local the call
    // writes into.
    unsafe { GetWindowRect(control, &mut window) }.ok()?;

    let mut corners = [
        POINT {
            x: window.left,
            y: window.top,
        },
        POINT {
            x: window.right,
            y: window.bottom,
        },
    ];
    // SAFETY: both handles are live windows on this thread, and `corners` is a
    // two-point array of exactly the length the call is given. A null "from"
    // window means the points are screen coordinates.
    unsafe { MapWindowPoints(None, Some(page), &mut corners) };

    Some(Rect::new(
        corners[0].x,
        corners[0].y,
        corners[1].x,
        corners[1].y,
    ))
}

/// A child window whose text is `text`, or `None`.
///
/// Used only for the template's `IDC_STATIC` labels, which have no usable id.
fn find_child_with_text(page: HWND, text: &str) -> Option<HWND> {
    let wanted: Vec<u16> = text.encode_utf16().collect();
    let mut search = TextSearch {
        wanted: &wanted,
        found: None,
    };

    // SAFETY: the callback is a plain `extern "system"` function with the shape
    // `EnumChildWindows` calls, and `search` outlives the enumeration.
    unsafe {
        let _ = EnumChildWindows(
            Some(page),
            Some(search_child_by_text),
            LPARAM((&mut search as *mut TextSearch<'_>) as isize),
        );
    }

    search.found
}

/// The state behind [`find_child_with_text`]'s enumeration.
struct TextSearch<'a> {
    wanted: &'a [u16],
    found: Option<HWND>,
}

/// `EnumChildWindows` callback: stop on the first child whose text matches.
unsafe extern "system" fn search_child_by_text(child: HWND, lparam: LPARAM) -> BOOL {
    // SAFETY: `lparam` is the `&mut TextSearch` `find_child_with_text` passed, and
    // the enumeration cannot outlive that borrow.
    let search = unsafe { &mut *(lparam.0 as *mut TextSearch<'_>) };

    let mut buffer = [0u16; 64];
    // SAFETY: `child` is a window being enumerated and `buffer` is writable for
    // its full length; the call returns the number of units written.
    let length = unsafe { GetWindowTextW(child, &mut buffer) };
    let length = usize::try_from(length).unwrap_or(0).min(buffer.len());

    if &buffer[..length] == search.wanted {
        search.found = Some(child);
        // FALSE stops the enumeration: the text is unique in this template.
        return false.into();
    }
    true.into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The template's page is 280 x 230 dialog units. The numbers below are
    /// representative sizes in that coordinate space, not measured pixels: every
    /// expectation is about which edge moves, which is DPI independent.
    const CLIENT: (i32, i32) = (280, 230);

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect {
        Rect::new(left, top, right, bottom)
    }

    /// Growing the page moves the list's right and bottom edges and leaves its
    /// origin and margins alone.
    #[test]
    fn a_stretching_control_keeps_its_margins() {
        let placed = place(Anchor::Stretch, rect(7, 7, 273, 131), CLIENT, (480, 380));
        assert_eq!(placed, rect(7, 7, 473, 281));
        assert_eq!(480 - placed.right, 7);
        assert_eq!(380 - placed.bottom, 99);
    }

    /// A status line follows the bottom edge: same height, same distance from the
    /// bottom, width from the right margin.
    #[test]
    fn a_bottom_stretching_control_moves_down_and_widens() {
        let placed = place(
            Anchor::StretchWidthBottom,
            rect(7, 135, 273, 144),
            CLIENT,
            (480, 380),
        );
        assert_eq!(placed, rect(7, 285, 473, 294));
        assert_eq!(380 - placed.bottom, 86);
    }

    /// A bottom-right button keeps its size and both margins.
    #[test]
    fn a_bottom_right_control_keeps_its_corner() {
        let placed = place(
            Anchor::BottomRight,
            rect(204, 147, 273, 162),
            CLIENT,
            (480, 380),
        );
        assert_eq!(placed, rect(404, 297, 473, 312));
        assert_eq!(480 - placed.right, 7);
        assert_eq!(380 - placed.bottom, 68);
    }

    /// A bottom-left control keeps its column and size and moves down with the
    /// bottom margin; it does not widen.
    #[test]
    fn a_bottom_left_control_moves_down_without_resizing() {
        let placed = place(
            Anchor::BottomLeft,
            rect(7, 194, 107, 209),
            CLIENT,
            (480, 380),
        );
        assert_eq!(placed, rect(7, 344, 107, 359));
        assert_eq!(placed.width(), 100);
        assert_eq!(placed.height(), 15);
    }

    /// A page that is somehow smaller than its template collapses the stretching
    /// controls instead of producing an inverted rectangle; the fixed anchors are
    /// pulled to the top-left edge.
    #[test]
    fn a_smaller_than_template_page_never_produces_negative_geometry() {
        let narrow = (10, 10);

        let stretched = place(Anchor::Stretch, rect(7, 7, 273, 131), CLIENT, narrow);
        assert!(stretched.width() >= 0);
        assert!(stretched.height() >= 0);

        let status = place(
            Anchor::StretchWidthBottom,
            rect(7, 135, 273, 144),
            CLIENT,
            narrow,
        );
        assert!(status.width() >= 0);
        assert_eq!(status.top, 0, "the control is clamped to the page's top");
        assert_eq!(status.height(), 9, "clamping must not resize the control");

        let button = place(
            Anchor::BottomRight,
            rect(204, 147, 273, 162),
            CLIENT,
            narrow,
        );
        assert!(button.left >= 0);
        assert!(button.top >= 0);
        assert_eq!(button.width(), 69);
        assert_eq!(button.height(), 15);
    }

    /// A control whose template rectangle is already partly above/left of the page
    /// keeps its allowed position rather than being dragged to the origin by the
    /// clamp on the *other* axis.
    #[test]
    fn clamping_one_edge_does_not_move_the_other() {
        let placed = place(
            Anchor::BottomRight,
            rect(204, 7, 273, 22),
            CLIENT,
            (480, 20),
        );
        assert_eq!(placed.left, 404, "the horizontal position is independent");
        assert_eq!(placed.top, 0, "only the vertical position is clamped");
    }
}
