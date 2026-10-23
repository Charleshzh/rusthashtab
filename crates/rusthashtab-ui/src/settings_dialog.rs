//! The settings dialog: every algorithm as a check box, plus the display and
//! checklist-export options.
//!
//! # Why a list view and not thirty-one check boxes
//!
//! The algorithm table has 31 rows, they change only with a release, and they all
//! mean the same thing. A report-mode list view with check boxes carries them in
//! one control: one font, one scroll bar, and one place to read the state back
//! from. Thirty-one `BS_AUTOCHECKBOX` controls would also need thirty-one
//! identifiers that the dialog template and `resource.rs` both had to agree on.
//!
//! # Modal on purpose, and what that costs testing
//!
//! A properties sheet owns the dialog thread, so a settings dialog is modal
//! (`DialogBoxParamW`) rather than a modeless window with a hand-written message
//! loop. That is the supported shape, and it is also the reason this module's
//! window wiring is covered by the manual acceptance run rather than by a hosted
//! test: `DialogBoxParamW` blocks until the dialog closes, which a single-threaded
//! test cannot drive. Everything that decides *what* gets saved --
//! [`SettingsForm`] -- is a plain struct tested without a window.
//!
//! # What OK guarantees
//!
//! At least one algorithm must be selected. A page with none checked would hash
//! nothing and look broken; refusing is more honest than saving a state the user
//! cannot see the consequences of. The dialog does not write the registry itself:
//! it returns the settings, and the page saves them (so one place reports a failed
//! write).

#![cfg(windows)]

use crate::{algorithm_names, resource};
use rusthashtab_settings::Settings;
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
    COLOR_BTNFACE, COLOR_BTNTEXT, COLOR_WINDOW, COLOR_WINDOWTEXT, CreateSolidBrush, DeleteObject,
    GetSysColor, GetSysColorBrush, HBRUSH, HDC, HGDIOBJ, InvalidateRect, SetBkColor, SetTextColor,
};
use windows::Win32::UI::Controls::Dialogs::{CC_FULLOPEN, CC_RGBINIT, CHOOSECOLORW, ChooseColorW};
use windows::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, CheckDlgButton, IsDlgButtonChecked, LIST_VIEW_ITEM_STATE_FLAGS,
    LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVIS_STATEIMAGEMASK, LVITEMW, LVM_DELETEALLITEMS,
    LVM_GETITEMSTATE, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETCOLUMNWIDTH,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVS_EX_CHECKBOXES, LVS_EX_FULLROWSELECT,
    LVSCW_AUTOSIZE_USEHEADER,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CB_ADDSTRING, CB_GETCURSEL, CB_RESETCONTENT, CB_SETCURSEL, DialogBoxParamW, EndDialog,
    GetDlgCtrlID, GetDlgItem, MB_ICONWARNING, MB_OK, MessageBoxW, SendMessageW, SetWindowTextW,
    WM_COMMAND, WM_CTLCOLORSTATIC, WM_INITDIALOG, WM_NCDESTROY,
};
use windows::core::{PCWSTR, PWSTR, w};

/// The state-image index Windows' list view uses for "checked".
///
/// The list view stores a one-based image index in the state-image bits; 0 means
/// "no check box", 1 unchecked, 2 checked. These are not exposed as constants by
/// the bindings, so they are named here instead of as bare literals.
const STATE_IMAGE_UNCHECKED: u32 = 1;
/// See [`STATE_IMAGE_UNCHECKED`].
const STATE_IMAGE_CHECKED: u32 = 2;

/// `IDOK` and `IDCANCEL` are declared by `ui.rc`; Win32 defines them as these
/// values, and `WM_COMMAND` carries them in the low word.
const ID_OK: i32 = 1;
/// See [`ID_OK`].
const ID_CANCEL: i32 = 2;

/// The editable state of the settings dialog.
///
/// Pure data, so the meaningful parts of the dialog -- what a set of checked rows
/// turns into, and whether OK is allowed -- are tested without a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsForm {
    /// Everything except the algorithm flags, as loaded when the dialog opened.
    pub settings: Settings,
    /// One flag per [`rusthashtab_hash::ALGORITHMS`] row, in table order.
    pub algorithms: Vec<bool>,
}

impl SettingsForm {
    /// The form the dialog opens with.
    pub fn from_settings(settings: &Settings) -> Self {
        let names = algorithm_names();
        let algorithms = (0..names.len())
            .map(|index| settings.is_enabled(index, &names))
            .collect();
        Self {
            settings: settings.clone(),
            algorithms,
        }
    }

    /// Whether OK is allowed: at least one algorithm must be enabled.
    pub fn any_enabled(&self) -> bool {
        self.algorithms.iter().any(|enabled| *enabled)
    }

    /// The settings the dialog would return, or `None` when the choice is not
    /// saveable.
    ///
    /// The algorithm vector is written out explicitly even when it equals the
    /// defaults: "the user looked at the page and accepted it" is a different
    /// state from "the user has never chosen", and writing it makes the next load
    /// show exactly what was confirmed.
    pub fn to_settings(&self) -> Option<Settings> {
        if !self.any_enabled() {
            return None;
        }
        let mut settings = self.settings.clone();
        settings.algorithms = self.algorithms.clone();
        Some(settings)
    }

    /// Restore the built-in defaults, keeping the registry key the form points at.
    pub fn reset_to_defaults(&mut self) {
        let key = self.settings.key.clone();
        self.settings = Settings::default().with_key(key);
        let names = algorithm_names();
        self.algorithms = (0..names.len())
            .map(|index| self.settings.is_enabled(index, &names))
            .collect();
    }

    /// Set one algorithm's check state; an out-of-range index is ignored.
    pub fn set_algorithm(&mut self, index: usize, enabled: bool) {
        if let Some(slot) = self.algorithms.get_mut(index) {
            *slot = enabled;
        }
    }
}

/// The state behind the dialog window.
struct DialogState {
    form: SettingsForm,
    /// Set by OK; `None` means cancelled or failed.
    result: Option<Settings>,
    /// The sample's background brush; owned only when the user chose a custom
    /// background. `None` means the dialog face brush.
    preview_brush: Option<HBRUSH>,
}

impl core::fmt::Debug for DialogState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DialogState")
            .field("form", &self.form)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

/// Show the modal settings dialog.
///
/// Returns the settings the user confirmed, or `None` when the dialog was
/// cancelled, closed, or could not be created. The caller saves them and decides
/// what to do with a write failure; this module never touches the registry.
pub fn show(parent: HWND, instance: HINSTANCE, current: &Settings) -> Option<Settings> {
    if instance.is_invalid() {
        return None;
    }

    let mut state = Box::new(DialogState {
        form: SettingsForm::from_settings(current),
        result: None,
        preview_brush: None,
    });
    let pointer = (&mut *state) as *mut DialogState;

    // SAFETY: the template identifier is the one `ui.rc` declares in this module,
    // the parent is a live window (or null, which the API accepts), and the state
    // outlives the dialog because `DialogBoxParamW` returns before `state` is
    // dropped. `WM_INITDIALOG` is where the pointer is stored for the later
    // messages.
    let outcome = unsafe {
        DialogBoxParamW(
            Some(instance),
            PCWSTR(resource::IDD_SETTINGS as usize as *const u16),
            Some(parent),
            Some(dialog_proc),
            LPARAM(pointer as isize),
        )
    };

    // -1 means the dialog could not be created; anything else is the value OK or
    // Cancel passed to `EndDialog`. The result itself is authoritative: a dialog
    // that could be created but closed through the title bar returns 0 with no
    // result.
    if outcome < 0 {
        return None;
    }
    state.result.take()
}

/// The dialog procedure.
///
/// `extern "system"` because that is the type `DialogBoxParamW` takes. It cannot
/// panic in practice (the work is field copies and Win32 calls), but it also runs
/// on the shell's thread, so nothing here blocks or does I/O.
extern "system" fn dialog_proc(hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match message {
        WM_INITDIALOG => {
            on_init(hwnd, lparam);
            1
        }
        WM_COMMAND => {
            if on_command(hwnd, wparam) {
                1
            } else {
                0
            }
        }
        WM_CTLCOLORSTATIC => on_ctlcolor_static(hwnd, wparam, lparam),
        WM_NCDESTROY => {
            if let Some(state) = state(hwnd)
                && let Some(brush) = state.preview_brush.take()
            {
                // SAFETY: the brush was created by `CreateSolidBrush` in
                // `update_colour_preview` and is not selected anywhere.
                let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
            }
            // A message already in the queue will still be dispatched here after
            // this returns; it must not find a window that no longer points at
            // the caller's state.
            crate::window_data::store(hwnd, 0);
            0
        }
        _ => 0,
    }
}

/// `WM_INITDIALOG`: remember the caller's state and fill the controls.
fn on_init(hwnd: HWND, lparam: LPARAM) {
    if lparam.0 == 0 {
        return;
    }

    let pointer = lparam.0 as *mut DialogState;
    crate::window_data::store(hwnd, pointer as isize);

    // SAFETY: the caller of `DialogBoxParamW` passed a live `Box<DialogState>`
    // that outlives the dialog, and this is the only place it is read through
    // the window data. The borrow ends with this function.
    let state = unsafe { &mut *pointer };
    let Some(list) = control(hwnd, resource::IDC_SETTINGS_ALGORITHMS) else {
        return;
    };

    // SAFETY: `list` is this dialog's list view, and both parameters are plain
    // integers.
    unsafe {
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            Some(WPARAM((LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT) as usize)),
            Some(LPARAM((LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT) as isize)),
        );
    }
    add_algorithm_column(list);
    fill_algorithms(list, &state.form);
    // The column is sized after the items exist, so its width covers the longest
    // algorithm name rather than the initial guess.
    autosize_algorithm_column(list);
    fill_options(hwnd, &state.form);
    fill_colour_classes(hwnd);
    update_colour_controls(hwnd, state);
}

/// The five colour classes, in the order the selector lists them.
const COLOUR_CLASSES: [rusthashtab_settings::ColourClass; 5] = [
    rusthashtab_settings::ColourClass::Matched,
    rusthashtab_settings::ColourClass::Weak,
    rusthashtab_settings::ColourClass::Mismatched,
    rusthashtab_settings::ColourClass::Error,
    rusthashtab_settings::ColourClass::Neutral,
];

/// Human-readable name for one class.
fn class_label(class: rusthashtab_settings::ColourClass) -> &'static str {
    use rusthashtab_settings::ColourClass;
    match class {
        ColourClass::Matched => crate::strings::text(crate::strings::Key::ColourMatched),
        ColourClass::Weak => crate::strings::text(crate::strings::Key::ColourWeakMatch),
        ColourClass::Mismatched => crate::strings::text(crate::strings::Key::ColourMismatch),
        ColourClass::Error => crate::strings::text(crate::strings::Key::ColourError),
        ColourClass::Neutral => crate::strings::text(crate::strings::Key::ColourUnchecked),
    }
}

/// Fill the colour-class selector.
fn fill_colour_classes(hwnd: HWND) {
    let Some(combo) = control(hwnd, resource::IDC_SETTINGS_COLOUR_CLASS) else {
        return;
    };
    // SAFETY: `combo` is the dialog's combo box; every message copies the string
    // it is given and no pointer outlives the call.
    unsafe {
        SendMessageW(combo, CB_RESETCONTENT, Some(WPARAM(0)), Some(LPARAM(0)));
        for (index, class) in COLOUR_CLASSES.iter().enumerate() {
            let mut text = class_label(*class)
                .encode_utf16()
                .chain(core::iter::once(0))
                .collect::<Vec<u16>>();
            SendMessageW(
                combo,
                CB_ADDSTRING,
                Some(WPARAM(0)),
                Some(LPARAM(text.as_mut_ptr() as isize)),
            );
            let _ = index;
        }
        let _ = SendMessageW(combo, CB_SETCURSEL, Some(WPARAM(0)), Some(LPARAM(0)));
    }
}

/// The class the selector is showing, defaulting to Matched.
fn selected_class(hwnd: HWND) -> rusthashtab_settings::ColourClass {
    let Some(combo) = control(hwnd, resource::IDC_SETTINGS_COLOUR_CLASS) else {
        return rusthashtab_settings::ColourClass::Matched;
    };
    // SAFETY: `combo` is the dialog's combo box; the message takes no pointers.
    let selected = unsafe { SendMessageW(combo, CB_GETCURSEL, Some(WPARAM(0)), Some(LPARAM(0))).0 };
    COLOUR_CLASSES
        .get(selected.max(0) as usize)
        .copied()
        .unwrap_or(rusthashtab_settings::ColourClass::Matched)
}

/// One class's colour pair.
fn colour_of(
    settings: &Settings,
    class: rusthashtab_settings::ColourClass,
) -> rusthashtab_settings::RowColour {
    use rusthashtab_settings::ColourClass;
    match class {
        ColourClass::Matched => settings.colours.matched,
        ColourClass::Weak => settings.colours.weak,
        ColourClass::Mismatched => settings.colours.mismatched,
        ColourClass::Error => settings.colours.error,
        ColourClass::Neutral => settings.colours.neutral,
    }
}

/// One class's colour pair, mutably.
fn colour_of_mut(
    settings: &mut Settings,
    class: rusthashtab_settings::ColourClass,
) -> &mut rusthashtab_settings::RowColour {
    use rusthashtab_settings::ColourClass;
    match class {
        ColourClass::Matched => &mut settings.colours.matched,
        ColourClass::Weak => &mut settings.colours.weak,
        ColourClass::Mismatched => &mut settings.colours.mismatched,
        ColourClass::Error => &mut settings.colours.error,
        ColourClass::Neutral => &mut settings.colours.neutral,
    }
}

/// Render one colour as `#RRGGBB`, or `off` for the sentinel.
fn colour_text(colour: u32) -> String {
    if colour == rusthashtab_settings::SYSTEM_COLOUR {
        return String::from("off");
    }
    let red = colour & 0xFF;
    let green = (colour >> 8) & 0xFF;
    let blue = (colour >> 16) & 0xFF;
    format!("#{red:02X}{green:02X}{blue:02X}")
}

/// Tick the two enabled boxes and redraw the preview for the selected class.
fn update_colour_controls(hwnd: HWND, state: &mut DialogState) {
    let class = selected_class(hwnd);
    let colour = colour_of(&state.form.settings, class);
    let text_state = if colour.text_enabled {
        BST_CHECKED
    } else {
        BST_UNCHECKED
    };
    let background_state = if colour.background_enabled {
        BST_CHECKED
    } else {
        BST_UNCHECKED
    };
    // SAFETY: both identifiers are check boxes this dialog declares.
    unsafe {
        let _ = CheckDlgButton(hwnd, resource::IDC_SETTINGS_COLOUR_TEXT_ENABLED, text_state);
        let _ = CheckDlgButton(
            hwnd,
            resource::IDC_SETTINGS_COLOUR_BG_ENABLED,
            background_state,
        );
    }
    update_colour_preview(hwnd, state);
}

/// Apply the two enabled check boxes to the selected class.
///
/// The colour value is kept while a half is disabled, so re-enabling restores
/// the user's previous choice rather than falling back to black or white.
fn apply_colour_checkboxes(hwnd: HWND, form: &mut SettingsForm) {
    let class = selected_class(hwnd);
    // SAFETY: both identifiers name check boxes this dialog declares.
    let text_enabled = unsafe {
        IsDlgButtonChecked(hwnd, resource::IDC_SETTINGS_COLOUR_TEXT_ENABLED) == BST_CHECKED.0
    };
    // SAFETY: as above.
    let background_enabled = unsafe {
        IsDlgButtonChecked(hwnd, resource::IDC_SETTINGS_COLOUR_BG_ENABLED) == BST_CHECKED.0
    };
    let colour = colour_of_mut(&mut form.settings, class);
    colour.text_enabled = text_enabled;
    colour.background_enabled = background_enabled;
}

/// Read the enabled check boxes back into the settings, without touching the
/// stored colour values.
fn read_colour_controls(hwnd: HWND, form: &mut SettingsForm) {
    // SAFETY: both identifiers name check boxes this dialog declares.
    let text_enabled = unsafe {
        IsDlgButtonChecked(hwnd, resource::IDC_SETTINGS_COLOUR_TEXT_ENABLED) == BST_CHECKED.0
    };
    // SAFETY: as above.
    let background_enabled = unsafe {
        IsDlgButtonChecked(hwnd, resource::IDC_SETTINGS_COLOUR_BG_ENABLED) == BST_CHECKED.0
    };
    let class = selected_class(hwnd);
    let colour = colour_of_mut(&mut form.settings, class);
    colour.text_enabled = text_enabled;
    colour.background_enabled = background_enabled;
}

/// Paint the live sample with the selected foreground and background.
///
/// A static control's text colour and background come from
/// `WM_CTLCOLORSTATIC`: `SetTextColor`/`SetBkColor` set the DC, and the returned
/// brush fills the control behind the text. This is more dependable than an
/// owner-drawn static, and it makes the preview a real sample of the list
/// colours rather than a label that merely says what they are.
fn on_ctlcolor_static(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) -> isize {
    let Some(state) = state(hwnd) else {
        return 0;
    };
    // SAFETY: `WM_CTLCOLORSTATIC` passes a display DC in `wParam` and the child
    // window handle in `lParam`; both are valid for the message's lifetime.
    let dc = HDC(wparam.0 as *mut core::ffi::c_void);
    // SAFETY: as above.
    let child = HWND(lparam.0 as *mut core::ffi::c_void);
    // SAFETY: `child` is the control that sent the message.
    let id = unsafe { GetDlgCtrlID(child) };

    if id == resource::IDC_SETTINGS_COLOUR_PREVIEW {
        let class = selected_class(hwnd);
        let colour = colour_of(&state.form.settings, class);
        // SAFETY: `GetSysColor` reads a system colour table entry.
        let system_text = COLORREF(unsafe { GetSysColor(COLOR_BTNTEXT) });
        // SAFETY: as above.
        let system_face = COLORREF(unsafe { GetSysColor(COLOR_BTNFACE) });
        let text = if colour.text_enabled && colour.text != rusthashtab_settings::SYSTEM_COLOUR {
            COLORREF(colour.text)
        } else {
            system_text
        };
        let background = if colour.background_enabled
            && colour.background != rusthashtab_settings::SYSTEM_COLOUR
        {
            COLORREF(colour.background)
        } else {
            system_face
        };
        // SAFETY: `dc` is a valid display DC for the duration of the message.
        unsafe {
            let _ = SetTextColor(dc, text);
            let _ = SetBkColor(dc, background);
        }
        // SAFETY: `GetSysColorBrush` returns a system-owned brush for a valid
        // colour index; it must not be deleted.
        let brush = unsafe {
            state
                .preview_brush
                .unwrap_or_else(|| GetSysColorBrush(COLOR_BTNFACE))
        };
        return brush.0 as isize;
    }

    if id == resource::IDC_SETTINGS_COLOUR_PREVIEW_LABEL {
        // SAFETY: `GetSysColor` reads a system colour table entry; `dc` is a
        // valid display DC for the duration of the message.
        let (text, face) = unsafe {
            (
                COLORREF(GetSysColor(COLOR_BTNTEXT)),
                COLORREF(GetSysColor(COLOR_BTNFACE)),
            )
        };
        // SAFETY: as above.
        unsafe {
            let _ = SetTextColor(dc, text);
            let _ = SetBkColor(dc, face);
        }
        // SAFETY: the system brush is owned by USER32 and must not be deleted.
        return unsafe { GetSysColorBrush(COLOR_BTNFACE) }.0 as isize;
    }

    0
}

/// Update the sample brush and the hex/off label for the selected class.
fn update_colour_preview(hwnd: HWND, state: &mut DialogState) {
    let Some(preview) = control(hwnd, resource::IDC_SETTINGS_COLOUR_PREVIEW) else {
        return;
    };
    let class = selected_class(hwnd);
    let colour = colour_of(&state.form.settings, class);
    let labels = format!(
        "text {} / bg {}",
        if colour.text_enabled {
            colour_text(colour.text)
        } else {
            String::from("off")
        },
        if colour.background_enabled {
            colour_text(colour.background)
        } else {
            String::from("off")
        }
    );
    if let Some(label) = control(hwnd, resource::IDC_SETTINGS_COLOUR_PREVIEW_LABEL) {
        let wide: Vec<u16> = labels.encode_utf16().chain(core::iter::once(0)).collect();
        // SAFETY: `label` is the dialog's static and the string outlives the call.
        unsafe {
            let _ = SetWindowTextW(label, PCWSTR(wide.as_ptr()));
        }
    }

    if let Some(brush) = state.preview_brush.take() {
        // SAFETY: the brush was created by `CreateSolidBrush` below and is not
        // selected into any DC outside the `WM_CTLCOLORSTATIC` handler.
        let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
    }
    if colour.background_enabled && colour.background != rusthashtab_settings::SYSTEM_COLOUR {
        // SAFETY: `CreateSolidBrush` takes a plain `COLORREF` and returns an
        // owned brush; it is stored in the dialog state and deleted on the next
        // change or at `WM_NCDESTROY`.
        state.preview_brush = Some(unsafe { CreateSolidBrush(COLORREF(colour.background)) });
    }

    // SAFETY: both controls belong to this dialog and are still alive.
    unsafe {
        let _ = InvalidateRect(Some(preview), None, true);
        if let Some(label) = control(hwnd, resource::IDC_SETTINGS_COLOUR_PREVIEW_LABEL) {
            let _ = InvalidateRect(Some(label), None, true);
        }
    }
}

/// Show the colour picker and return the chosen `COLORREF`.
fn pick_colour(
    hwnd: HWND,
    initial: u32,
    system_index: windows::Win32::Graphics::Gdi::SYS_COLOR_INDEX,
) -> Option<u32> {
    let initial = if initial == rusthashtab_settings::SYSTEM_COLOUR {
        // SAFETY: `GetSysColor` reads a system colour table entry.
        unsafe { GetSysColor(system_index) }
    } else {
        initial
    };
    let mut custom = [COLORREF(0); 16];
    let mut chooser = CHOOSECOLORW {
        lStructSize: core::mem::size_of::<CHOOSECOLORW>() as u32,
        hwndOwner: hwnd,
        rgbResult: COLORREF(initial),
        lpCustColors: custom.as_mut_ptr(),
        Flags: CC_RGBINIT | CC_FULLOPEN,
        ..Default::default()
    };
    // SAFETY: `chooser` declares its own size, every pointer in it refers to a
    // live local, and the call is modal on this thread exactly like the other
    // user-initiated dialogs.
    let chosen = unsafe { ChooseColorW(&mut chooser) }.as_bool();
    chosen.then_some(chooser.rgbResult.0)
}

/// Give the checklist its one column.
///
/// The template declares a **report-mode** list view. A report view with no
/// columns draws no item text at all, so the dialog looks empty even though every
/// row is inserted correctly -- which is exactly how it failed once. One column is
/// all this dialog needs.
fn add_algorithm_column(list: HWND) {
    let mut heading: Vec<u16> = String::from("Algorithm")
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut column = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        // A starting width; [`autosize_algorithm_column`] replaces it once the
        // rows exist.
        cx: 240,
        pszText: PWSTR(heading.as_mut_ptr()),
        ..Default::default()
    };

    // SAFETY: `list` is the dialog's list view, `column` and the heading it points
    // at live for the call, and `LVM_INSERTCOLUMNW` copies the text.
    unsafe {
        SendMessageW(
            list,
            LVM_INSERTCOLUMNW,
            Some(WPARAM(0)),
            Some(LPARAM((&mut column as *mut LVCOLUMNW) as isize)),
        );
    }
}

/// Widen the algorithm column to its contents and header.
fn autosize_algorithm_column(list: HWND) {
    // SAFETY: the column index is the one `add_algorithm_column` inserted, and the
    // message reads only the two integers.
    unsafe {
        SendMessageW(
            list,
            LVM_SETCOLUMNWIDTH,
            Some(WPARAM(0)),
            Some(LPARAM(LVSCW_AUTOSIZE_USEHEADER as isize)),
        );
    }
}

/// `WM_COMMAND`: OK, Cancel, or Defaults.
fn on_command(hwnd: HWND, wparam: WPARAM) -> bool {
    let id = (wparam.0 & 0xFFFF) as i32;
    let code = ((wparam.0 >> 16) & 0xFFFF) as u16;
    let Some(state) = state(hwnd) else {
        return false;
    };

    // `CBN_SELCHANGE` is 1. The class selector only changes the preview; the
    // settings object is updated when a colour is actually picked.
    if id == resource::IDC_SETTINGS_COLOUR_CLASS && code == 1 {
        update_colour_controls(hwnd, state);
        return true;
    }
    if id == resource::IDC_SETTINGS_COLOUR_TEXT_ENABLED
        || id == resource::IDC_SETTINGS_COLOUR_BG_ENABLED
    {
        apply_colour_checkboxes(hwnd, &mut state.form);
        update_colour_preview(hwnd, state);
        return true;
    }

    match id {
        ID_OK => {
            read_options(hwnd, &mut state.form);
            match state.form.to_settings() {
                Some(settings) => {
                    state.result = Some(settings);
                    // SAFETY: `hwnd` is the dialog this procedure belongs to.
                    let _ = unsafe { EndDialog(hwnd, 1) };
                }
                None => {
                    let message: Vec<u16> = "Select at least one algorithm."
                        .encode_utf16()
                        .chain(core::iter::once(0))
                        .collect();
                    // SAFETY: the string is NUL-terminated and outlives the call;
                    // `hwnd` is a live dialog.
                    unsafe {
                        let _ = MessageBoxW(
                            Some(hwnd),
                            PCWSTR(message.as_ptr()),
                            w!("rustHashTab Settings"),
                            MB_OK | MB_ICONWARNING,
                        );
                    }
                }
            }
            true
        }
        ID_CANCEL => {
            // SAFETY: as above.
            let _ = unsafe { EndDialog(hwnd, 0) };
            true
        }
        resource::IDC_SETTINGS_DEFAULTS => {
            state.form.reset_to_defaults();
            if let Some(list) = control(hwnd, resource::IDC_SETTINGS_ALGORITHMS) {
                fill_algorithms(list, &state.form);
            }
            fill_options(hwnd, &state.form);
            update_colour_controls(hwnd, state);
            true
        }
        resource::IDC_SETTINGS_COLOUR_TEXT => {
            let class = selected_class(hwnd);
            let current = colour_of(&state.form.settings, class);
            if let Some(colour) = pick_colour(hwnd, current.text, COLOR_WINDOWTEXT) {
                let stored = colour_of_mut(&mut state.form.settings, class);
                stored.text = colour;
                stored.text_enabled = true;
                update_colour_controls(hwnd, state);
            }
            true
        }
        resource::IDC_SETTINGS_COLOUR_BG => {
            let class = selected_class(hwnd);
            let current = colour_of(&state.form.settings, class);
            if let Some(colour) = pick_colour(hwnd, current.background, COLOR_WINDOW) {
                colour_of_mut(&mut state.form.settings, class).background = colour;
                colour_of_mut(&mut state.form.settings, class).background_enabled = true;
                update_colour_controls(hwnd, state);
            }
            true
        }
        resource::IDC_SETTINGS_COLOUR_DEFAULTS => {
            state.form.settings.colours = rusthashtab_settings::RowColours::default();
            update_colour_controls(hwnd, state);
            true
        }
        _ => false,
    }
}

/// The state behind the dialog, if the window is still one of ours.
fn state(hwnd: HWND) -> Option<&'static mut DialogState> {
    let stored = crate::window_data::load(hwnd);
    if !crate::window_data::holds_address(stored) {
        return None;
    }
    // SAFETY: the only non-zero value ever stored here is the `Box` pointer from
    // `on_init`, and the caller owns it until `DialogBoxParamW` returns.
    Some(unsafe { &mut *(stored as *mut DialogState) })
}

/// Find one of the dialog's controls.
fn control(hwnd: HWND, id: i32) -> Option<HWND> {
    // SAFETY: `hwnd` is the dialog and `id` is an identifier its template
    // declares; a missing control returns an error rather than faulting.
    unsafe { GetDlgItem(Some(hwnd), id) }.ok()
}

/// Put the algorithm rows and their check states into the list view.
fn fill_algorithms(list: HWND, form: &SettingsForm) {
    // SAFETY: `list` is this dialog's list view, and clearing it takes no
    // arguments.
    unsafe {
        SendMessageW(list, LVM_DELETEALLITEMS, Some(WPARAM(0)), Some(LPARAM(0)));
    }

    for (index, algorithm) in rusthashtab_hash::ALGORITHMS.iter().enumerate() {
        let mut text: Vec<u16> = algorithm
            .name
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let mut item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: index as i32,
            pszText: windows::core::PWSTR(text.as_mut_ptr()),
            ..Default::default()
        };
        // SAFETY: `list` is the dialog's list view; `item` and the string it
        // points at live for the call, and `LVM_INSERTITEMW` copies the text.
        unsafe {
            SendMessageW(
                list,
                LVM_INSERTITEMW,
                Some(WPARAM(index)),
                Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
            );
        }
    }

    for (index, enabled) in form.algorithms.iter().enumerate() {
        set_checked(list, index, *enabled);
    }
}

/// Set one row's check state.
fn set_checked(list: HWND, row: usize, checked: bool) {
    let image = if checked {
        STATE_IMAGE_CHECKED
    } else {
        STATE_IMAGE_UNCHECKED
    };
    let mut item = LVITEMW {
        state: LIST_VIEW_ITEM_STATE_FLAGS(image << 12),
        stateMask: LVIS_STATEIMAGEMASK,
        ..Default::default()
    };
    // SAFETY: `row` is one of the items `fill_algorithms` inserted, and `item`
    // lives for the call. `LVM_SETITEMSTATE` reads only the state fields.
    unsafe {
        SendMessageW(
            list,
            LVM_SETITEMSTATE,
            Some(WPARAM(row)),
            Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
        );
    }
}

/// Read one row's check state.
fn is_checked(list: HWND, row: usize) -> bool {
    // SAFETY: `row` is an item index the list view was given, and the message
    // takes integers only.
    let state = unsafe {
        SendMessageW(
            list,
            LVM_GETITEMSTATE,
            Some(WPARAM(row)),
            Some(LPARAM(LVIS_STATEIMAGEMASK.0 as isize)),
        )
    };
    ((state.0 as u32) >> 12) == STATE_IMAGE_CHECKED
}

/// Tick the option check boxes from the form.
fn fill_options(hwnd: HWND, form: &SettingsForm) {
    let settings = &form.settings;
    let boxes: [(i32, bool); 15] = [
        (resource::IDC_SETTINGS_UPPERCASE, settings.display_uppercase),
        (resource::IDC_SETTINGS_MONOSPACE, settings.display_monospace),
        (
            resource::IDC_SETTINGS_LOOK_FOR_SUMFILES,
            settings.look_for_sumfiles,
        ),
        (resource::IDC_SETTINGS_VERIFY_STRICT, settings.verify_strict),
        (
            resource::IDC_SETTINGS_VERIFY_AUTO_FORMAT,
            settings.verify_auto_format,
        ),
        (
            resource::IDC_SETTINGS_VERIFY_CLIPBOARD,
            settings.verify_from_clipboard,
        ),
        (
            resource::IDC_SETTINGS_HASH_SUMFILE,
            settings.hash_sumfile_too,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_ALGORITHM_ONLY,
            settings.sumfile_algorithm_only,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_UPPERCASE,
            settings.sumfile_uppercase,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_LF,
            settings.sumfile_unix_endings,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_DOUBLE_SPACE,
            settings.sumfile_double_space,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_FORWARD_SLASH,
            settings.sumfile_forward_slashes,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_CORZ,
            settings.sumfile_dot_hash_compatible,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_BANNER,
            settings.sumfile_banner,
        ),
        (
            resource::IDC_SETTINGS_SUMFILE_BANNER_DATE,
            settings.sumfile_banner_date,
        ),
    ];

    for (id, checked) in boxes {
        let state = if checked { BST_CHECKED } else { BST_UNCHECKED };
        // SAFETY: `hwnd` is the dialog and each identifier is a check box its
        // template declares.
        let _ = unsafe { CheckDlgButton(hwnd, id, state) };
    }
}

/// Read the option check boxes back into the form.
fn read_options(hwnd: HWND, form: &mut SettingsForm) {
    let checked = |id: i32| -> bool {
        // SAFETY: `hwnd` is the dialog and `id` names a check box.
        unsafe { IsDlgButtonChecked(hwnd, id) == BST_CHECKED.0 }
    };

    let settings = &mut form.settings;
    settings.display_uppercase = checked(resource::IDC_SETTINGS_UPPERCASE);
    settings.display_monospace = checked(resource::IDC_SETTINGS_MONOSPACE);
    settings.look_for_sumfiles = checked(resource::IDC_SETTINGS_LOOK_FOR_SUMFILES);
    settings.verify_strict = checked(resource::IDC_SETTINGS_VERIFY_STRICT);
    settings.verify_auto_format = checked(resource::IDC_SETTINGS_VERIFY_AUTO_FORMAT);
    settings.verify_from_clipboard = checked(resource::IDC_SETTINGS_VERIFY_CLIPBOARD);
    settings.hash_sumfile_too = checked(resource::IDC_SETTINGS_HASH_SUMFILE);
    settings.sumfile_algorithm_only = checked(resource::IDC_SETTINGS_SUMFILE_ALGORITHM_ONLY);
    settings.sumfile_uppercase = checked(resource::IDC_SETTINGS_SUMFILE_UPPERCASE);
    settings.sumfile_unix_endings = checked(resource::IDC_SETTINGS_SUMFILE_LF);
    settings.sumfile_double_space = checked(resource::IDC_SETTINGS_SUMFILE_DOUBLE_SPACE);
    settings.sumfile_forward_slashes = checked(resource::IDC_SETTINGS_SUMFILE_FORWARD_SLASH);
    settings.sumfile_dot_hash_compatible = checked(resource::IDC_SETTINGS_SUMFILE_CORZ);
    settings.sumfile_banner = checked(resource::IDC_SETTINGS_SUMFILE_BANNER);
    settings.sumfile_banner_date = checked(resource::IDC_SETTINGS_SUMFILE_BANNER_DATE);

    if let Some(list) = control(hwnd, resource::IDC_SETTINGS_ALGORITHMS) {
        for index in 0..rusthashtab_hash::ALGORITHMS.len() {
            form.set_algorithm(index, is_checked(list, index));
        }
    }
    read_colour_controls(hwnd, form);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The preview's text half shows `off` for the system sentinel; the
    /// owner-draw swatch uses the same predicate to decide whether to paint it.
    #[test]
    fn a_disabled_colour_half_is_labelled_off() {
        assert_eq!(colour_text(rusthashtab_settings::SYSTEM_COLOUR), "off");
        assert_eq!(colour_text(0x0017_AA2D), "#2DAA17");
    }

    /// The defaults are exactly the four documented algorithms, at their real
    /// table positions. This is the regression guard for the settings loader
    /// having once mapped the four names onto the first four table slots.
    #[test]
    fn the_default_form_checks_the_four_default_algorithms_at_their_positions() {
        let form = SettingsForm::from_settings(&Settings::default());
        let names = algorithm_names();
        let enabled: Vec<&str> = names
            .iter()
            .enumerate()
            .filter(|(index, _)| form.algorithms[*index])
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(enabled, vec!["MD5", "SHA-1", "SHA-256", "SHA-512"]);
        assert!(form.any_enabled());
    }

    /// OK is refused when nothing is checked: a page that hashes nothing is not
    /// a state the dialog is allowed to save.
    #[test]
    fn a_form_with_no_algorithms_has_nothing_to_save() {
        let mut form = SettingsForm::from_settings(&Settings::default());
        form.algorithms = vec![false; algorithm_names().len()];
        assert!(!form.any_enabled());
        assert_eq!(form.to_settings(), None);
    }

    /// The confirmed choices are written out explicitly, even when they equal the
    /// defaults, so the next load shows exactly what the user saw.
    #[test]
    fn a_form_saves_every_checked_algorithm() {
        let mut form = SettingsForm::from_settings(&Settings::default());
        let sha256 = algorithm_names()
            .iter()
            .position(|name| *name == "SHA-256")
            .expect("SHA-256 is in the table");
        let crc32 = algorithm_names()
            .iter()
            .position(|name| *name == "CRC32")
            .expect("CRC32 is in the table");
        form.set_algorithm(sha256, true);
        form.set_algorithm(crc32, true);
        form.settings.display_uppercase = false;

        let saved = form
            .to_settings()
            .expect("at least one algorithm is checked");
        assert_eq!(saved.algorithms.len(), algorithm_names().len());
        assert!(saved.algorithms[crc32]);
        assert!(saved.algorithms[sha256]);
        assert!(!saved.display_uppercase);
        assert_eq!(saved.key, form.settings.key);
    }

    /// Defaults restores both halves and keeps the key, so the dialog cannot
    /// start writing to the product's registry key by accident.
    #[test]
    fn defaults_restore_the_settings_and_keep_the_key() {
        let mut form = SettingsForm::from_settings(
            &Settings::default().with_key(r"Software\rustHashTab-test"),
        );
        form.algorithms = vec![false; algorithm_names().len()];
        form.settings.display_uppercase = false;
        form.reset_to_defaults();

        assert_eq!(form.settings.key, r"Software\rustHashTab-test");
        assert!(form.settings.display_uppercase);
        assert_eq!(
            form.algorithms,
            SettingsForm::from_settings(&Settings::default()).algorithms
        );
    }

    /// The three Phase 6 checkboxes are part of the form, so a change made in the
    /// dialog survives `to_settings`; the dialog never drops one silently.
    #[test]
    fn the_phase_six_options_round_trip_through_the_form() {
        let settings = Settings {
            verify_from_clipboard: true,
            hash_sumfile_too: true,
            sumfile_algorithm_only: false,
            ..Settings::default()
        };

        let form = SettingsForm::from_settings(&settings);
        let saved = form.to_settings().expect("algorithms are enabled");
        assert!(saved.verify_from_clipboard);
        assert!(saved.hash_sumfile_too);
        assert!(!saved.sumfile_algorithm_only);

        let mut defaults = SettingsForm::from_settings(&settings);
        defaults.reset_to_defaults();
        let defaults = defaults.to_settings().expect("defaults keep algorithms on");
        assert!(!defaults.verify_from_clipboard);
        assert!(!defaults.hash_sumfile_too);
        assert!(defaults.sumfile_algorithm_only);
    }

    /// An out-of-range toggle is ignored rather than panicking on the shell's
    /// thread.
    #[test]
    fn a_toggle_past_the_end_is_ignored() {
        let mut form = SettingsForm::from_settings(&Settings::default());
        let before = form.algorithms.clone();
        form.set_algorithm(usize::MAX, true);
        assert_eq!(form.algorithms, before);
    }

    /// The checklist is a **report-mode** list view, so it needs a column: a
    /// report view with no columns draws no item text at all. That is how the
    /// dialog once opened with a blank algorithm box -- the rows were inserted
    /// correctly, they simply had nowhere to be drawn.
    ///
    /// This builds a real list view, fills it the way `WM_INITDIALOG` does, and
    /// reads the first row's text back through the control.
    #[test]
    fn the_algorithm_checklist_has_a_column_and_every_row() {
        use windows::Win32::UI::Controls::{
            ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX, INITCOMMONCONTROLSEX_ICC,
            InitCommonControlsEx, LVITEMW, LVM_GETCOLUMNWIDTH, LVM_GETITEMCOUNT, LVM_GETITEMTEXTW,
            LVS_REPORT,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, WINDOW_EX_STYLE, WINDOW_STYLE,
        };
        use windows::core::PWSTR;

        let classes = INITCOMMONCONTROLSEX {
            dwSize: core::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: INITCOMMONCONTROLSEX_ICC(ICC_LISTVIEW_CLASSES.0),
        };
        // SAFETY: `classes` declares its own size and lives for the call.
        let initialised = unsafe { InitCommonControlsEx(&classes) };
        assert!(initialised.as_bool(), "common controls must initialise");

        // SAFETY: a predefined system class, no parent, and every optional
        // handle is null; the window is never shown. The report view style is
        // what the dialog template declares, and it is what makes columns exist.
        let list = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("SysListView32"),
                w!(""),
                WINDOW_STYLE(LVS_REPORT),
                0,
                0,
                400,
                400,
                None,
                None,
                None,
                None,
            )
        }
        .expect("a list view can be created");
        assert!(!list.is_invalid());

        add_algorithm_column(list);
        let form = SettingsForm::from_settings(&Settings::default());
        fill_algorithms(list, &form);
        autosize_algorithm_column(list);

        // SAFETY: these messages take integers only; `list` is live.
        let (items, width) = unsafe {
            (
                SendMessageW(list, LVM_GETITEMCOUNT, Some(WPARAM(0)), Some(LPARAM(0))).0,
                SendMessageW(list, LVM_GETCOLUMNWIDTH, Some(WPARAM(0)), Some(LPARAM(0))).0,
            )
        };
        assert_eq!(
            items,
            rusthashtab_hash::ALGORITHMS.len() as isize,
            "every algorithm must have a row"
        );
        assert!(
            width > 0,
            "a report-mode list with no column width draws nothing; got {width}"
        );

        let mut buffer = [0u16; 64];
        let mut item = LVITEMW {
            iSubItem: 0,
            pszText: PWSTR(buffer.as_mut_ptr()),
            cchTextMax: buffer.len() as i32,
            ..Default::default()
        };
        // SAFETY: `buffer` is a live array of `cchTextMax` units and `item`
        // outlives the call; the control copies the text into `buffer`.
        unsafe {
            SendMessageW(
                list,
                LVM_GETITEMTEXTW,
                Some(WPARAM(0)),
                Some(LPARAM((&mut item as *mut LVITEMW) as isize)),
            );
        }
        let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(0);
        assert_eq!(
            String::from_utf16_lossy(&buffer[..end]),
            rusthashtab_hash::ALGORITHMS[0].name,
            "the first row must show the first algorithm's name"
        );

        // SAFETY: `list` was created by this test and is destroyed once.
        unsafe {
            let _ = DestroyWindow(list);
        }
    }
}
