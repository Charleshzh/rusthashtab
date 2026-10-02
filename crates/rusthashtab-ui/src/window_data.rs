//! `GWLP_USERDATA` in the one type that works on every supported target.
//!
//! # The problem
//!
//! `SetWindowLongPtrW` is not a real Win32 function. On a 64-bit target it is
//! `SetWindowLongPtrW` and takes a 64-bit `LONG_PTR`; on a 32-bit target the same
//! name resolves to `SetWindowLongW` and takes an `i32`, because a pointer fits in
//! a word either way. `windows-rs` models each correctly, which means the argument
//! type differs by target and a call written for one does not compile for the
//! other.
//!
//! The project supports `x86_64`, `i686` and `aarch64` and the gate compiles all
//! three, so this is not a hypothetical: it is exactly the class of bug the gate
//! exists to catch, and it was caught here.
//!
//! # The answer
//!
//! Convert through `isize` in one module, with a `cfg` on each side, and let
//! nothing else in the crate know about it. Widening is lossless in both
//! directions: on a 32-bit target the `i32` the API stores and returns is a
//! pointer that fits in 32 bits, which is why the API is written that way.
//!
//! # Why a cleared slot is not `== 0`
//!
//! On a 32-bit target the stored value comes back sign-extended to `isize`. A
//! pointer whose low half is zero would arrive as a *negative* `isize`, so the
//! "is anything stored here" test has to look at the low 32 bits rather than
//! compare the widened value with zero. Getting this wrong would read state that
//! is not there.

#![cfg(windows)]
// `load` and `holds_address` are the read side of the round trip, and they belong
// to the dialog's message handlers -- the next piece of the page. The conversions
// themselves are exercised by the tests below, so they are not untested; they are
// only uncalled for now.
#![allow(dead_code)]

use windows::Win32::Foundation::HWND;

/// Widen what the window-data API takes into `isize`.
#[cfg(target_pointer_width = "32")]
fn widen(stored: i32) -> isize {
    i64::from(stored) as isize
}

/// Widen what the window-data API takes into `isize`.
#[cfg(target_pointer_width = "64")]
fn widen(stored: isize) -> isize {
    stored
}

/// Narrow an `isize` back to what the window-data API accepts.
#[cfg(target_pointer_width = "32")]
fn narrow(value: isize) -> i32 {
    value as i32
}

/// Narrow an `isize` back to what the window-data API accepts.
#[cfg(target_pointer_width = "64")]
fn narrow(value: isize) -> isize {
    value
}

/// Install a value in the window-data slot, or clear it with `0`.
pub(super) fn store(hwnd: HWND, value: isize) {
    // SAFETY: `hwnd` is the window the caller owns, and `GWLP_USERDATA` is a slot
    // nothing else in this crate writes. `narrow` is lossless for any address the
    // target can hold, which is the only thing ever stored here.
    unsafe {
        windows::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(
            hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            narrow(value),
        )
    };
}

/// Read the window-data slot.
pub(super) fn load(hwnd: HWND) -> isize {
    // SAFETY: `hwnd` is the window the caller owns; the slot is only ever written
    // by `store` above.
    let stored = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(
            hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
        )
    };
    widen(stored)
}

/// Whether the slot holds an address rather than having been cleared.
///
/// See the module documentation for why this is not `value != 0` on every target.
pub(super) fn holds_address(value: isize) -> bool {
    #[cfg(target_pointer_width = "32")]
    {
        (value as i32) != 0
    }
    #[cfg(target_pointer_width = "64")]
    {
        value != 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The round trip has to be exact in both directions, because a truncated
    /// pointer here would be read as a `DialogState` that is not there.
    #[test]
    fn widening_and_narrowing_round_trips() {
        for value in [0isize, 1, 0x7fff_ffff, -1, isize::MIN, isize::MAX] {
            assert_eq!(widen(narrow(value)), value);
        }
    }

    /// A cleared slot must read as "nothing stored" on every target.
    #[test]
    fn a_cleared_slot_holds_no_address() {
        assert!(!holds_address(widen(narrow(0))));
    }

    /// A real pointer must read as "something stored".
    ///
    /// The interesting case is a plausible heap address on the low end of the
    /// range, which on a 32-bit target sign-extends to a negative `isize`.
    #[test]
    fn an_address_is_recognised_whatever_its_sign() {
        assert!(holds_address(widen(narrow(0x1000))));
        #[cfg(target_pointer_width = "32")]
        {
            // A 32-bit address with the top bit set sign-extends to a negative
            // `isize`. That is still an address.
            assert!(holds_address(widen(0x8000_1000u32 as i32)));
            assert!(holds_address(-1));
        }
    }
}
