//! Deciding what an incoming window message means.
//!
//! # Why this is a separate, pure module
//!
//! The rule that matters here -- "ignore everything that did not come from our
//! own hashing thread" -- is the kind of thing that is easy to write, hard to
//! notice being wrong, and impossible to test once it is tangled up with a
//! window handle and a live list view. As a pure function over `(message,
//! wParam, lParam)` it is testable directly, and the dialog procedure becomes a
//! thin dispatch over its answer.
//!
//! # What can go wrong without it
//!
//! The property sheet manager, the list view, the progress bar and the shell's
//! own controls all post and send messages to the page's window. Acting on one of
//! those as though it were our scan's progress would at best show a wrong
//! progress bar and at worst make the page believe the scan had finished.

#![cfg(windows)]
// The router is reached only through the dialog procedure in this crate, so its
// items are crate-visible; `unreachable_pub` would otherwise flag every one of
// them for being `pub` in a private module.
#![allow(unreachable_pub)]
// with the list view it needs to push results into. Until then the module is
// exercised by its own tests, which is why it is written and tested first.

use crate::{MESSAGE_MAGIC, PROGRESS_RESOLUTION};

/// What the dialog procedure should do with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// One file produced results: drain the shared queue.
    Results,
    /// Cumulative progress, in steps of [`PROGRESS_RESOLUTION`].
    Progress(u64),
    /// The scan is over, successfully or not.
    Finished,
    /// A verification request finished; the payload is its sequence number.
    ///
    /// The sequence matters: a user who picks one checksum file and then another
    /// must not see the first one's verdict applied to the second.
    Verification(u32),
    /// An export request finished; the payload is its sequence number.
    ExportDone(u32),
    /// Discovery found this many files so far.
    Discovery(usize),
    /// The job list is published; the payload is the job count.
    JobsReady(usize),
    /// This window has no state: `WM_NCDESTROY` already ran, and the page is
    /// about to be freed. Nothing may be touched.
    NoState,
    /// The message is not ours. It belongs to another handler in this window --
    /// it must be passed on, **not** swallowed by returning TRUE.
    NotOurs,
}

/// Classify a message.
///
/// `hwnd_has_state` is whether `GWLP_USERDATA` is still set, which is false
/// between `WM_NCDESTROY` and `PSPCB_RELEASE`.
pub fn route(message: u32, wparam: usize, lparam: isize, hwnd_has_state: bool) -> Route {
    if !is_ours(message, wparam) {
        return Route::NotOurs;
    }
    if !hwnd_has_state {
        return Route::NoState;
    }

    match message {
        crate::WM_FILE_FINISHED => Route::Results,
        crate::WM_FILE_PROGRESS => Route::Progress(decode_progress(lparam)),
        crate::WM_SCAN_FINISHED => Route::Finished,
        crate::WM_VERIFY_READY => Route::Verification(decode_sequence(lparam)),
        crate::WM_EXPORT_DONE => Route::ExportDone(decode_sequence(lparam)),
        crate::WM_DISCOVERY_PROGRESS => Route::Discovery(decode_count(lparam)),
        crate::WM_JOBS_READY => Route::JobsReady(decode_count(lparam)),
        _ => Route::NotOurs,
    }
}

/// Whether a message carries our authentication.
///
/// A failure here is indistinguishable, from outside, from the message never
/// arriving -- which is the correct behaviour: silently ignoring something that
/// *might* be ours is safe, while acting on something that is not is not.
fn is_ours(message: u32, wparam: usize) -> bool {
    matches!(
        message,
        crate::WM_FILE_FINISHED
            | crate::WM_FILE_PROGRESS
            | crate::WM_SCAN_FINISHED
            | crate::WM_VERIFY_READY
            | crate::WM_EXPORT_DONE
            | crate::WM_DISCOVERY_PROGRESS
            | crate::WM_JOBS_READY
    ) && wparam == MESSAGE_MAGIC
}

/// Turn a count carried in `lParam` into a `usize`.
///
/// Clamped rather than trusted: a count from another thread is only used to
/// decide what to display, and a negative payload can only be a stray message.
fn decode_count(lparam: isize) -> usize {
    lparam.max(0) as usize
}

/// Turn the `lParam` of a completion message back into its request sequence.
///
/// A sequence is a `u32` assigned on the dialog thread. `LPARAM` is signed and
/// pointer-width, but values we produce are non-negative and fit, so a negative
/// payload can only be a stray message; it maps to zero, which matches no issued
/// request and is therefore ignored.
fn decode_sequence(lparam: isize) -> u32 {
    lparam.max(0) as u64 as u32
}

/// Turn the `lParam` of a progress message back into a step count.
///
/// Clamped rather than trusted: the value crosses a thread boundary, and a
/// progress bar is not worth a panic on the shell's thread.
fn decode_progress(lparam: isize) -> u64 {
    let raw = lparam.max(0) as u64;
    raw.min(PROGRESS_RESOLUTION)
}

/// Quantise byte progress into the step count carried by a message.
///
/// # Why quantise at all
///
/// A 10 GB scan reports progress once per 2 MiB block, which is 5,000 messages --
/// fine. But the value is recomputed after every block for every file, and a
/// message per block per file would still be a message storm for a scan of a
/// directory of small files. The bar has [`PROGRESS_RESOLUTION`] positions, so
/// posting more than that is pure overhead.
///
/// The result never exceeds [`PROGRESS_RESOLUTION`] and never decreases as `done`
/// grows, which is what keeps the bar from going backwards when two files finish
/// out of order.
pub fn quantise(done: u64, total: u64) -> u64 {
    if total == 0 {
        // Nothing to hash is "finished", not "0%": a page showing an empty bar
        // forever on an empty selection would look hung.
        return PROGRESS_RESOLUTION;
    }
    if done >= total {
        return PROGRESS_RESOLUTION;
    }

    // The multiplication cannot overflow for realistic sizes, but `total` comes
    // from a sum of file sizes and a saturating multiply costs nothing.
    done.saturating_mul(PROGRESS_RESOLUTION) / total
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        WM_DISCOVERY_PROGRESS, WM_EXPORT_DONE, WM_FILE_FINISHED, WM_FILE_PROGRESS, WM_JOBS_READY,
        WM_SCAN_FINISHED, WM_VERIFY_READY,
    };

    /// The whole point of the module: a message that is not ours is passed on,
    /// not swallowed. Swallowing it would break every other handler in the
    /// window.
    #[test]
    fn a_stray_message_is_not_ours() {
        // A control notification: plausible-looking message number, no magic.
        assert_eq!(
            route(WM_FILE_PROGRESS, 0, 128, true),
            Route::NotOurs,
            "a message without the magic must not be treated as progress"
        );
        // A `WM_USER`-range message from some other control, with a plausible
        // payload.
        assert_eq!(route(0x0400, 0x0400, 0, true), Route::NotOurs);
        // Our message number, but not our magic.
        assert_eq!(
            route(WM_FILE_FINISHED, MESSAGE_MAGIC ^ 1, 0, true),
            Route::NotOurs
        );
    }

    /// Our own messages are recognised, and that is the only thing that makes the
    /// magic worth having.
    #[test]
    fn our_messages_are_recognised() {
        assert_eq!(
            route(WM_FILE_PROGRESS, MESSAGE_MAGIC, 7, true),
            Route::Progress(7)
        );
        assert_eq!(
            route(WM_FILE_FINISHED, MESSAGE_MAGIC, 0, true),
            Route::Results
        );
        assert_eq!(
            route(WM_SCAN_FINISHED, MESSAGE_MAGIC, 0, true),
            Route::Finished
        );
        assert_eq!(
            route(WM_VERIFY_READY, MESSAGE_MAGIC, 3, true),
            Route::Verification(3)
        );
        assert_eq!(
            route(WM_EXPORT_DONE, MESSAGE_MAGIC, 9, true),
            Route::ExportDone(9)
        );
        assert_eq!(
            route(WM_DISCOVERY_PROGRESS, MESSAGE_MAGIC, 17, true),
            Route::Discovery(17)
        );
        assert_eq!(
            route(WM_JOBS_READY, MESSAGE_MAGIC, 4, true),
            Route::JobsReady(4)
        );
    }

    /// A completion message carries the request's sequence so a superseded
    /// request can be ignored. Negative payloads are stray, not requests.
    #[test]
    fn a_completion_sequence_is_decoded_and_stray_values_are_zero() {
        assert_eq!(
            route(WM_VERIFY_READY, MESSAGE_MAGIC, -1, true),
            Route::Verification(0)
        );
        assert_eq!(
            route(WM_EXPORT_DONE, MESSAGE_MAGIC, -5, true),
            Route::ExportDone(0)
        );
        assert_eq!(
            route(WM_VERIFY_READY, MESSAGE_MAGIC ^ 1, 3, true),
            Route::NotOurs,
            "a completion message without the magic must not be acted on"
        );
    }

    /// After `WM_NCDESTROY` the state is about to be freed, so a late message
    /// must not reach it -- even though the message itself is genuinely ours.
    #[test]
    fn a_late_message_with_no_state_is_recognised_as_such() {
        assert_eq!(
            route(WM_FILE_FINISHED, MESSAGE_MAGIC, 0, false),
            Route::NoState
        );
    }

    /// A negative or oversized `lParam` is clamped rather than trusted.
    #[test]
    fn a_progress_value_outside_the_range_is_clamped() {
        assert_eq!(
            route(WM_FILE_PROGRESS, MESSAGE_MAGIC, -5, true),
            Route::Progress(0)
        );
        assert_eq!(
            route(WM_FILE_PROGRESS, MESSAGE_MAGIC, isize::MAX, true),
            Route::Progress(PROGRESS_RESOLUTION)
        );
    }

    #[test]
    fn quantisation_spans_the_whole_range() {
        assert_eq!(quantise(0, 100), 0);
        assert_eq!(quantise(50, 100), PROGRESS_RESOLUTION / 2);
        assert_eq!(quantise(100, 100), PROGRESS_RESOLUTION);
        assert_eq!(quantise(150, 100), PROGRESS_RESOLUTION);
    }

    /// An empty scan is finished, not stuck at zero.
    #[test]
    fn nothing_to_hash_is_reported_as_complete() {
        assert_eq!(quantise(0, 0), PROGRESS_RESOLUTION);
        assert_eq!(quantise(7, 0), PROGRESS_RESOLUTION);
    }

    /// The bar must never go backwards, which is the property that matters when
    /// two files finish out of order and the total is revised.
    #[test]
    fn quantisation_never_decreases_as_progress_grows() {
        let total = 5_000_000u64;
        let mut previous = 0;
        for step in 0..=1000 {
            let done = total / 1000 * step;
            let current = quantise(done, total);
            assert!(
                current >= previous,
                "went backwards at {done}/{total}: {previous} -> {current}"
            );
            assert!(current <= PROGRESS_RESOLUTION);
            previous = current;
        }
    }

    /// A byte count that overflows the multiplication must not panic in a
    /// release build or wrap into a nonsense value.
    #[test]
    fn an_enormous_progress_value_saturates_rather_than_wrapping() {
        assert_eq!(quantise(u64::MAX, u64::MAX), PROGRESS_RESOLUTION);
        assert!(quantise(u64::MAX / 2, u64::MAX) <= PROGRESS_RESOLUTION);
    }
}
