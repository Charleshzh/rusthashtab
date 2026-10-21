//! One-shot background work that reports completion with a window message.
//!
//! # Why a thread rather than a synchronous call
//!
//! Two page actions touch the file system: reading the checksum file a user
//! picked, and writing the checksum file an export names. Both are small in the
//! ordinary case, and both are unbounded in the pathological one. The dialog
//! procedure runs on the thread that owns the Properties window, so doing either
//! there would freeze the shell for as long as the disk takes -- the project
//! forbids blocking work on that thread outright. (Registry writes are the one
//! documented exception: `AddPages` already reads settings there, and a handful
//! of `RegSetValueExW` calls are microseconds.)
//!
//! # What crosses the boundary, and what does not
//!
//! A value and an acknowledgement. The worker stores its result in a mutex and
//! then posts a message that carries only a sequence number; the dialog takes the
//! value when it handles that message. No pointer is ever posted, because a
//! message discarded during teardown would leak whatever it pointed at.
//!
//! The message is posted only when the page it belongs to is still alive: the
//! generation counter is the same one the scan's notifications use, and it is
//! bumped on `WM_NCDESTROY`. A worker that finishes after the window is gone
//! therefore stores its result and posts nothing.
//!
//! # Panic containment
//!
//! This is not a COM boundary, so an unwind here cannot abort the process; but a
//! panicking worker must still be *reported* rather than leaving the page waiting
//! for a message that will never come. The body is wrapped in `catch_unwind` and
//! a panic becomes [`TaskError::Panicked`], which the dialog turns into a status
//! line.

#![cfg(windows)]

use crate::session::Shared;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// Why a background task produced no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskError {
    /// The worker panicked. The payload is dropped deliberately: it is not
    /// useful inside `explorer.exe`, and formatting it could allocate.
    Panicked,
    /// The worker thread could not be created.
    SpawnFailed,
}

/// A background task whose result is collected on the dialog thread.
///
/// `T` is plain data by construction (`FileResult`, `usize`, ...), so sharing it
/// across the boundary costs nothing and needs no lifetime.
pub struct Background<T> {
    /// The worker's result, present once it has finished.
    slot: Arc<Mutex<Option<Result<T, TaskError>>>>,
    /// The worker, joined on drop so no thread outlives the page state it was
    /// started from.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl<T> core::fmt::Debug for Background<T> {
    /// Deliberately opaque: the page's state is dumped for diagnostics, and the
    /// worker's payload is neither useful nor printable in general. Whether a
    /// worker is still running is the part a dump needs.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Background")
            .field("running", &self.thread.is_some())
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> Background<T> {
    /// Start `work` on its own thread and post `message` when it finishes.
    ///
    /// `sequence` travels in the message's `lParam`; the dialog compares it with
    /// the sequence it issued, so a result from an action the user has already
    /// superseded is ignored instead of overwriting a newer verdict.
    pub fn spawn<F>(
        work: F,
        message: u32,
        sequence: u32,
        hwnd: isize,
        generation: u64,
        shared: Arc<Shared>,
    ) -> Self
    where
        F: FnOnce() -> T + Send + 'static,
    {
        let slot = Arc::new(Mutex::new(None));
        let worker_slot = Arc::clone(&slot);
        let worker_shared = Arc::clone(&shared);

        let thread = std::thread::Builder::new()
            .name("rusthashtab-task".to_string())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
                let value = match outcome {
                    Ok(value) => Ok(value),
                    Err(_payload) => Err(TaskError::Panicked),
                };
                *worker_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value);

                // The same two checks the scan's sink makes: the page is still
                // the one this task was started for, and its window still
                // exists. `PostMessageW` fails rather than faults for a handle
                // that has gone away, and the message carries integers only.
                if hwnd == 0 || worker_shared.generation.load(Ordering::Acquire) != generation {
                    return;
                }
                // SAFETY: `hwnd` was live when the task was started and the
                // generation check above says the page has not been retired
                // since. The message carries two integers, so a discarded post
                // cannot leak anything.
                unsafe {
                    let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                        Some(windows::Win32::Foundation::HWND(
                            hwnd as *mut core::ffi::c_void,
                        )),
                        message,
                        windows::Win32::Foundation::WPARAM(crate::MESSAGE_MAGIC),
                        windows::Win32::Foundation::LPARAM(sequence as isize),
                    );
                }
            });

        match thread {
            Ok(thread) => Self {
                slot,
                thread: Some(thread),
            },
            Err(_) => {
                // No worker, no message loop event. Record the failure and post
                // it from this thread so the page still learns what happened.
                *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(Err(TaskError::SpawnFailed));
                if hwnd != 0 && shared.generation.load(Ordering::Acquire) == generation {
                    // SAFETY: as above; the handle was live at start and has not
                    // been retired, and the message carries integers only.
                    unsafe {
                        let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                            Some(windows::Win32::Foundation::HWND(
                                hwnd as *mut core::ffi::c_void,
                            )),
                            message,
                            windows::Win32::Foundation::WPARAM(crate::MESSAGE_MAGIC),
                            windows::Win32::Foundation::LPARAM(sequence as isize),
                        );
                    }
                }
                Self { slot, thread: None }
            }
        }
    }

    /// Take the worker's result, if the message has said it is ready.
    ///
    /// `None` means the task is still running (or the message arrived before a
    /// previous `take`), which callers treat as "nothing to do yet".
    pub fn take(&mut self) -> Option<Result<T, TaskError>> {
        self.slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

impl<T> Drop for Background<T> {
    /// A dropped task must not leave a thread behind writing into state the page
    /// is about to free. Joining is bounded: the work is a bounded file read or
    /// write, not an open-ended wait.
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The result is handed over exactly once: a second `take` sees nothing, so
    /// handling a duplicate message cannot act on stale data.
    #[test]
    fn a_result_is_taken_once() {
        let shared = Arc::new(Shared::new());
        // hwnd == 0 makes the post a no-op; this test is about the slot.
        let mut task = Background::spawn(|| 7usize, 0, 0, 0, 0, shared);
        // Wait for the worker by polling the slot rather than sleeping on a
        // message that is deliberately not posted.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(value) = task.take() {
                assert_eq!(value, Ok(7));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "worker never finished"
            );
            std::thread::yield_now();
        }
        assert_eq!(task.take(), None);
    }

    /// A panic is reported, not propagated: this runs on a plain thread rather
    /// than a COM boundary, but the page still has to be told.
    #[test]
    fn a_panicking_worker_is_reported() {
        let shared = Arc::new(Shared::new());
        let mut task = Background::spawn(
            || -> usize { panic!("deliberate test panic") },
            0,
            0,
            0,
            0,
            shared,
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(value) = task.take() {
                assert_eq!(value, Err(TaskError::Panicked));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "worker never finished"
            );
            std::thread::yield_now();
        }
    }
}
